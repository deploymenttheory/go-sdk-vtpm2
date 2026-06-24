// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

// hashExec runs TPM2_Hash and returns the digest and the validation ticket fields.
func hashExec(t *testing.T, tpm *TPM, data []byte, hierarchy uint32) (digest []byte, tkHier uint32, tkDigest []byte) {
	t.Helper()
	var w writer
	w.tpm2b(data)
	w.u16(AlgSHA256)
	w.u32(hierarchy)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCHash, w.bytes())))
	if rc != RCSuccess {
		t.Fatalf("Hash rc = 0x%x", rc)
	}
	r := newReader(p)
	digest = r.tpm2b()
	_ = r.u16() // TPMT_TK_HASHCHECK tag
	tkHier = r.u32()
	tkDigest = r.tpm2b()
	return digest, tkHier, tkDigest
}

func signWithTicket(t *testing.T, tpm *TPM, keyH uint32, digest []byte, tkHier uint32, tkDigest []byte) uint32 {
	t.Helper()
	var w writer
	w.tpm2b(digest)
	w.u16(AlgNull) // inScheme NULL → key's scheme
	w.u16(STHashCheck)
	w.u32(tkHier)
	w.tpm2b(tkDigest)
	_, rc, _ := parseResp(t, tpm.Execute(buildHierarchyCmd(CCSign, keyH, nil, w.bytes())))
	return rc
}

// TestHashDRBG covers #3: the SP800-90A Hash_DRBG that derives primary keys is
// deterministic, independent of read chunking, and seed-sensitive.
func TestHashDRBG(t *testing.T) {
	mk := func() *hashDRBG {
		return newHashDRBG(AlgSHA256, []byte("primary-seed"), []byte("template-hash"), []byte("CreatePrimary"))
	}
	a := make([]byte, 200)
	_, _ = io.ReadFull(mk(), a)
	b := make([]byte, 200)
	_, _ = io.ReadFull(mk(), b)
	if !bytes.Equal(a, b) {
		t.Fatal("Hash_DRBG not deterministic for the same seed")
	}
	d := mk()
	c := make([]byte, 200)
	for i := range c {
		var one [1]byte
		_, _ = io.ReadFull(d, one[:])
		c[i] = one[0]
	}
	if !bytes.Equal(a, c) {
		t.Fatal("Hash_DRBG output depends on read chunking")
	}
	e := make([]byte, 200)
	_, _ = io.ReadFull(newHashDRBG(AlgSHA256, []byte("different-seed")), e)
	if bytes.Equal(a, e) {
		t.Fatal("different seed produced the same DRBG stream")
	}
}

// TestPrivateBlobRandomIV covers #1: the spec-exact wrap uses a random symIv, so
// two wraps of the same sensitive differ, and both still unwrap (TPM 2.0 Part 1
// §23.3).
func TestPrivateBlobRandomIV(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srkH, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	parent, _ := tpm.objects.get(srkH)

	child := &sensitive{Type: AlgKeyedHash, SeedValue: bytes.Repeat([]byte{0x11}, 32), Secret: []byte("sealed")}
	name := []byte("fixed-child-name")
	b1 := wrapSensitive(parent, child, name, rand.Reader)
	b2 := wrapSensitive(parent, child, name, rand.Reader)
	if bytes.Equal(b1, b2) {
		t.Fatal("two wraps are identical — symIv is not random")
	}
	s, ok := unwrapPrivate(parent, b1[2:], name) // b1[2:] strips the TPM2B_PRIVATE size prefix
	if !ok || !bytes.Equal(s.Secret, child.Secret) {
		t.Fatal("unwrap of the spec-exact blob failed")
	}
}

// TestHashCheckTicket covers #6: a valid hashcheck ticket for safe-to-sign data
// under a hierarchy, a null ticket for the NULL hierarchy, and a null ticket when
// the data begins with TPM_GENERATED_VALUE.
func TestHashCheckTicket(t *testing.T) {
	tpm := New()
	startup(t, tpm)

	digest, hier, tk := hashExec(t, tpm, []byte("safe data"), RHOwner)
	if hier != RHOwner || len(tk) == 0 {
		t.Fatalf("expected a valid ticket under a hierarchy; hier=0x%x len=%d", hier, len(tk))
	}
	want := hmacSum(AlgSHA256, tpm.hierarchyProof(RHOwner), be16(STHashCheck), digest)
	if !bytes.Equal(tk, want) {
		t.Fatal("hashcheck ticket is not HMAC(hierarchyProof, ST_HASHCHECK ‖ digest)")
	}

	if _, h2, tk2 := hashExec(t, tpm, []byte("safe data"), RHNull); h2 != RHNull || len(tk2) != 0 {
		t.Fatal("NULL hierarchy must yield a null ticket")
	}
	forged := append(be32(tpmGeneratedValue), []byte("forge")...)
	if _, h3, tk3 := hashExec(t, tpm, forged, RHOwner); h3 != RHNull || len(tk3) != 0 {
		t.Fatal("TPM_GENERATED-prefixed data must yield a null ticket")
	}
}

// TestRestrictedSignNeedsTicket covers #6's signing side: a restricted signing key
// signs only a digest the TPM produced, proven by a valid hashcheck ticket.
func TestRestrictedSignNeedsTicket(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	tmpl := eccSigningTemplate()
	tmpl.Attrs |= ObjRestricted
	keyH := createSigningKey(t, tpm, srk, tmpl)

	digest, tkHier, tkDigest := hashExec(t, tpm, []byte("payload to attest"), RHOwner)

	if rc := signWithTicket(t, tpm, keyH, digest, RHNull, nil); baseRC(rc) != RCTicket {
		t.Fatalf("restricted Sign without a ticket rc = 0x%x, want RC_TICKET (0x%x)", rc, RCTicket)
	}
	if rc := signWithTicket(t, tpm, keyH, digest, tkHier, tkDigest); rc != RCSuccess {
		t.Fatalf("restricted Sign with a valid ticket rc = 0x%x", rc)
	}
}

// TestClearFlushesStorageAndResetsClock covers the completed TPM2_Clear
// (Part 3 §24.6.1): owner/endorsement persistent objects and owner-created NV are
// removed, platform-hierarchy state survives, and the Clock + counters are zeroed.
func TestClearFlushesStorageAndResetsClock(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	evictControl(t, tpm, RHOwner, srk, 0x81000001) // owner persistent (must be flushed)

	// Platform-hierarchy state that must SURVIVE Clear.
	tpm.objects.persistent[0x81800001] = &object{name: []byte("platform-obj")}
	tpm.nv.indices[0x01800020] = &nvIndex{public: nvPublic{Index: 0x01800020, Attrs: NVPlatformCreate}}
	// Owner-created NV (PLATFORMCREATE clear) that must be DELETED.
	tpm.nv.indices[0x01000010] = &nvIndex{public: nvPublic{Index: 0x01000010, Attrs: NVOwnerWrite}}
	tpm.clock.resetCount, tpm.clock.clock, tpm.clock.safe = 7, 12345, 0

	if _, rc, _ := parseResp(t, tpm.Execute(buildHierarchyCmd(CCClear, RHPlatform, nil, nil))); rc != RCSuccess {
		t.Fatalf("Clear rc = 0x%x", rc)
	}
	if _, ok := tpm.objects.get(0x81000001); ok {
		t.Fatal("owner persistent object survived Clear")
	}
	if _, ok := tpm.objects.get(0x81800001); !ok {
		t.Fatal("platform persistent object was wrongly flushed by Clear")
	}
	if _, ok := tpm.nv.get(0x01000010); ok {
		t.Fatal("owner-created NV survived Clear")
	}
	if _, ok := tpm.nv.get(0x01800020); !ok {
		t.Fatal("platform-created NV (PLATFORMCREATE) was wrongly deleted by Clear")
	}
	if tpm.clock.resetCount != 0 || tpm.clock.clock != 0 || tpm.clock.safe != 1 {
		t.Fatalf("clock not reset by Clear: reset=%d clock=%d safe=%d", tpm.clock.resetCount, tpm.clock.clock, tpm.clock.safe)
	}
}

// TestVerifiedTicketKeyedByProof covers #2: the TPM2_VerifySignature ticket is
// keyed by the hierarchy proof, not a volatile internal key.
func TestVerifiedTicketKeyedByProof(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	keyH := createSigningKey(t, tpm, srk, eccSigningTemplate())

	digest := hashSum(AlgSHA256, []byte("to be signed"))
	sig := signDigest(t, tpm, keyH, digest)

	var body writer
	body.u32(keyH)
	body.tpm2b(digest)
	body.raw(sig)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCVerifySignature, body.bytes())))
	if rc != RCSuccess {
		t.Fatalf("VerifySignature rc = 0x%x", rc)
	}
	r := newReader(p)
	_ = r.u16() // STVerified
	_ = r.u32() // hierarchy (RHNull)
	tk := r.tpm2b()
	want := hmacSum(AlgSHA256, tpm.hierarchyProof(RHNull), be16(STVerified), digest)
	if !bytes.Equal(tk, want) {
		t.Fatal("verified ticket is not keyed by the NULL-hierarchy proof")
	}
}
