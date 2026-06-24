// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"testing"
)

// hmacKeyTemplate is a keyed-hash HMAC-SHA256 signing key (the TPM generates the
// key material).
func hmacKeyTemplate() public {
	return public{
		Type:    AlgKeyedHash,
		NameAlg: AlgSHA256,
		Attrs:   ObjFixedTPM | ObjFixedParent | ObjSensitiveDataOrigin | ObjUserWithAuth | ObjSign | ObjNoDA,
		Scheme:  hashScheme{Scheme: AlgHMAC, HashAlg: AlgSHA256},
	}
}

func hashSeqStart(t *testing.T, tpm *TPM, hashAlg uint16) uint32 {
	t.Helper()
	var b writer
	b.tpm2b(nil) // auth
	b.u16(hashAlg)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCHashSequenceStart, b.bytes())))
	if rc != RCSuccess {
		t.Fatalf("HashSequenceStart rc = 0x%x", rc)
	}
	return newReader(p).u32()
}

func seqUpdate(t *testing.T, tpm *TPM, h uint32, data []byte) {
	t.Helper()
	var b writer
	b.tpm2b(data)
	if _, rc, _ := parseResp(t, tpm.Execute(buildHierarchyCmd(CCSequenceUpdate, h, nil, b.bytes()))); rc != RCSuccess {
		t.Fatalf("SequenceUpdate rc = 0x%x", rc)
	}
}

func seqComplete(t *testing.T, tpm *TPM, h uint32, data []byte, hierarchy uint32) []byte {
	t.Helper()
	var b writer
	b.tpm2b(data)
	b.u32(hierarchy)
	_, rc, p := parseResp(t, tpm.Execute(buildHierarchyCmd(CCSequenceComplete, h, nil, b.bytes())))
	if rc != RCSuccess {
		t.Fatalf("SequenceComplete rc = 0x%x", rc)
	}
	r := newReader(p)
	_ = r.u32() // parameterSize
	return r.tpm2b()
}

// TestHashSequence builds a digest across three updates and checks it equals the
// one-shot hash of the concatenation (TPM 2.0 Part 3, §17.3-17.5).
func TestHashSequence(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	h := hashSeqStart(t, tpm, AlgSHA256)
	seqUpdate(t, tpm, h, []byte("hello "))
	seqUpdate(t, tpm, h, []byte("world"))
	got := seqComplete(t, tpm, h, []byte("!"), RHNull)
	if want := hashSum(AlgSHA256, []byte("hello world!")); !bytes.Equal(got, want) {
		t.Fatalf("hash sequence = %x, want %x", got, want)
	}
	// The sequence handle is flushed on completion.
	if _, ok := tpm.sequences.get(h); ok {
		t.Fatal("sequence not flushed after SequenceComplete")
	}
}

// TestHMACOneShotVsSequence confirms the one-shot TPM2_HMAC and an HMAC sequence
// over the same data and key produce the same MAC.
func TestHMACOneShotVsSequence(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	keyH := createSigningKey(t, tpm, srk, hmacKeyTemplate())
	data := []byte("message to authenticate with HMAC")

	// One-shot TPM2_HMAC (hashAlg NULL ⇒ use the key's scheme).
	var hb writer
	hb.tpm2b(data)
	hb.u16(AlgNull)
	_, rc, p := parseResp(t, tpm.Execute(buildHierarchyCmd(CCHMAC, keyH, nil, hb.bytes())))
	if rc != RCSuccess {
		t.Fatalf("HMAC rc = 0x%x", rc)
	}
	r := newReader(p)
	_ = r.u32()
	oneShot := r.tpm2b()

	// HMAC sequence over the same data, split across updates.
	var sb writer
	sb.tpm2b(nil) // sequence auth
	sb.u16(AlgNull)
	_, rc2, sp := parseResp(t, tpm.Execute(buildHierarchyCmd(CCHMACStart, keyH, nil, sb.bytes())))
	if rc2 != RCSuccess {
		t.Fatalf("HMAC_Start rc = 0x%x", rc2)
	}
	sh := newReader(sp).u32() // response handle = sequenceHandle
	seqUpdate(t, tpm, sh, data[:10])
	seqMac := seqComplete(t, tpm, sh, data[10:], RHNull)

	if !bytes.Equal(oneShot, seqMac) {
		t.Fatalf("HMAC one-shot %x != sequence %x", oneShot, seqMac)
	}
}

// TestEventSequence runs an event sequence and confirms it returns a digest per
// PCR bank and extends the named PCR (TPM 2.0 Part 3, §17.6).
func TestEventSequence(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	before := append([]byte(nil), tpm.pcr.banks[AlgSHA256][0]...)

	h := hashSeqStart(t, tpm, AlgNull) // hashAlg NULL ⇒ event sequence
	seqUpdate(t, tpm, h, []byte("measured "))

	// EventSequenceComplete: 2 handles (pcrHandle=0, sequenceHandle), 2 password sessions.
	var body writer
	body.u32(0) // pcrHandle = PCR[0]
	body.u32(h) // sequenceHandle
	var auth writer
	for i := 0; i < 2; i++ {
		auth.u32(RHPW)
		auth.tpm2b(nil)
		auth.u8(1) // continueSession
		auth.tpm2b(nil)
	}
	body.u32(uint32(len(auth.bytes())))
	body.raw(auth.bytes())
	body.tpm2b([]byte("boot event"))
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCEventSequenceComplete, body.bytes())))
	if rc != RCSuccess {
		t.Fatalf("EventSequenceComplete rc = 0x%x", rc)
	}

	r := newReader(p)
	_ = r.u32() // parameterSize
	count := r.u32()
	if int(count) != len(supportedPCRBanks) {
		t.Fatalf("digest count = %d, want %d", count, len(supportedPCRBanks))
	}
	full := append([]byte("measured "), []byte("boot event")...)
	var sha256Digest []byte
	for i := 0; i < int(count); i++ {
		alg := r.u16()
		d := r.bytes(hashSize(alg))
		if alg == AlgSHA256 {
			sha256Digest = d
		}
	}
	if want := hashSum(AlgSHA256, full); !bytes.Equal(sha256Digest, want) {
		t.Fatalf("event SHA-256 digest = %x, want %x", sha256Digest, want)
	}
	// PCR[0] SHA-256 must have been extended with the event digest.
	if after := tpm.pcr.banks[AlgSHA256][0]; bytes.Equal(after, before) {
		t.Fatal("PCR[0] was not extended by the event sequence")
	}
	if want := hashSum(AlgSHA256, before, sha256Digest); !bytes.Equal(tpm.pcr.banks[AlgSHA256][0], want) {
		t.Fatal("PCR[0] extend value does not match H(old ‖ eventDigest)")
	}
}
