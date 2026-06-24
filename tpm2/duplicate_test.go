// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"testing"
)

// duplicableTemplate is an ECC signing key that may be duplicated (fixedParent and
// fixedTPM CLEAR) and whose ADMIN-role actions use its authValue.
func duplicableTemplate() public {
	return public{
		Type:    AlgECC,
		NameAlg: AlgSHA256,
		Attrs:   ObjSensitiveDataOrigin | ObjUserWithAuth | ObjSign | ObjNoDA,
		Sym:     symDef{Alg: AlgNull},
		Scheme:  hashScheme{Scheme: AlgECDSA, HashAlg: AlgSHA256},
		Curve:   ECCNistP256,
		KDF:     hashScheme{Scheme: AlgNull},
	}
}

func onePasswordAuth() []byte {
	var auth writer
	auth.u32(RHPW)
	auth.tpm2b(nil)
	auth.u8(1)
	auth.tpm2b(nil)
	var w writer
	w.u32(uint32(len(auth.bytes())))
	w.raw(auth.bytes())
	return w.bytes()
}

// duplicate runs TPM2_Duplicate of objH to newParent (no inner wrap) and returns
// the duplicate blob and outSymSeed.
func duplicate(t *testing.T, tpm *TPM, objH, newParent uint32) (dup, seed []byte) {
	t.Helper()
	var b writer
	b.u32(objH)
	b.u32(newParent)
	b.raw(onePasswordAuth())
	b.tpm2b(nil)   // encryptionKeyIn
	b.u16(AlgNull) // symmetricAlg
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCDuplicate, b.bytes())))
	if rc != RCSuccess {
		t.Fatalf("Duplicate rc = 0x%x", rc)
	}
	r := newReader(p)
	_ = r.u32()   // parameterSize
	_ = r.tpm2b() // encryptionKeyOut
	dup = r.tpm2b()
	seed = r.tpm2b()
	return dup, seed
}

// importObj runs TPM2_Import of (public, dup, seed) under parent and returns the
// re-wrapped private content.
func importObj(t *testing.T, tpm *TPM, parent uint32, public public, dup, seed []byte) []byte {
	t.Helper()
	var b writer
	b.u32(parent)
	b.raw(onePasswordAuth())
	b.tpm2b(nil) // encryptionKey
	public.marshal2B(&b)
	b.tpm2b(dup)
	b.tpm2b(seed)
	b.u16(AlgNull) // symmetricAlg
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCImport, b.bytes())))
	if rc != RCSuccess {
		t.Fatalf("Import rc = 0x%x", rc)
	}
	r := newReader(p)
	_ = r.u32()
	return r.tpm2b()
}

// TestDuplicateImport duplicates an object to a new parent, imports it there, and
// loads it — the full migration round-trip (TPM 2.0 Part 3, §13).
func TestDuplicateImport(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	objH := createSigningKey(t, tpm, srk, duplicableTemplate())
	obj, _ := tpm.objects.get(objH)
	dest, _, _ := createPrimary(t, tpm, RHPlatform, eccStorageTemplate())

	dup, seed := duplicate(t, tpm, objH, dest)
	outPrivate := importObj(t, tpm, dest, obj.public, dup, seed)

	h, rc := loadObject(t, tpm, dest, outPrivate, obj.public)
	if rc != RCSuccess {
		t.Fatalf("Load imported object rc = 0x%x", rc)
	}
	loaded, _ := tpm.objects.get(h)
	if !bytes.Equal(loaded.name, obj.name) {
		t.Fatal("imported object Name differs from the original")
	}
	if !bytes.Equal(loaded.sensitive.Secret, obj.sensitive.Secret) {
		t.Fatal("imported sensitive key material differs from the original")
	}
}

// TestRewrap duplicates to parent A, rewraps A→B, then imports/loads under B.
func TestRewrap(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	objH := createSigningKey(t, tpm, srk, duplicableTemplate())
	obj, _ := tpm.objects.get(objH)
	pA, _, _ := createPrimary(t, tpm, RHEndorsement, eccStorageTemplate())
	pB, _, _ := createPrimary(t, tpm, RHPlatform, eccStorageTemplate())

	dup, seedA := duplicate(t, tpm, objH, pA)

	// Rewrap from pA to pB.
	var b writer
	b.u32(pA)
	b.u32(pB)
	b.raw(onePasswordAuth())
	b.tpm2b(dup)      // inDuplicate
	b.tpm2b(obj.name) // name
	b.tpm2b(seedA)    // inSymSeed
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCRewrap, b.bytes())))
	if rc != RCSuccess {
		t.Fatalf("Rewrap rc = 0x%x", rc)
	}
	r := newReader(p)
	_ = r.u32()
	outDup := r.tpm2b()
	seedB := r.tpm2b()

	outPrivate := importObj(t, tpm, pB, obj.public, outDup, seedB)
	if h, rc := loadObject(t, tpm, pB, outPrivate, obj.public); rc != RCSuccess {
		t.Fatalf("Load after rewrap rc = 0x%x", rc)
	} else if loaded, _ := tpm.objects.get(h); !bytes.Equal(loaded.name, obj.name) {
		t.Fatal("rewrapped object Name differs from the original")
	}
}
