// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func eccSigningTemplate() public {
	return public{
		Type:    AlgECC,
		NameAlg: AlgSHA256,
		Attrs:   ObjFixedTPM | ObjFixedParent | ObjSensitiveDataOrigin | ObjUserWithAuth | ObjSign,
		Sym:     symDef{Alg: AlgNull},
		Scheme:  hashScheme{Scheme: AlgECDSA, HashAlg: AlgSHA256},
		Curve:   ECCNistP256,
		KDF:     hashScheme{Scheme: AlgNull},
	}
}

func rsaSigningTemplate() public {
	return public{
		Type:    AlgRSA,
		NameAlg: AlgSHA256,
		Attrs:   ObjFixedTPM | ObjFixedParent | ObjSensitiveDataOrigin | ObjUserWithAuth | ObjSign,
		Sym:     symDef{Alg: AlgNull},
		Scheme:  hashScheme{Scheme: AlgRSASSA, HashAlg: AlgSHA256},
		KeyBits: 2048,
	}
}

// createSigningKey creates and loads a child signing key under parent.
func createSigningKey(t *testing.T, tpm *TPM, parent uint32, tmpl public) uint32 {
	t.Helper()
	var inner writer
	inner.tpm2b(nil)
	inner.tpm2b(nil)
	var params writer
	params.tpm2b(inner.bytes())
	tmpl.marshal2B(&params)
	params.tpm2b(nil)
	params.u32(0)
	_, rc, p := parseResp(t, tpm.Execute(buildHierarchyCmd(CCCreate, parent, nil, params.bytes())))
	if rc != RCSuccess {
		t.Fatalf("Create signing key rc = 0x%x", rc)
	}
	r := newReader(p)
	_ = r.u32()
	priv := r.tpm2b()
	pub := readPublic2B(r)
	h, rc2 := loadObject(t, tpm, parent, priv, pub)
	if rc2 != RCSuccess {
		t.Fatalf("Load signing key rc = 0x%x", rc2)
	}
	return h
}

// signDigest runs TPM2_Sign and returns the marshalled TPMT_SIGNATURE.
func signDigest(t *testing.T, tpm *TPM, keyH uint32, digest []byte) []byte {
	t.Helper()
	var params writer
	params.tpm2b(digest)
	params.u16(AlgNull) // inScheme NULL → use the key's scheme
	params.u16(STHashCheck)
	params.u32(RHNull)
	params.tpm2b(nil) // validation
	_, rc, p := parseResp(t, tpm.Execute(buildHierarchyCmd(CCSign, keyH, nil, params.bytes())))
	if rc != RCSuccess {
		t.Fatalf("Sign rc = 0x%x", rc)
	}
	r := newReader(p)
	return r.bytes(int(r.u32())) // the response parameter area is the TPMT_SIGNATURE
}

// verifySig runs TPM2_VerifySignature and reports whether it accepted.
func verifySig(t *testing.T, tpm *TPM, keyH uint32, digest, tpmtSig []byte) uint32 {
	t.Helper()
	var body writer
	body.u32(keyH)
	body.tpm2b(digest)
	body.raw(tpmtSig)
	_, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCVerifySignature, body.bytes())))
	return rc
}

// TestUnseal is the BitLocker VMK release: seal → load → unseal.
func TestUnseal(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	vmk := []byte("volume-master-key-secret")
	priv, pub := createSealed(t, tpm, srk, vmk)
	h, _ := loadObject(t, tpm, srk, priv, pub)

	var auth writer
	auth.u32(RHPW)
	auth.u16(0)
	auth.u8(0)
	auth.u16(0)
	var body writer
	body.u32(h)
	body.u32(uint32(len(auth.bytes())))
	body.raw(auth.bytes())
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCUnseal, body.bytes())))
	if rc != RCSuccess {
		t.Fatalf("Unseal rc = 0x%x", rc)
	}
	r := newReader(p)
	_ = r.u32() // parameterSize
	if out := r.tpm2b(); !bytes.Equal(out, vmk) {
		t.Fatalf("unsealed data = %q, want %q", out, vmk)
	}
}

func TestSignVerifyECC(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	keyH := createSigningKey(t, tpm, srk, eccSigningTemplate())

	digest := bytes.Repeat([]byte{0x33}, 32)
	sig := signDigest(t, tpm, keyH, digest)
	if rc := verifySig(t, tpm, keyH, digest, sig); rc != RCSuccess {
		t.Fatalf("VerifySignature rc = 0x%x, want success", rc)
	}
	// A different digest must fail verification.
	if rc := verifySig(t, tpm, keyH, bytes.Repeat([]byte{0x44}, 32), sig); rc != RCSignature {
		t.Fatalf("verify(wrong digest) rc = 0x%x, want SIGNATURE", rc)
	}
}

func TestSignVerifyRSA(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	keyH := createSigningKey(t, tpm, srk, rsaSigningTemplate())

	digest := bytes.Repeat([]byte{0x55}, 32)
	sig := signDigest(t, tpm, keyH, digest)
	if rc := verifySig(t, tpm, keyH, digest, sig); rc != RCSuccess {
		t.Fatalf("RSA VerifySignature rc = 0x%x", rc)
	}
}

func TestHashCommand(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	var params writer
	params.tpm2b([]byte("abc"))
	params.u16(AlgSHA256)
	params.u32(RHNull)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCHash, params.bytes())))
	if rc != RCSuccess {
		t.Fatalf("Hash rc = 0x%x", rc)
	}
	r := newReader(p)
	out := r.tpm2b()
	want := sha256.Sum256([]byte("abc"))
	if !bytes.Equal(out, want[:]) {
		t.Fatalf("Hash = %x, want %x", out, want)
	}
}
