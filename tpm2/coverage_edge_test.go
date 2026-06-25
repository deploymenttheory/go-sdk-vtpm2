// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"testing"
)

// TestSignVerifyP384 exercises the P-384 curve helpers (curveFor, ecdhCurveFor,
// padLeft, eccPointFromScalar) by signing and verifying on NIST P-384.
func TestSignVerifyP384(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	tmpl := eccSigningTemplate()
	tmpl.Curve = ECCNistP384
	tmpl.Scheme = hashScheme{Scheme: AlgECDSA, HashAlg: AlgSHA384}
	keyH := createSigningKey(t, tpm, srk, tmpl)

	digest := bytes.Repeat([]byte{0x71}, 48) // SHA-384 digest
	sig := signDigest(t, tpm, keyH, digest)
	if rc := verifySig(t, tpm, keyH, digest, sig); rc != RCSuccess {
		t.Fatalf("P-384 verify rc = 0x%x", rc)
	}
}

// TestSignVerifyRSAPSS exercises the RSA-PSS signing/verification branches.
func TestSignVerifyRSAPSS(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	tmpl := rsaSigningTemplate()
	tmpl.Scheme = hashScheme{Scheme: AlgRSAPSS, HashAlg: AlgSHA256}
	keyH := createSigningKey(t, tpm, srk, tmpl)

	digest := bytes.Repeat([]byte{0x44}, 32)
	sig := signDigest(t, tpm, keyH, digest)
	if rc := verifySig(t, tpm, keyH, digest, sig); rc != RCSuccess {
		t.Fatalf("RSA-PSS verify rc = 0x%x", rc)
	}
}

// TestCertifyX509RSA exercises the RSA branches of objectPublicKey/sigAlgIdentifier.
func TestCertifyX509RSA(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	signKey := createSigningKey(t, tpm, srk, rsaSigningTemplate())
	obj := createSigningKey(t, tpm, srk, rsaSigningTemplate())
	partial := buildPartialCert(t, 0x80, 1) // digitalSignature

	var b writer
	b.u32(obj)
	b.u32(signKey)
	b.raw(twoPasswordAuth())
	b.tpm2b(nil)   // reserved
	b.u16(AlgNull) // inScheme
	b.tpm2b(partial)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCCertifyX509, b.bytes())))
	if rc != RCSuccess {
		t.Fatalf("CertifyX509(RSA) rc = 0x%x", rc)
	}
	r := newReader(p)
	params := r.bytes(int(r.u32()))
	pr := newReader(params)
	_ = pr.tpm2b() // addedToCertificate
	tbsDigest := pr.tpm2b()
	sig := pr.bytes(pr.remaining())
	if verifySig(t, tpm, signKey, tbsDigest, sig) != RCSuccess {
		t.Fatal("CertifyX509(RSA) signature did not verify")
	}
}

// TestEncryptDecryptModeMismatch confirms a mode conflicting with the key's fixed
// mode is rejected (TPM_RC_MODE), and that mode=NULL on a NULL-mode key fails.
func TestEncryptDecryptModeMismatch(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	keyH := createSigningKey(t, tpm, srk, symCipherTemplate(AlgCFB)) // fixed mode CFB
	iv := make([]byte, 16)

	// Caller asks for CBC, but the key fixes CFB ⇒ RC_MODE.
	var b writer
	b.u32(keyH)
	b.raw(onePasswordAuth())
	b.u8(0)       // decrypt
	b.u16(AlgCBC) // conflicting mode
	b.tpm2b(iv)   // ivIn
	b.tpm2b([]byte("0123456789abcdef"))
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCEncryptDecrypt, b.bytes()))); baseRC(rc) != RCMode {
		t.Fatalf("mode-mismatch EncryptDecrypt rc = 0x%x, want RC_MODE", rc)
	}
}

// TestSignNonSigningKey covers the not-a-signing-key error branch.
func TestSignNonSigningKey(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate()) // a storage (decrypt) key, not sign

	var b writer
	b.u32(srk)
	b.raw(onePasswordAuth())
	b.tpm2b(bytes.Repeat([]byte{0x01}, 32)) // digest
	b.u16(AlgNull)                          // inScheme
	b.u16(STHashCheck)
	b.u32(RHNull)
	b.tpm2b(nil)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCSign, b.bytes()))); baseRC(rc) != RCAttributes {
		t.Fatalf("Sign with non-signing key rc = 0x%x, want RC_ATTRIBUTES", rc)
	}
}

// TestPolicyORBounds covers the branch-count limits of PolicyOR.
func TestPolicyORBounds(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	s := startSession(t, tpm, sePolicy, AlgSHA256)
	// A single branch is below the minimum of two ⇒ rejected.
	var one writer
	one.u32(1)
	one.tpm2b(make([]byte, 32))
	if _, rc, _ := parseResp(t, tpm.Execute(policyCmd(CCPolicyOR, s, one.bytes()))); rc == RCSuccess {
		t.Fatal("PolicyOR with one branch unexpectedly succeeded")
	}
	// Nine branches exceed the maximum of eight ⇒ rejected.
	var many writer
	many.u32(9)
	for i := 0; i < 9; i++ {
		many.tpm2b(make([]byte, 32))
	}
	if _, rc, _ := parseResp(t, tpm.Execute(policyCmd(CCPolicyOR, s, many.bytes()))); rc == RCSuccess {
		t.Fatal("PolicyOR with nine branches unexpectedly succeeded")
	}
}
