// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"testing"
)

// TestPolicySecret binds a policy to proof of the endorsement hierarchy's
// authValue and checks the two-step PolicyUpdate digest (Part 3, §23.4).
func TestPolicySecret(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	s := startSession(t, tpm, sePolicy, AlgSHA256)
	policyRef := []byte("secret-ref")

	var body writer
	body.u32(RHEndorsement) // authHandle
	body.u32(s)             // policySession
	var auth writer
	auth.u32(RHPW)
	auth.tpm2b(nil)
	auth.u8(1)
	auth.tpm2b(nil)
	body.u32(uint32(len(auth.bytes())))
	body.raw(auth.bytes())
	body.tpm2b(nil)       // nonceTPM
	body.tpm2b(nil)       // cpHashA
	body.tpm2b(policyRef) // policyRef
	body.u32(0)           // expiration
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCPolicySecret, body.bytes()))); rc != RCSuccess {
		t.Fatalf("PolicySecret rc = 0x%x", rc)
	}

	name := permanentName(RHEndorsement)
	d := hashSum(AlgSHA256, make([]byte, 32), be32(CCPolicySecret), name) // H(0 ‖ CC ‖ name)
	want := hashSum(AlgSHA256, d, policyRef)                              // H(… ‖ ref)
	if got := policyGetDigest(t, tpm, s); !bytes.Equal(got, want) {
		t.Fatalf("PolicySecret digest = %x, want %x", got, want)
	}
}

// TestPolicySigned binds a policy to a signature by an authority over the session
// authorization hash (Part 3, §23.3).
func TestPolicySigned(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	keyH := createSigningKey(t, tpm, srk, eccSigningTemplate())
	key, _ := tpm.objects.get(keyH)
	policyRef := []byte("signed-ref")
	s := startSession(t, tpm, sePolicy, AlgSHA256)

	// aHash = H(nonceTPM ‖ expiration ‖ cpHashA ‖ policyRef); all empty but expiration=0 and policyRef.
	aHash := hashSum(AlgSHA256, nil, be32(0), nil, policyRef)
	sig := signDigest(t, tpm, keyH, aHash) // TPMT_SIGNATURE over aHash

	var body writer
	body.u32(keyH) // authObject
	body.u32(s)    // policySession
	body.tpm2b(nil)
	body.tpm2b(nil)
	body.tpm2b(policyRef)
	body.u32(0) // expiration
	body.raw(sig)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCPolicySigned, body.bytes()))); rc != RCSuccess {
		t.Fatalf("PolicySigned rc = 0x%x", rc)
	}

	d := hashSum(AlgSHA256, make([]byte, 32), be32(CCPolicySigned), key.name)
	want := hashSum(AlgSHA256, d, policyRef)
	if got := policyGetDigest(t, tpm, s); !bytes.Equal(got, want) {
		t.Fatalf("PolicySigned digest = %x, want %x", got, want)
	}

	// A bad signature is rejected.
	s2 := startSession(t, tpm, sePolicy, AlgSHA256)
	badSig := append([]byte(nil), sig...)
	badSig[len(badSig)-1] ^= 0xFF
	var bb writer
	bb.u32(keyH)
	bb.u32(s2)
	bb.tpm2b(nil)
	bb.tpm2b(nil)
	bb.tpm2b(policyRef)
	bb.u32(0)
	bb.raw(badSig)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCPolicySigned, bb.bytes()))); baseRC(rc) != RCSignature {
		t.Fatalf("bad-signature PolicySigned rc = 0x%x, want RC_SIGNATURE", rc)
	}
}

// TestPolicyAuthorize replaces an accumulated (empty) policy with one an authority
// has signed, verified via a TPMT_TK_VERIFIED ticket (Part 3, §23.16).
func TestPolicyAuthorize(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	keyH := createSigningKey(t, tpm, srk, eccSigningTemplate())
	key, _ := tpm.objects.get(keyH)
	policyRef := []byte("authz-ref")

	approvedPolicy := make([]byte, 32) // a fresh policy session's Zero Digest
	aHash := hashSum(AlgSHA256, approvedPolicy, policyRef)
	sig := signDigest(t, tpm, keyH, aHash)

	// VerifySignature(aHash, sig) → TPMT_TK_VERIFIED ticket.
	var vb writer
	vb.u32(keyH)
	vb.tpm2b(aHash)
	vb.raw(sig)
	_, rc, vp := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCVerifySignature, vb.bytes())))
	if rc != RCSuccess {
		t.Fatalf("VerifySignature rc = 0x%x", rc)
	}
	vr := newReader(vp)
	tkTag := vr.u16()
	tkHier := vr.u32()
	tkDigest := vr.tpm2b()

	s := startSession(t, tpm, sePolicy, AlgSHA256) // digest == approvedPolicy (zero)
	var body writer
	body.u32(s)
	body.tpm2b(approvedPolicy)
	body.tpm2b(policyRef)
	body.tpm2b(key.name) // keySign
	body.u16(tkTag)
	body.u32(tkHier)
	body.tpm2b(tkDigest)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCPolicyAuthorize, body.bytes()))); rc != RCSuccess {
		t.Fatalf("PolicyAuthorize rc = 0x%x", rc)
	}

	d := hashSum(AlgSHA256, make([]byte, 32), be32(CCPolicyAuthorize), key.name)
	want := hashSum(AlgSHA256, d, policyRef)
	if got := policyGetDigest(t, tpm, s); !bytes.Equal(got, want) {
		t.Fatalf("PolicyAuthorize digest = %x, want %x", got, want)
	}
}
