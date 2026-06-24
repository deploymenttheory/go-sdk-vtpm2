// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"testing"
)

// TestSimplePolicy3dDigests checks the digest-extend assertions added in 3d.
func TestSimplePolicy3dDigests(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	zero := make([]byte, 32)
	pHash := bytes.Repeat([]byte{0xCD}, 32)
	objName := bytes.Repeat([]byte{0x11}, 34)
	parentName := bytes.Repeat([]byte{0x22}, 34)

	// PolicyParameters: H(0 ‖ CC ‖ pHash).
	var pp writer
	pp.tpm2b(pHash)
	if got := runPolicy(t, tpm, CCPolicyParameters, pp.bytes()); !bytes.Equal(got, hashSum(AlgSHA256, zero, be32(CCPolicyParameters), pHash)) {
		t.Fatal("PolicyParameters digest mismatch")
	}

	// PolicyCapability: H(0 ‖ CC ‖ H(operandB ‖ offset ‖ operation ‖ capability ‖ property)).
	operandB := []byte{0, 0, 0, 5}
	var pc writer
	pc.tpm2b(operandB)
	pc.u16(0)          // offset
	pc.u16(0)          // operation EQ
	pc.u32(0x00000006) // capability TPM_CAP_TPM_PROPERTIES
	pc.u32(0x00000100) // property
	args := hashSum(AlgSHA256, operandB, be16(0), be16(0), be32(0x00000006), be32(0x00000100))
	if got := runPolicy(t, tpm, CCPolicyCapability, pc.bytes()); !bytes.Equal(got, hashSum(AlgSHA256, zero, be32(CCPolicyCapability), args)) {
		t.Fatal("PolicyCapability digest mismatch")
	}

	// PolicyDuplicationSelect with includeObject SET.
	var pd writer
	pd.tpm2b(objName)
	pd.tpm2b(parentName)
	pd.u8(1)
	want := hashSum(AlgSHA256, zero, be32(CCPolicyDuplicationSelect), objName, parentName, []byte{1})
	if got := runPolicy(t, tpm, CCPolicyDuplicationSelect, pd.bytes()); !bytes.Equal(got, want) {
		t.Fatal("PolicyDuplicationSelect (include) digest mismatch")
	}

	// PolicyDuplicationSelect with includeObject CLEAR omits objectName.
	var pd0 writer
	pd0.tpm2b(objName)
	pd0.tpm2b(parentName)
	pd0.u8(0)
	want0 := hashSum(AlgSHA256, zero, be32(CCPolicyDuplicationSelect), parentName, []byte{0})
	if got := runPolicy(t, tpm, CCPolicyDuplicationSelect, pd0.bytes()); !bytes.Equal(got, want0) {
		t.Fatal("PolicyDuplicationSelect (no include) digest mismatch")
	}
}

// TestPolicyTicketReplay runs PolicySecret with an expiration to mint a ticket,
// then replays it with PolicyTicket and confirms the same digest results
// (TPM 2.0 Part 3, §23.4-23.5).
func TestPolicyTicketReplay(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	policyRef := []byte("ticket-ref")
	name := permanentName(RHEndorsement)

	// PolicySecret with a non-zero expiration ⇒ a replayable ticket.
	s1 := startSession(t, tpm, sePolicy, AlgSHA256)
	var body writer
	body.u32(RHEndorsement)
	body.u32(s1)
	var auth writer
	auth.u32(RHPW)
	auth.tpm2b(nil)
	auth.u8(1)
	auth.tpm2b(nil)
	body.u32(uint32(len(auth.bytes())))
	body.raw(auth.bytes())
	body.tpm2b(nil) // nonceTPM
	body.tpm2b(nil) // cpHashA
	body.tpm2b(policyRef)
	body.u32(60) // expiration (non-zero)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCPolicySecret, body.bytes())))
	if rc != RCSuccess {
		t.Fatalf("PolicySecret rc = 0x%x", rc)
	}
	pr := newReader(p)
	_ = pr.u32() // parameterSize
	timeout := pr.tpm2b()
	tkTag := pr.u16()
	tkHier := pr.u32()
	tkDigest := pr.tpm2b()
	if len(tkDigest) == 0 {
		t.Fatal("expected a non-NULL ticket for a non-zero expiration")
	}
	want := policyGetDigest(t, tpm, s1)

	// Replay the ticket on a fresh session.
	s2 := startSession(t, tpm, sePolicy, AlgSHA256)
	var tk writer
	tk.tpm2b(timeout)
	tk.tpm2b(nil) // cpHashA
	tk.tpm2b(policyRef)
	tk.tpm2b(name) // authName
	tk.u16(tkTag)
	tk.u32(tkHier)
	tk.tpm2b(tkDigest)
	if _, rc, _ := parseResp(t, tpm.Execute(policyCmd(CCPolicyTicket, s2, tk.bytes()))); rc != RCSuccess {
		t.Fatalf("PolicyTicket rc = 0x%x", rc)
	}
	if got := policyGetDigest(t, tpm, s2); !bytes.Equal(got, want) {
		t.Fatalf("PolicyTicket digest = %x, want %x (PolicySecret)", got, want)
	}
}

// TestPolicyAuthorizeNV approves the accumulated policy from a TPMT_HA stored in
// an NV Index (TPM 2.0 Part 3, §23.17).
func TestPolicyAuthorizeNV(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	const nvH = 0x01000030
	defineSpace(t, tpm, RHOwner, nvH, nvOrdinary, NVOwnerWrite|NVOwnerRead, 34, nil)

	// Build a non-trivial policy on the session.
	s := startSession(t, tpm, sePolicy, AlgSHA256)
	if _, rc, _ := parseResp(t, tpm.Execute(policyCmd(CCPolicyAuthValue, s, nil))); rc != RCSuccess {
		t.Fatalf("PolicyAuthValue rc = 0x%x", rc)
	}
	approved := policyGetDigest(t, tpm, s)

	// Store TPMT_HA(SHA256, approved) in the NV Index.
	nvData := append(be16(AlgSHA256), approved...)
	var wp writer
	wp.tpm2b(nvData)
	wp.u16(0)
	if _, rc, _ := parseResp(t, tpm.Execute(nvCmd(CCNVWrite, RHOwner, nvH, nil, wp.bytes()))); rc != RCSuccess {
		t.Fatalf("NV_Write rc = 0x%x", rc)
	}
	idx, _ := tpm.nv.get(nvH)

	// PolicyAuthorizeNV: 3 handles (authHandle=owner, nvIndex, policySession).
	var body writer
	body.u32(RHOwner)
	body.u32(nvH)
	body.u32(s)
	var auth writer
	auth.u32(RHPW)
	auth.tpm2b(nil)
	auth.u8(1)
	auth.tpm2b(nil)
	body.u32(uint32(len(auth.bytes())))
	body.raw(auth.bytes())
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCPolicyAuthorizeNV, body.bytes()))); rc != RCSuccess {
		t.Fatalf("PolicyAuthorizeNV rc = 0x%x", rc)
	}
	// Digest reset to zero then folded with the NV Index Name.
	want := hashSum(AlgSHA256, make([]byte, 32), be32(CCPolicyAuthorizeNV), idx.name)
	if got := policyGetDigest(t, tpm, s); !bytes.Equal(got, want) {
		t.Fatalf("PolicyAuthorizeNV digest = %x, want %x", got, want)
	}
}
