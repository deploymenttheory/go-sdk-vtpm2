// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"testing"
)

// counterTimerParams marshals the PolicyCounterTimer parameters.
func counterTimerParams(operandB []byte, offset, op uint16) []byte {
	var w writer
	w.tpm2b(operandB)
	w.u16(offset)
	w.u16(op)
	return w.bytes()
}

// TestPolicyCounterTimer checks the digest formula and the comparison against the
// TPMS_TIME_INFO (TPM 2.0 Part 3, §23.6).
func TestPolicyCounterTimer(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	zero := make([]byte, 32)
	operandB := make([]byte, 8) // compare against 0

	// Trial session: digest = H(0…0 ‖ CC ‖ H(operandB ‖ offset ‖ operation)).
	got := runPolicy(t, tpm, CCPolicyCounterTimer, counterTimerParams(operandB, 0, 0x0007)) // UNSIGNED_GE
	args := hashSum(AlgSHA256, operandB, be16(0), be16(0x0007))
	if want := hashSum(AlgSHA256, zero, be32(CCPolicyCounterTimer), args); !bytes.Equal(got, want) {
		t.Fatalf("PolicyCounterTimer digest = %x, want %x", got, want)
	}

	// Real policy session: time (offset 0) >= 0 succeeds.
	s := startSession(t, tpm, sePolicy, AlgSHA256)
	if _, rc, _ := parseResp(t, tpm.Execute(policyCmd(CCPolicyCounterTimer, s, counterTimerParams(operandB, 0, 0x0007)))); rc != RCSuccess {
		t.Fatalf("time >= 0 rc = 0x%x, want success", rc)
	}
	// time > 0xFFFF…FF fails the comparison.
	big := bytes.Repeat([]byte{0xFF}, 8)
	s2 := startSession(t, tpm, sePolicy, AlgSHA256)
	if _, rc, _ := parseResp(t, tpm.Execute(policyCmd(CCPolicyCounterTimer, s2, counterTimerParams(big, 0, 0x0003)))); baseRC(rc) != RCPolicyFail {
		t.Fatalf("time > max rc = 0x%x, want RC_POLICY_FAIL", rc)
	}
}

// policyNVCmd frames a 3-handle TPM2_PolicyNV with one password session for the
// authorizing handle.
func policyNVCmd(authHi, nvIndex, policySession uint32, operandB []byte, offset, op uint16) []byte {
	var body writer
	body.u32(authHi)
	body.u32(nvIndex)
	body.u32(policySession)
	var auth writer
	auth.u32(RHPW)
	auth.tpm2b(nil)
	auth.u8(1)
	auth.tpm2b(nil)
	body.u32(uint32(len(auth.bytes())))
	body.raw(auth.bytes())
	body.tpm2b(operandB)
	body.u16(offset)
	body.u16(op)
	return buildCmd(TPMSTSessions, CCPolicyNV, body.bytes())
}

// TestPolicyNV checks the NV-content comparison and digest (TPM 2.0 Part 3, §23.8).
func TestPolicyNV(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	const nvH = 0x01000020
	defineSpace(t, tpm, RHOwner, nvH, nvOrdinary, NVOwnerWrite|NVOwnerRead, 8, nil)
	val := []byte{0, 0, 0, 0, 0, 0, 0, 5}
	var wp writer
	wp.tpm2b(val)
	wp.u16(0) // offset
	if _, rc, _ := parseResp(t, tpm.Execute(nvCmd(CCNVWrite, RHOwner, nvH, nil, wp.bytes()))); rc != RCSuccess {
		t.Fatalf("NV_Write rc = 0x%x", rc)
	}
	idx, _ := tpm.nv.get(nvH)

	// Equal comparison succeeds and folds the spec digest.
	s := startSession(t, tpm, sePolicy, AlgSHA256)
	if _, rc, _ := parseResp(t, tpm.Execute(policyNVCmd(RHOwner, nvH, s, val, 0, 0x0000))); rc != RCSuccess { // EQ
		t.Fatalf("PolicyNV EQ rc = 0x%x", rc)
	}
	got := policyGetDigest(t, tpm, s)
	args := hashSum(AlgSHA256, val, be16(0), be16(0x0000))
	zero := make([]byte, 32)
	if want := hashSum(AlgSHA256, zero, be32(CCPolicyNV), args, idx.name); !bytes.Equal(got, want) {
		t.Fatalf("PolicyNV digest = %x, want %x", got, want)
	}

	// A mismatching operand fails the comparison.
	s2 := startSession(t, tpm, sePolicy, AlgSHA256)
	other := []byte{0, 0, 0, 0, 0, 0, 0, 6}
	if _, rc, _ := parseResp(t, tpm.Execute(policyNVCmd(RHOwner, nvH, s2, other, 0, 0x0000))); baseRC(rc) != RCPolicyFail {
		t.Fatalf("PolicyNV mismatch rc = 0x%x, want RC_POLICY_FAIL", rc)
	}
}

// TestPolicyCompareOps unit-tests the TPM_EO comparison engine.
func TestPolicyCompareOps(t *testing.T) {
	five := []byte{0, 0, 0, 5}
	six := []byte{0, 0, 0, 6}
	for _, c := range []struct {
		op   uint16
		a, b []byte
		want bool
	}{
		{0x0000, five, five, true},                  // EQ
		{0x0000, five, six, false},                  // EQ
		{0x0001, five, six, true},                   // NEQ
		{0x0003, six, five, true},                   // UNSIGNED_GT
		{0x0005, five, six, true},                   // UNSIGNED_LT
		{0x0007, five, five, true},                  // UNSIGNED_GE
		{0x000A, []byte{0x0F}, []byte{0x0C}, true},  // BITSET: 0x0C set in 0x0F
		{0x000A, []byte{0x0F}, []byte{0x10}, false}, // BITSET: 0x10 not in 0x0F
		{0x000B, []byte{0x0F}, []byte{0xF0}, true},  // BITCLEAR: 0xF0 clear in 0x0F
	} {
		if got := policyCompare(c.op, c.a, c.b); got != c.want {
			t.Errorf("op 0x%x cmp(%x,%x) = %v, want %v", c.op, c.a, c.b, got, c.want)
		}
	}
}
