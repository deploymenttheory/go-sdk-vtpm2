// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"testing"
)

// policyGetDigest runs TPM2_PolicyGetDigest and returns the session's digest.
func policyGetDigest(t *testing.T, tpm *TPM, session uint32) []byte {
	t.Helper()
	_, rc, p := parseResp(t, tpm.Execute(policyCmd(CCPolicyGetDigest, session, nil)))
	if rc != RCSuccess {
		t.Fatalf("PolicyGetDigest rc = 0x%x", rc)
	}
	return newReader(p).tpm2b()
}

// runPolicy starts a fresh trial session, runs one policy command, and returns the
// resulting policyDigest.
func runPolicy(t *testing.T, tpm *TPM, cc uint32, params []byte) []byte {
	t.Helper()
	s := startSession(t, tpm, seTrial, AlgSHA256)
	if _, rc, _ := parseResp(t, tpm.Execute(policyCmd(cc, s, params))); rc != RCSuccess {
		t.Fatalf("policy 0x%x rc = 0x%x", cc, rc)
	}
	return policyGetDigest(t, tpm, s)
}

// TestSimplePolicyDigests checks each digest-extend policy against the spec
// formula policyDigestnew = H(0…0 ‖ TPM_CC ‖ data) on a fresh trial session
// (TPM 2.0 Part 3, §23).
func TestSimplePolicyDigests(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	zero := make([]byte, 32)
	digest := bytes.Repeat([]byte{0xAB}, 32) // a stand-in cpHash/nameHash/templateHash

	wrap := func(b []byte) []byte { // TPM2B wire wrapper
		var w writer
		w.tpm2b(b)
		return w.bytes()
	}

	cases := []struct {
		name   string
		cc     uint32
		params []byte // wire params after the session handle
		want   []byte // expected digest
	}{
		{"PolicyLocality", CCPolicyLocality, []byte{0x1F}, hashSum(AlgSHA256, zero, be32(CCPolicyLocality), []byte{0x1F})},
		{"PolicyCpHash", CCPolicyCpHash, wrap(digest), hashSum(AlgSHA256, zero, be32(CCPolicyCpHash), digest)},
		{"PolicyNameHash", CCPolicyNameHash, wrap(digest), hashSum(AlgSHA256, zero, be32(CCPolicyNameHash), digest)},
		{"PolicyTemplate", CCPolicyTemplate, wrap(digest), hashSum(AlgSHA256, zero, be32(CCPolicyTemplate), digest)},
		{"PolicyNvWritten", CCPolicyNvWritten, []byte{0x01}, hashSum(AlgSHA256, zero, be32(CCPolicyNvWritten), []byte{0x01})},
		{"PolicyPhysicalPresence", CCPolicyPhysicalPresence, nil, hashSum(AlgSHA256, zero, be32(CCPolicyPhysicalPresence))},
		// PolicyPassword folds the same digest as PolicyAuthValue.
		{"PolicyPassword", CCPolicyPassword, nil, hashSum(AlgSHA256, zero, be32(CCPolicyAuthValue))},
	}
	for _, c := range cases {
		if got := runPolicy(t, tpm, c.cc, c.params); !bytes.Equal(got, c.want) {
			t.Errorf("%s digest = %x, want %x", c.name, got, c.want)
		}
	}
}

// TestPolicyLocalityAndsBitmaps confirms repeated PolicyLocality calls AND their
// bitmaps and reject a contradiction (TPM 2.0 Part 3, §23.9).
func TestPolicyLocalityAndsBitmaps(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	s := startSession(t, tpm, seTrial, AlgSHA256)
	if _, rc, _ := parseResp(t, tpm.Execute(policyCmd(CCPolicyLocality, s, []byte{0x03}))); rc != RCSuccess {
		t.Fatalf("first PolicyLocality rc = 0x%x", rc)
	}
	// 0x04 has no bit in common with 0x03 ⇒ contradiction ⇒ RC_VALUE.
	if _, rc, _ := parseResp(t, tpm.Execute(policyCmd(CCPolicyLocality, s, []byte{0x04}))); baseRC(rc) != RCValue {
		t.Fatalf("contradictory PolicyLocality rc = 0x%x, want RC_VALUE", rc)
	}
}
