// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"testing"
)

func TestPolicyTransportSPDM(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	s := startSession(t, tpm, sePolicy, AlgSHA256)

	// A valid secure-channel key Name: SHA-256 alg id + a 32-byte digest.
	reqKeyName := append(be16(AlgSHA256), bytes.Repeat([]byte{0x11}, 32)...)
	tpmKeyName := []byte(nil) // omitted

	var b writer
	b.tpm2b(reqKeyName)
	b.tpm2b(tpmKeyName)
	if _, rc, _ := parseResp(t, tpm.Execute(policyCmd(CCPolicyTransportSPDM, s, b.bytes()))); rc != RCSuccess {
		t.Fatalf("PolicyTransportSPDM rc = 0x%x", rc)
	}

	// Expected digest: H(0 ‖ CC ‖ H(reqKeyName-2B ‖ tpmKeyName-2B)).
	var nb writer
	nb.tpm2b(reqKeyName)
	nb.tpm2b(tpmKeyName)
	scKeyNameHash := hashSum(AlgSHA256, nb.bytes())
	want := hashSum(AlgSHA256, make([]byte, 32), be32(CCPolicyTransportSPDM), scKeyNameHash)
	if got := policyGetDigest(t, tpm, s); !bytes.Equal(got, want) {
		t.Fatalf("PolicyTransportSPDM digest = %x, want %x", got, want)
	}

	// It is a one-shot assertion: a second call is rejected.
	if _, rc, _ := parseResp(t, tpm.Execute(policyCmd(CCPolicyTransportSPDM, s, b.bytes()))); baseRC(rc) != RCValue {
		t.Fatalf("repeated PolicyTransportSPDM rc = 0x%x, want RC_VALUE", rc)
	}

	// An invalid key Name (bad hash algorithm) is rejected.
	s2 := startSession(t, tpm, sePolicy, AlgSHA256)
	var bb writer
	bb.tpm2b(append(be16(0x9999), bytes.Repeat([]byte{0x22}, 32)...))
	bb.tpm2b(nil)
	if _, rc, _ := parseResp(t, tpm.Execute(policyCmd(CCPolicyTransportSPDM, s2, bb.bytes()))); baseRC(rc) != RCHash {
		t.Fatalf("bad-hash PolicyTransportSPDM rc = 0x%x, want RC_HASH", rc)
	}
}
