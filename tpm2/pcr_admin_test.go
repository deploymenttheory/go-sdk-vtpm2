// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"testing"
)

func TestPCREvent(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	const index = 16 // a debug PCR, extendable at locality 0
	before := append([]byte(nil), tpm.pcr.banks[AlgSHA256][index]...)
	eventData := []byte("measured-event")

	var b writer
	b.u32(index)
	b.raw(onePasswordAuth())
	b.tpm2b(eventData)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCPCREvent, b.bytes())))
	if rc != RCSuccess {
		t.Fatalf("PCR_Event rc = 0x%x", rc)
	}

	// The response lists a digest per bank; find the SHA-256 one.
	r := newReader(p)
	count := r.u32()
	var sha256Digest []byte
	for i := uint32(0); i < count; i++ {
		alg := r.u16()
		d := r.bytes(hashSize(alg))
		if alg == AlgSHA256 {
			sha256Digest = d
		}
	}
	wantEvent := hashSum(AlgSHA256, eventData)
	if !bytes.Equal(sha256Digest, wantEvent) {
		t.Fatal("returned SHA-256 event digest mismatch")
	}
	// PCR[index] := H(old ‖ H(eventData)).
	if got := tpm.pcr.banks[AlgSHA256][index]; !bytes.Equal(got, hashSum(AlgSHA256, before, wantEvent)) {
		t.Fatal("PCR not extended with the event digest")
	}
}

// pcrSelectionList builds a TPML_PCR_SELECTION for the given banks, each selecting
// all PCRs.
func pcrSelectionList(algs ...uint16) []byte {
	var w writer
	w.u32(uint32(len(algs)))
	full := make([]byte, pcrSelectMin)
	for i := range full {
		full[i] = 0xFF
	}
	for _, alg := range algs {
		w.u16(alg)
		w.u8(uint8(pcrSelectMin))
		w.raw(full)
	}
	return w.bytes()
}

func TestPCRAllocate(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	// Reallocate to a SHA-256-only bank set.
	var b writer
	b.u32(RHPlatform)
	b.raw(onePasswordAuth())
	b.raw(pcrSelectionList(AlgSHA256))
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCPCRAllocate, b.bytes())))
	if rc != RCSuccess {
		t.Fatalf("PCR_Allocate rc = 0x%x", rc)
	}
	r := newReader(p)
	_ = r.u32() // parameterSize
	if ok := r.u8(); ok != yes {
		t.Fatalf("allocationSuccess = %d, want yes", ok)
	}
	if mx := r.u32(); mx != numPCR {
		t.Fatalf("maxPCR = %d, want %d", mx, numPCR)
	}
	// The bank set is now SHA-256 only.
	if _, ok := tpm.pcr.banks[AlgSHA1]; ok {
		t.Fatal("SHA-1 bank still present after reallocating to SHA-256 only")
	}
	if _, ok := tpm.pcr.banks[AlgSHA256]; !ok {
		t.Fatal("SHA-256 bank missing after reallocation")
	}
}

func TestPCRSetAuthValue(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	const pcr = 20
	var b writer
	b.u32(pcr)
	b.raw(onePasswordAuth()) // current PCR auth is empty
	b.tpm2b([]byte("pcr-secret"))
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCPCRSetAuthValue, b.bytes()))); rc != RCSuccess {
		t.Fatalf("PCR_SetAuthValue rc = 0x%x", rc)
	}
	if got := tpm.pcr.authValues[pcr]; !bytes.Equal(got, []byte("pcr-secret")) {
		t.Fatalf("PCR auth = %q, want \"pcr-secret\"", got)
	}
	// The new auth is now required: an empty-auth attempt fails.
	var bb writer
	bb.u32(pcr)
	bb.raw(onePasswordAuth())
	bb.tpm2b([]byte("again"))
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCPCRSetAuthValue, bb.bytes()))); baseRC(rc) != RCAuthFail {
		t.Fatalf("stale-auth PCR_SetAuthValue rc = 0x%x, want RC_AUTH_FAIL", rc)
	}
}

func TestPCRSetAuthPolicy(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	const pcr = 20
	policy := bytes.Repeat([]byte{0xAB}, 32)
	var b writer
	b.u32(RHPlatform)
	b.raw(onePasswordAuth())
	b.tpm2b(policy)
	b.u16(AlgSHA256)
	b.u32(pcr)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCPCRSetAuthPolicy, b.bytes()))); rc != RCSuccess {
		t.Fatalf("PCR_SetAuthPolicy rc = 0x%x", rc)
	}
	if got := tpm.pcr.authPolicies[pcr]; !bytes.Equal(got, policy) {
		t.Fatal("PCR auth policy was not stored")
	}
}
