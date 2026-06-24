// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"testing"
)

// pcrSelectionList builds a TPML_PCR_SELECTION DER for the given banks, each
// selecting all PCRs.
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

// defineSpaceFull is defineSpace with a settable authPolicy (and an empty Index
// auth), needed for POLICY_DELETE indices.
func defineSpaceFull(t *testing.T, tpm *TPM, authHi, index, nt, attrs uint32, dataSize uint16, authPolicy []byte) {
	t.Helper()
	public := nvPublic{
		Index:      index,
		NameAlg:    AlgSHA256,
		Attrs:      attrs | (nt << NVNTShift),
		AuthPolicy: authPolicy,
		DataSize:   dataSize,
	}
	var params writer
	params.tpm2b(nil)
	public.marshal2B(&params)
	var auth writer
	auth.u32(RHPW)
	auth.u16(0)
	auth.u8(0)
	auth.u16(0)
	var body writer
	body.u32(authHi)
	body.u32(uint32(len(auth.bytes())))
	body.raw(auth.bytes())
	body.raw(params.bytes())
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCNVDefineSpace, body.bytes()))); rc != RCSuccess {
		t.Fatalf("NV_DefineSpace rc = 0x%x", rc)
	}
}

func TestNVUndefineSpaceSpecial(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	const nvH = 0x01000060
	// A POLICY_DELETE index with a zero authPolicy, so a fresh policy session
	// (whose digest is the Zero Digest) satisfies its ADMIN-role authorization.
	zeroPolicy := make([]byte, 32)
	defineSpaceFull(t, tpm, RHPlatform, nvH, nvOrdinary, NVPolicyDelete|NVAuthRead, 8, zeroPolicy)

	s := startSession(t, tpm, sePolicy, AlgSHA256)
	var auth writer
	auth.u32(s)
	auth.tpm2b(nil)
	auth.u8(attrContinue)
	auth.tpm2b(nil)
	var pw writer // platform password session
	pw.u32(RHPW)
	pw.tpm2b(nil)
	pw.u8(attrContinue)
	pw.tpm2b(nil)

	var area writer
	area.u32(uint32(len(auth.bytes()) + len(pw.bytes())))
	area.raw(auth.bytes())
	area.raw(pw.bytes())

	var b writer
	b.u32(nvH)
	b.u32(RHPlatform)
	b.raw(area.bytes())
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCNVUndefineSpaceSpecial, b.bytes()))); rc != RCSuccess {
		t.Fatalf("NV_UndefineSpaceSpecial rc = 0x%x", rc)
	}
	if _, ok := tpm.nv.get(nvH); ok {
		t.Fatal("index still present after NV_UndefineSpaceSpecial")
	}
}
