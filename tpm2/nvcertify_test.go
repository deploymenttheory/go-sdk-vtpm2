// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"testing"
)

func TestGetTime(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	signKey := createSigningKey(t, tpm, srk, eccSigningTemplate())
	signObj, _ := tpm.objects.get(signKey)
	qual := []byte("gt-nonce")

	var b writer
	b.u32(RHEndorsement) // privacyAdminHandle
	b.u32(signKey)
	b.raw(twoPasswordAuth())
	b.tpm2b(qual)
	b.u16(AlgNull)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCGetTime, b.bytes())))
	if rc != RCSuccess {
		t.Fatalf("GetTime rc = 0x%x", rc)
	}
	attest, sig := parseAttestSig(t, p)
	verifyAttestSig(t, tpm, signKey, attest, sig)
	checkAttestHeader(t, attest, STAttestTime, signObj.name, qual)
}

func TestNVCertify(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	signKey := createSigningKey(t, tpm, srk, eccSigningTemplate())
	signObj, _ := tpm.objects.get(signKey)

	const nvH = 0x01000040
	defineSpace(t, tpm, RHOwner, nvH, nvOrdinary, NVOwnerWrite|NVOwnerRead|NVAuthWrite|NVAuthRead, 16, nil)
	payload := []byte("nv-attested-data")
	var wp writer
	wp.tpm2b(payload)
	wp.u16(0)
	if _, rc, _ := parseResp(t, tpm.Execute(nvCmd(CCNVWrite, RHOwner, nvH, nil, wp.bytes()))); rc != RCSuccess {
		t.Fatalf("NV_Write rc = 0x%x", rc)
	}
	idx, _ := tpm.nv.get(nvH)

	var b writer
	b.u32(signKey)
	b.u32(RHOwner) // authHandle (NV owner auth)
	b.u32(nvH)     // nvIndex (not authorized)
	b.raw(twoPasswordAuth())
	b.tpm2b([]byte("nvc"))
	b.u16(AlgNull)
	b.u16(uint16(len(payload))) // size
	b.u16(0)                    // offset
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCNVCertify, b.bytes())))
	if rc != RCSuccess {
		t.Fatalf("NV_Certify rc = 0x%x", rc)
	}
	attest, sig := parseAttestSig(t, p)
	verifyAttestSig(t, tpm, signKey, attest, sig)

	// TPMS_NV_CERTIFY_INFO = indexName ‖ offset ‖ nvContents.
	body := checkAttestHeader(t, attest, STAttestNV, signObj.name, []byte("nvc"))
	br := newReader(body)
	if name := br.tpm2b(); !bytes.Equal(name, idx.name) {
		t.Fatal("certified NV indexName mismatch")
	}
	if off := br.u16(); off != 0 {
		t.Fatalf("offset = %d, want 0", off)
	}
	if contents := br.tpm2b(); !bytes.Equal(contents, payload) {
		t.Fatalf("certified NV contents = %q, want %q", contents, payload)
	}
}
