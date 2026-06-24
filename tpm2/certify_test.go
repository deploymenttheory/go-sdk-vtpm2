// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"testing"
)

// parseAttestSig splits a sessions response into the TPM2B_ATTEST and the
// TPMT_SIGNATURE that follow parameterSize.
func parseAttestSig(t *testing.T, p []byte) (attest, sig []byte) {
	t.Helper()
	r := newReader(p)
	params := r.bytes(int(r.u32())) // exactly the parameter area
	pr := newReader(params)
	attest = pr.tpm2b()
	sig = pr.bytes(pr.remaining())
	if pr.err != nil {
		t.Fatalf("parse attest/sig: %v", pr.err)
	}
	return attest, sig
}

// verifyAttestSig checks an attestation signature via TPM2_VerifySignature.
func verifyAttestSig(t *testing.T, tpm *TPM, signKey uint32, attest, sig []byte) {
	t.Helper()
	var v writer
	v.u32(signKey)
	v.tpm2b(hashSum(AlgSHA256, attest))
	v.raw(sig)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCVerifySignature, v.bytes()))); rc != RCSuccess {
		t.Fatalf("attestation signature did not verify: rc = 0x%x", rc)
	}
}

// attestedBody returns the [type]attested portion of a TPMS_ATTEST after checking
// magic, type, signer and extraData.
func checkAttestHeader(t *testing.T, attest []byte, wantType uint16, signerName, qual []byte) []byte {
	t.Helper()
	r := newReader(attest)
	if magic := r.u32(); magic != tpmGeneratedValue {
		t.Fatalf("magic = 0x%x", magic)
	}
	if typ := r.u16(); typ != wantType {
		t.Fatalf("attest type = 0x%x, want 0x%x", typ, wantType)
	}
	if signer := r.tpm2b(); !bytes.Equal(signer, signerName) {
		t.Fatal("qualifiedSigner mismatch")
	}
	if extra := r.tpm2b(); !bytes.Equal(extra, qual) {
		t.Fatal("extraData (qualifyingData) mismatch")
	}
	_ = r.bytes(17) // clockInfo
	_ = r.u64()     // firmwareVersion
	return attest[len(attest)-r.remaining():]
}

func TestCertify(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	signKey := createSigningKey(t, tpm, srk, eccSigningTemplate())
	signObj, _ := tpm.objects.get(signKey)
	obj, _, objName := createPrimary(t, tpm, RHEndorsement, eccStorageTemplate())
	qual := []byte("qualify-1234")

	var b writer
	b.u32(obj)
	b.u32(signKey)
	b.raw(twoPasswordAuth())
	b.tpm2b(qual)
	b.u16(AlgNull) // inScheme ⇒ key's scheme
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCCertify, b.bytes())))
	if rc != RCSuccess {
		t.Fatalf("Certify rc = 0x%x", rc)
	}
	attest, sig := parseAttestSig(t, p)
	verifyAttestSig(t, tpm, signKey, attest, sig)

	// TPMS_CERTIFY_INFO = name ‖ qualifiedName; the certified Name must be obj's.
	body := checkAttestHeader(t, attest, STAttestCertify, signObj.name, qual)
	if certName := newReader(body).tpm2b(); !bytes.Equal(certName, objName) {
		t.Fatal("certified Name does not match the object")
	}
}

// createPrimaryFull is createPrimary plus the creationHash and creation ticket.
func createPrimaryFull(t *testing.T, tpm *TPM, hierarchy uint32, tmpl public) (handle uint32, name, creationHash, ticket []byte) {
	t.Helper()
	var inner writer
	inner.tpm2b(nil)
	inner.tpm2b(nil)
	var params writer
	params.tpm2b(inner.bytes())
	tmpl.marshal2B(&params)
	params.tpm2b(nil)
	params.u32(0)
	_, rc, p := parseResp(t, tpm.Execute(buildHierarchyCmd(CCCreatePrimary, hierarchy, nil, params.bytes())))
	if rc != RCSuccess {
		t.Fatalf("CreatePrimary rc = 0x%x", rc)
	}
	r := newReader(p)
	handle = r.u32()
	_ = r.u32() // parameterSize
	_ = readPublic2B(r)
	_ = r.tpm2b() // creationData
	creationHash = r.tpm2b()
	var tk writer
	tk.u16(r.u16()) // ticket tag
	tk.u32(r.u32()) // ticket hierarchy
	tk.tpm2b(r.tpm2b())
	ticket = tk.bytes()
	name = r.tpm2b()
	if r.err != nil {
		t.Fatalf("parse CreatePrimary: %v", r.err)
	}
	return handle, name, creationHash, ticket
}

func TestCertifyCreation(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	signKey := createSigningKey(t, tpm, srk, eccSigningTemplate())
	signObj, _ := tpm.objects.get(signKey)
	objH, objName, creationHash, ticket := createPrimaryFull(t, tpm, RHEndorsement, eccStorageTemplate())
	qual := []byte("cc-qual")

	var b writer
	b.u32(signKey)
	b.u32(objH)
	b.raw(onePasswordAuth()) // only signHandle is authorized
	b.tpm2b(qual)
	b.tpm2b(creationHash)
	b.u16(AlgNull) // inScheme
	b.raw(ticket)  // creationTicket (TPMT_TK_CREATION)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCCertifyCreation, b.bytes())))
	if rc != RCSuccess {
		t.Fatalf("CertifyCreation rc = 0x%x", rc)
	}
	attest, sig := parseAttestSig(t, p)
	verifyAttestSig(t, tpm, signKey, attest, sig)

	body := checkAttestHeader(t, attest, STAttestCreation, signObj.name, qual)
	br := newReader(body)
	if cn := br.tpm2b(); !bytes.Equal(cn, objName) { // TPMS_CREATION_INFO.objectName
		t.Fatal("creation objectName mismatch")
	}
	if ch := br.tpm2b(); !bytes.Equal(ch, creationHash) {
		t.Fatal("creation hash mismatch")
	}

	// A tampered creation ticket is rejected.
	bad := append([]byte(nil), ticket...)
	bad[len(bad)-1] ^= 0xFF
	var bb writer
	bb.u32(signKey)
	bb.u32(objH)
	bb.raw(onePasswordAuth())
	bb.tpm2b(qual)
	bb.tpm2b(creationHash)
	bb.u16(AlgNull)
	bb.raw(bad)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCCertifyCreation, bb.bytes()))); baseRC(rc) != RCTicket {
		t.Fatalf("bad-ticket CertifyCreation rc = 0x%x, want RC_TICKET", rc)
	}
}
