// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"testing"
)

// auditedChangeAuthCP is the cpParams of TPM2_HierarchyChangeAuth(owner, newAuth).
func auditedChangeAuthCP(newAuth []byte) []byte {
	var cp writer
	cp.tpm2b(newAuth)
	return cp.bytes()
}

// TestSessionAudit drives an HMAC session with the audit bit over one command,
// then signs and checks its session-audit digest (TPM 2.0 Part 3, §22.2).
func TestSessionAudit(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	signKey := createSigningKey(t, tpm, srk, eccSigningTemplate())
	signObj, _ := tpm.objects.get(signKey)

	sh, nonceTPM := startHMACSession(t, tpm, AlgSHA256)
	nonceCaller := bytes.Repeat([]byte{0x22}, 16)
	newAuth := []byte("audited-pw")
	cpParams := auditedChangeAuthCP(newAuth)
	cph := cpHash(AlgSHA256, CCHierarchyChangeAuth, [][]byte{permanentName(RHOwner)}, cpParams)
	const attrs = attrContinue | attrAudit
	mac := commandAuthHMAC(AlgSHA256, nil, cph, nonceCaller, nonceTPM, attrs) // empty key (unbound, empty auth)
	if _, rc, _ := parseResp(t, tpm.Execute(changeAuthCmd(RHOwner, sh, nonceCaller, attrs, mac, newAuth))); rc != RCSuccess {
		t.Fatalf("audited HierarchyChangeAuth rc = 0x%x", rc)
	}

	rph := rpHash(AlgSHA256, RCSuccess, CCHierarchyChangeAuth, nil)
	want := hashSum(AlgSHA256, make([]byte, 32), cph, rph)

	var gb writer
	gb.u32(RHEndorsement)
	gb.u32(signKey)
	gb.u32(sh) // sessionHandle (audit session, not authorized)
	gb.raw(twoPasswordAuth())
	gb.tpm2b([]byte("sa-qual"))
	gb.u16(AlgNull)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCGetSessionAuditDigest, gb.bytes())))
	if rc != RCSuccess {
		t.Fatalf("GetSessionAuditDigest rc = 0x%x", rc)
	}
	attest, sig := parseAttestSig(t, p)
	verifyAttestSig(t, tpm, signKey, attest, sig)

	body := checkAttestHeader(t, attest, STAttestSessionAudit, signObj.name, []byte("sa-qual"))
	br := newReader(body)
	if excl := br.u8(); excl != yes {
		t.Fatalf("exclusiveSession = %d, want yes", excl)
	}
	if d := br.tpm2b(); !bytes.Equal(d, want) {
		t.Fatalf("session audit digest = %x, want %x", d, want)
	}
}

// TestCommandAudit configures command audit, runs an audited command, then signs
// and checks the command-audit digest (TPM 2.0 Part 3, §22.1/22.3).
func TestCommandAudit(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	signKey := createSigningKey(t, tpm, srk, eccSigningTemplate())
	signObj, _ := tpm.objects.get(signKey)

	// Audit TPM2_HierarchyChangeAuth under SHA-256.
	var sb writer
	sb.u32(RHOwner)
	sb.raw(onePasswordAuth())
	sb.u16(AlgSHA256)
	sb.u32(1)
	sb.u32(CCHierarchyChangeAuth) // setList
	sb.u32(0)                     // clearList
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCSetCommandCodeAuditStatus, sb.bytes()))); rc != RCSuccess {
		t.Fatalf("SetCommandCodeAuditStatus rc = 0x%x", rc)
	}

	// Run the audited command (password-authorized).
	newAuth := []byte("ca-newpw")
	var cb writer
	cb.u32(RHOwner)
	cb.raw(onePasswordAuth())
	cb.tpm2b(newAuth)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCHierarchyChangeAuth, cb.bytes()))); rc != RCSuccess {
		t.Fatalf("HierarchyChangeAuth rc = 0x%x", rc)
	}
	cph := cpHash(AlgSHA256, CCHierarchyChangeAuth, [][]byte{permanentName(RHOwner)}, auditedChangeAuthCP(newAuth))
	rph := rpHash(AlgSHA256, RCSuccess, CCHierarchyChangeAuth, nil)
	want := hashSum(AlgSHA256, make([]byte, 32), cph, rph)

	var gb writer
	gb.u32(RHEndorsement)
	gb.u32(signKey)
	gb.raw(twoPasswordAuth())
	gb.tpm2b([]byte("ca-qual"))
	gb.u16(AlgNull)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCGetCommandAuditDigest, gb.bytes())))
	if rc != RCSuccess {
		t.Fatalf("GetCommandAuditDigest rc = 0x%x", rc)
	}
	attest, sig := parseAttestSig(t, p)
	verifyAttestSig(t, tpm, signKey, attest, sig)

	body := checkAttestHeader(t, attest, STAttestCommandAudit, signObj.name, []byte("ca-qual"))
	br := newReader(body)
	_ = br.u64() // auditCounter
	if alg := br.u16(); alg != AlgSHA256 {
		t.Fatalf("digestAlg = 0x%x, want SHA256", alg)
	}
	if d := br.tpm2b(); !bytes.Equal(d, want) {
		t.Fatalf("command audit digest = %x, want %x", d, want)
	}
	if cd := br.tpm2b(); !bytes.Equal(cd, hashSum(AlgSHA256, be32(CCHierarchyChangeAuth))) {
		t.Fatal("commandDigest mismatch")
	}

	// Signing reset the digest; a second GetCommandAuditDigest sees the Zero Digest.
	var gb2 writer
	gb2.u32(RHEndorsement)
	gb2.u32(signKey)
	gb2.raw(twoPasswordAuth())
	gb2.tpm2b(nil)
	gb2.u16(AlgNull)
	_, rc, p2 := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCGetCommandAuditDigest, gb2.bytes())))
	if rc != RCSuccess {
		t.Fatalf("second GetCommandAuditDigest rc = 0x%x", rc)
	}
	attest2, _ := parseAttestSig(t, p2)
	body2 := checkAttestHeader(t, attest2, STAttestCommandAudit, signObj.name, nil)
	br2 := newReader(body2)
	if c := br2.u64(); c != 1 {
		t.Fatalf("auditCounter = %d, want 1 after a reset", c)
	}
	_ = br2.u16()
	if d := br2.tpm2b(); !bytes.Equal(d, make([]byte, 32)) {
		t.Fatalf("post-reset digest = %x, want zero", d)
	}
}
