// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"testing"
)

// passwordAuthFor builds a single-session auth area authorizing with authValue.
func passwordAuthFor(authValue []byte) []byte {
	var a writer
	a.u32(RHPW)
	a.tpm2b(nil)
	a.u8(attrContinue)
	a.tpm2b(authValue)
	var w writer
	w.u32(uint32(len(a.bytes())))
	w.raw(a.bytes())
	return w.bytes()
}

func TestNVChangeAuth(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	const nvH = 0x01000050
	defineSpace(t, tpm, RHOwner, nvH, nvOrdinary, NVAuthWrite|NVAuthRead, 8, []byte("old"))

	var b writer
	b.u32(nvH)
	b.raw(passwordAuthFor([]byte("old")))
	b.tpm2b([]byte("new"))
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCNVChangeAuth, b.bytes()))); rc != RCSuccess {
		t.Fatalf("NV_ChangeAuth rc = 0x%x", rc)
	}
	if idx, _ := tpm.nv.get(nvH); !bytes.Equal(idx.authValue, []byte("new")) {
		t.Fatalf("authValue = %q, want \"new\"", idx.authValue)
	}

	// The old auth no longer works.
	var bb writer
	bb.u32(nvH)
	bb.raw(passwordAuthFor([]byte("old")))
	bb.tpm2b([]byte("xxx"))
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCNVChangeAuth, bb.bytes()))); baseRC(rc) != RCAuthFail {
		t.Fatalf("stale-auth NV_ChangeAuth rc = 0x%x, want RC_AUTH_FAIL", rc)
	}
}

func TestNVGlobalWriteLock(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	const nvH = 0x01000051
	defineSpace(t, tpm, RHOwner, nvH, nvOrdinary, NVOwnerWrite|NVOwnerRead|NVGlobalLock, 8, nil)

	var b writer
	b.u32(RHOwner)
	b.raw(onePasswordAuth())
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCNVGlobalWriteLock, b.bytes()))); rc != RCSuccess {
		t.Fatalf("NV_GlobalWriteLock rc = 0x%x", rc)
	}
	if idx, _ := tpm.nv.get(nvH); !idx.writeLocked {
		t.Fatal("GLOBALLOCK index was not write-locked")
	}
	// A subsequent write fails.
	var wp writer
	wp.tpm2b([]byte("12345678"))
	wp.u16(0)
	if _, rc, _ := parseResp(t, tpm.Execute(nvCmd(CCNVWrite, RHOwner, nvH, nil, wp.bytes()))); rc == RCSuccess {
		t.Fatal("write to a globally write-locked index unexpectedly succeeded")
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
