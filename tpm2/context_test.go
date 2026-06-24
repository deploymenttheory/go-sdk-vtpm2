// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"testing"
)

func TestObjectChangeAuth(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	priv, pub := createSealed(t, tpm, srk, []byte("data"))
	h, _ := loadObject(t, tpm, srk, priv, pub)

	// ObjectChangeAuth(objectHandle=h, parentHandle=srk, newAuth="newauth").
	var auth writer
	auth.u32(RHPW)
	auth.u16(0)
	auth.u8(0)
	auth.u16(0)
	var body writer
	body.u32(h)
	body.u32(srk)
	body.u32(uint32(len(auth.bytes())))
	body.raw(auth.bytes())
	body.tpm2b([]byte("newauth"))
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCObjectChangeAuth, body.bytes())))
	if rc != RCSuccess {
		t.Fatalf("ObjectChangeAuth rc = 0x%x", rc)
	}
	r := newReader(p)
	_ = r.u32() // parameterSize
	newPriv := r.tpm2b()

	// Reloading the new blob yields an object with the new authValue.
	h2, rc2 := loadObject(t, tpm, srk, newPriv, pub)
	if rc2 != RCSuccess {
		t.Fatalf("reload rc = 0x%x", rc2)
	}
	o, _ := tpm.objects.get(h2)
	if !bytes.Equal(o.sensitive.AuthValue, []byte("newauth")) {
		t.Fatalf("authValue not changed: %q", o.sensitive.AuthValue)
	}
}

func TestContextSaveLoadObject(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	priv, pub := createSealed(t, tpm, srk, []byte("ctx-secret"))
	h, _ := loadObject(t, tpm, srk, priv, pub)

	// ContextSave the loaded object.
	var cs writer
	cs.u32(h)
	_, rc, ctx := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCContextSave, cs.bytes())))
	if rc != RCSuccess {
		t.Fatalf("ContextSave rc = 0x%x", rc)
	}

	// Flush the original, then ContextLoad the blob back.
	var fp writer
	fp.u32(h)
	if _, frc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCFlushContext, fp.bytes()))); frc != RCSuccess {
		t.Fatalf("FlushContext rc = 0x%x", frc)
	}
	_, rc2, p2 := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCContextLoad, ctx)))
	if rc2 != RCSuccess {
		t.Fatalf("ContextLoad rc = 0x%x", rc2)
	}
	h2 := newReader(p2).u32()
	o2, ok := tpm.objects.get(h2)
	if !ok || !bytes.Equal(o2.sensitive.Secret, []byte("ctx-secret")) {
		t.Fatal("context-loaded object did not recover its secret")
	}
}

func TestContextSaveLoadSession(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	ps := startSession(t, tpm, sePolicy, AlgSHA256)
	var pc writer
	pc.u32(CCClear)
	if _, rc, _ := parseResp(t, tpm.Execute(policyCmd(CCPolicyCommandCode, ps, pc.bytes()))); rc != RCSuccess {
		t.Fatalf("PolicyCommandCode rc = 0x%x", rc)
	}
	want := policyDigest(t, tpm, ps)

	var cs writer
	cs.u32(ps)
	_, rc, ctx := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCContextSave, cs.bytes())))
	if rc != RCSuccess {
		t.Fatalf("ContextSave session rc = 0x%x", rc)
	}
	var fp writer
	fp.u32(ps)
	tpm.Execute(buildCmd(TPMSTNoSessions, CCFlushContext, fp.bytes()))
	if _, ok := tpm.sessions.get(ps); ok {
		t.Fatal("session not flushed")
	}

	if _, rc2, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCContextLoad, ctx))); rc2 != RCSuccess {
		t.Fatalf("ContextLoad session rc = 0x%x", rc2)
	}
	if got := policyDigest(t, tpm, ps); !bytes.Equal(got, want) {
		t.Fatal("session policyDigest lost across context save/load")
	}
}

func TestContextLoadTamperedFails(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	priv, pub := createSealed(t, tpm, srk, []byte("x"))
	h, _ := loadObject(t, tpm, srk, priv, pub)

	var cs writer
	cs.u32(h)
	_, _, ctx := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCContextSave, cs.bytes())))
	ctx[len(ctx)-1] ^= 0xFF // corrupt the context blob

	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCContextLoad, ctx))); rc != RCIntegrity {
		t.Fatalf("tampered ContextLoad rc = 0x%x, want INTEGRITY", rc)
	}
}
