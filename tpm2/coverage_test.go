// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"testing"
)

func TestShutdownAndStartupState(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	for _, su := range []uint16{SUState, SUClear} {
		var w writer
		w.u16(su)
		if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCShutdown, w.bytes()))); rc != RCSuccess {
			t.Fatalf("Shutdown(%d) rc = 0x%x", su, rc)
		}
	}
	// An invalid shutdown type is rejected.
	var bad writer
	bad.u16(0x1234)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCShutdown, bad.bytes()))); baseRC(rc) != RCValue {
		t.Fatalf("Shutdown(bad) rc = 0x%x, want RC_VALUE", rc)
	}
}

func TestShutdownBeforeStartup(t *testing.T) {
	tpm := New() // no TPM2_Startup
	var w writer
	w.u16(SUClear)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCShutdown, w.bytes()))); rc != RCInitialize {
		t.Fatalf("Shutdown before Startup rc = 0x%x, want RC_INITIALIZE", rc)
	}
}

func TestStirRandom(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	var w writer
	w.tpm2b([]byte("entropy to stir into the pool"))
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCStirRandom, w.bytes()))); rc != RCSuccess {
		t.Fatalf("StirRandom rc = 0x%x", rc)
	}
}

func TestSetPrimaryPolicy(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	policy := bytes.Repeat([]byte{0xC3}, 32)

	var b writer
	b.u32(RHOwner)
	b.raw(onePasswordAuth())
	b.tpm2b(policy)
	b.u16(AlgSHA256)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCSetPrimaryPolicy, b.bytes()))); rc != RCSuccess {
		t.Fatalf("SetPrimaryPolicy rc = 0x%x", rc)
	}
	if !bytes.Equal(tpm.h.owner.authPolicy, policy) {
		t.Fatal("owner authPolicy not set")
	}

	// A digest whose length does not match the hash is rejected.
	var bad writer
	bad.u32(RHOwner)
	bad.raw(onePasswordAuth())
	bad.tpm2b(bytes.Repeat([]byte{0x01}, 10)) // wrong size for SHA-256
	bad.u16(AlgSHA256)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCSetPrimaryPolicy, bad.bytes()))); baseRC(rc) != RCSize {
		t.Fatalf("bad-size SetPrimaryPolicy rc = 0x%x, want RC_SIZE", rc)
	}

	// Clearing the policy (empty digest + TPM_ALG_NULL) succeeds.
	var clr writer
	clr.u32(RHOwner)
	clr.raw(onePasswordAuth())
	clr.tpm2b(nil)
	clr.u16(AlgNull)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCSetPrimaryPolicy, clr.bytes()))); rc != RCSuccess {
		t.Fatalf("clear SetPrimaryPolicy rc = 0x%x", rc)
	}
}

func TestLoadExternalPublic(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	obj, _ := tpm.objects.get(srk)

	var b writer
	b.tpm2b(nil) // inPrivate (public-only)
	obj.public.marshal2B(&b)
	b.u32(RHNull) // hierarchy
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCLoadExternal, b.bytes())))
	if rc != RCSuccess {
		t.Fatalf("LoadExternal rc = 0x%x", rc)
	}
	r := newReader(p)
	h := r.u32()
	name := r.tpm2b()
	if !bytes.Equal(name, obj.name) {
		t.Fatal("LoadExternal Name does not match the source public area")
	}
	if loaded, ok := tpm.objects.get(h); !ok || !bytes.Equal(loaded.name, obj.name) {
		t.Fatal("external object not loaded")
	}
}

func TestStateBlobRoundTrip(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	tpm.h.owner.authValue = []byte("owner-secret")
	const nvH = 0x01000070
	defineSpace(t, tpm, RHPlatform, nvH, nvOrdinary, NVOwnerWrite|NVOwnerRead|NVAuthRead, 8, nil)

	blob, err := tpm.StateBlob()
	if err != nil {
		t.Fatalf("StateBlob: %v", err)
	}

	restored := New()
	if err := restored.LoadStateBlob(blob); err != nil {
		t.Fatalf("LoadStateBlob: %v", err)
	}
	if !bytes.Equal(restored.h.owner.authValue, []byte("owner-secret")) {
		t.Fatal("owner authValue did not survive the state blob round-trip")
	}
	if _, ok := restored.nv.get(nvH); !ok {
		t.Fatal("NV index did not survive the state blob round-trip")
	}

	// A corrupt blob is reported as an error, not a panic.
	if err := restored.LoadStateBlob([]byte("not json")); err == nil {
		t.Fatal("LoadStateBlob accepted a corrupt blob")
	}
}

func TestInitClearsVolatile(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	s := startSession(t, tpm, sePolicy, AlgSHA256)
	if _, ok := tpm.sessions.get(s); !ok {
		t.Fatal("session not created")
	}
	tpm.Init(false) // a reset: volatile sessions are dropped
	if _, ok := tpm.sessions.get(s); ok {
		t.Fatal("session survived Init")
	}
	tpm.Init(true) // a clear: also resets PCRs
}
