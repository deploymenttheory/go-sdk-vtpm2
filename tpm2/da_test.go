// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"encoding/json"
	"testing"
)

// failOwnerAuth attempts an owner-authorized command with a deliberately wrong
// password and returns the response code.
func failOwnerAuth(t *testing.T, tpm *TPM) uint32 {
	t.Helper()
	_, rc, _ := parseResp(t, tpm.Execute(buildHierarchyCmd(CCHierarchyChangeAuth, RHOwner, []byte("wrong"), authValueParam([]byte("x")))))
	return rc
}

func TestDALockoutAfterMaxTries(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	tpm.h.owner.authValue = []byte("correct")
	tpm.da.maxTries = 3

	// Three wrong attempts increment the counter and report AUTH_FAIL.
	for i := 0; i < 3; i++ {
		if rc := failOwnerAuth(t, tpm); baseRC(rc) != RCAuthFail {
			t.Fatalf("attempt %d rc = 0x%x, want AUTH_FAIL", i, rc)
		}
	}
	if tpm.da.failedTries != 3 || !tpm.da.inLockout() {
		t.Fatalf("after 3 failures: failedTries=%d inLockout=%v", tpm.da.failedTries, tpm.da.inLockout())
	}
	// Now in lockout: even the correct password is refused with LOCKOUT.
	_, rc, _ := parseResp(t, tpm.Execute(buildHierarchyCmd(CCHierarchyChangeAuth, RHOwner, []byte("correct"), authValueParam([]byte("y")))))
	if rc != RCLockout {
		t.Fatalf("in lockout rc = 0x%x, want LOCKOUT (0x%x)", rc, RCLockout)
	}
}

func TestDASuccessResetsCounter(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	tpm.h.owner.authValue = []byte("correct")
	tpm.da.maxTries = 5

	failOwnerAuth(t, tpm)
	failOwnerAuth(t, tpm)
	if tpm.da.failedTries != 2 {
		t.Fatalf("failedTries = %d, want 2", tpm.da.failedTries)
	}
	// A correct owner auth clears the counter.
	if _, rc, _ := parseResp(t, tpm.Execute(buildHierarchyCmd(CCHierarchyChangeAuth, RHOwner, []byte("correct"), authValueParam([]byte("z"))))); rc != RCSuccess {
		t.Fatalf("correct auth rc = 0x%x", rc)
	}
	if tpm.da.failedTries != 0 {
		t.Fatalf("failedTries = %d after success, want 0", tpm.da.failedTries)
	}
}

func TestDictionaryAttackLockReset(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	tpm.h.owner.authValue = []byte("correct")
	tpm.da.maxTries = 2
	failOwnerAuth(t, tpm)
	failOwnerAuth(t, tpm)
	if !tpm.da.inLockout() {
		t.Fatal("expected lockout")
	}
	// LockReset under lockout auth (empty by default) recovers.
	if _, rc, _ := parseResp(t, tpm.Execute(buildHierarchyCmd(CCDictionaryAttackLockReset, RHLockout, nil, nil))); rc != RCSuccess {
		t.Fatalf("LockReset rc = 0x%x", rc)
	}
	if tpm.da.failedTries != 0 || tpm.da.inLockout() {
		t.Fatalf("after LockReset: failedTries=%d inLockout=%v", tpm.da.failedTries, tpm.da.inLockout())
	}
}

func TestDictionaryAttackParameters(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	var p writer
	p.u32(10)    // newMaxTries
	p.u32(600)   // newRecoveryTime
	p.u32(86400) // lockoutRecovery
	if _, rc, _ := parseResp(t, tpm.Execute(buildHierarchyCmd(CCDictionaryAttackParameters, RHLockout, nil, p.bytes()))); rc != RCSuccess {
		t.Fatalf("DA parameters rc = 0x%x", rc)
	}
	if tpm.da.maxTries != 10 || tpm.da.recoveryTime != 600 || tpm.da.lockoutRecovery != 86400 {
		t.Fatalf("DA parameters not applied: %+v", tpm.da)
	}
}

func TestClearResetsDA(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	tpm.da.failedTries = 5
	tpm.da.maxTries = 9
	if _, rc, _ := parseResp(t, tpm.Execute(buildHierarchyCmd(CCClear, RHPlatform, nil, nil))); rc != RCSuccess {
		t.Fatalf("Clear rc = 0x%x", rc)
	}
	if tpm.da.failedTries != 0 || tpm.da.maxTries != 32 {
		t.Fatalf("Clear must reset DA to defaults: %+v", tpm.da)
	}
}

func TestLockoutPropertiesReported(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	tpm.da.failedTries = 4
	tpm.da.maxTries = 11
	r := newReader(getCap(t, tpm, CapTPMProperties, PTLockoutCounter, 2))
	_ = r.u8() // moreData
	_ = r.u32()
	count := r.u32()
	if count != 2 {
		t.Fatalf("property count = %d, want 2", count)
	}
	if prop, val := r.u32(), r.u32(); prop != PTLockoutCounter || val != 4 {
		t.Fatalf("lockout counter property = (0x%x, %d), want (PTLockoutCounter, 4)", prop, val)
	}
	if prop, val := r.u32(), r.u32(); prop != PTMaxAuthFail || val != 11 {
		t.Fatalf("max-auth-fail property = (0x%x, %d), want (PTMaxAuthFail, 11)", prop, val)
	}
}

func TestSnapshotV3PersistsDA(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	tpm.da.failedTries = 7
	tpm.da.maxTries = 20

	data, err := json.Marshal(tpm.Snapshot())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Snapshot
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	restored := New()
	if err := restored.Restore(back); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if restored.da.failedTries != 7 || restored.da.maxTries != 20 {
		t.Fatalf("DA not restored: %+v", restored.da)
	}
}
