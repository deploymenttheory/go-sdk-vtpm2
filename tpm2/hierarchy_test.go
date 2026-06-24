// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
)

// buildHierarchyCmd frames a hierarchy-administration command: the auth handle,
// a single password authorization session carrying password, then params.
func buildHierarchyCmd(cc, authHandle uint32, password, params []byte) []byte {
	var auth writer
	auth.u32(RHPW)       // sessionHandle = TPM_RS_PW
	auth.u16(0)          // empty nonce
	auth.u8(0)           // attributes
	auth.tpm2b(password) // password carried in the hmac field

	var body writer
	body.u32(authHandle)                // handle area
	body.u32(uint32(len(auth.bytes()))) // authorizationSize
	body.raw(auth.bytes())
	body.raw(params)
	return buildCmd(TPMSTSessions, cc, body.bytes())
}

// authValueParam builds a TPM2B_AUTH parameter (e.g. newAuth).
func authValueParam(v []byte) []byte {
	var w writer
	w.tpm2b(v)
	return w.bytes()
}

func TestHierarchyChangeAuthAndVerify(t *testing.T) {
	tpm := New()
	startup(t, tpm)

	// Set owner auth (initial auth is empty).
	_, rc, _ := parseResp(t, tpm.Execute(buildHierarchyCmd(CCHierarchyChangeAuth, RHOwner, nil, authValueParam([]byte("owner-pw")))))
	if rc != RCSuccess {
		t.Fatalf("set owner auth rc = 0x%x", rc)
	}
	if !bytes.Equal(tpm.h.owner.authValue, []byte("owner-pw")) {
		t.Fatal("owner authValue not stored")
	}

	// Wrong password is rejected with AUTH_FAIL.
	_, rc, _ = parseResp(t, tpm.Execute(buildHierarchyCmd(CCHierarchyChangeAuth, RHOwner, []byte("wrong"), authValueParam([]byte("x")))))
	if baseRC(rc) != RCAuthFail {
		t.Fatalf("wrong password rc = 0x%x, want AUTH_FAIL (0x%x)", rc, RCAuthFail)
	}

	// Correct password succeeds and updates the value.
	_, rc, _ = parseResp(t, tpm.Execute(buildHierarchyCmd(CCHierarchyChangeAuth, RHOwner, []byte("owner-pw"), authValueParam([]byte("next")))))
	if rc != RCSuccess {
		t.Fatalf("correct password rc = 0x%x", rc)
	}
	if !bytes.Equal(tpm.h.owner.authValue, []byte("next")) {
		t.Fatal("owner authValue not updated")
	}
}

func TestClearResetsHierarchyAuth(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	tpm.h.owner.authValue = []byte("set")
	tpm.h.endorsement.authValue = []byte("set")
	oldSPS := append([]byte(nil), tpm.h.owner.seed...)
	oldEPS := append([]byte(nil), tpm.h.endorsement.seed...)

	_, rc, _ := parseResp(t, tpm.Execute(buildHierarchyCmd(CCClear, RHPlatform, nil, nil)))
	if rc != RCSuccess {
		t.Fatalf("Clear rc = 0x%x", rc)
	}
	if len(tpm.h.owner.authValue) != 0 || len(tpm.h.endorsement.authValue) != 0 {
		t.Fatal("Clear must reset owner and endorsement auth")
	}
	if bytes.Equal(tpm.h.owner.seed, oldSPS) {
		t.Fatal("Clear must regenerate the storage primary seed")
	}
	if !bytes.Equal(tpm.h.endorsement.seed, oldEPS) {
		t.Fatal("Clear must NOT change the endorsement seed (EK stays stable)")
	}
}

func TestClearControlDisablesLockoutClear(t *testing.T) {
	tpm := New()
	startup(t, tpm)

	_, rc, _ := parseResp(t, tpm.Execute(buildHierarchyCmd(CCClearControl, RHPlatform, nil, []byte{yes})))
	if rc != RCSuccess || !tpm.h.disableClear {
		t.Fatalf("ClearControl(disable) rc = 0x%x, disableClear=%v", rc, tpm.h.disableClear)
	}
	// Clear via lockout is now disabled...
	_, rc, _ = parseResp(t, tpm.Execute(buildHierarchyCmd(CCClear, RHLockout, nil, nil)))
	if rc != RCDisabled {
		t.Fatalf("Clear via lockout rc = 0x%x, want DISABLED (0x%x)", rc, RCDisabled)
	}
	// ...but Clear via platform still works.
	_, rc, _ = parseResp(t, tpm.Execute(buildHierarchyCmd(CCClear, RHPlatform, nil, nil)))
	if rc != RCSuccess {
		t.Fatalf("Clear via platform rc = 0x%x", rc)
	}
}

func TestChangeEPSRegeneratesEndorsementSeed(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	oldEPS := append([]byte(nil), tpm.h.endorsement.seed...)
	oldSPS := append([]byte(nil), tpm.h.owner.seed...)

	_, rc, _ := parseResp(t, tpm.Execute(buildHierarchyCmd(CCChangeEPS, RHPlatform, nil, nil)))
	if rc != RCSuccess {
		t.Fatalf("ChangeEPS rc = 0x%x", rc)
	}
	if bytes.Equal(tpm.h.endorsement.seed, oldEPS) {
		t.Fatal("ChangeEPS must regenerate the endorsement seed")
	}
	if !bytes.Equal(tpm.h.owner.seed, oldSPS) {
		t.Fatal("ChangeEPS must not touch the storage seed")
	}
}

func TestHierarchyControlDisableEnable(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	// Disable the storage hierarchy via platform: enable(u32)=RHOwner, state=NO.
	var p writer
	p.u32(RHOwner)
	p.u8(no)
	_, rc, _ := parseResp(t, tpm.Execute(buildHierarchyCmd(CCHierarchyControl, RHPlatform, nil, p.bytes())))
	if rc != RCSuccess || tpm.h.owner.enabled {
		t.Fatalf("disable storage rc = 0x%x, enabled=%v", rc, tpm.h.owner.enabled)
	}
	// Re-enable requires platform auth.
	var p2 writer
	p2.u32(RHOwner)
	p2.u8(yes)
	_, rc, _ = parseResp(t, tpm.Execute(buildHierarchyCmd(CCHierarchyControl, RHPlatform, nil, p2.bytes())))
	if rc != RCSuccess || !tpm.h.owner.enabled {
		t.Fatalf("enable storage rc = 0x%x, enabled=%v", rc, tpm.h.owner.enabled)
	}
}

func TestHierarchyCommandRequiresSession(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	body := make([]byte, 4)
	binary.BigEndian.PutUint32(body, RHPlatform)
	_, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCClear, body)))
	if rc != RCAuthMissing {
		t.Fatalf("Clear without sessions rc = 0x%x, want AUTH_MISSING", rc)
	}
}

func TestClearRejectsNonAdminHandle(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	_, rc, _ := parseResp(t, tpm.Execute(buildHierarchyCmd(CCClear, RHOwner, nil, nil)))
	if baseRC(rc) != RCHandle {
		t.Fatalf("Clear via owner rc = 0x%x, want HANDLE", rc)
	}
}

func TestGetCapabilityPermanentHandles(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	r := newReader(getCap(t, tpm, CapHandles, htPermanent, 100))
	_ = r.u8() // moreData
	if c := r.u32(); c != CapHandles {
		t.Fatalf("capability echo = 0x%x, want CapHandles", c)
	}
	if n := r.u32(); n != uint32(len(permanentHandles)) {
		t.Fatalf("handle count = %d, want %d", n, len(permanentHandles))
	}
	if h := r.u32(); h != RHOwner {
		t.Fatalf("first permanent handle = 0x%x, want RHOwner", h)
	}
}

func TestSnapshotV2RoundTrip(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	tpm.h.owner.authValue = []byte("ownerpw")
	tpm.h.disableClear = true
	ownerSeed := append([]byte(nil), tpm.h.owner.seed...)

	snap := tpm.Snapshot()
	if snap.Version != snapshotVersion {
		t.Fatalf("snapshot version = %d, want %d", snap.Version, snapshotVersion)
	}

	// Through JSON, the way the state package persists it.
	data, err := json.Marshal(snap)
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
	if !bytes.Equal(restored.h.owner.authValue, []byte("ownerpw")) {
		t.Fatal("owner auth not restored")
	}
	if !restored.h.disableClear {
		t.Fatal("disableClear not restored")
	}
	if !bytes.Equal(restored.h.owner.seed, ownerSeed) {
		t.Fatal("storage seed not restored — the SRK would change across reboot")
	}
}

func TestSnapshotV1Migration(t *testing.T) {
	// A v1 snapshot has no hierarchies; Restore must accept it and keep the fresh
	// seeds New minted (forward migration).
	v1 := Snapshot{Version: 1, Started: true, PCRBanks: map[uint16][][]byte{}}
	tpm := New()
	if err := tpm.Restore(v1); err != nil {
		t.Fatalf("v1 restore: %v", err)
	}
	if len(tpm.h.owner.seed) != seedSize || len(tpm.h.endorsement.seed) != seedSize {
		t.Fatal("v1 migration should retain freshly minted primary seeds")
	}
}
