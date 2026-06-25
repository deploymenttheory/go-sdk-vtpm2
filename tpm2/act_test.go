// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import "testing"

func TestACTSetTimeout(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	const act = rhACTFirst

	var b writer
	b.u32(act)
	b.raw(onePasswordAuth())
	b.u32(3600)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCACTSetTimeout, b.bytes()))); rc != RCSuccess {
		t.Fatalf("ACT_SetTimeout rc = 0x%x", rc)
	}
	if timer := tpm.actTimers[act]; timer == nil || timer.timeout != 3600 || timer.signaled {
		t.Fatalf("ACT timer = %+v, want {3600 false}", tpm.actTimers[act])
	}

	// A handle outside the ACT range is rejected.
	var bb writer
	bb.u32(0x40000200)
	bb.raw(onePasswordAuth())
	bb.u32(1)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCACTSetTimeout, bb.bytes()))); baseRC(rc) != RCValue {
		t.Fatalf("out-of-range ACT_SetTimeout rc = 0x%x, want RC_VALUE", rc)
	}
}

func TestReadOnlyControl(t *testing.T) {
	tpm := New()
	startup(t, tpm)

	var b writer
	b.u32(RHPlatform)
	b.raw(onePasswordAuth())
	b.u8(yes)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCReadOnlyControl, b.bytes()))); rc != RCSuccess {
		t.Fatalf("ReadOnlyControl rc = 0x%x", rc)
	}
	if !tpm.readOnly {
		t.Fatal("read-only mode was not enabled")
	}

	// Only the platform hierarchy may control it.
	var bb writer
	bb.u32(RHOwner)
	bb.raw(onePasswordAuth())
	bb.u8(no)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCReadOnlyControl, bb.bytes()))); baseRC(rc) != RCValue {
		t.Fatalf("owner ReadOnlyControl rc = 0x%x, want RC_VALUE", rc)
	}
}
