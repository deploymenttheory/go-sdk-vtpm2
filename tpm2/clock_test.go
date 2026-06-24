// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import "testing"

// readClockValue returns the Clock value (clockInfo.clock) via TPM2_ReadClock.
func readClockValue(t *testing.T, tpm *TPM) uint64 {
	t.Helper()
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCReadClock, nil)))
	if rc != RCSuccess {
		t.Fatalf("ReadClock rc = 0x%x", rc)
	}
	r := newReader(p)
	_ = r.u64() // time
	return r.u64()
}

func TestClockSet(t *testing.T) {
	tpm := New()
	startup(t, tpm)

	var b writer
	b.u32(RHOwner)
	b.raw(onePasswordAuth())
	b.u64(1_000_000)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCClockSet, b.bytes()))); rc != RCSuccess {
		t.Fatalf("ClockSet rc = 0x%x", rc)
	}
	if c := readClockValue(t, tpm); c < 1_000_000 {
		t.Fatalf("Clock = %d, want >= 1000000", c)
	}

	// Clock cannot move backward.
	var bb writer
	bb.u32(RHOwner)
	bb.raw(onePasswordAuth())
	bb.u64(500_000)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCClockSet, bb.bytes()))); baseRC(rc) != RCValue {
		t.Fatalf("backward ClockSet rc = 0x%x, want RC_VALUE", rc)
	}
}

func TestClockRateAdjust(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	for _, adj := range []byte{0x00, 0x03, 0xFF /* -1 */, 0xFD /* -3 */} {
		var b writer
		b.u32(RHOwner)
		b.raw(onePasswordAuth())
		b.u8(adj)
		if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCClockRateAdjust, b.bytes()))); rc != RCSuccess {
			t.Fatalf("ClockRateAdjust(%#x) rc = 0x%x", adj, rc)
		}
	}
	// Out of range (-4) is rejected.
	var b writer
	b.u32(RHOwner)
	b.raw(onePasswordAuth())
	b.u8(0xFC) // -4
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCClockRateAdjust, b.bytes()))); baseRC(rc) != RCValue {
		t.Fatalf("out-of-range ClockRateAdjust rc = 0x%x, want RC_VALUE", rc)
	}
}
