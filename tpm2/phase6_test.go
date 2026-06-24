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

func TestPCREvent(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	const index = 16 // a debug PCR, extendable at locality 0
	before := append([]byte(nil), tpm.pcr.banks[AlgSHA256][index]...)
	eventData := []byte("measured-event")

	var b writer
	b.u32(index)
	b.raw(onePasswordAuth())
	b.tpm2b(eventData)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCPCREvent, b.bytes())))
	if rc != RCSuccess {
		t.Fatalf("PCR_Event rc = 0x%x", rc)
	}

	// The response lists a digest per bank; find the SHA-256 one.
	r := newReader(p)
	count := r.u32()
	var sha256Digest []byte
	for i := uint32(0); i < count; i++ {
		alg := r.u16()
		d := r.bytes(hashSize(alg))
		if alg == AlgSHA256 {
			sha256Digest = d
		}
	}
	wantEvent := hashSum(AlgSHA256, eventData)
	if !bytes.Equal(sha256Digest, wantEvent) {
		t.Fatal("returned SHA-256 event digest mismatch")
	}
	// PCR[index] := H(old ‖ H(eventData)).
	if got := tpm.pcr.banks[AlgSHA256][index]; !bytes.Equal(got, hashSum(AlgSHA256, before, wantEvent)) {
		t.Fatal("PCR not extended with the event digest")
	}
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
