// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// rsPWHandle is TPM_RS_PW, the reserved password-authorization session handle.
const rsPWHandle uint32 = 0x40000009

// buildCmd frames a command blob: header (tag, size, code) + params.
func buildCmd(tag uint16, code uint32, params []byte) []byte {
	out := make([]byte, headerLen)
	binary.BigEndian.PutUint16(out[0:], tag)
	binary.BigEndian.PutUint32(out[2:], uint32(headerLen+len(params)))
	binary.BigEndian.PutUint32(out[6:], code)
	return append(out, params...)
}

// parseResp returns the tag, responseCode, and parameter bytes of a response.
func parseResp(t *testing.T, resp []byte) (uint16, uint32, []byte) {
	t.Helper()
	if len(resp) < headerLen {
		t.Fatalf("response shorter than header: %d bytes", len(resp))
	}
	tag := binary.BigEndian.Uint16(resp[0:])
	size := binary.BigEndian.Uint32(resp[2:])
	rc := binary.BigEndian.Uint32(resp[6:])
	if int(size) != len(resp) {
		t.Fatalf("responseSize %d != actual %d", size, len(resp))
	}
	return tag, rc, resp[headerLen:]
}

// startup runs TPM2_Startup(CLEAR) and fails the test if it does not succeed.
func startup(t *testing.T, tpm *TPM) {
	t.Helper()
	su := make([]byte, 2)
	binary.BigEndian.PutUint16(su, SUClear)
	_, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCStartup, su)))
	if rc != RCSuccess {
		t.Fatalf("Startup rc = 0x%x, want success", rc)
	}
}

func TestStartupSequencing(t *testing.T) {
	tpm := New()
	su := make([]byte, 2)
	binary.BigEndian.PutUint16(su, SUClear)

	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCStartup, su))); rc != RCSuccess {
		t.Fatalf("first Startup rc = 0x%x", rc)
	}
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCStartup, su))); rc != RCInitialize {
		t.Fatalf("second Startup rc = 0x%x, want INITIALIZE (0x%x)", rc, RCInitialize)
	}
}

func TestGetRandom(t *testing.T) {
	tpm := New()
	startup(t, tpm)

	params := make([]byte, 2)
	binary.BigEndian.PutUint16(params, 16)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCGetRandom, params)))
	if rc != RCSuccess {
		t.Fatalf("GetRandom rc = 0x%x", rc)
	}
	r := newReader(p)
	n := int(r.u16())
	got := r.bytes(n)
	if r.err != nil || n != 16 || len(got) != 16 {
		t.Fatalf("GetRandom returned %d bytes (err %v)", n, r.err)
	}
}

func TestGetRandomCapped(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	params := make([]byte, 2)
	binary.BigEndian.PutUint16(params, 1024) // over the cap
	_, _, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCGetRandom, params)))
	if n := int(binary.BigEndian.Uint16(p)); n != maxRandomBytes {
		t.Fatalf("capped GetRandom = %d, want %d", n, maxRandomBytes)
	}
}

func TestSelfTestAndResult(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCSelfTest, []byte{yes}))); rc != RCSuccess {
		t.Fatalf("SelfTest rc = 0x%x", rc)
	}
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCGetTestResult, nil)))
	if rc != RCSuccess {
		t.Fatalf("GetTestResult rc = 0x%x", rc)
	}
	r := newReader(p)
	_ = r.bytes(int(r.u16())) // outData
	if result := r.u32(); result != RCSuccess {
		t.Fatalf("testResult = 0x%x, want success", result)
	}
}

func TestGetCapabilityProperties(t *testing.T) {
	tpm := New()
	startup(t, tpm)

	params := make([]byte, 12)
	binary.BigEndian.PutUint32(params[0:], CapTPMProperties)
	binary.BigEndian.PutUint32(params[4:], PTPCRCount)
	binary.BigEndian.PutUint32(params[8:], 1)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCGetCapability, params)))
	if rc != RCSuccess {
		t.Fatalf("GetCapability rc = 0x%x", rc)
	}
	r := newReader(p)
	_ = r.u8() // moreData
	cap := r.u32()
	count := r.u32()
	prop := r.u32()
	val := r.u32()
	if r.err != nil || cap != CapTPMProperties || count != 1 || prop != PTPCRCount || val != numPCR {
		t.Fatalf("PCR_COUNT property = (cap 0x%x, count %d, prop 0x%x, val %d), err %v", cap, count, prop, val, r.err)
	}
}

func TestGetCapabilityPCRs(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	params := make([]byte, 12)
	binary.BigEndian.PutUint32(params[0:], CapPCRs)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCGetCapability, params)))
	if rc != RCSuccess {
		t.Fatalf("rc = 0x%x", rc)
	}
	r := newReader(p)
	_ = r.u8()
	_ = r.u32() // capability
	if banks := r.u32(); int(banks) != len(supportedPCRBanks) {
		t.Fatalf("advertised %d PCR banks, want %d", banks, len(supportedPCRBanks))
	}
}

// oneSHA256Selection builds a TPML_PCR_SELECTION selecting a single SHA-256 PCR.
func oneSHA256Selection(index int) []byte {
	var w writer
	bitmap := make([]byte, 3)
	bitmap[index/8] |= 1 << (uint(index) % 8)
	w.u32(1) // one selection
	w.u16(AlgSHA256)
	w.u8(3)
	w.raw(bitmap)
	return w.bytes()
}

func TestPCRExtendAndRead(t *testing.T) {
	tpm := New()
	startup(t, tpm)

	// Read PCR0/SHA-256 — must be all zero at power-on.
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCPCRRead, oneSHA256Selection(0))))
	if rc != RCSuccess {
		t.Fatalf("PCR_Read rc = 0x%x", rc)
	}
	initial := firstDigest(t, p)
	if !bytes.Equal(initial, make([]byte, 32)) {
		t.Fatalf("initial PCR0 not zero: %x", initial)
	}

	// Extend PCR0/SHA-256 with a known digest.
	digest := bytes.Repeat([]byte{0xAB}, 32)
	var ext writer
	ext.u32(0) // pcrHandle = PCR index 0
	// authorization area: one empty password session
	var auth writer
	auth.u32(rsPWHandle) // sessionHandle = TPM_RS_PW
	auth.u16(0)          // empty nonce
	auth.u8(0)           // attributes
	auth.u16(0)          // empty hmac
	ext.u32(uint32(len(auth.bytes())))
	ext.raw(auth.bytes())
	ext.u32(1) // TPML_DIGEST_VALUES count
	ext.u16(AlgSHA256)
	ext.raw(digest)

	_, rc, _ = parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCPCRExtend, ext.bytes())))
	if rc != RCSuccess {
		t.Fatalf("PCR_Extend rc = 0x%x", rc)
	}

	// Re-read; PCR0 must equal SHA256(zeros || digest).
	_, _, p = parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCPCRRead, oneSHA256Selection(0))))
	want := sha256.Sum256(append(make([]byte, 32), digest...))
	if got := firstDigest(t, p); !bytes.Equal(got, want[:]) {
		t.Fatalf("extended PCR0 = %x, want %x", got, want)
	}
}

// firstDigest extracts the first digest from a PCR_Read response body.
func firstDigest(t *testing.T, p []byte) []byte {
	t.Helper()
	r := newReader(p)
	_ = r.u32() // pcrUpdateCounter
	// skip pcrSelectionOut
	for i := r.u32(); i > 0; i-- {
		_ = r.u16()              // hash
		_ = r.bytes(int(r.u8())) // bitmap
	}
	if n := r.u32(); n == 0 {
		t.Fatal("no digests returned")
	}
	d := r.bytes(int(r.u16()))
	if r.err != nil {
		t.Fatalf("parse digest: %v", r.err)
	}
	return d
}

func TestErrorResponses(t *testing.T) {
	tpm := New()
	startup(t, tpm)

	// Bad tag.
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(0x1234, CCGetRandom, []byte{0, 1}))); rc != RCBadTag {
		t.Fatalf("bad tag rc = 0x%x, want BAD_TAG", rc)
	}
	// Unknown command code.
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, 0x0000FFFF, nil))); rc != RCCommandCode {
		t.Fatalf("unknown cc rc = 0x%x, want COMMAND_CODE", rc)
	}
	// Declared size disagreeing with actual length.
	cmd := buildCmd(TPMSTNoSessions, CCGetRandom, []byte{0, 1})
	binary.BigEndian.PutUint32(cmd[2:], 999)
	if _, rc, _ := parseResp(t, tpm.Execute(cmd)); rc != RCCommandSize {
		t.Fatalf("bad size rc = 0x%x, want COMMAND_SIZE", rc)
	}
}
