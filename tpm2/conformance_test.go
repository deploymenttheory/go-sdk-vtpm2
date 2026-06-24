// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"encoding/binary"
	"testing"
)

// These tests pin spec-conformance fixes: correct format-one response-code
// values, accurate pcrSelectionOut, the proper error codes for missing/oversized
// authorization, GetCapability handling of unknown selectors and propertyCount 0,
// and TPMI_YES_NO range checking. Each references the TPM 2.0 Library spec.

// selectionEntry is one TPMS_PCR_SELECTION used to build PCR_Read requests.
type selectionEntry struct {
	hash   uint16
	bitmap []byte
}

// buildSelections frames a TPML_PCR_SELECTION from the given entries.
func buildSelections(sels ...selectionEntry) []byte {
	var w writer
	w.u32(uint32(len(sels)))
	for _, s := range sels {
		w.u16(s.hash)
		w.u8(byte(len(s.bitmap)))
		w.raw(s.bitmap)
	}
	return w.bytes()
}

// pcrBit returns a fresh 3-byte select bitmap with one PCR index set.
func pcrBit(index int) []byte {
	b := make([]byte, 3)
	b[index/8] |= 1 << (uint(index) % 8)
	return b
}

// bitsSet counts the set bits in b.
func bitsSet(b byte) int {
	n := 0
	for ; b != 0; b &= b - 1 {
		n++
	}
	return n
}

// TestFormatOneResponseCodeValues checks that TPM_RC_VALUE / TPM_RC_INSUFFICIENT
// are built on RC_FMT1 (0x080), not RC_VER1 — values like 0x104 / 0x19A are not
// decodable response codes (TPM 2.0 Part 2, Response Code Details).
func TestFormatOneResponseCodeValues(t *testing.T) {
	if RCValue != 0x084 {
		t.Errorf("RCValue = 0x%x, want 0x084", RCValue)
	}
	if RCInsufficient != 0x09A {
		t.Errorf("RCInsufficient = 0x%x, want 0x09A", RCInsufficient)
	}
	if RCSize != 0x095 {
		t.Errorf("RCSize = 0x%x, want 0x095", RCSize)
	}
	for _, rc := range []uint32{RCValue, RCSize, RCInsufficient} {
		if rc&rcFmt1 == 0 {
			t.Errorf("format-one code 0x%x missing RC_FMT1 bit", rc)
		}
		if rc&rcVer1 != 0 {
			t.Errorf("format-one code 0x%x must not set the RC_VER1 bit", rc)
		}
	}
}

// TestStartupBadTypeReturnsValue exercises the corrected TPM_RC_VALUE on the
// happy error path of an invalid TPM_SU.
func TestStartupBadTypeReturnsValue(t *testing.T) {
	tpm := New()
	su := make([]byte, 2)
	binary.BigEndian.PutUint16(su, 0x0099) // neither CLEAR nor STATE
	_, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCStartup, su)))
	if rc != withParam(RCValue, 1) {
		t.Fatalf("Startup(bad su) rc = 0x%x, want VALUE+param1 (0x%x)", rc, withParam(RCValue, 1))
	}
	if baseRC(rc) != RCValue {
		t.Fatalf("baseRC(0x%x) = 0x%x, want VALUE (0x%x)", rc, baseRC(rc), RCValue)
	}
}

// TestFormatOneDecoration checks the parameter/handle/session number encoding and
// that baseRC recovers the canonical code (TPM 2.0 Part 2, Response Code Details).
func TestFormatOneDecoration(t *testing.T) {
	// Parameter 1 on TPM_RC_VALUE: P bit (0x40) + N=1 (<<8).
	if got := withParam(RCValue, 1); got != RCValue|0x040|0x100 {
		t.Errorf("withParam(VALUE,1) = 0x%x, want 0x%x", got, RCValue|0x040|0x100)
	}
	// Handle 1: P clear, N=1.
	if got := withHandle(RCValue, 1); got != RCValue|0x100 {
		t.Errorf("withHandle(VALUE,1) = 0x%x, want 0x%x", got, RCValue|0x100)
	}
	for _, rc := range []uint32{withParam(RCValue, 3), withHandle(RCSize, 2), RCInsufficient} {
		if baseRC(rc) != (rc&0x03F | rcFmt1) {
			t.Errorf("baseRC(0x%x) = 0x%x, lost the bare error number", rc, baseRC(rc))
		}
	}
	// Format-zero codes pass through baseRC unchanged.
	if baseRC(RCInitialize) != RCInitialize {
		t.Errorf("baseRC must not touch format-zero codes")
	}
}

// TestTruncatedParamsReturnsInsufficient confirms a short parameter area yields
// the corrected TPM_RC_INSUFFICIENT.
func TestTruncatedParamsReturnsInsufficient(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	// GetRandom's bytesRequested is a UINT16; supply only one byte.
	_, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCGetRandom, []byte{0x00})))
	if rc != RCInsufficient {
		t.Fatalf("truncated GetRandom rc = 0x%x, want INSUFFICIENT (0x%x)", rc, RCInsufficient)
	}
}

// TestSelfTestRejectsNonBoolean checks TPMI_YES_NO range validation.
func TestSelfTestRejectsNonBoolean(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	_, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCSelfTest, []byte{2})))
	if baseRC(rc) != RCValue {
		t.Fatalf("SelfTest(fullTest=2) rc = 0x%x, want VALUE (0x%x)", rc, RCValue)
	}
}

// TestPCRReadUnsupportedBankClearsSelection: requesting a bank the TPM does not
// implement must read nothing and clear that bank's bits in pcrSelectionOut, so
// the selection and the digest list stay consistent (TPM 2.0 Part 3,
// TPM2_PCR_Read).
func TestPCRReadUnsupportedBankClearsSelection(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	req := buildSelections(selectionEntry{AlgSHA384, pcrBit(0)})
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCPCRRead, req)))
	if rc != RCSuccess {
		t.Fatalf("PCR_Read rc = 0x%x", rc)
	}
	r := newReader(p)
	_ = r.u32() // pcrUpdateCounter
	if nSel := r.u32(); nSel != 1 {
		t.Fatalf("pcrSelectionOut has %d selections, want 1", nSel)
	}
	if hash := r.u16(); hash != AlgSHA384 {
		t.Fatalf("selection hash = 0x%x, want SHA384", hash)
	}
	for i, b := range r.bytes(int(r.u8())) {
		if b != 0 {
			t.Fatalf("unsupported-bank bitmap byte %d = 0x%x, want 0 (nothing read)", i, b)
		}
	}
	if n := r.u32(); n != 0 {
		t.Fatalf("pcrValues count = %d, want 0", n)
	}
	if r.err != nil {
		t.Fatalf("parse: %v", r.err)
	}
}

// TestPCRReadMixedBanksConsistent: across a mix of supported and unsupported
// banks the number of set bits in pcrSelectionOut must equal the digest count.
func TestPCRReadMixedBanksConsistent(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	req := buildSelections(
		selectionEntry{AlgSHA256, pcrBit(0)}, // supported → read
		selectionEntry{AlgSHA384, pcrBit(0)}, // unsupported → cleared
	)
	_, _, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCPCRRead, req)))
	r := newReader(p)
	_ = r.u32() // pcrUpdateCounter
	setBits := 0
	for i := r.u32(); i > 0; i-- {
		_ = r.u16() // hash
		for _, b := range r.bytes(int(r.u8())) {
			setBits += bitsSet(b)
		}
	}
	nVals := r.u32()
	if r.err != nil {
		t.Fatalf("parse: %v", r.err)
	}
	if uint32(setBits) != nVals {
		t.Fatalf("pcrSelectionOut sets %d bits but pcrValues has %d digests", setBits, nVals)
	}
	if nVals != 1 {
		t.Fatalf("expected exactly 1 digest (SHA-256 PCR0), got %d", nVals)
	}
}

// TestPCRReadBadSelectSize: a sizeofSelect outside [PCR_SELECT_MIN, MAX] is a
// TPM_RC_VALUE, not an underrun (F-10).
func TestPCRReadBadSelectSize(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	for _, size := range []int{pcrSelectMin - 1, pcrSelectMax + 1} {
		req := buildSelections(selectionEntry{AlgSHA256, make([]byte, size)})
		_, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCPCRRead, req)))
		if baseRC(rc) != RCValue {
			t.Fatalf("PCR_Read(sizeofSelect=%d) rc = 0x%x, want VALUE", size, rc)
		}
	}
}

// TestPCRExtendWithoutSession: a command that requires authorization sent with
// no sessions is TPM_RC_AUTH_MISSING, not TPM_RC_FAILURE.
func TestPCRExtendWithoutSession(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	var ext writer
	ext.u32(0) // pcrHandle
	_, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCPCRExtend, ext.bytes())))
	if rc != RCAuthMissing {
		t.Fatalf("PCR_Extend(no session) rc = 0x%x, want AUTH_MISSING (0x%x)", rc, RCAuthMissing)
	}
}

// TestPCRExtendBadAuthSize: an authorizationSize that does not frame a valid auth
// area is TPM_RC_AUTHSIZE, not TPM_RC_FAILURE.
func TestPCRExtendBadAuthSize(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	var ext writer
	ext.u32(0)   // pcrHandle
	ext.u32(100) // authorizationSize far larger than the bytes that follow
	ext.u16(0)   // stray bytes, not a valid session
	_, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCPCRExtend, ext.bytes())))
	if rc != RCAuthSize {
		t.Fatalf("PCR_Extend(bad authSize) rc = 0x%x, want AUTHSIZE (0x%x)", rc, RCAuthSize)
	}
}

// TestGetCapabilityUnknownCapability: an out-of-range capability selector is a
// TPM_RC_VALUE error, not silent success (TPM 2.0 Part 3, TPM2_GetCapability).
func TestGetCapabilityUnknownCapability(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	params := make([]byte, 12)
	binary.BigEndian.PutUint32(params[0:], 0x99999999) // not a defined TPM_CAP
	_, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCGetCapability, params)))
	if baseRC(rc) != RCValue {
		t.Fatalf("GetCapability(unknown cap) rc = 0x%x, want VALUE (0x%x)", rc, RCValue)
	}
	if rc != withParam(RCValue, 1) {
		t.Fatalf("unknown cap rc = 0x%x, want VALUE+param1 (0x%x)", rc, withParam(RCValue, 1))
	}
}

// TestGetCapabilityKnownEmpty: a defined-but-unenumerated capability (ECC curves,
// not supported yet) returns a correctly-typed empty list, not an error — even
// with a non-zero requested count.
func TestGetCapabilityKnownEmpty(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	r := newReader(getCap(t, tpm, CapECCCurves, 0, 100))
	_ = r.u8() // moreData
	if cap := r.u32(); cap != CapECCCurves {
		t.Fatalf("capability echo = 0x%x, want CapECCCurves", cap)
	}
	if n := r.u32(); n != 0 {
		t.Fatalf("empty list count = %d, want 0", n)
	}
}

// getCap issues TPM2_GetCapability and returns the response parameter bytes.
func getCap(t *testing.T, tpm *TPM, capability, property, count uint32) []byte {
	t.Helper()
	params := make([]byte, 12)
	binary.BigEndian.PutUint32(params[0:], capability)
	binary.BigEndian.PutUint32(params[4:], property)
	binary.BigEndian.PutUint32(params[8:], count)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCGetCapability, params)))
	if rc != RCSuccess {
		t.Fatalf("GetCapability(0x%x) rc = 0x%x", capability, rc)
	}
	return p
}

// TestGetCapabilityAlgs enumerates TPM_CAP_ALGS as a TPML_ALG_PROPERTY.
func TestGetCapabilityAlgs(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	r := newReader(getCap(t, tpm, CapAlgs, 0, 100))
	_ = r.u8() // moreData
	if c := r.u32(); c != CapAlgs {
		t.Fatalf("capability echo = 0x%x, want CapAlgs", c)
	}
	n := r.u32()
	if n != uint32(len(advertisedAlgs)) {
		t.Fatalf("algorithm count = %d, want %d", n, len(advertisedAlgs))
	}
	alg := r.u16()
	attrs := r.u32()
	if r.err != nil || alg != AlgSHA1 || attrs&algAttrHash == 0 {
		t.Fatalf("first alg = (0x%x, attrs 0x%x), want SHA1 with hash attr (err %v)", alg, attrs, r.err)
	}
}

// TestGetCapabilityCommands enumerates TPM_CAP_COMMANDS as a TPML_CCA and checks
// that PCR_Extend reports one command handle.
func TestGetCapabilityCommands(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	r := newReader(getCap(t, tpm, CapCommands, 0, 256))
	_ = r.u8() // moreData
	if c := r.u32(); c != CapCommands {
		t.Fatalf("capability echo = 0x%x, want CapCommands", c)
	}
	n := r.u32()
	if n != uint32(len(commandTable)) {
		t.Fatalf("command count = %d, want %d", n, len(commandTable))
	}
	var sawExtend bool
	for i := uint32(0); i < n; i++ {
		cc := r.u32()
		if cc&ccAttrIndexMask == CCPCRExtend&ccAttrIndexMask {
			sawExtend = true
			if got := cc >> ccAttrCHandleSh & 0x7; got != 1 {
				t.Fatalf("PCR_Extend cHandles = %d, want 1", got)
			}
		}
	}
	if r.err != nil || !sawExtend {
		t.Fatalf("PCR_Extend not found in command list (err %v)", r.err)
	}
}

// TestCapabilityListsAscending guards the ordering GetCapability relies on: the
// property/algorithm/command lists must be strictly ascending by tag.
func TestCapabilityListsAscending(t *testing.T) {
	for i := 1; i < len(fixedProperties); i++ {
		if fixedProperties[i].property <= fixedProperties[i-1].property {
			t.Fatalf("fixedProperties not ascending at %d: 0x%x then 0x%x", i, fixedProperties[i-1].property, fixedProperties[i].property)
		}
	}
	for i := 1; i < len(advertisedAlgs); i++ {
		if advertisedAlgs[i].property <= advertisedAlgs[i-1].property {
			t.Fatalf("advertisedAlgs not ascending at %d", i)
		}
	}
	for i := 1; i < len(commandTable); i++ {
		if commandTable[i].cc <= commandTable[i-1].cc {
			t.Fatalf("commandTable not ascending at %d", i)
		}
	}
}

// TestGetCapabilityPropertyCountZero: propertyCount 0 returns no properties but
// reports moreData=YES because properties exist.
func TestGetCapabilityPropertyCountZero(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	params := make([]byte, 12)
	binary.BigEndian.PutUint32(params[0:], CapTPMProperties)
	binary.BigEndian.PutUint32(params[4:], PTFamilyIndicator) // from the first property
	binary.BigEndian.PutUint32(params[8:], 0)                 // propertyCount = 0
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCGetCapability, params)))
	if rc != RCSuccess {
		t.Fatalf("rc = 0x%x", rc)
	}
	r := newReader(p)
	more := r.u8()
	_ = r.u32() // capability
	if count := r.u32(); count != 0 {
		t.Fatalf("propertyCount 0 returned %d properties, want 0", count)
	}
	if more != yes {
		t.Fatalf("moreData = %d, want yes (properties exist beyond the 0 returned)", more)
	}
}
