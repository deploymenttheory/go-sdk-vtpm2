package tpm2

import "testing"

// TestFixedPropertyTagsMatchSpec pins every PT_FIXED tag to TPM 2.0 Part 2 (PT_FIXED =
// 0x100). Four of these were previously misnumbered — TOTAL_COMMANDS/LIBRARY_COMMANDS/
// VENDOR_COMMANDS/MODES sat at 0x129/0x12A/0x12B/0x12D instead of 0x127/0x128/0x129/0x12B
// — which reported len(commandTable) as VENDOR_COMMANDS and NV_BUFFER_MAX and emitted a
// property 0x12D that does not exist in the spec. Windows' tpm.sys reads this table during
// StartDevice and refused the device (CM_PROB_FAILED_START, TpmPresent=False), so a
// numbering slip here is not cosmetic: it costs the whole TPM.
func TestFixedPropertyTagsMatchSpec(t *testing.T) {
	want := map[string]uint32{
		"FAMILY_INDICATOR": 0x100, "LEVEL": 0x101, "REVISION": 0x102, "DAY_OF_YEAR": 0x103,
		"YEAR": 0x104, "MANUFACTURER": 0x105, "VENDOR_STRING_1": 0x106, "VENDOR_STRING_2": 0x107,
		"VENDOR_STRING_3": 0x108, "VENDOR_STRING_4": 0x109, "VENDOR_TPM_TYPE": 0x10A,
		"FIRMWARE_VERSION_1": 0x10B, "FIRMWARE_VERSION_2": 0x10C, "INPUT_BUFFER": 0x10D,
		"HR_TRANSIENT_MIN": 0x10E, "HR_PERSISTENT_MIN": 0x10F, "HR_LOADED_MIN": 0x110,
		"ACTIVE_SESSIONS_MAX": 0x111, "PCR_COUNT": 0x112, "PCR_SELECT_MIN": 0x113,
		"CONTEXT_GAP_MAX": 0x114, "NV_COUNTERS_MAX": 0x116, "NV_INDEX_MAX": 0x117,
		"MEMORY": 0x118, "CLOCK_UPDATE": 0x119, "CONTEXT_HASH": 0x11A, "CONTEXT_SYM": 0x11B,
		"CONTEXT_SYM_SIZE": 0x11C, "ORDERLY_COUNT": 0x11D, "MAX_COMMAND_SIZE": 0x11E,
		"MAX_RESPONSE_SIZE": 0x11F, "MAX_DIGEST": 0x120, "MAX_OBJECT_CONTEXT": 0x121,
		"MAX_SESSION_CONTEXT": 0x122, "PS_FAMILY_INDICATOR": 0x123, "PS_LEVEL": 0x124,
		"PS_REVISION": 0x125, "SPLIT_MAX": 0x126, "TOTAL_COMMANDS": 0x127,
		"LIBRARY_COMMANDS": 0x128, "VENDOR_COMMANDS": 0x129, "NV_BUFFER_MAX": 0x12A,
		"MODES": 0x12B, "MAX_CAP_BUFFER": 0x12C,
	}
	got := map[string]uint32{
		"FAMILY_INDICATOR": PTFamilyIndicator, "LEVEL": PTLevel, "REVISION": PTRevision,
		"DAY_OF_YEAR": PTDayOfYear, "YEAR": PTYear, "MANUFACTURER": PTManufacturer,
		"VENDOR_STRING_1": PTVendorString1, "VENDOR_STRING_2": PTVendorString2,
		"VENDOR_STRING_3": PTVendorString3, "VENDOR_STRING_4": PTVendorString4,
		"VENDOR_TPM_TYPE": PTVendorTPMType, "FIRMWARE_VERSION_1": PTFirmwareVersion1,
		"FIRMWARE_VERSION_2": PTFirmwareVersion2, "INPUT_BUFFER": PTInputBuffer,
		"HR_TRANSIENT_MIN": PTHRTransientMin, "HR_PERSISTENT_MIN": PTHRPersistentMin,
		"HR_LOADED_MIN": PTHRLoadedMin, "ACTIVE_SESSIONS_MAX": PTActiveSessionMax,
		"PCR_COUNT": PTPCRCount, "PCR_SELECT_MIN": PTPCRSelectMin,
		"CONTEXT_GAP_MAX": PTContextGapMax, "NV_COUNTERS_MAX": PTNVCountersMax,
		"NV_INDEX_MAX": PTNVIndexMax, "MEMORY": PTMemory, "CLOCK_UPDATE": PTClockUpdate,
		"CONTEXT_HASH": PTContextHash, "CONTEXT_SYM": PTContextSym,
		"CONTEXT_SYM_SIZE": PTContextSymSize, "ORDERLY_COUNT": PTOrderlyCount,
		"MAX_COMMAND_SIZE": PTMaxCommandSize, "MAX_RESPONSE_SIZE": PTMaxResponseSize,
		"MAX_DIGEST": PTMaxDigest, "MAX_OBJECT_CONTEXT": PTMaxObjectContext,
		"MAX_SESSION_CONTEXT": PTMaxSessionContext, "PS_FAMILY_INDICATOR": PTPSFamilyIndicator,
		"PS_LEVEL": PTPSLevel, "PS_REVISION": PTPSRevision, "SPLIT_MAX": PTSplitMax,
		"TOTAL_COMMANDS": PTTotalCommands, "LIBRARY_COMMANDS": PTLibraryCommands,
		"VENDOR_COMMANDS": PTVendorCommands, "NV_BUFFER_MAX": PTNVBufferMax,
		"MODES": PTModes, "MAX_CAP_BUFFER": PTMaxCapBuffer,
	}
	for name, w := range want {
		if g := got[name]; g != w {
			t.Errorf("TPM_PT_%s = %#x, want %#x", name, g, w)
		}
	}
}

// TestFixedPropertiesArePCClientComplete checks the reported table actually covers the
// PT_FIXED group. A PC Client TPM must publish the PS_* triple that identifies the
// platform profile; without it Windows will not bring the device up.
func TestFixedPropertiesArePCClientComplete(t *testing.T) {
	have := map[uint32]uint32{}
	for _, p := range fixedProperties {
		if _, dup := have[p.property]; dup {
			t.Errorf("property %#x listed twice", p.property)
		}
		have[p.property] = p.value
	}
	for p := uint32(0x100); p <= 0x12C; p++ {
		if p == 0x115 {
			continue // not assigned by the spec
		}
		if _, ok := have[p]; !ok {
			t.Errorf("PT_FIXED property %#x missing from fixedProperties", p)
		}
	}
	if have[PTPSFamilyIndicator] != 1 {
		t.Errorf("PS_FAMILY_INDICATOR = %d, want 1 (PC Client)", have[PTPSFamilyIndicator])
	}
	// Ascending order matters: writeProperties selects on ">= property" and truncates to
	// propertyCount, so an out-of-order table silently drops properties from a windowed read.
	for i := 1; i < len(fixedProperties); i++ {
		if fixedProperties[i].property <= fixedProperties[i-1].property {
			t.Fatalf("fixedProperties not ascending at index %d: %#x after %#x",
				i, fixedProperties[i].property, fixedProperties[i-1].property)
		}
	}
}

// TestGetCapabilityStaysInPropertyGroup guards the group-boundary leak: a PT_FIXED query
// used to run off the end of the fixed table and return PT_VAR values (0x20E..0x211)
// spliced on, while still reporting moreData=NO — so a caller reading the fixed group got
// run-time properties and no hint anything was wrong.
func TestGetCapabilityStaysInPropertyGroup(t *testing.T) {
	tpm := New()
	var w writer
	tpm.writeProperties(&w, ptFixed, 200) // far more than the group holds
	b := w.bytes()
	if len(b) < 4 {
		t.Fatal("empty property list")
	}
	count := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	off := 4
	for i := uint32(0); i < count; i++ {
		p := uint32(b[off])<<24 | uint32(b[off+1])<<16 | uint32(b[off+2])<<8 | uint32(b[off+3])
		off += 8
		if p/ptGroup != ptFixed/ptGroup {
			t.Errorf("PT_FIXED query returned %#x, which is outside the PT_FIXED group", p)
		}
	}
	// The PT_VAR group must still be reachable on its own.
	var v writer
	tpm.writeProperties(&v, ptVar, 200)
	vb := v.bytes()
	vcount := uint32(vb[0])<<24 | uint32(vb[1])<<16 | uint32(vb[2])<<8 | uint32(vb[3])
	if vcount == 0 {
		t.Error("PT_VAR query returned nothing; run-time properties are now unreachable")
	}
}
