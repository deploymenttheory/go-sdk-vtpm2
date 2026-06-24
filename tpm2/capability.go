// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import "sort"

// taggedProperty is one TPMS_TAGGED_PROPERTY (property tag + value).
type taggedProperty struct {
	property uint32
	value    uint32
}

// fixedProperties is the ascending list of TPM_PT values reported under
// TPM_CAP_TPM_PROPERTIES. Order matters: GetCapability returns properties with
// tag >= the requested property, in this order, up to propertyCount. These are
// PT_FIXED identity/capacity values; run-time PT_VAR properties are added with the
// subsystems that own them (hierarchies, sessions).
var fixedProperties = []taggedProperty{
	{PTFamilyIndicator, 0x322E3000}, // "2.0\0"
	{PTLevel, 0},
	{PTRevision, 185}, // TPM_SPEC_VERSION; since v184 PT_REVISION = TPM_SPEC_VERSION (not ×100)
	{PTDayOfYear, 71}, // 2026-03-12, the v1.85 release date
	{PTYear, 2026},
	{PTManufacturer, 0x44505448},  // "DPTH"
	{PTVendorString1, 0x76747061}, // "vtpa" (vtpm2)
	{PTVendorString2, 0},
	{PTVendorString3, 0},
	{PTVendorString4, 0},
	{PTVendorTPMType, 0},
	{PTFirmwareVersion1, 0x00010000}, // 1.0
	{PTFirmwareVersion2, 0},
	{PTInputBuffer, 1024},
	{PTHRTransientMin, 3},
	{PTHRPersistentMin, 7},
	{PTHRLoadedMin, 3},
	{PTActiveSessionMax, 64},
	{PTPCRCount, numPCR},
	{PTPCRSelectMin, pcrSelectMin},
	{PTMaxCommandSize, 4096},
	{PTMaxResponseSize, 4096},
	{PTMaxDigest, 32}, // SHA-256
	{PTTotalCommands, uint32(len(commandTable))},
	{PTLibraryCommands, uint32(len(commandTable))},
	{PTVendorCommands, 0},
	{PTModes, 0},
}

// advertisedAlgs is the ascending list of algorithms reported under
// TPM_CAP_ALGS as TPMS_ALG_PROPERTY (alg id + TPMA_ALGORITHM). Only the hash
// primitives are wired in today; symmetric/asymmetric algorithms join as the key
// and session commands land.
var advertisedAlgs = []taggedProperty{
	{uint32(AlgSHA1), algAttrHash},
	{uint32(AlgSHA256), algAttrHash},
	{uint32(AlgSHA384), algAttrHash},
	{uint32(AlgSHA512), algAttrHash},
}

// commandTable lists the implemented commands in ascending command-code order
// with their command-handle count, used to build TPM_CAP_COMMANDS (TPML_CCA).
var commandTable = []struct {
	cc       uint32
	cHandles uint32
}{
	{CCEvictControl, 2}, // auth hierarchy, objectHandle
	{CCHierarchyControl, 1},
	{CCNVUndefineSpace, 2}, // authHandle, nvIndex
	{CCChangeEPS, 1},
	{CCChangePPS, 1},
	{CCClear, 1},
	{CCClearControl, 1},
	{CCHierarchyChangeAuth, 1},
	{CCNVDefineSpace, 1},
	{CCSetPrimaryPolicy, 1},
	{CCCreatePrimary, 1},
	{CCNVIncrement, 2},
	{CCNVSetBits, 2},
	{CCNVExtend, 2},
	{CCNVWrite, 2},
	{CCNVWriteLock, 2},
	{CCDictionaryAttackLockReset, 1},
	{CCDictionaryAttackParameters, 1},
	{CCPCRReset, 1},
	{CCSequenceComplete, 1}, // 0x13E
	{CCSelfTest, 0},
	{CCStartup, 0},
	{CCShutdown, 0},
	{CCStirRandom, 0},
	{CCPolicyNV, 3}, // 0x149 (authHandle, nvIndex, policySession)
	{CCNVRead, 2},
	{CCNVReadLock, 2},
	{CCObjectChangeAuth, 2}, // objectHandle, parentHandle
	{CCPolicySecret, 2},     // 0x151 (authHandle, policySession)
	{CCCreate, 1},
	{CCECDHZGen, 1}, // 0x154
	{CCHMAC, 1},     // 0x155 (= TPM2_MAC)
	{CCLoad, 1},
	{CCQuote, 1},
	{CCRSADecrypt, 1},     // 0x159
	{CCHMACStart, 1},      // 0x15B (= TPM2_MAC_Start)
	{CCSequenceUpdate, 1}, // 0x15C
	{CCSign, 1},
	{CCUnseal, 1},
	{CCPolicySigned, 2}, // 0x160 (authObject, policySession)
	{CCContextLoad, 0},  // context is a parameter
	{CCContextSave, 1},  // saveHandle
	{CCECDHKeyGen, 1},   // 0x163
	{CCFlushContext, 0}, // flushHandle is a parameter, not a command handle
	{CCLoadExternal, 0},
	{CCNVReadPublic, 1},
	{CCPolicyAuthorize, 1}, // 0x16A
	{CCPolicyAuthValue, 1},
	{CCPolicyCommandCode, 1},
	{CCPolicyCounterTimer, 1}, // 0x16D
	{CCPolicyCpHash, 1},       // 0x16E
	{CCPolicyLocality, 1},     // 0x16F
	{CCPolicyNameHash, 1},     // 0x170
	{CCPolicyOR, 1},
	{CCPolicyTicket, 1}, // 0x172
	{CCReadPublic, 1},
	{CCRSAEncrypt, 1},       // 0x174
	{CCStartAuthSession, 2}, // tpmKey, bind
	{CCVerifySignature, 1},
	{CCECCParameters, 0}, // 0x178 (no handle)
	{CCGetCapability, 0},
	{CCGetRandom, 0},
	{CCGetTestResult, 0},
	{CCHash, 0},
	{CCPCRRead, 0},
	{CCPolicyPCR, 1},
	{CCPolicyRestart, 1},
	{CCReadClock, 0},
	{CCPCRExtend, 1},
	{CCEventSequenceComplete, 2},   // 0x185 (pcrHandle, sequenceHandle)
	{CCHashSequenceStart, 0},       // 0x186 (no handle)
	{CCPolicyPhysicalPresence, 1},  // 0x187
	{CCPolicyDuplicationSelect, 1}, // 0x188
	{CCPolicyGetDigest, 1},
	{CCPolicyPassword, 1},    // 0x18C
	{CCPolicyNvWritten, 1},   // 0x18F
	{CCPolicyTemplate, 1},    // 0x190
	{CCPolicyAuthorizeNV, 3}, // 0x192 (authHandle, nvIndex, policySession)
	{CCPolicyCapability, 1},  // 0x19B
	{CCPolicyParameters, 1},  // 0x19C
}

// cmdGetCapability implements TPM2_GetCapability for the capabilities the
// emulator advertises. Unsupported capabilities return an empty (count 0) list
// of the requested type, which is structurally valid since every relevant
// capability union member is a TPML_* beginning with a UINT32 count.
func (t *TPM) cmdGetCapability(r *reader) []byte {
	cap := r.u32()
	property := r.u32()
	count := r.u32()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}

	// An out-of-range capability selector is a TPM_RC_VALUE error, not a silent
	// empty result (TPM 2.0 Part 3, TPM2_GetCapability). Defined selectors are
	// the contiguous TPM_CAP block plus the vendor selector.
	if cap > capLast && cap != CapVendorProperty {
		return errorResponse(withParam(RCValue, 1)) // capability is parameter 1
	}

	var w writer
	switch cap {
	case CapTPMProperties:
		more := t.writeProperties(&w, property, count)
		return capabilityResponse(more, cap, w.bytes())
	case CapAlgs:
		more := writeAlgs(&w, property, count)
		return capabilityResponse(more, cap, w.bytes())
	case CapCommands:
		more := writeCommands(&w, property, count)
		return capabilityResponse(more, cap, w.bytes())
	case CapHandles:
		more := t.writeHandles(&w, property, count)
		return capabilityResponse(more, cap, w.bytes())
	case CapPCRs:
		writePCRBanks(&w)
		return capabilityResponse(no, cap, w.bytes())
	default:
		// Defined capability the emulator does not yet enumerate (e.g.
		// TPM_CAP_ALGS, TPM_CAP_COMMANDS): a correctly-typed empty TPML_*. Every
		// capability union member begins with a UINT32 count, so count 0 is a
		// valid empty list of the requested type.
		w.u32(0)
		return capabilityResponse(no, cap, w.bytes())
	}
}

// writeProperties emits the TPML_TAGGED_TPM_PROPERTY for properties with tag >=
// property, capped at count, and reports whether more remain (moreData).
func (t *TPM) writeProperties(w *writer, property, count uint32) byte {
	// The fixed identity/capacity properties precede the run-time PT_VAR group;
	// both are ascending, so the concatenation stays ascending.
	all := append(append([]taggedProperty(nil), fixedProperties...), t.varProperties()...)
	var selected []taggedProperty
	for _, p := range all {
		if p.property >= property {
			selected = append(selected, p)
		}
	}
	// propertyCount bounds the number returned; count 0 yields an empty list with
	// moreData=YES when properties exist (TPM 2.0 Part 3, TPM2_GetCapability).
	more := no
	if uint32(len(selected)) > count {
		selected = selected[:count]
		more = yes
	}
	w.u32(uint32(len(selected)))
	for _, p := range selected {
		w.u32(p.property)
		w.u32(p.value)
	}
	return more
}

// writeAlgs emits the TPML_ALG_PROPERTY for algorithms with id >= property,
// capped at count, reporting moreData. Each entry is a TPMS_ALG_PROPERTY: the
// TPM_ALG_ID (UINT16) followed by its TPMA_ALGORITHM attributes (UINT32).
func writeAlgs(w *writer, property, count uint32) byte {
	var sel []taggedProperty
	for _, a := range advertisedAlgs {
		if a.property >= property {
			sel = append(sel, a)
		}
	}
	more := no
	if uint32(len(sel)) > count {
		sel = sel[:count]
		more = yes
	}
	w.u32(uint32(len(sel)))
	for _, a := range sel {
		w.u16(uint16(a.property)) // TPM_ALG_ID
		w.u32(a.value)            // TPMA_ALGORITHM
	}
	return more
}

// writeCommands emits the TPML_CCA for commands with code >= property, capped at
// count, reporting moreData. Each entry is a TPMA_CC: the command index in the
// low 16 bits plus the command-handle count in bits [27:25].
func writeCommands(w *writer, property, count uint32) byte {
	var sel []uint32
	for _, c := range commandTable {
		if c.cc >= property {
			sel = append(sel, c.cc&ccAttrIndexMask|c.cHandles<<ccAttrCHandleSh)
		}
	}
	more := no
	if uint32(len(sel)) > count {
		sel = sel[:count]
		more = yes
	}
	w.u32(uint32(len(sel)))
	for _, v := range sel {
		w.u32(v)
	}
	return more
}

// permanentHandles is the ascending list of permanent handles the TPM exposes,
// reported under TPM_CAP_HANDLES for the permanent range.
var permanentHandles = []uint32{
	RHOwner, RHNull, RHPW, RHLockout, RHEndorsement, RHPlatform, RHPlatformNV,
}

// writeHandles emits the TPML_HANDLE of in-use handles at or above property,
// within property's handle range: permanent handles, loaded sessions, and
// transient/persistent objects. NV index handles arrive with that subsystem.
func (t *TPM) writeHandles(w *writer, property, count uint32) byte {
	var pool []uint32
	switch classifyHandle(property) {
	case htPermanent:
		pool = permanentHandles
	case htHMACSession, htPolicySession:
		pool = t.sessions.handles()
	case htTransient:
		for h := range t.objects.transient {
			pool = append(pool, h)
		}
	case htPersistent:
		pool = t.objects.persistentHandles()
	case htNVIndex:
		pool = t.nv.handles()
	}
	sort.Slice(pool, func(i, j int) bool { return pool[i] < pool[j] })

	var sel []uint32
	for _, h := range pool {
		if h >= property {
			sel = append(sel, h)
		}
	}
	more := no
	if uint32(len(sel)) > count {
		sel = sel[:count]
		more = yes
	}
	w.u32(uint32(len(sel)))
	for _, h := range sel {
		w.u32(h)
	}
	return more
}

// writePCRBanks emits a TPML_PCR_SELECTION advertising every supported bank with
// all numPCR PCRs present.
func writePCRBanks(w *writer) {
	sels := make([]pcrSelection, 0, len(supportedPCRBanks))
	for _, alg := range supportedPCRBanks {
		sels = append(sels, pcrSelection{hash: alg, selectMap: fullPCRBitmap()})
	}
	writePCRSelectionList(w, sels)
}

// fullPCRBitmap returns a select bitmap with PCRs 0..numPCR-1 set.
func fullPCRBitmap() []byte {
	b := make([]byte, (numPCR+7)/8)
	for i := 0; i < numPCR; i++ {
		b[i/8] |= 1 << (uint(i) % 8)
	}
	return b
}

// capabilityResponse frames the TPM2_GetCapability response: moreData followed
// by the capability tag and the capability-specific list already in data.
func capabilityResponse(more byte, cap uint32, data []byte) []byte {
	var w writer
	w.u8(more)
	w.u32(cap)
	w.raw(data)
	return successResponse(w.bytes(), 0)
}
