// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import "sort"

// This file implements the PCR administration commands (TPM 2.0 Part 3, §22):
// TPM2_PCR_Event, TPM2_PCR_Allocate, TPM2_PCR_SetAuthValue and
// TPM2_PCR_SetAuthPolicy. The PCR banks themselves live in pcrState (pcr.go).

// sortedAlgs returns the configured PCR bank algorithms ascending, so
// TPML_DIGEST_VALUES output (TPM2_PCR_Event) is deterministic.
func (s *pcrState) sortedAlgs() []uint16 {
	algs := make([]uint16, 0, len(s.banks))
	for alg := range s.banks {
		algs = append(algs, alg)
	}
	sort.Slice(algs, func(i, j int) bool { return algs[i] < algs[j] })
	return algs
}

// cmdPCREvent implements TPM2_PCR_Event (Part 3, §22.2): hash eventData in every
// bank, extend the PCR (unless pcrHandle is TPM_RH_NULL) and return the per-bank
// digests as a TPML_DIGEST_VALUES.
func (t *TPM) cmdPCREvent(tag uint16, r *reader) []byte {
	if tag != TPMSTSessions {
		return errorResponse(RCAuthMissing)
	}
	pcrHandle := r.u32()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	sessions, ok := readAuthArea(r)
	if !ok {
		return errorResponse(RCAuthSize)
	}
	eventData := r.tpm2b()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}

	extend := pcrHandle != RHNull
	index := int(pcrHandle)
	if extend {
		if index < 0 || index >= numPCR {
			return errorResponse(withHandle(RCValue, 1))
		}
		if !localityAllowed(pcrExtendLocalities(index), t.locality) {
			return errorResponse(RCLocality)
		}
	}

	var w writer
	algs := t.pcr.sortedAlgs()
	w.u32(uint32(len(algs))) // TPML_DIGEST_VALUES count
	for _, alg := range algs {
		d := hashSum(alg, eventData)
		if extend {
			t.pcr.extend(alg, index, d)
		}
		w.u16(alg) // TPMT_HA.hashAlg
		w.raw(d)   // TPMT_HA.digest (raw, hashSize bytes)
	}
	return successResponse(w.bytes(), len(sessions))
}

// cmdPCRAllocate implements TPM2_PCR_Allocate (Part 3, §22.4): change the set of
// PCR banks. The spec applies the new allocation at the next _TPM_Init; this
// emulator applies it immediately (rebuilding the banks zeroed) and also records
// it so subsequent resets keep the allocation.
func (t *TPM) cmdPCRAllocate(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCPCRAllocate, 1, r) // @authHandle (platform)
	if errResp != nil {
		return errResp
	}
	sels := readPCRSelectionList(r)
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if ac.handles[0] != RHPlatform {
		return errorResponse(withHandle(RCValue, 1))
	}
	if errResp := t.authorizeHierarchy(ac, RHPlatform); errResp != nil {
		return errResp
	}

	// A bank is allocated for each selection naming a hash the emulator can
	// compute and whose selection has at least one PCR set.
	var algs []uint16
	for _, s := range sels {
		if hashSize(s.hash) == 0 || !anyBitSet(s.selectMap) {
			continue
		}
		algs = append(algs, s.hash)
	}
	t.pcr.allocated = algs
	t.pcr.reset() // apply immediately (deviation: spec defers to next _TPM_Init)

	sizeNeeded := uint32(0)
	for _, alg := range algs {
		sizeNeeded += uint32(numPCR) * uint32(hashSize(alg))
	}

	var w writer
	w.u8(yes)         // allocationSuccess
	w.u32(numPCR)     // maxPCR
	w.u32(sizeNeeded) // sizeNeeded
	w.u32(1 << 16)    // sizeAvailable (ample NV for PCR state)
	return t.authResponse(ac, nil, w.bytes())
}

// anyBitSet reports whether a PCR select bitmap selects any PCR.
func anyBitSet(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return true
		}
	}
	return false
}

// cmdPCRSetAuthValue implements TPM2_PCR_SetAuthValue (Part 3, §22.7): set the
// authorization value of an auth-PCR. USER-role auth uses the PCR's current value.
func (t *TPM) cmdPCRSetAuthValue(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCPCRSetAuthValue, 1, r) // @pcrHandle
	if errResp != nil {
		return errResp
	}
	newAuth := r.tpm2b()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	pcrHandle := ac.handles[0]
	if int(pcrHandle) >= numPCR {
		return errorResponse(withHandle(RCValue, 1))
	}
	current := t.pcr.authValues[pcrHandle]
	if errResp := t.verifyAuth(ac, 0, be32(pcrHandle), current, nil, false); errResp != nil {
		return errResp
	}
	if t.pcr.authValues == nil {
		t.pcr.authValues = make(map[uint32][]byte)
	}
	t.pcr.authValues[pcrHandle] = append([]byte(nil), newAuth...)
	return t.authResponse(ac, nil, nil)
}

// cmdPCRSetAuthPolicy implements TPM2_PCR_SetAuthPolicy (Part 3, §22.6): set the
// authorization policy of an auth-PCR. Authorized by the platform hierarchy.
func (t *TPM) cmdPCRSetAuthPolicy(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCPCRSetAuthPolicy, 1, r) // @authHandle (platform)
	if errResp != nil {
		return errResp
	}
	authPolicy := r.tpm2b()
	hashAlg := r.u16()
	pcrNum := r.u32()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if ac.handles[0] != RHPlatform {
		return errorResponse(withHandle(RCValue, 1))
	}
	if errResp := t.authorizeHierarchy(ac, RHPlatform); errResp != nil {
		return errResp
	}
	if int(pcrNum) >= numPCR {
		return errorResponse(withParam(RCValue, 3))
	}
	if hashAlg != AlgNull && len(authPolicy) != hashSize(hashAlg) {
		return errorResponse(withParam(RCSize, 1)) // policy digest must match the hash size
	}
	if t.pcr.authPolicies == nil {
		t.pcr.authPolicies = make(map[uint32][]byte)
	}
	t.pcr.authPolicies[pcrNum] = append([]byte(nil), authPolicy...)
	return t.authResponse(ac, nil, nil)
}
