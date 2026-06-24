// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

// This file adds the structural PCR/NV commands of Phase 6b: TPM2_PCR_Allocate,
// TPM2_PCR_SetAuthValue, TPM2_PCR_SetAuthPolicy and TPM2_NV_UndefineSpaceSpecial.

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

// cmdNVUndefineSpaceSpecial implements TPM2_NV_UndefineSpaceSpecial (Part 3,
// §31.6): delete an Index with the POLICY_DELETE attribute. Handles: nvIndex
// (ADMIN-role policy auth), platform (USER auth).
func (t *TPM) cmdNVUndefineSpaceSpecial(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCNVUndefineSpaceSpecial, 2, r) // nvIndex, platform
	if errResp != nil {
		return errResp
	}
	idx, ok := t.nv.get(ac.handles[0])
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if idx.public.Attrs&NVPolicyDelete == 0 {
		return errorResponse(withHandle(RCAttributes, 1)) // only POLICY_DELETE Indices
	}
	// nvIndex is authorized at ADMIN role by its own policy.
	if errResp := t.verifyAuth(ac, 0, idx.name, idx.authValue, idx.public.AuthPolicy, false); errResp != nil {
		return errResp
	}
	if ac.handles[1] != RHPlatform {
		return errorResponse(withHandle(RCValue, 2))
	}
	if errResp := t.authorizeHierarchyAt(ac, 1, RHPlatform); errResp != nil {
		return errResp
	}
	delete(t.nv.indices, ac.handles[0])
	return t.authResponse(ac, nil, nil)
}
