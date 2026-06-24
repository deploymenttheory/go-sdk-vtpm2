// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import "io"

// maxRandomBytes caps a single TPM2_GetRandom response. A real TPM returns at
// most the size of its largest digest; SHA-512 (64 bytes) is the ceiling here.
const maxRandomBytes = 64

// cmdStartup implements TPM2_Startup. TPM_SU_CLEAR resets the resettable PCRs;
// a second Startup after a successful one is a sequencing error.
func (t *TPM) cmdStartup(r *reader) []byte {
	su := r.u16()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if su != SUClear && su != SUState {
		return errorResponse(withParam(RCValue, 1)) // startupType is parameter 1
	}
	if t.started {
		return errorResponse(RCInitialize)
	}
	if su == SUClear {
		t.pcr.reset()
		t.h.reset()
	}
	t.clock.restartCount++ // a TPM restart/resume
	t.started = true
	return successResponse(nil, 0)
}

// cmdShutdown implements TPM2_Shutdown. State persistence on TPM_SU_STATE is a
// later concern; the command is accepted so guest firmware can shut down cleanly.
func (t *TPM) cmdShutdown(r *reader) []byte {
	if resp := t.requireStarted(); resp != nil {
		return resp
	}
	su := r.u16()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if su != SUClear && su != SUState {
		return errorResponse(withParam(RCValue, 1)) // shutdownType is parameter 1
	}
	return successResponse(nil, 0)
}

// cmdSelfTest implements TPM2_SelfTest. The Go stdlib primitives are always
// healthy, so the test trivially passes.
func (t *TPM) cmdSelfTest(r *reader) []byte {
	fullTest := r.u8() // fullTest (TPMI_YES_NO) — no distinct behavior, but must be 0/1
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if fullTest != byte(no) && fullTest != byte(yes) {
		return errorResponse(withParam(RCValue, 1)) // fullTest (param 1) is TPMI_YES_NO
	}
	return successResponse(nil, 0)
}

// cmdGetTestResult implements TPM2_GetTestResult. It reports an empty outData
// and a passing testResult, and answers even before Startup / in failure mode.
func (t *TPM) cmdGetTestResult(_ *reader) []byte {
	var w writer
	w.u16(0) // outData: empty TPM2B_MAX_BUFFER
	result := RCSuccess
	if t.failed {
		result = RCFailure
	}
	w.u32(result) // testResult (TPM_RC)
	return successResponse(w.bytes(), 0)
}

// cmdGetRandom implements TPM2_GetRandom.
func (t *TPM) cmdGetRandom(r *reader) []byte {
	n := int(r.u16())
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if n > maxRandomBytes {
		n = maxRandomBytes
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(t.rand, buf); err != nil {
		return errorResponse(RCFailure)
	}
	var w writer
	w.u16(uint16(len(buf))) // TPM2B_DIGEST size
	w.raw(buf)
	return successResponse(w.bytes(), 0)
}

// cmdStirRandom implements TPM2_StirRandom. crypto/rand cannot be seeded, so the
// provided entropy is consumed and discarded; the command still succeeds.
func (t *TPM) cmdStirRandom(r *reader) []byte {
	_ = r.bytes(int(r.u16())) // inData (TPM2B_SENSITIVE_DATA)
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	return successResponse(nil, 0)
}

// cmdPCRRead implements TPM2_PCR_Read: it returns the update counter, the
// selection actually read back, and the corresponding digests.
func (t *TPM) cmdPCRRead(r *reader) []byte {
	sels := readPCRSelectionList(r)
	if r.err != nil {
		if r.err == errBadValue {
			return errorResponse(withParam(RCValue, 1)) // pcrSelectionIn is parameter 1
		}
		return errorResponse(RCInsufficient)
	}

	// pcrSelectionOut must report the PCR actually read back, not the request:
	// a requested bank the TPM does not implement (or an unselectable index)
	// contributes no digest, so its bits must be cleared in the output selection
	// or pcrSelectionOut and pcrValues would disagree (TPM 2.0 Part 3,
	// TPM2_PCR_Read).
	var digests [][]byte
	out := make([]pcrSelection, 0, len(sels))
	for _, sel := range sels {
		readMap := make([]byte, len(sel.selectMap))
		for i := 0; i < numPCR; i++ {
			if !sel.selected(i) {
				continue
			}
			d := t.pcr.read(sel.hash, i)
			if d == nil {
				continue // unsupported bank or index: not read back
			}
			digests = append(digests, d)
			readMap[i/8] |= 1 << (uint(i) % 8)
		}
		out = append(out, pcrSelection{hash: sel.hash, selectMap: readMap})
	}

	var w writer
	w.u32(t.pcr.updateCounter)     // pcrUpdateCounter
	writePCRSelectionList(&w, out) // pcrSelectionOut (only PCR actually read)
	w.u32(uint32(len(digests)))    // pcrValues: TPML_DIGEST count
	for _, d := range digests {
		w.u16(uint16(len(d)))
		w.raw(d)
	}
	return successResponse(w.bytes(), 0)
}

// cmdPCRExtend implements TPM2_PCR_Extend. The command carries one handle (the
// PCR) and requires an authorization session; the auth value of a PCR is empty
// by default, so any well-formed session is accepted.
func (t *TPM) cmdPCRExtend(tag uint16, r *reader) []byte {
	if tag != TPMSTSessions {
		return errorResponse(RCAuthMissing) // a command needing auth was sent with no sessions
	}
	pcrHandle := r.u32()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	sessions, ok := readAuthArea(r)
	if !ok {
		return errorResponse(RCAuthSize) // authorizationSize did not frame a valid auth area
	}
	values := readDigestValues(r)
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}

	index := int(pcrHandle) // PCR handles are 0x00..0x17, equal to the index
	if index < 0 || index >= numPCR {
		return errorResponse(withHandle(RCValue, 1)) // pcrHandle is the first handle
	}
	if !localityAllowed(pcrExtendLocalities(index), t.locality) {
		return errorResponse(RCLocality) // PCR not extendable at this locality
	}
	for _, v := range values {
		if !t.pcr.extend(v.alg, index, v.digest) {
			return errorResponse(withParam(RCValue, 1)) // digests is the first parameter
		}
	}
	return successResponse(nil, len(sessions))
}

// cmdPCRReset implements TPM2_PCR_Reset: zero a PCR across all banks, subject to
// the PCR's reset-locality attribute.
func (t *TPM) cmdPCRReset(tag uint16, r *reader) []byte {
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
	index := int(pcrHandle)
	if index < 0 || index >= numPCR {
		return errorResponse(withHandle(RCValue, 1))
	}
	if !localityAllowed(pcrResetLocalities(index), t.locality) {
		return errorResponse(RCLocality) // PCR not resettable at this locality
	}
	t.pcr.resetAt(index)
	return successResponse(nil, len(sessions))
}
