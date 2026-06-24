// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

// This file implements the clock and signed attestation (TPM 2.0 Part 3, §18/§23):
// TPM2_ReadClock and TPM2_Quote (a signed statement over a set of PCR values).

// firmwareVersion is reported in attestation structures (TPMS_ATTEST).
const firmwareVersion uint64 = 0x0001_0000_0000_0000

// clockState is the TPM's time/clock state (TPMS_CLOCK_INFO). It persists across
// reboots; resetCount advances on TPM2_Clear and restartCount on each Startup.
type clockState struct {
	clock        uint64 // milliseconds
	resetCount   uint32
	restartCount uint32
	safe         byte
}

func newClockState() *clockState { return &clockState{safe: 1} }

// marshalInfo writes a TPMS_CLOCK_INFO.
func (c *clockState) marshalInfo(w *writer) {
	w.u64(c.clock)
	w.u32(c.resetCount)
	w.u32(c.restartCount)
	w.u8(c.safe)
}

// buildAttest assembles a TPMS_ATTEST with the given type and attested payload.
func (t *TPM) buildAttest(signerName, qualifyingData []byte, attestType uint16, attested []byte) []byte {
	var w writer
	w.u32(tpmGeneratedValue) // magic
	w.u16(attestType)        // type
	w.tpm2b(signerName)      // qualifiedSigner
	w.tpm2b(qualifyingData)  // extraData
	t.clock.marshalInfo(&w)  // clockInfo
	w.u64(firmwareVersion)   // firmwareVersion
	w.raw(attested)          // attested (TPMU_ATTEST)
	return w.bytes()
}

// cmdQuote implements TPM2_Quote: sign a statement over the selected PCR values.
func (t *TPM) cmdQuote(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCQuote, 1, r) // signHandle
	if errResp != nil {
		return errResp
	}
	qualifyingData := r.tpm2b()
	scheme := r.u16()
	var schemeHash uint16
	if scheme != AlgNull {
		schemeHash = r.u16()
	}
	pcrs := readPCRSelectionList(r)
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	key, ok := t.objects.get(ac.handles[0])
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if key.public.Attrs&ObjSign == 0 {
		return errorResponse(withHandle(RCAttributes, 1))
	}
	if errResp := t.authorizeObject(ac, 0, key); errResp != nil {
		return errResp
	}
	sigAlg, hashAlg := key.public.Scheme.Scheme, key.public.Scheme.HashAlg
	if sigAlg == AlgNull {
		sigAlg, hashAlg = scheme, schemeHash
	}
	if _, ok := cryptoHash(hashAlg); !ok {
		return errorResponse(withParam(RCValue, 2))
	}

	// TPMS_QUOTE_INFO: the selection and the digest of the selected PCR values.
	var qi writer
	writePCRSelectionList(&qi, pcrs)
	qi.tpm2b(t.pcrSelectionDigest(hashAlg, pcrs))

	attest := t.buildAttest(key.name, qualifyingData, STAttestQuote, qi.bytes())
	sig, errResp := t.signWith(key, sigAlg, hashAlg, hashSum(hashAlg, attest))
	if errResp != nil {
		return errResp
	}
	t.clock.clock++

	var w writer
	w.tpm2b(attest) // quoted (TPM2B_ATTEST)
	w.raw(sig)      // signature (TPMT_SIGNATURE)
	return t.authResponse(ac, nil, w.bytes())
}

// cmdReadClock implements TPM2_ReadClock (no authorization).
func (t *TPM) cmdReadClock(r *reader) []byte {
	t.clock.clock++
	var w writer
	w.u64(t.clock.clock)    // TPMS_TIME_INFO.time
	t.clock.marshalInfo(&w) // TPMS_TIME_INFO.clockInfo
	return successResponse(w.bytes(), 0)
}
