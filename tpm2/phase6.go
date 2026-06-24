// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import "sort"

// This file adds the clock, PCR and NV management commands of Phase 6:
// TPM2_ClockSet, TPM2_ClockRateAdjust, TPM2_PCR_Event, TPM2_NV_ChangeAuth and
// TPM2_NV_GlobalWriteLock.

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

// cmdClockSet implements TPM2_ClockSet (Part 3, §29.2): advance Clock to newTime.
// Clock may only move forward.
func (t *TPM) cmdClockSet(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCClockSet, 1, r) // @auth (owner/platform)
	if errResp != nil {
		return errResp
	}
	newTime := r.u64()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	authHandle := ac.handles[0]
	if authHandle != RHOwner && authHandle != RHPlatform {
		return errorResponse(withHandle(RCValue, 1))
	}
	if errResp := t.authorizeHierarchy(ac, authHandle); errResp != nil {
		return errResp
	}
	if newTime < t.clock.clock {
		return errorResponse(withParam(RCValue, 1)) // Clock cannot be set backward
	}
	t.clock.clock = newTime
	return t.authResponse(ac, nil, nil)
}

// cmdClockRateAdjust implements TPM2_ClockRateAdjust (Part 3, §29.3): nudge the
// Clock update rate. The emulated Clock has no adjustable rate, so a valid request
// is validated and accepted with no observable effect.
func (t *TPM) cmdClockRateAdjust(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCClockRateAdjust, 1, r)
	if errResp != nil {
		return errResp
	}
	rateAdjust := int8(r.u8()) // TPM_CLOCK_ADJUST: -3..+3
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	authHandle := ac.handles[0]
	if authHandle != RHOwner && authHandle != RHPlatform {
		return errorResponse(withHandle(RCValue, 1))
	}
	if errResp := t.authorizeHierarchy(ac, authHandle); errResp != nil {
		return errResp
	}
	if rateAdjust < -3 || rateAdjust > 3 {
		return errorResponse(withParam(RCValue, 1))
	}
	return t.authResponse(ac, nil, nil)
}

// cmdPCREvent implements TPM2_PCR_Event (Part 3, §22.3 of the integrity group):
// hash eventData in every bank, extend the PCR (unless pcrHandle is TPM_RH_NULL)
// and return the per-bank digests as a TPML_DIGEST_VALUES.
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

// cmdNVChangeAuth implements TPM2_NV_ChangeAuth (Part 3, §31.14): change an NV
// Index's authValue. Authorization is the Index's own (ADMIN-role) auth.
func (t *TPM) cmdNVChangeAuth(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCNVChangeAuth, 1, r) // @nvIndex
	if errResp != nil {
		return errResp
	}
	newAuth := r.tpm2b()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	idx, ok := t.nv.get(ac.handles[0])
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if len(newAuth) > hashSize(idx.public.NameAlg) {
		return errorResponse(withParam(RCSize, 1))
	}
	if errResp := t.verifyAuth(ac, 0, idx.name, idx.authValue, idx.public.AuthPolicy, false); errResp != nil {
		return errResp
	}
	idx.authValue = append([]byte(nil), newAuth...)
	return t.authResponse(ac, nil, nil)
}

// cmdNVGlobalWriteLock implements TPM2_NV_GlobalWriteLock (Part 3, §31.10): set the
// write-lock on every Index carrying the GLOBALLOCK attribute.
func (t *TPM) cmdNVGlobalWriteLock(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCNVGlobalWriteLock, 1, r) // @authHandle
	if errResp != nil {
		return errResp
	}
	authHandle := ac.handles[0]
	if authHandle != RHOwner && authHandle != RHPlatform {
		return errorResponse(withHandle(RCValue, 1))
	}
	if errResp := t.authorizeHierarchy(ac, authHandle); errResp != nil {
		return errResp
	}
	for _, h := range t.nv.handles() {
		if idx, ok := t.nv.get(h); ok && idx.public.Attrs&NVGlobalLock != 0 {
			idx.writeLocked = true
		}
	}
	return t.authResponse(ac, nil, nil)
}
