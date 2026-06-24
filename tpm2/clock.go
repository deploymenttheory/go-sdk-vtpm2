// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

// This file implements the Clock management commands (TPM 2.0 Part 3, §29):
// TPM2_ClockSet and TPM2_ClockRateAdjust. The clock/time state itself lives in
// clockState (attest.go).

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
