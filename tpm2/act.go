// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

// This file implements the Authenticated Countdown Timer (TPM2_ACT_SetTimeout,
// Part 3 §39) and the NV read-only control (TPM2_ReadOnlyControl, Part 3 §24.9).

// ACT handle range (TPM_RH_ACT_0 .. TPM_RH_ACT_F).
const (
	rhACTFirst uint32 = 0x40000110
	rhACTLast  uint32 = 0x4000011F
)

// actTimer is one Authenticated Countdown Timer. The emulated TPM has no real-time
// tick, so timeout simply records the most recent start value.
type actTimer struct {
	timeout  uint32
	signaled bool
}

// cmdACTSetTimeout implements TPM2_ACT_SetTimeout (Part 3, §39.2): (re)start an
// ACT with a new countdown value, clearing its signaled status.
func (t *TPM) cmdACTSetTimeout(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCACTSetTimeout, 1, r) // @actHandle
	if errResp != nil {
		return errResp
	}
	startTimeout := r.u32()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	actHandle := ac.handles[0]
	if actHandle < rhACTFirst || actHandle > rhACTLast {
		return errorResponse(withHandle(RCValue, 1))
	}
	// The ACT is authorized at USER role by its authValue (empty by default).
	if errResp := t.verifyAuth(ac, 0, permanentName(actHandle), nil, nil, false); errResp != nil {
		return errResp
	}
	if t.actTimers == nil {
		t.actTimers = make(map[uint32]*actTimer)
	}
	t.actTimers[actHandle] = &actTimer{timeout: startTimeout, signaled: false}
	return t.authResponse(ac, nil, nil)
}

// cmdReadOnlyControl implements TPM2_ReadOnlyControl (Part 3, §24.9): enable or
// disable the NV read-only mode of operation. Platform-authorized.
func (t *TPM) cmdReadOnlyControl(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCReadOnlyControl, 1, r) // @authHandle (platform)
	if errResp != nil {
		return errResp
	}
	state := r.u8()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if ac.handles[0] != RHPlatform {
		return errorResponse(withHandle(RCValue, 1))
	}
	if errResp := t.authorizeHierarchy(ac, RHPlatform); errResp != nil {
		return errResp
	}
	t.readOnly = state == yes
	return t.authResponse(ac, nil, nil)
}
