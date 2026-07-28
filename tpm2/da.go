// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

// This file implements dictionary-attack (DA) protection (TPM 2.0 Part 1, §19.8).
// Failed authorizations against DA-protected entities increment a counter; once
// it reaches maxTries the TPM is in lockout and further DA-protected auth returns
// TPM_RC_LOCKOUT. The counter is cleared by TPM2_DictionaryAttackLockReset (under
// lockout authorization) or TPM2_Clear.
//
// Time-based recovery (recoveryTime / lockoutRecovery) is not yet enforced — the
// TPM has no clock until the time subsystem lands — so lockout is cleared only by
// the reset command. Lockout authorization itself is therefore never DA-blocked,
// so recovery is always reachable.

// daState holds the dictionary-attack counters and parameters. It is persistent:
// the lockout survives a reboot (the whole point of DA protection).
type daState struct {
	failedTries     uint32
	maxTries        uint32 // failures tolerated before lockout
	recoveryTime    uint32 // seconds before failedTries decrements (not yet enforced)
	lockoutRecovery uint32 // seconds before lockoutAuth recovers (not yet enforced)
}

func newDAState() *daState {
	return &daState{maxTries: 32, recoveryTime: 7200, lockoutRecovery: 86400}
}

func (d *daState) inLockout() bool { return d.failedTries >= d.maxTries }
func (d *daState) recordFailure()  { d.failedTries++ }
func (d *daState) recordSuccess()  { d.failedTries = 0 }

// cmdDictionaryAttackLockReset implements TPM2_DictionaryAttackLockReset: clear
// the failed-tries counter. Authorized by lockout authorization.
func (t *TPM) cmdDictionaryAttackLockReset(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCDictionaryAttackLockReset, 1, r)
	if errResp != nil {
		return errResp
	}
	if ac.handles[0] != RHLockout {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if errResp := t.authorizeHierarchy(ac, RHLockout); errResp != nil {
		return errResp
	}
	t.da.failedTries = 0
	return t.authResponse(ac, nil, nil)
}

// cmdDictionaryAttackParameters implements TPM2_DictionaryAttackParameters: set
// newMaxTries / newRecoveryTime / lockoutRecovery and clear the counter.
func (t *TPM) cmdDictionaryAttackParameters(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCDictionaryAttackParameters, 1, r)
	if errResp != nil {
		return errResp
	}
	newMaxTries := r.u32()
	newRecoveryTime := r.u32()
	lockoutRecovery := r.u32()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if ac.handles[0] != RHLockout {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if newMaxTries == 0 {
		return errorResponse(withParam(RCValue, 1)) // maxTries of 0 would lock immediately
	}
	if errResp := t.authorizeHierarchy(ac, RHLockout); errResp != nil {
		return errResp
	}
	t.da.maxTries = newMaxTries
	t.da.recoveryTime = newRecoveryTime
	t.da.lockoutRecovery = lockoutRecovery
	t.da.failedTries = 0
	return t.authResponse(ac, nil, nil)
}
