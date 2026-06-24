// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import "crypto/rand"

// seedSize is the length of a primary seed. Primary keys for a hierarchy are
// derived from its seed, so the seed must survive reboots for the EK/SRK to be
// stable; it is regenerated only by Clear (SPS) / ChangeEPS / ChangePPS.
const seedSize = 32

// hierarchy is the mutable state of one TPM authorization hierarchy.
type hierarchy struct {
	enabled    bool
	authValue  []byte // empty by default
	authPolicy []byte // empty by default
	seed       []byte // primary seed (nil for the lockout hierarchy)
}

// hierarchies holds every authorization hierarchy plus the global controls that
// live alongside them. The null hierarchy's seed is volatile (regenerated on
// every TPM reset); all others persist.
type hierarchies struct {
	owner        hierarchy // storage hierarchy (TPM_RH_OWNER), seed = SPS
	endorsement  hierarchy // TPM_RH_ENDORSEMENT, seed = EPS
	platform     hierarchy // TPM_RH_PLATFORM, seed = PPS
	lockout      hierarchy // TPM_RH_LOCKOUT (auth/policy only)
	null         hierarchy // TPM_RH_NULL (volatile seed, always enabled, no auth)
	phEnableNV   bool
	disableClear bool
}

func randomSeed() []byte {
	s := make([]byte, seedSize)
	_, _ = rand.Read(s)
	return s
}

// newHierarchies mints a fresh set of hierarchies with new primary seeds — the
// state of a never-provisioned TPM. The seeds are persisted on first save and
// stay stable thereafter (so the EK/SRK are stable across reboots).
func newHierarchies() *hierarchies {
	return &hierarchies{
		owner:       hierarchy{enabled: true, seed: randomSeed()},
		endorsement: hierarchy{enabled: true, seed: randomSeed()},
		platform:    hierarchy{enabled: true, seed: randomSeed()},
		lockout:     hierarchy{enabled: true},
		null:        hierarchy{enabled: true, seed: randomSeed()},
		phEnableNV:  true,
	}
}

// reset models a TPM Reset (power-on / Startup CLEAR): the null hierarchy seed is
// regenerated so null-hierarchy objects do not survive, and the hierarchy enables
// return to their power-on (enabled) state. Persistent seeds and auth are kept.
func (h *hierarchies) reset() {
	h.null.seed = randomSeed()
	h.owner.enabled = true
	h.endorsement.enabled = true
	h.platform.enabled = true
	h.phEnableNV = true
}

// byHandle returns the hierarchy a permanent handle authorizes, or nil.
func (h *hierarchies) byHandle(handle uint32) *hierarchy {
	switch handle {
	case RHOwner:
		return &h.owner
	case RHEndorsement:
		return &h.endorsement
	case RHPlatform:
		return &h.platform
	case RHLockout:
		return &h.lockout
	case RHNull:
		return &h.null
	}
	return nil
}

// clear models TPM2_Clear: a new storage primary seed and the owner, endorsement
// and lockout auth/policy reset to empty; the storage and endorsement hierarchies
// are re-enabled. The platform hierarchy, the EPS and the PPS are untouched, so
// the EK survives (TPM 2.0 Part 3, TPM2_Clear).
func (h *hierarchies) clear() {
	h.owner.seed = randomSeed()
	h.owner.authValue, h.owner.authPolicy, h.owner.enabled = nil, nil, true
	h.endorsement.authValue, h.endorsement.authPolicy, h.endorsement.enabled = nil, nil, true
	h.lockout.authValue, h.lockout.authPolicy = nil, nil
}

// authorizeHierarchy verifies the first session of ac against the hierarchy named
// by authHandle. Owner and endorsement authorizations are DA-protected; platform
// is not, and lockout is left reachable so DictionaryAttackLockReset can recover.
func (t *TPM) authorizeHierarchy(ac *commandAuth, authHandle uint32) []byte {
	hi := t.h.byHandle(authHandle)
	if hi == nil {
		return errorResponse(withHandle(RCHierarchy, 1))
	}
	daProtected := authHandle == RHOwner || authHandle == RHEndorsement
	return t.verifyAuth(ac, 0, permanentName(authHandle), hi.authValue, hi.authPolicy, daProtected)
}

// cmdClear implements TPM2_Clear: regenerate the storage seed and reset the owner,
// endorsement and lockout authorizations. Authorized by Platform or Lockout.
func (t *TPM) cmdClear(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCClear, 1, r)
	if errResp != nil {
		return errResp
	}
	authHandle := ac.handles[0]
	if authHandle != RHPlatform && authHandle != RHLockout {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if errResp := t.authorizeHierarchy(ac, authHandle); errResp != nil {
		return errResp
	}
	if t.h.disableClear && authHandle == RHLockout {
		return errorResponse(RCDisabled) // Clear via lockout is disabled
	}
	t.h.clear()
	t.da = newDAState()  // Clear resets the DA counters and parameters to defaults
	t.clock.resetCount++ // a TPM reset of ownership
	return t.authResponse(ac, nil, nil)
}

// cmdClearControl implements TPM2_ClearControl: enable/disable the ability to run
// TPM2_Clear. Authorized by Platform or Lockout.
func (t *TPM) cmdClearControl(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCClearControl, 1, r)
	if errResp != nil {
		return errResp
	}
	disable := r.u8()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if disable != byte(no) && disable != byte(yes) {
		return errorResponse(withParam(RCValue, 1))
	}
	authHandle := ac.handles[0]
	if authHandle != RHPlatform && authHandle != RHLockout {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if errResp := t.authorizeHierarchy(ac, authHandle); errResp != nil {
		return errResp
	}
	t.h.disableClear = disable == byte(yes)
	return t.authResponse(ac, nil, nil)
}

// cmdHierarchyChangeAuth implements TPM2_HierarchyChangeAuth: set a hierarchy's
// authValue. The command is authorized by the same hierarchy.
func (t *TPM) cmdHierarchyChangeAuth(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCHierarchyChangeAuth, 1, r)
	if errResp != nil {
		return errResp
	}
	t.decryptCommandParams(ac, r) // newAuth may be encrypted by a decrypt session
	newAuth := r.tpm2b()          // newAuth (TPM2B_AUTH)
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	authHandle := ac.handles[0]
	hi := t.h.byHandle(authHandle)
	if hi == nil || authHandle == RHNull {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if errResp := t.authorizeHierarchy(ac, authHandle); errResp != nil {
		return errResp
	}
	hi.authValue = newAuth
	return t.authResponse(ac, nil, nil)
}

// cmdSetPrimaryPolicy implements TPM2_SetPrimaryPolicy: set a hierarchy's
// authPolicy. The authPolicy hash is bound to a nameAlg; an Empty policy clears it.
func (t *TPM) cmdSetPrimaryPolicy(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCSetPrimaryPolicy, 1, r)
	if errResp != nil {
		return errResp
	}
	authPolicy := r.tpm2b() // authPolicy (TPM2B_DIGEST)
	hashAlg := r.u16()      // hashAlg (TPMI_ALG_HASH+)
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	authHandle := ac.handles[0]
	hi := t.h.byHandle(authHandle)
	if hi == nil || authHandle == RHNull {
		return errorResponse(withHandle(RCHandle, 1))
	}
	// An empty policy uses TPM_ALG_NULL; otherwise the digest length must match
	// the named hash.
	if len(authPolicy) == 0 {
		if hashAlg != AlgNull {
			return errorResponse(withParam(RCValue, 2))
		}
	} else if hashSize(hashAlg) != len(authPolicy) {
		return errorResponse(withParam(RCSize, 1))
	}
	if errResp := t.authorizeHierarchy(ac, authHandle); errResp != nil {
		return errResp
	}
	hi.authPolicy = authPolicy
	return t.authResponse(ac, nil, nil)
}

// cmdHierarchyControl implements TPM2_HierarchyControl: enable or disable a
// hierarchy. Enabling requires Platform authorization; a hierarchy may disable
// itself. Modeled for the storage, endorsement and platform enables.
func (t *TPM) cmdHierarchyControl(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCHierarchyControl, 1, r)
	if errResp != nil {
		return errResp
	}
	target := r.u32() // enable (TPMI_RH_HIERARCHY)
	state := r.u8()   // state (TPMI_YES_NO)
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if state != byte(no) && state != byte(yes) {
		return errorResponse(withParam(RCValue, 2))
	}
	hi := t.h.byHandle(target)
	if hi == nil || target == RHNull || target == RHLockout {
		return errorResponse(withHandle(RCValue, 2))
	}
	// Enabling, or acting on a hierarchy other than the target, needs Platform.
	authHandle := ac.handles[0]
	enabling := state == byte(yes)
	if (enabling || authHandle != target) && authHandle != RHPlatform {
		return errorResponse(RCAuthType)
	}
	if t.h.byHandle(authHandle) == nil {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if errResp := t.authorizeHierarchy(ac, authHandle); errResp != nil {
		return errResp
	}
	hi.enabled = enabling
	return t.authResponse(ac, nil, nil)
}

// cmdChangeSeed implements TPM2_ChangeEPS and TPM2_ChangePPS: the Platform
// regenerates the endorsement or platform primary seed.
func (t *TPM) cmdChangeSeed(tag uint16, cc uint32, r *reader, target *hierarchy) []byte {
	ac, errResp := parseCommandAuth(tag, cc, 1, r)
	if errResp != nil {
		return errResp
	}
	authHandle := ac.handles[0]
	if authHandle != RHPlatform {
		return errorResponse(RCAuthType)
	}
	if errResp := t.authorizeHierarchy(ac, authHandle); errResp != nil {
		return errResp
	}
	target.seed = randomSeed()
	return t.authResponse(ac, nil, nil)
}
