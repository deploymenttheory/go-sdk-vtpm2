// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

// This file implements the NV administration commands (TPM 2.0 Part 3, §31):
// TPM2_NV_ChangeAuth, TPM2_NV_GlobalWriteLock and TPM2_NV_UndefineSpaceSpecial.
// The NV store itself lives in nvStore (nv.go).

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
