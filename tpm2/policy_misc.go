// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
)

// This file completes the policy command set (TPM 2.0 Part 3, §23): PolicyTicket,
// PolicyAuthorizeNV, PolicyDuplicationSelect, PolicyCapability and
// PolicyParameters.

// cmdPolicyTicket implements TPM2_PolicyTicket (Part 3, §23.5): replay a ticket
// produced by an earlier PolicySigned/PolicySecret instead of re-proving.
func (t *TPM) cmdPolicyTicket(r *reader) []byte {
	s, errResp := t.policySession(r)
	if errResp != nil {
		return errResp
	}
	timeout := r.tpm2b()
	cpHashA := r.tpm2b()
	policyRef := r.tpm2b()
	authName := r.tpm2b()
	_ = r.u16() // ticket: TPMT_TK_AUTH tag
	tkHier := r.u32()
	tkDigest := r.tpm2b()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	// The ticket tag determines which authorization the ticket stands in for; we
	// recompute the digest with both tags and accept whichever matches.
	if s.kind != seTrial {
		proof := t.hierarchyProof(tkHier)
		if proof == nil {
			return errorResponse(withParam(RCValue, 5))
		}
		secretWant := hmacSum(AlgSHA256, proof, be16(STAuthSecret), timeout, cpHashA, policyRef, authName)
		signedWant := hmacSum(AlgSHA256, proof, be16(STAuthSigned), timeout, cpHashA, policyRef, authName)
		switch {
		case hmac.Equal(tkDigest, secretWant):
			s.policyUpdate(CCPolicySecret, authName, policyRef)
		case hmac.Equal(tkDigest, signedWant):
			s.policyUpdate(CCPolicySigned, authName, policyRef)
		default:
			return errorResponse(withParam(RCPolicyFail, 5))
		}
	} else {
		// A trial session cannot tell which authorization a ticket represents; the
		// spec has the caller use PolicySigned/PolicySecret to build a trial policy.
		return errorResponse(withHandle(RCAttributes, 1))
	}
	if len(cpHashA) != 0 {
		s.policyCpHash = append([]byte(nil), cpHashA...)
	}
	return successResponse(nil, 0)
}

// cmdPolicyAuthorizeNV implements TPM2_PolicyAuthorizeNV (Part 3, §23.17): approve
// the accumulated policy by comparing it to a TPMT_HA stored in an NV Index, then
// reset and fold the NV Index Name. Handles: authHandle, nvIndex, policySession.
func (t *TPM) cmdPolicyAuthorizeNV(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCPolicyAuthorizeNV, 3, r)
	if errResp != nil {
		return errResp
	}
	authHandle, nvHandle, policyHandle := ac.handles[0], ac.handles[1], ac.handles[2]
	idx, ok := t.nv.get(nvHandle)
	if !ok {
		return errorResponse(withHandle(RCHandle, 2))
	}
	if errResp := t.authorizeNV(ac, idx, authHandle, false); errResp != nil {
		return errResp
	}
	s, ok := t.sessions.get(policyHandle)
	if !ok || (s.kind != sePolicy && s.kind != seTrial) {
		return errorResponse(withHandle(RCHandle, 3))
	}
	if s.kind != seTrial {
		if idx.public.Attrs&NVWritten == 0 {
			return errorResponse(RCNVUninitialized)
		}
		// The Index holds a TPMT_HA: hashAlg(2) ‖ digest. It must match the session.
		if len(idx.data) < 2+len(s.policyDigest) {
			return errorResponse(withParam(RCSize, 2))
		}
		if binary.BigEndian.Uint16(idx.data) != s.authHash || !bytes.Equal(idx.data[2:2+len(s.policyDigest)], s.policyDigest) {
			return errorResponse(RCPolicyFail)
		}
	}
	s.policyDigest = make([]byte, hashSize(s.authHash))
	s.extend(be32(CCPolicyAuthorizeNV), idx.name)
	return successResponse(nil, 0)
}

// cmdPolicyDuplicationSelect implements TPM2_PolicyDuplicationSelect (Part 3,
// §23.7): restrict a policy to duplicating a specific object to a specific new
// parent. It also restricts the policy to TPM2_Duplicate.
func (t *TPM) cmdPolicyDuplicationSelect(r *reader) []byte {
	s, errResp := t.policySession(r)
	if errResp != nil {
		return errResp
	}
	objectName := r.tpm2b()
	newParentName := r.tpm2b()
	includeObject := r.u8()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if includeObject != 0 {
		s.extend(be32(CCPolicyDuplicationSelect), objectName, newParentName, []byte{includeObject})
	} else {
		s.extend(be32(CCPolicyDuplicationSelect), newParentName, []byte{includeObject})
	}
	s.commandCode = CCDuplicate // this assertion implies the policy authorizes only Duplicate
	return successResponse(nil, 0)
}

// cmdPolicyParameters implements TPM2_PolicyParameters (Part 3, §23.13): bind the
// policy to a specific set of command parameters via pHash.
func (t *TPM) cmdPolicyParameters(r *reader) []byte {
	s, errResp := t.policySession(r)
	if errResp != nil {
		return errResp
	}
	pHash := r.tpm2b()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	s.extend(be32(CCPolicyParameters), pHash)
	return successResponse(nil, 0)
}

// cmdPolicyCapability implements TPM2_PolicyCapability (Part 3, §23.19): bind the
// policy to a comparison against a GetCapability value. The digest folds
// args = H(operandB ‖ offset ‖ operation ‖ capability ‖ property).
func (t *TPM) cmdPolicyCapability(r *reader) []byte {
	s, errResp := t.policySession(r)
	if errResp != nil {
		return errResp
	}
	operandB := r.tpm2b()
	offset := r.u16()
	operation := r.u16()
	capability := r.u32()
	property := r.u32()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	args := hashSum(s.authHash, operandB, be16(offset), be16(operation), be32(capability), be32(property))
	s.extend(be32(CCPolicyCapability), args)
	return successResponse(nil, 0)
}

// validateSCKeyName checks an optional secure-channel key Name: an Empty Buffer is
// allowed; otherwise the first two octets must be a valid hash algorithm and the
// remainder its digest (TPM 2.0 Part 3, §23.25).
func validateSCKeyName(name []byte) []byte {
	if len(name) == 0 {
		return nil
	}
	if len(name) < 2 {
		return errorResponse(RCSize)
	}
	alg := uint16(name[0])<<8 | uint16(name[1])
	sz := hashSize(alg)
	if sz == 0 {
		return errorResponse(RCHash)
	}
	if len(name) != 2+sz {
		return errorResponse(RCSize)
	}
	return nil
}

// cmdPolicyTransportSPDM implements TPM2_PolicyTransportSPDM (Part 3, §23.25): a
// deferred assertion gating a policy on an SPDM secure transport channel, binding
// the requester and TPM secure-channel key Names into the policy digest.
//
// Note: this emulator has no SPDM transport layer, so the deferred secure-channel
// check at use is a no-op; only the (testable) policy-digest update is performed.
func (t *TPM) cmdPolicyTransportSPDM(r *reader) []byte {
	s, errResp := t.policySession(r)
	if errResp != nil {
		return errResp
	}
	reqKeyName := r.tpm2b()
	tpmKeyName := r.tpm2b()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if s.spdmTransport {
		return errorResponse(RCValue) // PolicyTransportSPDM may run only once per session
	}
	if errResp := validateSCKeyName(reqKeyName); errResp != nil {
		return errResp
	}
	if errResp := validateSCKeyName(tpmKeyName); errResp != nil {
		return errResp
	}
	// scKeyNameHash = H(reqKeyName.size ‖ reqKeyName ‖ tpmKeyName.size ‖ tpmKeyName).
	var nb writer
	nb.tpm2b(reqKeyName)
	nb.tpm2b(tpmKeyName)
	scKeyNameHash := hashSum(s.authHash, nb.bytes())

	s.extend(be32(CCPolicyTransportSPDM), scKeyNameHash)
	s.spdmTransport = true
	return successResponse(nil, 0)
}
