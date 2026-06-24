// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
)

// This file implements the auth/verification policy assertions (TPM 2.0 Part 3,
// §23.3 PolicySigned, §23.4 PolicySecret, §23.16 PolicyAuthorize). They share
// PolicyUpdate (Clause 23.2.3): a two-step fold of the command code + entity Name
// then the policy reference.

// policyUpdate applies PolicyUpdate(commandCode, name, ref):
//
//	policyDigest = H(policyDigest ‖ commandCode ‖ name)
//	policyDigest = H(policyDigest ‖ ref)
func (s *authSession) policyUpdate(cc uint32, name, ref []byte) {
	s.extend(be32(cc), name)
	s.extend(ref)
}

// authTicketDigest computes the TPMT_TK_AUTH digest binding a deferred
// authorization: HMAC over the tag, timeout, bound cpHash, policy reference and
// entity Name, keyed by the NULL-hierarchy proof.
func (t *TPM) authTicketDigest(tag uint16, timeout, cpHashA, policyRef, authName []byte) []byte {
	return hmacSum(AlgSHA256, t.hierarchyProof(RHNull), be16(tag), timeout, cpHashA, policyRef, authName)
}

// writeAuthTicket writes the timeout (TPM2B_TIMEOUT) and TPMT_TK_AUTH that
// PolicySecret/PolicySigned return. A zero expiration yields a NULL ticket;
// otherwise a ticket the caller can replay via TPM2_PolicyTicket.
func (t *TPM) writeAuthTicket(w *writer, tag uint16, expiration int32, cpHashA, policyRef, authName []byte) {
	if expiration == 0 {
		w.tpm2b(nil) // timeout
		w.u16(tag)
		w.u32(RHNull)
		w.tpm2b(nil) // NULL ticket
		return
	}
	timeout := be64(0) // wall-clock expiration is not tracked; the ticket is replayable
	w.tpm2b(timeout)
	w.u16(tag)
	w.u32(RHNull)
	w.tpm2b(t.authTicketDigest(tag, timeout, cpHashA, policyRef, authName))
}

// entityDAProtected reports whether failed authorization of an entity counts
// toward dictionary-attack lockout: owner/endorsement hierarchies and objects
// without ObjNoDA; NV indices and the platform/lockout hierarchies do not.
func (t *TPM) entityDAProtected(handle uint32) bool {
	if o, ok := t.objects.get(handle); ok {
		return o.public.Attrs&ObjNoDA == 0
	}
	return handle == RHOwner || handle == RHEndorsement
}

// cmdPolicySecret implements TPM2_PolicySecret (Part 3, §23.4): bind the policy to
// proof of an entity's authValue. Handles: authHandle (authorized), policySession.
func (t *TPM) cmdPolicySecret(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCPolicySecret, 2, r)
	if errResp != nil {
		return errResp
	}
	t.decryptCommandParams(ac, r)
	nonceTPM := r.tpm2b()
	cpHashA := r.tpm2b()
	policyRef := r.tpm2b()
	expiration := int32(r.u32())
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	authHandle, policyHandle := ac.handles[0], ac.handles[1]
	name := t.handleName(authHandle)
	if errResp := t.verifyAuth(ac, 0, name, t.entityAuthValue(authHandle), nil, t.entityDAProtected(authHandle)); errResp != nil {
		return errResp
	}
	s, ok := t.sessions.get(policyHandle)
	if !ok || (s.kind != sePolicy && s.kind != seTrial) {
		return errorResponse(withHandle(RCHandle, 2))
	}
	if len(nonceTPM) != 0 && !bytes.Equal(nonceTPM, s.nonceTPM) {
		return errorResponse(withParam(RCValue, 1)) // ties the authorization to this session
	}
	s.policyUpdate(CCPolicySecret, name, policyRef)
	if len(cpHashA) != 0 {
		s.policyCpHash = append([]byte(nil), cpHashA...)
	}
	var w writer
	t.writeAuthTicket(&w, STAuthSecret, expiration, cpHashA, policyRef, name)
	return t.authResponse(ac, nil, w.bytes())
}

// cmdPolicySigned implements TPM2_PolicySigned (Part 3, §23.3): bind the policy to
// a signature by an external authority over the session's authorization hash.
// Handles: authObject (the verification key), policySession. No auth sessions.
func (t *TPM) cmdPolicySigned(r *reader) []byte {
	authObjectH := r.u32()
	policyHandle := r.u32()
	nonceTPM := r.tpm2b()
	cpHashA := r.tpm2b()
	policyRef := r.tpm2b()
	expiration := r.u32()
	sigAlg := r.u16()
	hashAlg := r.u16()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	key, ok := t.objects.get(authObjectH)
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if key.public.Attrs&ObjSign == 0 {
		return errorResponse(withHandle(RCAttributes, 1))
	}
	s, ok := t.sessions.get(policyHandle)
	if !ok || (s.kind != sePolicy && s.kind != seTrial) {
		return errorResponse(withHandle(RCHandle, 2))
	}
	if len(nonceTPM) != 0 && !bytes.Equal(nonceTPM, s.nonceTPM) {
		return errorResponse(withParam(RCValue, 1))
	}
	if s.kind != seTrial {
		// The authority signs aHash = H(nonceTPM ‖ expiration ‖ cpHashA ‖ policyRef).
		aHash := hashSum(hashAlg, nonceTPM, be32(expiration), cpHashA, policyRef)
		if !verifySignature(key, sigAlg, hashAlg, aHash, r) {
			return errorResponse(RCSignature)
		}
	}
	s.policyUpdate(CCPolicySigned, key.name, policyRef)
	if len(cpHashA) != 0 {
		s.policyCpHash = append([]byte(nil), cpHashA...)
	}
	var w writer
	t.writeAuthTicket(&w, STAuthSigned, int32(expiration), cpHashA, policyRef, key.name)
	return successResponse(w.bytes(), 0)
}

// cmdPolicyAuthorize implements TPM2_PolicyAuthorize (Part 3, §23.16): replace the
// accumulated policy with one an authority has signed, allowing policies to be
// updated out-of-band. Handle: policySession.
func (t *TPM) cmdPolicyAuthorize(r *reader) []byte {
	s, errResp := t.policySession(r)
	if errResp != nil {
		return errResp
	}
	approvedPolicy := r.tpm2b()
	policyRef := r.tpm2b()
	keySign := r.tpm2b() // TPM2B_NAME of the authorizing key
	_ = r.u16()          // checkTicket: TPMT_TK_VERIFIED tag
	tkHier := r.u32()
	tkDigest := r.tpm2b()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if len(keySign) < 2 {
		return errorResponse(withParam(RCSize, 3))
	}
	if s.kind != seTrial {
		// The current policy must equal the approved one.
		if !bytes.Equal(approvedPolicy, s.policyDigest) {
			return errorResponse(withParam(RCValue, 1))
		}
		// checkTicket must be a valid TPMT_TK_VERIFIED over H(approvedPolicy ‖ policyRef)
		// under the key's name algorithm (matching TPM2_VerifySignature's ticket).
		keyNameAlg := binary.BigEndian.Uint16(keySign)
		aHash := hashSum(keyNameAlg, approvedPolicy, policyRef)
		if aHash == nil {
			return errorResponse(withParam(RCHash, 3))
		}
		proof := t.hierarchyProof(tkHier)
		want := hmacSum(AlgSHA256, proof, be16(STVerified), aHash)
		if proof == nil || !hmac.Equal(tkDigest, want) {
			return errorResponse(withParam(RCPolicyFail, 4))
		}
	}
	// Reset to a Zero Digest, then PolicyUpdate(TPM_CC_PolicyAuthorize, keySign, policyRef).
	s.policyDigest = make([]byte, hashSize(s.authHash))
	s.policyUpdate(CCPolicyAuthorize, keySign, policyRef)
	return successResponse(nil, 0)
}
