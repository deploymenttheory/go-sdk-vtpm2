// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"encoding/binary"
)

// This file implements the policy-session assertions (TPM 2.0 Part 3, §23). Each
// assertion folds a command-specific value into the session's policyDigest:
//
//	policyDigestnew = H_authHash(policyDigestold ‖ TPM_CC ‖ assertion-specific data)
//
// A satisfied policyDigest is later matched against an object's authPolicy to
// authorize a command (the authorization path lands with HMAC sessions).

// be32 returns v as 4 big-endian bytes (a marshalled TPM_CC / UINT32).
func be32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

// be16 returns v as 2 big-endian bytes (a marshalled UINT16 / TPM_ST).
func be16(v uint16) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return b[:]
}

// be64 returns v as 8 big-endian bytes (a marshalled UINT64).
func be64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

// extend folds parts into the session's policyDigest:
// policyDigest = H(policyDigest ‖ parts…).
func (s *authSession) extend(parts ...[]byte) {
	h := newHash(s.authHash)
	h.Write(s.policyDigest)
	for _, p := range parts {
		h.Write(p)
	}
	s.policyDigest = h.Sum(nil)
}

// policySession reads the leading policy-session handle and returns the session,
// or an error response if the handle is not a policy/trial session.
func (t *TPM) policySession(r *reader) (*authSession, []byte) {
	h := r.u32()
	if r.err != nil {
		return nil, errorResponse(RCInsufficient)
	}
	s, ok := t.sessions.get(h)
	if !ok {
		return nil, errorResponse(withHandle(RCHandle, 1))
	}
	if s.kind != sePolicy && s.kind != seTrial {
		// The handle is a session but not a policy session: wrong handle type.
		return nil, errorResponse(withHandle(RCHandle, 1))
	}
	return s, nil
}

// pcrSelectionDigest computes the digest of the selected PCR values, in the same
// order TPM2_PolicyPCR and TPM2_PCR_Read use (TPM 2.0 Part 1, §17.8).
func (t *TPM) pcrSelectionDigest(authHash uint16, sels []pcrSelection) []byte {
	h := newHash(authHash)
	for _, sel := range sels {
		for i := 0; i < numPCR; i++ {
			if !sel.selected(i) {
				continue
			}
			if d := t.pcr.read(sel.hash, i); d != nil {
				h.Write(d)
			}
		}
	}
	return h.Sum(nil)
}

// cmdPolicyPCR implements TPM2_PolicyPCR: bind the policy to a set of PCR values.
func (t *TPM) cmdPolicyPCR(r *reader) []byte {
	s, errResp := t.policySession(r)
	if errResp != nil {
		return errResp
	}
	pcrDigest := r.tpm2b()          // pcrDigest (TPM2B_DIGEST, may be empty)
	sels := readPCRSelectionList(r) // pcrs (TPML_PCR_SELECTION)
	if r.err != nil {
		if r.err == errBadValue {
			return errorResponse(withParam(RCValue, 2))
		}
		return errorResponse(RCInsufficient)
	}

	// For a real session the digest comes from the current PCR values (and the
	// caller's pcrDigest, if given, must match). A trial policy uses the caller's
	// pcrDigest directly, so a policy can be computed without the PCRs in question.
	digestUsed := pcrDigest
	if s.kind != seTrial {
		current := t.pcrSelectionDigest(s.authHash, sels)
		if len(pcrDigest) != 0 && !bytes.Equal(pcrDigest, current) {
			return errorResponse(withParam(RCValue, 1))
		}
		digestUsed = current
	}

	var sel writer
	writePCRSelectionList(&sel, sels)
	s.extend(be32(CCPolicyPCR), sel.bytes(), digestUsed)
	return successResponse(nil, 0)
}

// cmdPolicyCommandCode implements TPM2_PolicyCommandCode: restrict the policy to
// authorize only a single command code.
func (t *TPM) cmdPolicyCommandCode(r *reader) []byte {
	s, errResp := t.policySession(r)
	if errResp != nil {
		return errResp
	}
	code := r.u32() // code (TPM_CC)
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if s.commandCode != 0 && s.commandCode != code {
		return errorResponse(withParam(RCValue, 1)) // already restricted to a different code
	}
	s.commandCode = code
	s.extend(be32(CCPolicyCommandCode), be32(code))
	return successResponse(nil, 0)
}

// cmdPolicyAuthValue implements TPM2_PolicyAuthValue: require the object's
// authValue (via an HMAC over the session key and authValue) at use time.
func (t *TPM) cmdPolicyAuthValue(r *reader) []byte {
	s, errResp := t.policySession(r)
	if errResp != nil {
		return errResp
	}
	s.policyAuth = true
	s.extend(be32(CCPolicyAuthValue))
	return successResponse(nil, 0)
}

// cmdPolicyOR implements TPM2_PolicyOR: satisfy the policy if the current digest
// is any one of a list of approved digests. The digest is reset and folded with
// the whole list, so all branches converge to the same value.
func (t *TPM) cmdPolicyOR(r *reader) []byte {
	s, errResp := t.policySession(r)
	if errResp != nil {
		return errResp
	}
	count := r.u32() // pHashList: TPML_DIGEST count
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if count < 2 || count > 8 {
		return errorResponse(withParam(RCValue, 1)) // 2..8 branches
	}
	digests := make([][]byte, 0, count)
	var concat []byte
	for i := uint32(0); i < count; i++ {
		d := r.tpm2b()
		if r.err != nil {
			return errorResponse(RCInsufficient)
		}
		digests = append(digests, d)
		concat = append(concat, d...)
	}

	// A real session must currently match one of the branches; a trial just builds.
	if s.kind != seTrial {
		matched := false
		for _, d := range digests {
			if bytes.Equal(d, s.policyDigest) {
				matched = true
				break
			}
		}
		if !matched {
			return errorResponse(withParam(RCValue, 1))
		}
	}

	s.policyDigest = make([]byte, hashSize(s.authHash)) // reset to a Zero Digest
	s.extend(be32(CCPolicyOR), concat)
	return successResponse(nil, 0)
}

// cmdPolicyGetDigest implements TPM2_PolicyGetDigest: return the current digest.
func (t *TPM) cmdPolicyGetDigest(r *reader) []byte {
	s, errResp := t.policySession(r)
	if errResp != nil {
		return errResp
	}
	var w writer
	w.tpm2b(s.policyDigest) // policyDigest (TPM2B_DIGEST)
	return successResponse(w.bytes(), 0)
}

// cmdPolicyRestart implements TPM2_PolicyRestart: return the policy session to its
// freshly-started state.
func (t *TPM) cmdPolicyRestart(r *reader) []byte {
	s, errResp := t.policySession(r)
	if errResp != nil {
		return errResp
	}
	s.policyDigest = make([]byte, hashSize(s.authHash))
	s.commandCode = 0
	s.policyAuth = false
	s.policyCpHash = nil
	s.hasLocality = false
	s.policyLocality = 0
	return successResponse(nil, 0)
}

// cmdPolicyCpHash implements TPM2_PolicyCpHash (Part 3, §23.11): bind the policy to
// a specific command and its parameters via cpHashA.
func (t *TPM) cmdPolicyCpHash(r *reader) []byte {
	s, errResp := t.policySession(r)
	if errResp != nil {
		return errResp
	}
	cpHashA := r.tpm2b()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if len(s.policyCpHash) != 0 && !bytes.Equal(s.policyCpHash, cpHashA) {
		return errorResponse(withParam(RCValue, 1)) // already bound to a different cpHash
	}
	if len(cpHashA) != 0 && len(cpHashA) != hashSize(s.authHash) {
		return errorResponse(withParam(RCSize, 1))
	}
	s.policyCpHash = append([]byte(nil), cpHashA...)
	s.extend(be32(CCPolicyCpHash), cpHashA)
	return successResponse(nil, 0)
}

// cmdPolicyNameHash implements TPM2_PolicyNameHash (Part 3, §23.12): bind the
// policy to the Names of the command's handles via nameHash.
func (t *TPM) cmdPolicyNameHash(r *reader) []byte {
	s, errResp := t.policySession(r)
	if errResp != nil {
		return errResp
	}
	nameHash := r.tpm2b()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	s.extend(be32(CCPolicyNameHash), nameHash)
	return successResponse(nil, 0)
}

// cmdPolicyLocality implements TPM2_PolicyLocality (Part 3, §23.9): restrict the
// policy to a set of localities. Repeated calls AND the bitmaps.
func (t *TPM) cmdPolicyLocality(r *reader) []byte {
	s, errResp := t.policySession(r)
	if errResp != nil {
		return errResp
	}
	locality := r.u8() // TPMA_LOCALITY bitmap (localities 0..4)
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if locality == 0 {
		return errorResponse(withParam(RCValue, 1))
	}
	if s.hasLocality {
		if s.policyLocality&locality == 0 {
			return errorResponse(withParam(RCValue, 1)) // contradicts the prior restriction
		}
		s.policyLocality &= locality
	} else {
		s.policyLocality = locality
		s.hasLocality = true
	}
	s.extend(be32(CCPolicyLocality), []byte{locality})
	return successResponse(nil, 0)
}

// cmdPolicyPhysicalPresence implements TPM2_PolicyPhysicalPresence (Part 3,
// §23.10): require physical-presence assertion at use time.
func (t *TPM) cmdPolicyPhysicalPresence(r *reader) []byte {
	s, errResp := t.policySession(r)
	if errResp != nil {
		return errResp
	}
	s.extend(be32(CCPolicyPhysicalPresence))
	return successResponse(nil, 0)
}

// cmdPolicyPassword implements TPM2_PolicyPassword (Part 3, §23.18): require the
// object's authValue as a plaintext password at use. It folds the same digest as
// PolicyAuthValue (TPM_CC_PolicyAuthValue).
func (t *TPM) cmdPolicyPassword(r *reader) []byte {
	s, errResp := t.policySession(r)
	if errResp != nil {
		return errResp
	}
	s.policyAuth = true
	s.extend(be32(CCPolicyAuthValue)) // same digest as PolicyAuthValue
	return successResponse(nil, 0)
}

// cmdPolicyNvWritten implements TPM2_PolicyNvWritten (Part 3, §23.14): bind the
// policy to the TPMA_NV_WRITTEN state of an NV Index.
func (t *TPM) cmdPolicyNvWritten(r *reader) []byte {
	s, errResp := t.policySession(r)
	if errResp != nil {
		return errResp
	}
	writtenSet := r.u8() // TPMI_YES_NO
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	s.extend(be32(CCPolicyNvWritten), []byte{writtenSet})
	return successResponse(nil, 0)
}

// cmdPolicyTemplate implements TPM2_PolicyTemplate (Part 3, §23.15): bind the
// policy to a creation template via templateHash.
func (t *TPM) cmdPolicyTemplate(r *reader) []byte {
	s, errResp := t.policySession(r)
	if errResp != nil {
		return errResp
	}
	templateHash := r.tpm2b()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	s.extend(be32(CCPolicyTemplate), templateHash)
	return successResponse(nil, 0)
}
