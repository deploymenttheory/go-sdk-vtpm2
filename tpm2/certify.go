// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import "crypto/hmac"

// This file implements the object-attestation commands (TPM 2.0 Part 3, §18):
// TPM2_Certify (attest that an object is loaded) and TPM2_CertifyCreation (attest
// an object's creation). Both build a TPMS_ATTEST and sign it, like TPM2_Quote.

// signAttest resolves the signing scheme, builds the attestation block, signs it,
// and advances the clock — the flow shared by Quote/Certify/CertifyCreation.
func (t *TPM) signAttest(key *object, inScheme, inHash, attestType uint16, qualifyingData, attested []byte) (certifyInfo, signature, errResp []byte) {
	sigAlg, hashAlg := key.public.Scheme.Scheme, key.public.Scheme.HashAlg
	if sigAlg == AlgNull {
		sigAlg, hashAlg = inScheme, inHash
	}
	if _, ok := cryptoHash(hashAlg); !ok {
		return nil, nil, errorResponse(withParam(RCValue, 2))
	}
	attest := t.buildAttest(key.name, qualifyingData, attestType, attested)
	sig, errResp := t.signWith(key, sigAlg, hashAlg, hashSum(hashAlg, attest))
	if errResp != nil {
		return nil, nil, errResp
	}
	t.clock.clock++
	return attest, sig, nil
}

// readSigScheme reads a TPMT_SIG_SCHEME (scheme selector + hash if not NULL).
func readSigScheme(r *reader) (scheme, hash uint16) {
	scheme = r.u16()
	if scheme != AlgNull {
		hash = r.u16()
	}
	return scheme, hash
}

// cmdCertify implements TPM2_Certify (Part 3, §18.2): sign a statement that the
// object at objectHandle is loaded, binding its Name and Qualified Name. Two
// authorizations: the certified object, then the signing key.
func (t *TPM) cmdCertify(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCCertify, 2, r) // objectHandle, signHandle
	if errResp != nil {
		return errResp
	}
	qualifyingData := r.tpm2b()
	scheme, schemeHash := readSigScheme(r)
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	obj, ok := t.objects.get(ac.handles[0])
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	key, ok := t.objects.get(ac.handles[1])
	if !ok {
		return errorResponse(withHandle(RCHandle, 2))
	}
	if key.public.Attrs&ObjSign == 0 {
		return errorResponse(withHandle(RCAttributes, 2))
	}
	if errResp := t.authorizeObject(ac, 0, obj); errResp != nil {
		return errResp
	}
	if errResp := t.authorizeObject(ac, 1, key); errResp != nil {
		return errResp
	}

	// TPMS_CERTIFY_INFO = name ‖ qualifiedName.
	qn := obj.qualifiedName
	if len(qn) == 0 {
		qn = obj.name
	}
	var ci writer
	ci.tpm2b(obj.name)
	ci.tpm2b(qn)

	attest, sig, errResp := t.signAttest(key, scheme, schemeHash, STAttestCertify, qualifyingData, ci.bytes())
	if errResp != nil {
		return errResp
	}
	var w writer
	w.tpm2b(attest) // certifyInfo (TPM2B_ATTEST)
	w.raw(sig)      // signature (TPMT_SIGNATURE)
	return t.authResponse(ac, nil, w.bytes())
}

// cmdCertifyCreation implements TPM2_CertifyCreation (Part 3, §18.3): sign a
// statement about an object's creation, validated by its creation ticket. Handles:
// signHandle (authorized), objectHandle (public).
func (t *TPM) cmdCertifyCreation(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCCertifyCreation, 2, r) // signHandle, objectHandle
	if errResp != nil {
		return errResp
	}
	qualifyingData := r.tpm2b()
	creationHash := r.tpm2b()
	scheme, schemeHash := readSigScheme(r)
	_ = r.u16() // creationTicket: TPMT_TK_CREATION tag
	tkHier := r.u32()
	tkDigest := r.tpm2b()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	key, ok := t.objects.get(ac.handles[0])
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	obj, ok := t.objects.get(ac.handles[1])
	if !ok {
		return errorResponse(withHandle(RCHandle, 2))
	}
	if key.public.Attrs&ObjSign == 0 {
		return errorResponse(withHandle(RCAttributes, 1))
	}
	if errResp := t.authorizeObject(ac, 0, key); errResp != nil {
		return errResp
	}
	// The creation ticket must match what TPM2_Create(Primary) produced for obj:
	// HMAC(hierarchyProof, TPM_ST_CREATION ‖ objectName ‖ creationHash).
	proof := t.hierarchyProof(tkHier)
	want := hmacSum(obj.public.NameAlg, proof, be16(STCreation), obj.name, creationHash)
	if proof == nil || !hmac.Equal(tkDigest, want) {
		return errorResponse(RCTicket)
	}

	// TPMS_CREATION_INFO = objectName ‖ creationHash.
	var ci writer
	ci.tpm2b(obj.name)
	ci.tpm2b(creationHash)

	attest, sig, errResp := t.signAttest(key, scheme, schemeHash, STAttestCreation, qualifyingData, ci.bytes())
	if errResp != nil {
		return errResp
	}
	var w writer
	w.tpm2b(attest)
	w.raw(sig)
	return t.authResponse(ac, nil, w.bytes())
}

// cmdGetTime implements TPM2_GetTime (Part 3, §18.5): a signed statement of the
// TPM's time and clock. Handles: privacyAdminHandle (TPM_RH_ENDORSEMENT),
// signHandle — both authorized.
func (t *TPM) cmdGetTime(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCGetTime, 2, r) // privacyAdmin, signHandle
	if errResp != nil {
		return errResp
	}
	qualifyingData := r.tpm2b()
	scheme, schemeHash := readSigScheme(r)
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if ac.handles[0] != RHEndorsement {
		return errorResponse(withHandle(RCValue, 1)) // privacyAdminHandle must be endorsement
	}
	if errResp := t.authorizeHierarchyAt(ac, 0, RHEndorsement); errResp != nil {
		return errResp
	}
	key, ok := t.objects.get(ac.handles[1])
	if !ok {
		return errorResponse(withHandle(RCHandle, 2))
	}
	if key.public.Attrs&ObjSign == 0 {
		return errorResponse(withHandle(RCAttributes, 2))
	}
	if errResp := t.authorizeObject(ac, 1, key); errResp != nil {
		return errResp
	}

	// TPMS_TIME_ATTEST_INFO = TPMS_TIME_INFO (time ‖ clockInfo) ‖ firmwareVersion.
	var ti writer
	ti.u64(t.clock.clock)    // time
	t.clock.marshalInfo(&ti) // clockInfo
	ti.u64(firmwareVersion)

	attest, sig, errResp := t.signAttest(key, scheme, schemeHash, STAttestTime, qualifyingData, ti.bytes())
	if errResp != nil {
		return errResp
	}
	var w writer
	w.tpm2b(attest)
	w.raw(sig)
	return t.authResponse(ac, nil, w.bytes())
}

// cmdNVCertify implements TPM2_NV_Certify (Part 3, §31.16): a signed statement of
// an NV Index's contents. Handles: signHandle, authHandle (NV auth), nvIndex.
func (t *TPM) cmdNVCertify(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCNVCertify, 3, r) // signHandle, authHandle, nvIndex
	if errResp != nil {
		return errResp
	}
	qualifyingData := r.tpm2b()
	scheme, schemeHash := readSigScheme(r)
	size := r.u16()
	offset := r.u16()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	key, ok := t.objects.get(ac.handles[0])
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	idx, ok := t.nv.get(ac.handles[2])
	if !ok {
		return errorResponse(withHandle(RCHandle, 3))
	}
	if key.public.Attrs&ObjSign == 0 {
		return errorResponse(withHandle(RCAttributes, 1))
	}
	if errResp := t.authorizeObject(ac, 0, key); errResp != nil {
		return errResp
	}
	if errResp := t.authorizeNVAt(ac, 1, idx, ac.handles[1], false); errResp != nil {
		return errResp
	}
	if idx.public.Attrs&NVWritten == 0 {
		return errorResponse(RCNVUninitialized)
	}
	if int(offset)+int(size) > len(idx.data) {
		return errorResponse(withParam(RCValue, 4))
	}

	// TPMS_NV_CERTIFY_INFO = indexName ‖ offset ‖ nvContents.
	var ci writer
	ci.tpm2b(idx.name)
	ci.u16(offset)
	ci.tpm2b(idx.data[offset : int(offset)+int(size)])

	attest, sig, errResp := t.signAttest(key, scheme, schemeHash, STAttestNV, qualifyingData, ci.bytes())
	if errResp != nil {
		return errResp
	}
	var w writer
	w.tpm2b(attest)
	w.raw(sig)
	return t.authResponse(ac, nil, w.bytes())
}
