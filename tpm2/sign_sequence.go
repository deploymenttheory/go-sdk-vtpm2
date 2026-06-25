// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

// This file implements the sign/verify sequence commands (TPM 2.0 Part 3, §20):
// TPM2_SignSequenceStart/Complete and TPM2_VerifySequenceStart/Complete. Each
// Start opens a hash sequence (fed by TPM2_SequenceUpdate); Complete finishes the
// digest and signs it / verifies a signature over it. The digest is produced by
// the TPM, so signing it never needs a hashcheck ticket.

// newSignSeq opens a hash sequence whose algorithm is the key's scheme hash.
func (t *TPM) newSignSeq(key *object, auth []byte) (uint32, bool) {
	hashAlg := key.public.Scheme.HashAlg
	h := newHash(hashAlg)
	if h == nil {
		return 0, false
	}
	seq := &sequence{auth: append([]byte(nil), auth...), alg: hashAlg, state: h}
	return t.sequences.add(seq), true
}

// cmdSignSequenceStart implements TPM2_SignSequenceStart (Part 3, §20.6): open a
// hash sequence bound to a signing key's hash. No authorization.
func (t *TPM) cmdSignSequenceStart(r *reader) []byte {
	keyHandle := r.u32()
	auth := r.tpm2b()
	_ = r.tpm2b() // context (TPM2B_SIGNATURE_CTX)
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	key, ok := t.objects.get(keyHandle)
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if key.public.Attrs&ObjSign == 0 {
		return errorResponse(withHandle(RCAttributes, 1))
	}
	handle, ok := t.newSignSeq(key, auth)
	if !ok {
		return errorResponse(RCScheme) // the key needs a defined scheme hash
	}
	var w writer
	w.u32(handle) // sequenceHandle
	return successResponse(w.bytes(), 0)
}

// cmdSignSequenceComplete implements TPM2_SignSequenceComplete (Part 3, §20.6):
// finish the sequence digest and sign it. Handles: sequenceHandle, keyHandle.
func (t *TPM) cmdSignSequenceComplete(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCSignSequenceComplete, 2, r)
	if errResp != nil {
		return errResp
	}
	t.decryptCommandParams(ac, r)
	buffer := r.tpm2b()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	seq, ok := t.sequences.get(ac.handles[0])
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if seq.event || seq.hmac {
		return errorResponse(RCMode)
	}
	if errResp := t.authorizeSequence(ac, 0, ac.handles[0], seq); errResp != nil {
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
	seq.write(buffer)
	digest := seq.state.Sum(nil)
	t.sequences.flush(ac.handles[0])

	sigAlg, hashAlg := key.public.Scheme.Scheme, key.public.Scheme.HashAlg
	if sigAlg == AlgNull {
		return errorResponse(RCScheme)
	}
	sig, errResp := t.signWith(key, sigAlg, hashAlg, digest)
	if errResp != nil {
		return errResp
	}
	return t.authResponse(ac, nil, sig)
}

// cmdVerifySequenceStart implements TPM2_VerifySequenceStart (Part 3, §20.3): open
// a hash sequence bound to a verification key's hash. No authorization.
func (t *TPM) cmdVerifySequenceStart(r *reader) []byte {
	keyHandle := r.u32()
	auth := r.tpm2b()
	_ = r.tpm2b() // hint (TPM2B_SIGNATURE_HINT)
	_ = r.tpm2b() // context (TPM2B_SIGNATURE_CTX)
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	key, ok := t.objects.get(keyHandle)
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if key.public.Type != AlgRSA && key.public.Type != AlgECC {
		return errorResponse(withHandle(RCType, 1))
	}
	handle, ok := t.newSignSeq(key, auth)
	if !ok {
		return errorResponse(RCScheme)
	}
	var w writer
	w.u32(handle) // sequenceHandle
	return successResponse(w.bytes(), 0)
}

// cmdVerifySequenceComplete implements TPM2_VerifySequenceComplete (Part 3, §20.3):
// finish the sequence digest and verify a signature over it. Handles:
// sequenceHandle (authorized), keyHandle (public, not authorized).
func (t *TPM) cmdVerifySequenceComplete(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCVerifySequenceComplete, 2, r)
	if errResp != nil {
		return errResp
	}
	sigAlg := r.u16()
	hashAlg := r.u16()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	seq, ok := t.sequences.get(ac.handles[0])
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if seq.event || seq.hmac {
		return errorResponse(RCMode)
	}
	if errResp := t.authorizeSequence(ac, 0, ac.handles[0], seq); errResp != nil {
		return errResp
	}
	key, ok := t.objects.get(ac.handles[1])
	if !ok {
		return errorResponse(withHandle(RCHandle, 2))
	}
	if key.public.Type != AlgRSA && key.public.Type != AlgECC {
		return errorResponse(withHandle(RCType, 2))
	}
	digest := seq.state.Sum(nil)
	t.sequences.flush(ac.handles[0])

	if !verifySignature(key, sigAlg, hashAlg, digest, r) {
		if r.err != nil {
			return errorResponse(RCInsufficient)
		}
		return errorResponse(RCSignature)
	}
	var w writer
	w.u16(STVerified)
	w.u32(RHNull)
	w.tpm2b(hmacSum(AlgSHA256, t.hierarchyProof(RHNull), be16(STVerified), digest))
	return t.authResponse(ac, nil, w.bytes())
}
