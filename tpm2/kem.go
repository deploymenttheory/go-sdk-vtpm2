// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

// This file implements the key-encapsulation commands (TPM 2.0 Part 3, §14.10/14.11):
// TPM2_Encapsulate and TPM2_Decapsulate. For an asymmetric key these are the
// Labeled-KEM primitives (RSA-OAEP or ECDH+KDFe) already used for session salts and
// credentials, exposed directly: Encapsulate shares a secret + ciphertext,
// Decapsulate recovers the secret from the ciphertext with the private key.

// kemLabel is the Labeled-KEM label for the encapsulation commands.
var kemLabel = []byte("SECRET")

// cmdEncapsulate implements TPM2_Encapsulate (Part 3, §14.10): produce a shared
// secret and the ciphertext that recovers it. No authorization (a public-key op).
// The key must be a KEM key — decrypt SET, restricted CLEAR.
func (t *TPM) cmdEncapsulate(r *reader) []byte {
	keyHandle := r.u32()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	key, ok := t.objects.get(keyHandle)
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if key.public.Type != AlgRSA && key.public.Type != AlgECC {
		return errorResponse(withHandle(RCKey, 1))
	}
	if key.public.Attrs&ObjDecrypt == 0 || key.public.Attrs&ObjRestricted != 0 {
		return errorResponse(withHandle(RCAttributes, 1))
	}
	seed, secret, ok := encryptSeed(key, kemLabel, t.rand)
	if !ok {
		return errorResponse(RCKey)
	}
	var w writer
	w.tpm2b(seed)   // sharedSecret (TPM2B_SHARED_SECRET)
	w.tpm2b(secret) // ciphertext (TPM2B_KEM_CIPHERTEXT)
	return successResponse(w.bytes(), 0)
}

// cmdDecapsulate implements TPM2_Decapsulate (Part 3, §14.11): recover the shared
// secret from a ciphertext using the private key.
func (t *TPM) cmdDecapsulate(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCDecapsulate, 1, r) // @keyHandle
	if errResp != nil {
		return errResp
	}
	ciphertext := r.tpm2b()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	key, ok := t.objects.get(ac.handles[0])
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if key.public.Type != AlgRSA && key.public.Type != AlgECC {
		return errorResponse(withHandle(RCKey, 1))
	}
	if errResp := t.authorizeObject(ac, 0, key); errResp != nil {
		return errResp
	}
	seed, ok := decryptSeed(key, ciphertext, kemLabel, t.rand)
	if !ok {
		return errorResponse(withParam(RCValue, 1))
	}
	var w writer
	w.tpm2b(seed) // sharedSecret (TPM2B_SHARED_SECRET)
	return t.authResponse(ac, nil, w.bytes())
}
