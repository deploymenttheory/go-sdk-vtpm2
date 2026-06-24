// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"crypto/aes"
	"crypto/hmac"
)

// This file implements credential protection (TPM 2.0 Part 3, §24): the
// MakeCredential / ActivateCredential pair used for privacy-preserving key
// certification (e.g. AIK enrollment). The credential value is wrapped with a
// "STORAGE" symmetric key and an "INTEGRITY" HMAC, both KDFa-derived from a seed
// that is shared with the key via the "IDENTITY" Labeled KEM (Part 1, §24).

// wrapCredential builds the TPM2B_ID_OBJECT content (integrityHMAC ‖ encIdentity)
// for a credential bound to name. Encryption is zero-IV AES-CFB.
func wrapCredential(nameAlg uint16, seed, credential, name []byte, keyBits uint16) []byte {
	symKey := kdfa(nameAlg, seed, []byte("STORAGE"), name, nil, int(keyBits))
	var inner writer
	inner.tpm2b(credential) // the credential value is marshalled as a TPM2B_DIGEST
	enc := aesCFB(symKey, make([]byte, aes.BlockSize), inner.bytes(), true)

	hmacKey := kdfa(nameAlg, seed, []byte("INTEGRITY"), nil, nil, hashSize(nameAlg)*8)
	integrity := hmacSum(nameAlg, hmacKey, enc, name)

	var w writer
	w.tpm2b(integrity) // identityHMAC (TPM2B_DIGEST)
	w.raw(enc)         // encIdentity
	return w.bytes()
}

// unwrapCredential reverses wrapCredential: verify the HMAC bound to name, then
// decrypt and return the credential value.
func unwrapCredential(nameAlg uint16, seed, blob, name []byte, keyBits uint16) ([]byte, bool) {
	r := newReader(blob)
	integrity := r.tpm2b()
	enc := r.bytes(r.remaining())
	if r.err != nil {
		return nil, false
	}
	hmacKey := kdfa(nameAlg, seed, []byte("INTEGRITY"), nil, nil, hashSize(nameAlg)*8)
	if !hmac.Equal(hmacSum(nameAlg, hmacKey, enc, name), integrity) {
		return nil, false
	}
	symKey := kdfa(nameAlg, seed, []byte("STORAGE"), name, nil, int(keyBits))
	dec := aesCFB(symKey, make([]byte, aes.BlockSize), enc, false)
	sr := newReader(dec)
	cv := sr.tpm2b()
	if sr.err != nil {
		return nil, false
	}
	return cv, true
}

// cmdMakeCredential implements TPM2_MakeCredential (Part 3, §24.1): wrap a
// credential so only the holder of the named object loaded under handle can
// recover it. No authorization (a public-key operation).
func (t *TPM) cmdMakeCredential(r *reader) []byte {
	handle := r.u32()
	credential := r.tpm2b()
	objectName := r.tpm2b()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	key, ok := t.objects.get(handle)
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if key.public.Type != AlgRSA && key.public.Type != AlgECC {
		return errorResponse(withHandle(RCType, 1))
	}
	if key.public.Sym.Alg == AlgNull {
		return errorResponse(withHandle(RCType, 1)) // needs a storage key's symmetric algorithm
	}
	if len(credential) > hashSize(key.public.NameAlg) {
		return errorResponse(withParam(RCSize, 1)) // CV must fit in a digest
	}
	seed, secret, ok := encryptSeed(key, []byte("IDENTITY"), t.rand)
	if !ok {
		return errorResponse(RCKey)
	}
	blob := wrapCredential(key.public.NameAlg, seed, credential, objectName, key.public.Sym.KeyBits)

	var w writer
	w.tpm2b(blob)   // credentialBlob (TPM2B_ID_OBJECT)
	w.tpm2b(secret) // secret (TPM2B_ENCRYPTED_SECRET)
	return successResponse(w.bytes(), 0)
}

// cmdActivateCredential implements TPM2_ActivateCredential (Part 3, §24.2):
// recover a credential, proving the named object is loaded on this TPM. Two
// authorizations: the object being certified, then the decryption key.
func (t *TPM) cmdActivateCredential(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCActivateCredential, 2, r)
	if errResp != nil {
		return errResp
	}
	t.decryptCommandParams(ac, r)
	credentialBlob := r.tpm2b()
	secret := r.tpm2b()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	activateHandle, keyHandle := ac.handles[0], ac.handles[1]
	activeObj, ok := t.objects.get(activateHandle)
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	key, ok := t.objects.get(keyHandle)
	if !ok {
		return errorResponse(withHandle(RCHandle, 2))
	}
	if errResp := t.authorizeObject(ac, 0, activeObj); errResp != nil {
		return errResp
	}
	if errResp := t.authorizeObject(ac, 1, key); errResp != nil {
		return errResp
	}
	seed, ok := decryptSeed(key, secret, []byte("IDENTITY"), t.rand)
	if !ok {
		return errorResponse(withParam(RCValue, 2))
	}
	cv, ok := unwrapCredential(key.public.NameAlg, seed, credentialBlob, activeObj.name, key.public.Sym.KeyBits)
	if !ok {
		return errorResponse(RCIntegrity)
	}
	var w writer
	w.tpm2b(cv) // certInfo (the recovered credential value)
	return t.authResponse(ac, nil, w.bytes())
}
