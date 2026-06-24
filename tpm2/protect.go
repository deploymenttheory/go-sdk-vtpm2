// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"crypto/aes"
	"crypto/hmac"
	"encoding/binary"
	"io"
)

// This file implements object protection (TPM 2.0 Part 1, §23): a child object's
// TPMT_SENSITIVE is wrapped into a TPM2B_PRIVATE under its parent — symmetrically
// encrypted and bound to the object Name by an outer integrity HMAC, both keyed
// from the parent's symmetric seed via KDFa. The blob is opaque outside the TPM,
// so only this TPM (or a recreated parent with the same seed) can unwrap it.

// aesCFB applies AES in CFB-128 mode (the TPM symmetric-object mode). Encryption
// and decryption share the keystream feedback derived from the ciphertext.
func aesCFB(key, iv, data []byte, encrypt bool) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	bs := block.BlockSize()
	out := make([]byte, len(data))
	feedback := make([]byte, bs)
	copy(feedback, iv)
	ks := make([]byte, bs)
	for i := 0; i < len(data); i += bs {
		block.Encrypt(ks, feedback)
		n := bs
		if i+bs > len(data) {
			n = len(data) - i
		}
		for j := 0; j < n; j++ {
			c := data[i+j] ^ ks[j]
			out[i+j] = c
			if encrypt {
				feedback[j] = c // CFB feedback is the ciphertext byte
			} else {
				feedback[j] = data[i+j]
			}
		}
	}
	return out
}

// cryptParam encrypts (or decrypts) the data of the first TPM2B in params, in
// place, using a session's symmetric algorithm and a KDFa-derived key/IV
// (TPM 2.0 Part 1, §21). The KDFa key is the session value — sessionKey ‖
// authValue — with the same bound-session exception as the authorization HMAC:
// when the session is bound to the entity, authValue is omitted. The size prefix
// is left untouched; XOR is its own inverse, so encrypt only affects AES-CFB.
func cryptParam(as *authSession, authValue, nonceNewer, nonceOlder, params []byte, bound, encrypt bool) {
	if len(params) < 2 {
		return
	}
	size := int(binary.BigEndian.Uint16(params))
	if size == 0 || len(params) < 2+size {
		return
	}
	data := params[2 : 2+size]
	key := authHMACKey(as.sessionKey, authValue, bound)
	switch as.symmetric.Alg {
	case AlgXOR:
		mask := kdfa(as.authHash, key, []byte("XOR"), nonceNewer, nonceOlder, size*8)
		for i := range data {
			data[i] ^= mask[i]
		}
	case AlgAES:
		keyBits := int(as.symmetric.KeyBits)
		ki := kdfa(as.authHash, key, []byte("CFB"), nonceNewer, nonceOlder, keyBits+aes.BlockSize*8)
		copy(data, aesCFB(ki[:keyBits/8], ki[keyBits/8:keyBits/8+aes.BlockSize], data, encrypt))
	}
}

// wrapSensitive produces the TPM2B_PRIVATE for child under parent, following the
// outer-wrap construction of TPM 2.0 Part 1, §23.3 (equations 33–36): a random
// symIv encrypts the TPM2B_SENSITIVE under the parent's "STORAGE" key, and the
// "INTEGRITY" outer HMAC covers the marshaled TPM2B_IV, the ciphertext and the
// object Name. The private blob is integrityOuter ‖ symIv ‖ encSensitive, size-
// prefixed as a TPM2B_PRIVATE.
func wrapSensitive(parent *object, child *sensitive, childName []byte, rng io.Reader) []byte {
	var sw writer
	child.marshal2B(&sw) // TPM2B_SENSITIVE
	inner := wrapWithSeed(parent.public.NameAlg, parent.sensitive.SeedValue, sw.bytes(), childName, parent.public.Sym.KeyBits, rng)
	var out writer
	out.tpm2b(inner) // TPM2B_PRIVATE
	return out.bytes()
}

// unwrapPrivate reverses wrapSensitive: it verifies the outer HMAC (over the IV,
// ciphertext and childName), then decrypts and unmarshals the TPMT_SENSITIVE.
// privateContent is the inner bytes of TPM2B_PRIVATE (after the size prefix).
func unwrapPrivate(parent *object, privateContent, childName []byte) (*sensitive, bool) {
	dec, ok := unwrapWithSeed(parent.public.NameAlg, parent.sensitive.SeedValue, privateContent, childName, parent.public.Sym.KeyBits)
	if !ok {
		return nil, false
	}
	sr := newReader(dec)
	_ = sr.u16() // TPM2B_SENSITIVE outer size
	var sens sensitive
	sens.unmarshal(sr)
	if sr.err != nil {
		return nil, false
	}
	return &sens, true
}

// wrapWithSeed produces the outer-wrap TPM2B_PRIVATE content (integrity ‖ symIv ‖
// encSensitive) for a marshalled sensitive area bound to name, keyed from a seed
// (TPM 2.0 Part 1, §23.3): symKey = KDFa(seed,"STORAGE",name), a random symIv, and
// outerHMAC = HMAC(KDFa(seed,"INTEGRITY"), symIv ‖ encSensitive ‖ name). The seed
// is the parent's symmetric seed for object storage, or an asymmetrically-shared
// seed for duplication.
func wrapWithSeed(nameAlg uint16, seed, sensitive2B, name []byte, keyBits uint16, rng io.Reader) []byte {
	symIv := randBytes(rng, aes.BlockSize)
	symKey := kdfa(nameAlg, seed, []byte("STORAGE"), name, nil, int(keyBits))
	enc := aesCFB(symKey, symIv, sensitive2B, true)

	var ivb writer
	ivb.tpm2b(symIv)
	integrityKey := kdfa(nameAlg, seed, []byte("INTEGRITY"), nil, nil, hashSize(nameAlg)*8)
	integrity := hmacSum(nameAlg, integrityKey, ivb.bytes(), enc, name)

	var inner writer
	inner.tpm2b(integrity)
	inner.tpm2b(symIv)
	inner.raw(enc)
	return inner.bytes()
}

// unwrapWithSeed reverses wrapWithSeed, returning the marshalled TPM2B_SENSITIVE
// bytes (still to be unmarshalled by the caller).
func unwrapWithSeed(nameAlg uint16, seed, blob, name []byte, keyBits uint16) ([]byte, bool) {
	r := newReader(blob)
	integrity := r.tpm2b()
	symIv := r.tpm2b()
	enc := r.bytes(r.remaining())
	if r.err != nil {
		return nil, false
	}
	var ivb writer
	ivb.tpm2b(symIv)
	integrityKey := kdfa(nameAlg, seed, []byte("INTEGRITY"), nil, nil, hashSize(nameAlg)*8)
	if !hmac.Equal(hmacSum(nameAlg, integrityKey, ivb.bytes(), enc, name), integrity) {
		return nil, false
	}
	symKey := kdfa(nameAlg, seed, []byte("STORAGE"), name, nil, int(keyBits))
	return aesCFB(symKey, symIv, enc, false), true
}
