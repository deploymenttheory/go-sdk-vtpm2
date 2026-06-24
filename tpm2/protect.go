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
	nameAlg := parent.public.NameAlg
	symSeed := parent.sensitive.SeedValue

	var sw writer
	child.marshal2B(&sw) // TPM2B_SENSITIVE

	symIv := randBytes(rng, aes.BlockSize) // symIv := bits from the RNG (eq. before 34)
	symKey := kdfa(nameAlg, symSeed, []byte("STORAGE"), childName, nil, int(parent.public.Sym.KeyBits))
	enc := aesCFB(symKey, symIv, sw.bytes(), true) // encSensitive (eq. 34)

	// outerHMAC := HMAC(HMACkey, symIv ‖ encSensitive ‖ name), symIv a TPM2B_IV (eq. 36).
	var ivb writer
	ivb.tpm2b(symIv)
	integrityKey := kdfa(nameAlg, symSeed, []byte("INTEGRITY"), nil, nil, hashSize(nameAlg)*8)
	integrity := hmacSum(nameAlg, integrityKey, ivb.bytes(), enc, childName)

	var inner writer
	inner.tpm2b(integrity) // outer integrity (TPM2B_DIGEST)
	inner.tpm2b(symIv)     // symmetric IV (TPM2B_IV)
	inner.raw(enc)         // encrypted sensitive

	var out writer
	out.tpm2b(inner.bytes()) // TPM2B_PRIVATE
	return out.bytes()
}

// unwrapPrivate reverses wrapSensitive: it verifies the outer HMAC (over the IV,
// ciphertext and childName), then decrypts and unmarshals the TPMT_SENSITIVE.
// privateContent is the inner bytes of TPM2B_PRIVATE (after the size prefix).
func unwrapPrivate(parent *object, privateContent, childName []byte) (*sensitive, bool) {
	nameAlg := parent.public.NameAlg
	symSeed := parent.sensitive.SeedValue

	r := newReader(privateContent)
	integrity := r.tpm2b()
	symIv := r.tpm2b()
	enc := r.bytes(r.remaining())
	if r.err != nil {
		return nil, false
	}

	var ivb writer
	ivb.tpm2b(symIv)
	integrityKey := kdfa(nameAlg, symSeed, []byte("INTEGRITY"), nil, nil, hashSize(nameAlg)*8)
	if !hmac.Equal(hmacSum(nameAlg, integrityKey, ivb.bytes(), enc, childName), integrity) {
		return nil, false
	}

	symKey := kdfa(nameAlg, symSeed, []byte("STORAGE"), childName, nil, int(parent.public.Sym.KeyBits))
	dec := aesCFB(symKey, symIv, enc, false)

	sr := newReader(dec)
	_ = sr.u16() // TPM2B_SENSITIVE outer size
	var sens sensitive
	sens.unmarshal(sr)
	if sr.err != nil {
		return nil, false
	}
	return &sens, true
}
