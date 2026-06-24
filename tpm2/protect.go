// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"crypto/aes"
	"crypto/hmac"
	"encoding/binary"
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
// (TPM 2.0 Part 1, §21). The size prefix is left untouched. XOR is its own
// inverse, so the encrypt flag only affects AES-CFB direction.
func cryptParam(as *authSession, authValue, nonceNewer, nonceOlder, params []byte, encrypt bool) {
	if len(params) < 2 {
		return
	}
	size := int(binary.BigEndian.Uint16(params))
	if size == 0 || len(params) < 2+size {
		return
	}
	data := params[2 : 2+size]
	key := append(append([]byte(nil), as.sessionKey...), authValue...)
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

// wrapSensitive produces the TPM2B_PRIVATE for child under parent: the integrity
// HMAC (over the encrypted sensitive and the object Name) followed by the
// AES-CFB-encrypted TPM2B_SENSITIVE. The returned bytes are the full
// size-prefixed TPM2B_PRIVATE.
func wrapSensitive(parent *object, child *sensitive, childName []byte) []byte {
	nameAlg := parent.public.NameAlg
	symSeed := parent.sensitive.SeedValue

	var sw writer
	child.marshal2B(&sw) // TPM2B_SENSITIVE
	iv := make([]byte, aes.BlockSize)
	symKey := kdfa(nameAlg, symSeed, []byte("STORAGE"), childName, nil, int(parent.public.Sym.KeyBits))
	enc := aesCFB(symKey, iv, sw.bytes(), true)

	integrityKey := kdfa(nameAlg, symSeed, []byte("INTEGRITY"), nil, nil, hashSize(nameAlg)*8)
	integrity := hmacSum(nameAlg, integrityKey, enc, childName)

	var inner writer
	inner.tpm2b(integrity) // outer integrity (TPM2B_DIGEST)
	inner.raw(enc)         // encrypted sensitive

	var out writer
	out.tpm2b(inner.bytes()) // TPM2B_PRIVATE
	return out.bytes()
}

// unwrapPrivate reverses wrapSensitive: it verifies the integrity HMAC binding
// the blob to childName, then decrypts and unmarshals the TPMT_SENSITIVE.
// privateContent is the inner bytes of TPM2B_PRIVATE (after the size prefix).
func unwrapPrivate(parent *object, privateContent, childName []byte) (*sensitive, bool) {
	nameAlg := parent.public.NameAlg
	symSeed := parent.sensitive.SeedValue

	r := newReader(privateContent)
	integrity := r.tpm2b()
	enc := r.bytes(r.remaining())
	if r.err != nil {
		return nil, false
	}

	integrityKey := kdfa(nameAlg, symSeed, []byte("INTEGRITY"), nil, nil, hashSize(nameAlg)*8)
	if !hmac.Equal(hmacSum(nameAlg, integrityKey, enc, childName), integrity) {
		return nil, false
	}

	iv := make([]byte, aes.BlockSize)
	symKey := kdfa(nameAlg, symSeed, []byte("STORAGE"), childName, nil, int(parent.public.Sym.KeyBits))
	dec := aesCFB(symKey, iv, enc, false)

	sr := newReader(dec)
	_ = sr.u16() // TPM2B_SENSITIVE outer size
	var sens sensitive
	sens.unmarshal(sr)
	if sr.err != nil {
		return nil, false
	}
	return &sens, true
}
