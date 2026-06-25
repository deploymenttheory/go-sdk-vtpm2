// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"crypto/hmac"
	"math/big"
)

// This file implements the ECC (SM2-style) encryption commands (TPM 2.0 Part 3,
// §14): TPM2_ECC_Encrypt and TPM2_ECC_Decrypt. A message is encrypted to an ECC
// public key using an ephemeral ECDH point C1, a KDFe-derived key stream XORed
// with the plaintext (C2) and an integrity digest C3 over the shared point and
// plaintext.

// xorBytes returns data XOR the leading bytes of stream.
func xorBytes(data, stream []byte) []byte {
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ stream[i]
	}
	return out
}

// eccKDFHash resolves the hash for the ECC encryption KDF from the key's own KDF
// scheme or the caller-supplied inScheme.
func eccKDFHash(key *object, schemeHash uint16) (uint16, bool) {
	if key.public.KDF.Scheme != AlgNull {
		schemeHash = key.public.KDF.HashAlg
	}
	_, ok := cryptoHash(schemeHash)
	return schemeHash, ok
}

// cmdECCEncrypt implements TPM2_ECC_Encrypt (Part 3, §14.1). No authorization (a
// public-key operation).
func (t *TPM) cmdECCEncrypt(r *reader) []byte {
	keyHandle := r.u32()
	plainText := r.tpm2b()
	kdfScheme := r.u16()
	var kdfHash uint16
	if kdfScheme != AlgNull {
		kdfHash = r.u16()
	}
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	key, ok := t.objects.get(keyHandle)
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if key.public.Type != AlgECC {
		return errorResponse(withHandle(RCType, 1))
	}
	hashAlg, ok := eccKDFHash(key, kdfHash)
	if !ok {
		return errorResponse(RCScheme)
	}
	curve := curveFor(key.public.Curve)
	if curve == nil {
		return errorResponse(RCCurve)
	}
	size := (curve.Params().BitSize + 7) / 8

	k, ok := deriveEphemeralScalar(t.rand, curve.Params().N, size)
	if !ok {
		return errorResponse(RCNoResult)
	}
	c1x, c1y := curve.ScalarBaseMult(k.Bytes()) //nolint:staticcheck
	pubx := new(big.Int).SetBytes(key.public.UniqueX)
	puby := new(big.Int).SetBytes(key.public.UniqueY)
	zx, zy := curve.ScalarMult(pubx, puby, k.Bytes()) //nolint:staticcheck

	zxB, zyB := padLeft(zx.Bytes(), size), padLeft(zy.Bytes(), size)
	stream := kdfe(hashAlg, zxB, []byte("SM2"), padLeft(c1x.Bytes(), size), padLeft(key.public.UniqueX, size), len(plainText)*8)
	c2 := xorBytes(plainText, stream)
	c3 := hashSum(hashAlg, zxB, plainText, zyB)

	var w writer
	writeECCPoint(&w, padLeft(c1x.Bytes(), size), padLeft(c1y.Bytes(), size)) // C1
	w.tpm2b(c2)                                                               // C2
	w.tpm2b(c3)                                                               // C3
	return successResponse(w.bytes(), 0)
}

// cmdECCDecrypt implements TPM2_ECC_Decrypt (Part 3, §14.2). Authorized by the
// private key.
func (t *TPM) cmdECCDecrypt(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCECCDecrypt, 1, r) // @keyHandle
	if errResp != nil {
		return errResp
	}
	c1x, c1y := readECCPoint(r)
	c2 := r.tpm2b()
	c3 := r.tpm2b()
	kdfScheme := r.u16()
	var kdfHash uint16
	if kdfScheme != AlgNull {
		kdfHash = r.u16()
	}
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	key, ok := t.objects.get(ac.handles[0])
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if key.public.Type != AlgECC {
		return errorResponse(withHandle(RCType, 1))
	}
	if errResp := t.authorizeObject(ac, 0, key); errResp != nil {
		return errResp
	}
	hashAlg, ok := eccKDFHash(key, kdfHash)
	if !ok {
		return errorResponse(RCScheme)
	}
	curve := curveFor(key.public.Curve)
	if curve == nil {
		return errorResponse(RCCurve)
	}
	size := (curve.Params().BitSize + 7) / 8

	c1xi, c1yi := new(big.Int).SetBytes(c1x), new(big.Int).SetBytes(c1y)
	if !curve.IsOnCurve(c1xi, c1yi) { //nolint:staticcheck
		return errorResponse(withParam(RCECCPoint, 1))
	}
	zx, zy := curve.ScalarMult(c1xi, c1yi, key.sensitive.Secret) //nolint:staticcheck

	zxB, zyB := padLeft(zx.Bytes(), size), padLeft(zy.Bytes(), size)
	stream := kdfe(hashAlg, zxB, []byte("SM2"), padLeft(c1x, size), padLeft(key.public.UniqueX, size), len(c2)*8)
	plain := xorBytes(c2, stream)
	if !hmac.Equal(hashSum(hashAlg, zxB, plain, zyB), c3) {
		return errorResponse(withParam(RCValue, 3)) // C3 integrity check failed
	}

	var w writer
	w.tpm2b(plain) // plainText
	return t.authResponse(ac, nil, w.bytes())
}
