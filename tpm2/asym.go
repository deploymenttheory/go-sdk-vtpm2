// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"crypto/rsa"
	"io"
	"math/big"
)

// This file implements the asymmetric primitive commands (TPM 2.0 Part 3, §14
// RSA and §19 ECDH, plus §27 ECC_Parameters): RSA encrypt/decrypt, ECDH key
// generation and Z-point computation, and ECC curve-parameter retrieval. All
// cryptography is from the Go standard library.

// resolveRSAScheme picks the padding scheme: the key's own scheme wins; otherwise
// the caller's inScheme is used (TPM 2.0 Part 3, §14.2/§14.3).
func resolveRSAScheme(keyScheme hashScheme, inScheme, inHash uint16) (scheme, hash uint16) {
	if keyScheme.Scheme != AlgNull {
		return keyScheme.Scheme, keyScheme.HashAlg
	}
	return inScheme, inHash
}

// readRSAScheme reads a TPMT_RSA_DECRYPT: the scheme selector plus a hash only
// for OAEP (TPMS_ENC_SCHEME_OAEP). RSAES (PKCS#1 v1.5) and NULL carry no hash.
func readRSAScheme(r *reader) (scheme, hash uint16) {
	scheme = r.u16()
	if scheme == AlgOAEP {
		hash = r.u16()
	}
	return scheme, hash
}

// cmdRSAEncrypt implements TPM2_RSA_Encrypt (Part 3, §14.2): pad and encrypt
// message with the public part of an RSA key. No authorization — it is a
// public-key operation.
func (t *TPM) cmdRSAEncrypt(r *reader) []byte {
	keyHandle := r.u32()
	message := r.tpm2b()
	inScheme, inHash := readRSAScheme(r)
	label := r.tpm2b()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	key, ok := t.objects.get(keyHandle)
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if key.public.Type != AlgRSA {
		return errorResponse(withHandle(RCType, 1))
	}
	if key.public.Attrs&ObjDecrypt == 0 {
		return errorResponse(withHandle(RCAttributes, 1))
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(key.public.Unique), E: rsaExp(key.public.Exp)}
	scheme, hash := resolveRSAScheme(key.public.Scheme, inScheme, inHash)
	out, errResp := rsaPad(pub, scheme, hash, message, label, t.rand)
	if errResp != nil {
		return errResp
	}
	var w writer
	w.tpm2b(out) // outData (TPM2B_PUBLIC_KEY_RSA)
	return successResponse(w.bytes(), 0)
}

// cmdRSADecrypt implements TPM2_RSA_Decrypt (Part 3, §14.3): decrypt cipherText
// with the private key. Requires authorization (private-key operation).
func (t *TPM) cmdRSADecrypt(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCRSADecrypt, 1, r)
	if errResp != nil {
		return errResp
	}
	t.decryptCommandParams(ac, r)
	cipherText := r.tpm2b()
	inScheme, inHash := readRSAScheme(r)
	label := r.tpm2b()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	key, ok := t.objects.get(ac.handles[0])
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if key.public.Type != AlgRSA {
		return errorResponse(withHandle(RCType, 1))
	}
	if key.public.Attrs&ObjDecrypt == 0 || key.public.Attrs&ObjRestricted != 0 {
		return errorResponse(withHandle(RCAttributes, 1)) // unrestricted decryption key only
	}
	if errResp := t.authorizeObject(ac, 0, key); errResp != nil {
		return errResp
	}
	priv := rsaPrivateKey(key.public.Unique, key.sensitive.Secret, key.public.Exp)
	scheme, hash := resolveRSAScheme(key.public.Scheme, inScheme, inHash)
	out, errResp := rsaUnpad(priv, scheme, hash, cipherText, label, t.rand)
	if errResp != nil {
		return errResp
	}
	var w writer
	w.tpm2b(out) // message (TPM2B_PUBLIC_KEY_RSA)
	return t.authResponse(ac, nil, w.bytes())
}

// rsaPad encrypts message under pub using the TPM padding scheme: OAEP (with the
// null-terminated label), RSAES (PKCS#1 v1.5), or NULL (raw RSAEP).
func rsaPad(pub *rsa.PublicKey, scheme, hash uint16, message, label []byte, rng io.Reader) ([]byte, []byte) {
	switch scheme {
	case AlgOAEP:
		h := newHash(hash)
		if h == nil {
			return nil, errorResponse(withParam(RCScheme, 1))
		}
		out, err := rsa.EncryptOAEP(h, rng, pub, message, oaepLabel(label))
		if err != nil {
			return nil, errorResponse(withParam(RCValue, 2))
		}
		return out, nil
	case AlgRSAES:
		out, err := rsa.EncryptPKCS1v15(rng, pub, message) //nolint:staticcheck // RSAES (PKCS#1 v1.5) is a mandated TPM scheme
		if err != nil {
			return nil, errorResponse(withParam(RCValue, 2))
		}
		return out, nil
	case AlgNull:
		// Raw RSAEP: message^e mod n, left-padded to the modulus size.
		m := new(big.Int).SetBytes(message)
		if m.Cmp(pub.N) >= 0 {
			return nil, errorResponse(withParam(RCValue, 2))
		}
		c := new(big.Int).Exp(m, big.NewInt(int64(pub.E)), pub.N)
		return padLeft(c.Bytes(), (pub.N.BitLen()+7)/8), nil
	}
	return nil, errorResponse(withParam(RCScheme, 1))
}

// rsaUnpad reverses rsaPad with the private key.
func rsaUnpad(priv *rsa.PrivateKey, scheme, hash uint16, cipherText, label []byte, rng io.Reader) ([]byte, []byte) {
	switch scheme {
	case AlgOAEP:
		h := newHash(hash)
		if h == nil {
			return nil, errorResponse(withParam(RCScheme, 1))
		}
		out, err := rsa.DecryptOAEP(h, rng, priv, cipherText, oaepLabel(label))
		if err != nil {
			return nil, errorResponse(withParam(RCValue, 1))
		}
		return out, nil
	case AlgRSAES:
		out, err := rsa.DecryptPKCS1v15(rng, priv, cipherText) //nolint:staticcheck // RSAES (PKCS#1 v1.5) is a mandated TPM scheme
		if err != nil {
			return nil, errorResponse(withParam(RCValue, 1))
		}
		return out, nil
	case AlgNull:
		c := new(big.Int).SetBytes(cipherText)
		if c.Cmp(priv.N) >= 0 {
			return nil, errorResponse(withParam(RCValue, 1))
		}
		m := new(big.Int).Exp(c, priv.D, priv.N)
		return padLeft(m.Bytes(), (priv.N.BitLen()+7)/8), nil
	}
	return nil, errorResponse(withParam(RCScheme, 1))
}

// oaepLabel returns the OAEP label: the TPM uses a null-terminated string, so a
// non-empty label that lacks a trailing null gets one appended.
func oaepLabel(label []byte) []byte {
	if len(label) == 0 {
		return nil
	}
	if label[len(label)-1] == 0 {
		return label
	}
	return append(append([]byte(nil), label...), 0)
}
