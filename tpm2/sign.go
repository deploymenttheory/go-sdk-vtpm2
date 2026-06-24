// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"math/big"
)

// This file implements signing, verification and hashing (TPM 2.0 Part 3, §20).
// Signatures are produced/consumed as TPMT_SIGNATURE.

// signWith signs digest with object o and returns a marshalled TPMT_SIGNATURE.
// sigAlg/hashAlg come from the key's scheme (or the caller's inScheme).
func (t *TPM) signWith(o *object, sigAlg, hashAlg uint16, digest []byte) ([]byte, []byte) {
	ch, ok := cryptoHash(hashAlg)
	if !ok {
		return nil, errorResponse(withParam(RCValue, 2))
	}
	var w writer
	switch o.public.Type {
	case AlgRSA:
		priv := rsaPrivateKey(o.public.Unique, o.sensitive.Secret, o.public.Exp)
		var sig []byte
		var err error
		switch sigAlg {
		case AlgRSAPSS:
			sig, err = rsa.SignPSS(t.rand, priv, ch, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: ch})
		default: // RSASSA (PKCS#1 v1.5) is the default RSA signing scheme
			sigAlg = AlgRSASSA
			sig, err = rsa.SignPKCS1v15(t.rand, priv, ch, digest)
		}
		if err != nil {
			return nil, errorResponse(RCValue)
		}
		w.u16(sigAlg)
		w.u16(hashAlg)
		w.tpm2b(sig)
	case AlgECC:
		curve := curveFor(o.public.Curve)
		if curve == nil {
			return nil, errorResponse(RCValue)
		}
		priv := eccPrivateKey(curve, o.public.Curve, o.sensitive.Secret)
		rr, ss, err := ecdsa.Sign(t.rand, priv, digest)
		if err != nil {
			return nil, errorResponse(RCValue)
		}
		n := (curve.Params().BitSize + 7) / 8
		w.u16(AlgECDSA)
		w.u16(hashAlg)
		w.tpm2b(padLeft(rr.Bytes(), n))
		w.tpm2b(padLeft(ss.Bytes(), n))
	default:
		return nil, errorResponse(withHandle(RCType, 1))
	}
	return w.bytes(), nil
}

// cmdSign implements TPM2_Sign.
func (t *TPM) cmdSign(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCSign, 1, r) // keyHandle
	if errResp != nil {
		return errResp
	}
	digest := r.tpm2b()
	scheme := r.u16() // inScheme (TPMT_SIG_SCHEME)
	var schemeHash uint16
	if scheme != AlgNull {
		schemeHash = r.u16()
	}
	_ = r.u16()           // validation (TPMT_TK_HASHCHECK): tag
	tkHier := r.u32()     // ticket hierarchy
	tkDigest := r.tpm2b() // ticket digest
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	key, ok := t.objects.get(ac.handles[0])
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if key.public.Attrs&ObjSign == 0 {
		return errorResponse(withHandle(RCAttributes, 1)) // not a signing key
	}
	// A restricted signing key may only sign a digest the TPM itself produced,
	// proven by a valid TPMT_TK_HASHCHECK over that digest (TPM 2.0 Part 3, §20.1).
	if key.public.Attrs&ObjRestricted != 0 {
		proof := t.hierarchyProof(tkHier)
		want := hmacSum(AlgSHA256, proof, be16(STHashCheck), digest)
		if tkHier == RHNull || proof == nil || !hmac.Equal(tkDigest, want) {
			return errorResponse(RCTicket)
		}
	}
	if errResp := t.authorizeObject(ac, 0, key); errResp != nil {
		return errResp
	}
	// The key's own scheme takes precedence; otherwise use the caller's inScheme.
	sigAlg, hashAlg := key.public.Scheme.Scheme, key.public.Scheme.HashAlg
	if sigAlg == AlgNull {
		sigAlg, hashAlg = scheme, schemeHash
	}
	sig, errResp := t.signWith(key, sigAlg, hashAlg, digest)
	if errResp != nil {
		return errResp
	}
	return t.authResponse(ac, nil, sig)
}

// verifySignature reads the TPMU_SIGNATURE for key's type from r and verifies it
// over digest, returning false on any parse or verification failure. Shared by
// TPM2_VerifySignature and TPM2_PolicySigned.
func verifySignature(key *object, sigAlg, hashAlg uint16, digest []byte, r *reader) bool {
	ch, hashOK := cryptoHash(hashAlg)
	switch key.public.Type {
	case AlgRSA:
		sig := r.tpm2b()
		if r.err != nil || !hashOK {
			return false
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(key.public.Unique), E: rsaExp(key.public.Exp)}
		if sigAlg == AlgRSAPSS {
			return rsa.VerifyPSS(pub, ch, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: ch}) == nil
		}
		return rsa.VerifyPKCS1v15(pub, ch, digest, sig) == nil
	case AlgECC:
		rb := r.tpm2b()
		sb := r.tpm2b()
		curve := curveFor(key.public.Curve)
		if r.err != nil || curve == nil {
			return false
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(key.public.UniqueX), Y: new(big.Int).SetBytes(key.public.UniqueY)}
		return ecdsa.Verify(pub, digest, new(big.Int).SetBytes(rb), new(big.Int).SetBytes(sb))
	}
	return false
}

// cmdVerifySignature implements TPM2_VerifySignature (no authorization).
func (t *TPM) cmdVerifySignature(r *reader) []byte {
	keyHandle := r.u32()
	digest := r.tpm2b()
	sigAlg := r.u16()
	hashAlg := r.u16()
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
	if !verifySignature(key, sigAlg, hashAlg, digest, r) {
		if r.err != nil {
			return errorResponse(RCInsufficient)
		}
		return errorResponse(RCSignature)
	}
	// TPMT_TK_VERIFIED, keyed by the NULL-hierarchy proof (the verification key is
	// not in a persistent hierarchy here). HMAC(proof, TPM_ST_VERIFIED ‖ digest).
	var w writer
	w.u16(STVerified)
	w.u32(RHNull)
	w.tpm2b(hmacSum(AlgSHA256, t.hierarchyProof(RHNull), be16(STVerified), digest))
	return successResponse(w.bytes(), 0)
}

// cmdHash implements TPM2_Hash (no authorization).
func (t *TPM) cmdHash(r *reader) []byte {
	data := r.tpm2b()
	hashAlg := r.u16()
	tkHierarchy := r.u32() // hierarchy for the validation ticket
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if _, ok := cryptoHash(hashAlg); !ok {
		return errorResponse(withParam(RCValue, 2))
	}
	digest := hashSum(hashAlg, data)
	var w writer
	w.tpm2b(digest) // outHash
	// TPMT_TK_HASHCHECK (TPM 2.0 Part 3, §15.4): a valid ticket only when a real
	// hierarchy is requested AND the data is "safe to sign" — i.e. it does not begin
	// with TPM_GENERATED_VALUE, which would let a caller forge a TPM-produced
	// structure. Otherwise a NULL ticket (hierarchy NULL, empty digest).
	safe := !bytes.HasPrefix(data, be32(tpmGeneratedValue))
	proof := t.hierarchyProof(tkHierarchy)
	if tkHierarchy != RHNull && safe && proof != nil {
		w.u16(STHashCheck)
		w.u32(tkHierarchy)
		w.tpm2b(hmacSum(AlgSHA256, proof, be16(STHashCheck), digest))
	} else {
		w.u16(STHashCheck)
		w.u32(RHNull)
		w.tpm2b(nil)
	}
	return successResponse(w.bytes(), 0)
}

// rsaExp returns the effective RSA public exponent (0 means the default).
func rsaExp(e uint32) int {
	if e == 0 {
		return rsaExponent
	}
	return int(e)
}
