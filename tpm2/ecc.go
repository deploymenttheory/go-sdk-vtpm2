// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"io"
	"math/big"
)

// This file implements the ECC primitive commands: TPM2_ECDH_KeyGen and
// TPM2_ECDH_ZGen (TPM 2.0 Part 3, §19) and TPM2_ECC_Parameters (§27.2). The full
// elliptic-curve point operations use crypto/elliptic via curveFor; crypto/ecdh
// returns only the shared X coordinate, but these commands return full points.

// writeECCPoint marshals a TPM2B_ECC_POINT: a size-prefixed TPMS_ECC_POINT whose
// X and Y are each a TPM2B_ECC_PARAMETER.
func writeECCPoint(w *writer, x, y []byte) {
	var inner writer
	inner.tpm2b(x)
	inner.tpm2b(y)
	w.tpm2b(inner.bytes())
}

// readECCPoint reads a TPM2B_ECC_POINT, returning the X and Y coordinates.
func readECCPoint(r *reader) (x, y []byte) {
	_ = r.u16() // TPM2B_ECC_POINT size prefix
	x = r.tpm2b()
	y = r.tpm2b()
	return x, y
}

// deriveEphemeralScalar draws a scalar in [1, n-1] from rng for the curve.
func deriveEphemeralScalar(rng io.Reader, n *big.Int, size int) (*big.Int, bool) {
	buf := make([]byte, size)
	if _, err := io.ReadFull(rng, buf); err != nil {
		return nil, false
	}
	k := new(big.Int).SetBytes(buf)
	k.Mod(k, new(big.Int).Sub(n, big.NewInt(1)))
	k.Add(k, big.NewInt(1))
	return k, true
}

// cmdECDHKeyGen implements TPM2_ECDH_KeyGen (Part 3, §19.1): create an ephemeral
// key pair (de, Qe) for the loaded key's curve and return zPoint = [de]Qs and the
// ephemeral public point pubPoint = [de]G. No authorization (uses the public key).
func (t *TPM) cmdECDHKeyGen(r *reader) []byte {
	keyHandle := r.u32()
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
	curve := curveFor(key.public.Curve)
	if curve == nil {
		return errorResponse(withHandle(RCValue, 1))
	}
	cp := curve.Params()
	n := (cp.BitSize + 7) / 8
	de, ok := deriveEphemeralScalar(t.rand, cp.N, n)
	if !ok {
		return errorResponse(RCFailure)
	}
	qeX, qeY := curve.ScalarBaseMult(de.Bytes())                                                                                 //nolint:staticcheck // full point needed; crypto/ecdh returns only X
	pX, pY := curve.ScalarMult(new(big.Int).SetBytes(key.public.UniqueX), new(big.Int).SetBytes(key.public.UniqueY), de.Bytes()) //nolint:staticcheck
	var w writer
	writeECCPoint(&w, padLeft(pX.Bytes(), n), padLeft(pY.Bytes(), n))   // zPoint
	writeECCPoint(&w, padLeft(qeX.Bytes(), n), padLeft(qeY.Bytes(), n)) // pubPoint
	return successResponse(w.bytes(), 0)
}

// cmdECDHZGen implements TPM2_ECDH_ZGen (Part 3, §19.2): compute outPoint =
// [ds]inPoint with the key's private scalar. Requires authorization.
func (t *TPM) cmdECDHZGen(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCECDHZGen, 1, r)
	if errResp != nil {
		return errResp
	}
	inX, inY := readECCPoint(r)
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
	curve := curveFor(key.public.Curve)
	if curve == nil {
		return errorResponse(RCValue)
	}
	x, y := new(big.Int).SetBytes(inX), new(big.Int).SetBytes(inY)
	if !curve.IsOnCurve(x, y) { //nolint:staticcheck // validating the supplied point
		return errorResponse(withParam(RCECCPoint, 1)) // inPoint not on the key's curve
	}
	pX, pY := curve.ScalarMult(x, y, key.sensitive.Secret) //nolint:staticcheck
	n := (curve.Params().BitSize + 7) / 8
	var w writer
	writeECCPoint(&w, padLeft(pX.Bytes(), n), padLeft(pY.Bytes(), n)) // outPoint
	return t.authResponse(ac, nil, w.bytes())
}

// cmdECCParameters implements TPM2_ECC_Parameters (Part 3, §27.2): return the
// TPMS_ALGORITHM_DETAIL_ECC for a curve. No authorization, no handle.
func (t *TPM) cmdECCParameters(r *reader) []byte {
	curveID := r.u16()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	curve := curveFor(curveID)
	if curve == nil {
		return errorResponse(withParam(RCValue, 1)) // unsupported curve
	}
	cp := curve.Params()
	n := (cp.BitSize + 7) / 8
	// NIST short-Weierstrass curves have a ≡ -3 (mod p).
	a := new(big.Int).Mod(new(big.Int).Sub(cp.P, big.NewInt(3)), cp.P)

	var w writer
	w.u16(curveID)                     // curveID
	w.u16(uint16(cp.BitSize))          // keySize (bits)
	w.u16(AlgNull)                     // kdf (TPMT_KDF_SCHEME = NULL)
	w.u16(AlgNull)                     // sign (TPMT_ECC_SCHEME = NULL)
	w.tpm2b(padLeft(cp.P.Bytes(), n))  // p — field prime
	w.tpm2b(padLeft(a.Bytes(), n))     // a — curve coefficient
	w.tpm2b(padLeft(cp.B.Bytes(), n))  // b — curve coefficient
	w.tpm2b(padLeft(cp.Gx.Bytes(), n)) // gX — generator X
	w.tpm2b(padLeft(cp.Gy.Bytes(), n)) // gY — generator Y
	w.tpm2b(padLeft(cp.N.Bytes(), n))  // n — group order
	w.tpm2b([]byte{0x01})              // h — cofactor (1 for the NIST prime curves)
	return successResponse(w.bytes(), 0)
}
