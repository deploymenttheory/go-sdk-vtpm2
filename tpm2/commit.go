// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import "math/big"

// This file implements the EC commit / ECDAA / two-phase ECDH commands of Phase 7:
// TPM2_EC_Ephemeral, TPM2_Commit and TPM2_ZGen_2Phase. They share a commit table
// that holds the ephemeral private scalars the TPM generates, recoverable by the
// 16-bit counter returned to the caller (TPM 2.0 Part 1, §C.2).

// ecCommit is one committed ephemeral key: the private scalar and its curve.
type ecCommit struct {
	scalar *big.Int
	curve  uint16
}

// commitStore records an ephemeral scalar and returns its counter, advancing the
// commit count.
func (t *TPM) commitStore(scalar *big.Int, curveID uint16) uint16 {
	if t.committed == nil {
		t.committed = make(map[uint16]*ecCommit)
	}
	c := uint16(t.commitCount)
	t.committed[c] = &ecCommit{scalar: scalar, curve: curveID}
	t.commitCount++
	return c
}

// pointBytes returns the fixed-width X and Y coordinate buffers for a point.
func pointBytes(x, y *big.Int, size int) (px, py []byte) {
	return padLeft(x.Bytes(), size), padLeft(y.Bytes(), size)
}

// cmdECEphemeral implements TPM2_EC_Ephemeral (Part 3, §14.7): generate an
// ephemeral key Q = [r]G and return Q with the counter that regenerates r.
func (t *TPM) cmdECEphemeral(tag uint16, r *reader) []byte {
	var sessions int
	if tag == TPMSTSessions {
		s, ok := readAuthArea(r)
		if !ok {
			return errorResponse(RCAuthSize)
		}
		sessions = len(s)
	}
	curveID := r.u16()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	curve := curveFor(curveID)
	if curve == nil {
		return errorResponse(withParam(RCCurve, 1))
	}
	size := (curve.Params().BitSize + 7) / 8
	scalar, ok := deriveEphemeralScalar(t.rand, curve.Params().N, size)
	if !ok {
		return errorResponse(RCNoResult)
	}
	qx, qy := curve.ScalarBaseMult(scalar.Bytes())
	counter := t.commitStore(scalar, curveID)

	var w writer
	px, py := pointBytes(qx, qy, size)
	writeECCPoint(&w, px, py) // Q
	w.u16(counter)
	return successResponse(w.bytes(), sessions)
}

// cmdCommit implements TPM2_Commit (Part 3, §19.2): the first part of an ECC
// anonymous signature. It returns E = [r]P1 and, when a second base point is
// supplied via (s2, y2), K = [d](x2,y2) and L = [r](x2,y2).
//
// Note: the spec restricts signHandle to a key with an anonymous (ECDAA) scheme
// and derives x2 from s2 by the Part 1 hash-to-point method; this emulator accepts
// any ECC key and derives x2 = OS2IP(s2) mod p — sufficient for the point algebra,
// not byte-identical to a hardware TPM's ECDAA base point.
func (t *TPM) cmdCommit(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCCommit, 1, r) // @signHandle
	if errResp != nil {
		return errResp
	}
	p1X, p1Y := readECCPoint(r)
	s2 := r.tpm2b()
	y2 := r.tpm2b()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if len(s2) != 0 && len(y2) == 0 {
		return errorResponse(withParam(RCSize, 3)) // s2 present requires y2
	}
	key, ok := t.objects.get(ac.handles[0])
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if key.public.Type != AlgECC {
		return errorResponse(withHandle(RCKey, 1))
	}
	if errResp := t.authorizeObject(ac, 0, key); errResp != nil {
		return errResp
	}
	curve := curveFor(key.public.Curve)
	if curve == nil {
		return errorResponse(RCCurve)
	}
	size := (curve.Params().BitSize + 7) / 8
	scalar, ok := deriveEphemeralScalar(t.rand, curve.Params().N, size)
	if !ok {
		return errorResponse(RCNoResult)
	}

	emptyX, emptyY := []byte(nil), []byte(nil)
	kX, kY, lX, lY, eX, eY := emptyX, emptyY, emptyX, emptyY, emptyX, emptyY

	if len(p1X) != 0 || len(p1Y) != 0 {
		px, py := new(big.Int).SetBytes(p1X), new(big.Int).SetBytes(p1Y)
		if !curve.IsOnCurve(px, py) { //nolint:staticcheck
			return errorResponse(withParam(RCECCPoint, 1))
		}
		ex, ey := curve.ScalarMult(px, py, scalar.Bytes()) //nolint:staticcheck
		eX, eY = pointBytes(ex, ey, size)
	}
	if len(s2) != 0 {
		x2 := new(big.Int).Mod(new(big.Int).SetBytes(s2), curve.Params().P)
		y2i := new(big.Int).SetBytes(y2)
		if !curve.IsOnCurve(x2, y2i) { //nolint:staticcheck
			return errorResponse(withParam(RCECCPoint, 2))
		}
		kx, ky := curve.ScalarMult(x2, y2i, key.sensitive.Secret) //nolint:staticcheck
		kX, kY = pointBytes(kx, ky, size)
		lx, ly := curve.ScalarMult(x2, y2i, scalar.Bytes()) //nolint:staticcheck
		lX, lY = pointBytes(lx, ly, size)
	}
	counter := t.commitStore(scalar, key.public.Curve)

	var w writer
	writeECCPoint(&w, kX, kY) // K
	writeECCPoint(&w, lX, lY) // L
	writeECCPoint(&w, eX, eY) // E
	w.u16(counter)
	return t.authResponse(ac, nil, w.bytes())
}

// cmdZGen2Phase implements TPM2_ZGen_2Phase (Part 3, §14.6): two-phase ECDH using
// keyA's static private and the ephemeral scalar from a prior TPM2_EC_Ephemeral.
// For TPM_ALG_ECDH, outZ1 = Zs = [d_s]·QsB and outZ2 = Ze = [d_e]·QeB.
func (t *TPM) cmdZGen2Phase(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCZGen2Phase, 1, r) // @keyA
	if errResp != nil {
		return errResp
	}
	qsX, qsY := readECCPoint(r) // inQsB
	qeX, qeY := readECCPoint(r) // inQeB
	inScheme := r.u16()
	counter := r.u16()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if inScheme != AlgECDH {
		return errorResponse(withParam(RCScheme, 3)) // only ECDH supported (not ECMQV/SM2)
	}
	key, ok := t.objects.get(ac.handles[0])
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if key.public.Type != AlgECC {
		return errorResponse(withHandle(RCKey, 1))
	}
	if errResp := t.authorizeObject(ac, 0, key); errResp != nil {
		return errResp
	}
	commit, ok := t.committed[counter]
	if !ok || commit.curve != key.public.Curve {
		return errorResponse(withParam(RCValue, 4)) // no committed ephemeral for counter
	}
	curve := curveFor(key.public.Curve)
	if curve == nil {
		return errorResponse(RCCurve)
	}
	size := (curve.Params().BitSize + 7) / 8
	qsx, qsy := new(big.Int).SetBytes(qsX), new(big.Int).SetBytes(qsY)
	qex, qey := new(big.Int).SetBytes(qeX), new(big.Int).SetBytes(qeY)
	if !curve.IsOnCurve(qsx, qsy) { //nolint:staticcheck
		return errorResponse(withParam(RCECCPoint, 1))
	}
	if !curve.IsOnCurve(qex, qey) { //nolint:staticcheck
		return errorResponse(withParam(RCECCPoint, 2))
	}
	z1x, z1y := curve.ScalarMult(qsx, qsy, key.sensitive.Secret)  //nolint:staticcheck
	z2x, z2y := curve.ScalarMult(qex, qey, commit.scalar.Bytes()) //nolint:staticcheck
	delete(t.committed, counter)                                  // a committed value is consumed by use

	var w writer
	z1pX, z1pY := pointBytes(z1x, z1y, size)
	z2pX, z2pY := pointBytes(z2x, z2y, size)
	writeECCPoint(&w, z1pX, z1pY) // outZ1 = Zs
	writeECCPoint(&w, z2pX, z2pY) // outZ2 = Ze
	return t.authResponse(ac, nil, w.bytes())
}
