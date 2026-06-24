// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

// This file adds the management/test commands of Phase 8: TPM2_IncrementalSelfTest,
// TPM2_TestParms, TPM2_SetAlgorithmSet and TPM2_PP_Commands.

// cmdIncrementalSelfTest implements TPM2_IncrementalSelfTest (Part 3, §10.3): test
// the requested algorithms. This emulator self-tests synchronously, so the
// toDoList (algorithms still untested) is always empty.
func (t *TPM) cmdIncrementalSelfTest(r *reader) []byte {
	count := r.u32() // TPML_ALG toTest
	for i := uint32(0); i < count && r.err == nil; i++ {
		_ = r.u16()
	}
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	var w writer
	w.u32(0) // toDoList: empty
	return successResponse(w.bytes(), 0)
}

// readPublicParms reads a TPMT_PUBLIC_PARMS (object type + the parameter union).
func readPublicParms(r *reader) public {
	var p public
	p.Type = r.u16()
	switch p.Type {
	case AlgKeyedHash:
		p.Scheme.unmarshal(r)
	case AlgSymCipher:
		p.Sym.unmarshal(r)
	case AlgRSA:
		p.Sym.unmarshal(r)
		p.Scheme.unmarshal(r)
		p.KeyBits = r.u16()
		p.Exp = r.u32()
	case AlgECC:
		p.Sym.unmarshal(r)
		p.Scheme.unmarshal(r)
		p.Curve = r.u16()
		p.KDF.unmarshal(r)
	default:
		if r.err == nil {
			r.err = errBadValue
		}
	}
	return p
}

// cmdTestParms implements TPM2_TestParms (Part 3, §10.4): validate that a set of
// algorithm parameters is supported, without creating an object.
func (t *TPM) cmdTestParms(r *reader) []byte {
	p := readPublicParms(r)
	if r.err != nil {
		return errorResponse(withParam(RCValue, 1))
	}
	switch p.Type {
	case AlgRSA:
		switch p.KeyBits {
		case 1024, 2048, 3072, 4096:
		default:
			return errorResponse(withParam(RCValue, 1))
		}
	case AlgECC:
		if curveFor(p.Curve) == nil {
			return errorResponse(withParam(RCCurve, 1))
		}
	case AlgSymCipher:
		if p.Sym.Alg != AlgNull && p.Sym.Alg != AlgAES {
			return errorResponse(withParam(RCValue, 1))
		}
	case AlgKeyedHash:
		// Any keyed-hash scheme (HMAC/XOR/NULL) is acceptable.
	default:
		return errorResponse(withParam(RCValue, 1))
	}
	return successResponse(nil, 0)
}

// cmdSetAlgorithmSet implements TPM2_SetAlgorithmSet (Part 3, §24.4): record the
// vendor-defined algorithm set. Authorized by the platform hierarchy.
func (t *TPM) cmdSetAlgorithmSet(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCSetAlgorithmSet, 1, r) // @authHandle (platform)
	if errResp != nil {
		return errResp
	}
	algorithmSet := r.u32()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if ac.handles[0] != RHPlatform {
		return errorResponse(withHandle(RCValue, 1))
	}
	if errResp := t.authorizeHierarchy(ac, RHPlatform); errResp != nil {
		return errResp
	}
	t.algorithmSet = algorithmSet
	return t.authResponse(ac, nil, nil)
}

// cmdPPCommands implements TPM2_PP_Commands (Part 3, §24.3): change the set of
// commands that require physical-presence confirmation. Platform-authorized.
func (t *TPM) cmdPPCommands(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCPPCommands, 1, r) // @auth (platform)
	if errResp != nil {
		return errResp
	}
	setList := readCCList(r)
	clearList := readCCList(r)
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if ac.handles[0] != RHPlatform {
		return errorResponse(withHandle(RCValue, 1))
	}
	if errResp := t.authorizeHierarchy(ac, RHPlatform); errResp != nil {
		return errResp
	}
	if t.ppRequired == nil {
		t.ppRequired = make(map[uint32]bool)
	}
	for _, cc := range setList {
		t.ppRequired[cc] = true
	}
	for _, cc := range clearList {
		delete(t.ppRequired, cc)
	}
	return t.authResponse(ac, nil, nil)
}
