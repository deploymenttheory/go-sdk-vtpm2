// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"math/big"
)

// This file implements the comparison-based policy assertions (TPM 2.0 Part 3,
// §23.6 PolicyCounterTimer and §23.8 PolicyNV). Both fold
// args = H(operandB ‖ offset ‖ operation) into the policy digest and, for a real
// session, evaluate the TPM_EO comparison against a value read from the TPM.

// signedBig interprets x as a two's-complement signed integer of len(x) octets.
func signedBig(x []byte) *big.Int {
	v := new(big.Int).SetBytes(x)
	if len(x) > 0 && x[0]&0x80 != 0 {
		v.Sub(v, new(big.Int).Lsh(big.NewInt(1), uint(8*len(x))))
	}
	return v
}

// policyCompare evaluates a TPM_EO comparison: does value satisfy operation
// relative to operandB? value and operandB are equal-length octet strings
// (TPM 2.0 Part 2, TPM_EO).
func policyCompare(operation uint16, value, operandB []byte) bool {
	u := func(b []byte) *big.Int { return new(big.Int).SetBytes(b) }
	switch operation {
	case 0x0000: // EQ
		return bytes.Equal(value, operandB)
	case 0x0001: // NEQ
		return !bytes.Equal(value, operandB)
	case 0x0002: // SIGNED_GT
		return signedBig(value).Cmp(signedBig(operandB)) > 0
	case 0x0003: // UNSIGNED_GT
		return u(value).Cmp(u(operandB)) > 0
	case 0x0004: // SIGNED_LT
		return signedBig(value).Cmp(signedBig(operandB)) < 0
	case 0x0005: // UNSIGNED_LT
		return u(value).Cmp(u(operandB)) < 0
	case 0x0006: // SIGNED_GE
		return signedBig(value).Cmp(signedBig(operandB)) >= 0
	case 0x0007: // UNSIGNED_GE
		return u(value).Cmp(u(operandB)) >= 0
	case 0x0008: // SIGNED_LE
		return signedBig(value).Cmp(signedBig(operandB)) <= 0
	case 0x0009: // UNSIGNED_LE
		return u(value).Cmp(u(operandB)) <= 0
	case 0x000A: // BITSET: every bit set in operandB is set in value
		return andEqual(value, operandB, operandB)
	case 0x000B: // BITCLEAR: every bit set in operandB is clear in value
		return andEqual(value, operandB, make([]byte, len(operandB)))
	}
	return false
}

// andEqual reports whether (value & mask) == want, byte-aligned (right-aligned).
func andEqual(value, mask, want []byte) bool {
	if len(value) != len(mask) || len(mask) != len(want) {
		return false
	}
	for i := range mask {
		if value[i]&mask[i] != want[i] {
			return false
		}
	}
	return true
}

// cmdPolicyCounterTimer implements TPM2_PolicyCounterTimer (Part 3, §23.6):
// constrain a policy by comparing the TPMS_TIME_INFO against operandB.
func (t *TPM) cmdPolicyCounterTimer(r *reader) []byte {
	s, errResp := t.policySession(r)
	if errResp != nil {
		return errResp
	}
	operandB := r.tpm2b()
	offset := r.u16()
	operation := r.u16()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if s.kind != seTrial {
		var ti writer
		ti.u64(t.clock.clock)    // TPMS_TIME_INFO.time
		t.clock.marshalInfo(&ti) // TPMS_TIME_INFO.clockInfo
		info := ti.bytes()
		if int(offset)+len(operandB) > len(info) {
			return errorResponse(withParam(RCValue, 2))
		}
		value := info[offset : int(offset)+len(operandB)]
		if !policyCompare(operation, value, operandB) {
			return errorResponse(RCPolicyFail)
		}
	}
	args := hashSum(s.authHash, operandB, be16(offset), be16(operation))
	s.extend(be32(CCPolicyCounterTimer), args)
	return successResponse(nil, 0)
}

// cmdPolicyNV implements TPM2_PolicyNV (Part 3, §23.8): constrain a policy by
// comparing the contents of an NV Index against operandB. Three handles:
// authHandle (authorized), nvIndex, policySession.
func (t *TPM) cmdPolicyNV(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCPolicyNV, 3, r)
	if errResp != nil {
		return errResp
	}
	operandB := r.tpm2b()
	offset := r.u16()
	operation := r.u16()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	authHandle, nvHandle, policyHandle := ac.handles[0], ac.handles[1], ac.handles[2]
	idx, ok := t.nv.get(nvHandle)
	if !ok {
		return errorResponse(withHandle(RCHandle, 2))
	}
	if errResp := t.authorizeNV(ac, idx, authHandle, false); errResp != nil {
		return errResp
	}
	s, ok := t.sessions.get(policyHandle)
	if !ok || (s.kind != sePolicy && s.kind != seTrial) {
		return errorResponse(withHandle(RCHandle, 3))
	}
	if s.kind != seTrial {
		if idx.public.Attrs&NVWritten == 0 {
			return errorResponse(RCNVUninitialized)
		}
		if int(offset)+len(operandB) > len(idx.data) {
			return errorResponse(withParam(RCValue, 1))
		}
		value := idx.data[offset : int(offset)+len(operandB)]
		if !policyCompare(operation, value, operandB) {
			return errorResponse(RCPolicyFail)
		}
	}
	args := hashSum(s.authHash, operandB, be16(offset), be16(operation))
	s.extend(be32(CCPolicyNV), args, idx.name)
	return successResponse(nil, 0)
}
