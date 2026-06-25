// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"testing"
)

func TestPadLeft(t *testing.T) {
	if got := padLeft([]byte{0x01}, 4); !bytes.Equal(got, []byte{0, 0, 0, 1}) {
		t.Fatalf("padLeft short = %x", got)
	}
	if got := padLeft([]byte{1, 2, 3, 4}, 4); !bytes.Equal(got, []byte{1, 2, 3, 4}) {
		t.Fatalf("padLeft exact = %x", got)
	}
	// An input longer than the target is returned (right-aligned / unchanged length).
	if got := padLeft([]byte{1, 2, 3, 4, 5}, 4); len(got) < 4 {
		t.Fatalf("padLeft long = %x", got)
	}
}

func TestCurveHelpers(t *testing.T) {
	for _, c := range []uint16{ECCNistP256, ECCNistP384, ECCNistP521} {
		if curveFor(c) == nil {
			t.Fatalf("curveFor(0x%x) = nil", c)
		}
		if ecdhCurveFor(c) == nil {
			t.Fatalf("ecdhCurveFor(0x%x) = nil", c)
		}
	}
	if curveFor(0x9999) != nil || ecdhCurveFor(0x9999) != nil {
		t.Fatal("unknown curve resolved to a non-nil curve")
	}
}

func TestSigAlgIdentifier(t *testing.T) {
	for _, tc := range []struct {
		sig, hash uint16
		ok        bool
	}{
		{AlgECDSA, AlgSHA256, true}, {AlgECDSA, AlgSHA384, true}, {AlgECDSA, AlgSHA512, true},
		{AlgRSASSA, AlgSHA256, true}, {AlgRSASSA, AlgSHA384, true}, {AlgRSASSA, AlgSHA512, true},
		{AlgECDSA, AlgSHA1, false}, {AlgRSAPSS, AlgSHA256, false}, {AlgNull, AlgSHA256, false},
	} {
		der, ok := sigAlgIdentifier(tc.sig, tc.hash)
		if ok != tc.ok {
			t.Fatalf("sigAlgIdentifier(0x%x,0x%x) ok=%v, want %v", tc.sig, tc.hash, ok, tc.ok)
		}
		if ok && len(der) == 0 {
			t.Fatal("empty DER for a supported scheme")
		}
	}
}

func TestPolicyCompareAllOps(t *testing.T) {
	a := []byte{0, 0, 0, 5}
	b := []byte{0, 0, 0, 3}
	cases := []struct {
		op   uint16
		want bool
	}{
		{0x0000, false}, // EQ (5≠3)
		{0x0001, true},  // NEQ
		{0x0002, true},  // SIGNED_GT
		{0x0003, true},  // UNSIGNED_GT
		{0x0004, false}, // SIGNED_LT
		{0x0005, false}, // UNSIGNED_LT
		{0x0006, true},  // SIGNED_GE
		{0x0007, true},  // UNSIGNED_GE
		{0x0008, false}, // SIGNED_LE
		{0x0009, false}, // UNSIGNED_LE
		{0x000A, false}, // BITSET: bits of b not all set in a (3=011, 5=101)
		{0x000B, false}, // BITCLEAR
		{0x00FF, false}, // unknown op
	}
	for _, c := range cases {
		if got := policyCompare(c.op, a, b); got != c.want {
			t.Fatalf("policyCompare(0x%x, 5, 3) = %v, want %v", c.op, got, c.want)
		}
	}
	// signed interpretation: 0x80.. is negative.
	if !policyCompare(0x0004, []byte{0x80}, []byte{0x01}) { // SIGNED_LT: -128 < 1
		t.Fatal("signed comparison failed")
	}
}

func TestResponseCodeDecoration(t *testing.T) {
	if baseRC(withHandle(RCValue, 2)) != RCValue {
		t.Fatal("withHandle did not preserve the base RC_VALUE")
	}
	if baseRC(withParam(RCValue, 3)) != RCValue {
		t.Fatal("withParam did not preserve the base RC_VALUE")
	}
	if baseRC(withSession(RCAuthFail, 1)) != RCAuthFail {
		t.Fatal("withSession did not preserve the base RC_AUTH_FAIL")
	}
	// A format-zero (VER1) code is returned undecorated.
	if baseRC(RCInitialize) != RCInitialize {
		t.Fatal("baseRC mangled a format-zero code")
	}
}

func TestHashSizeAndNewHash(t *testing.T) {
	for _, tc := range []struct {
		alg  uint16
		size int
	}{{AlgSHA1, 20}, {AlgSHA256, 32}, {AlgSHA384, 48}, {AlgSHA512, 64}} {
		if hashSize(tc.alg) != tc.size {
			t.Fatalf("hashSize(0x%x) = %d, want %d", tc.alg, hashSize(tc.alg), tc.size)
		}
		if newHash(tc.alg) == nil {
			t.Fatalf("newHash(0x%x) = nil", tc.alg)
		}
	}
	if hashSize(AlgNull) != 0 || newHash(AlgNull) != nil {
		t.Fatal("a non-hash algorithm produced a hash")
	}
}

func TestSymCryptModesDirect(t *testing.T) {
	key := bytes.Repeat([]byte{0x2b}, 16)
	iv := make([]byte, 16)
	data := bytes.Repeat([]byte{0x41}, 32)
	for _, mode := range []uint16{AlgCFB, AlgOFB, AlgCTR, AlgCBC, AlgECB} {
		enc, _, ok := symCrypt(mode, key, iv, data, false)
		if !ok {
			t.Fatalf("symCrypt encrypt mode 0x%x failed", mode)
		}
		dec, _, ok := symCrypt(mode, key, iv, enc, true)
		if !ok || !bytes.Equal(dec, data) {
			t.Fatalf("symCrypt round-trip mode 0x%x failed", mode)
		}
	}
	// An unsupported mode and a bad key length fail cleanly.
	if _, _, ok := symCrypt(0x9999, key, iv, data, false); ok {
		t.Fatal("unsupported mode unexpectedly succeeded")
	}
	if _, _, ok := symCrypt(AlgCFB, []byte{1, 2, 3}, iv, data, false); ok {
		t.Fatal("bad AES key length unexpectedly succeeded")
	}
	// CBC/ECB reject unaligned data.
	if _, _, ok := symCrypt(AlgCBC, key, iv, []byte("not block aligned"), false); ok {
		t.Fatal("CBC accepted unaligned data")
	}
}

func TestMiscScalarHelpers(t *testing.T) {
	if rsaExp(0) != rsaExponent {
		t.Fatal("rsaExp(0) did not default")
	}
	if rsaExp(3) != 3 {
		t.Fatal("rsaExp(3) != 3")
	}
	if !bytes.Equal(be16(0x0102), []byte{0x01, 0x02}) {
		t.Fatal("be16")
	}
	if !bytes.Equal(be32(0x01020304), []byte{1, 2, 3, 4}) {
		t.Fatal("be32")
	}
	if !bytes.Equal(be64(0x0102030405060708), []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatal("be64")
	}
	if !anyBitSet([]byte{0, 0, 1}) || anyBitSet([]byte{0, 0, 0}) {
		t.Fatal("anyBitSet")
	}
	if xb := xorBytes([]byte{0xF0, 0x0F}, []byte{0xFF, 0xFF}); !bytes.Equal(xb, []byte{0x0F, 0xF0}) {
		t.Fatalf("xorBytes = %x", xb)
	}
}

func TestValidateSCKeyName(t *testing.T) {
	if validateSCKeyName(nil) != nil {
		t.Fatal("empty name should be valid")
	}
	good := append(be16(AlgSHA256), make([]byte, 32)...)
	if validateSCKeyName(good) != nil {
		t.Fatal("valid SHA-256 name rejected")
	}
	if validateSCKeyName([]byte{0x01}) == nil { // too short for an algorithm id
		t.Fatal("truncated name accepted")
	}
	if validateSCKeyName(append(be16(0x9999), make([]byte, 32)...)) == nil {
		t.Fatal("bad hash algorithm accepted")
	}
	if validateSCKeyName(append(be16(AlgSHA256), make([]byte, 10)...)) == nil {
		t.Fatal("wrong digest length accepted")
	}
}
