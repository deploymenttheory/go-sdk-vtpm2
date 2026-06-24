// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func TestHashAndHMACDispatch(t *testing.T) {
	for _, alg := range []uint16{AlgSHA1, AlgSHA256, AlgSHA384, AlgSHA512} {
		if got := len(hashSum(alg, []byte("abc"))); got != hashSize(alg) {
			t.Errorf("hashSum(0x%x) len = %d, want %d", alg, got, hashSize(alg))
		}
		if got := len(hmacSum(alg, []byte("k"), []byte("abc"))); got != hashSize(alg) {
			t.Errorf("hmacSum(0x%x) len = %d, want %d", alg, got, hashSize(alg))
		}
	}
	if hashSum(AlgNull, nil) != nil {
		t.Error("hashSum of an unsupported alg should be nil")
	}
}

// TestKDFaFirstBlock checks the KDFa construction against an independently
// computed first block: HMAC(key, BE32(1)‖label‖0x00‖ctxU‖ctxV‖BE32(bits)).
func TestKDFaFirstBlock(t *testing.T) {
	key := []byte("secret-key")
	label := []byte("STORAGE")
	ctxU := []byte{0x01, 0x02}
	ctxV := []byte{0x03, 0x04}
	const bits = 256

	m := hmac.New(sha256.New, key)
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], 1)
	m.Write(b4[:])
	m.Write(label)
	m.Write([]byte{0x00})
	m.Write(ctxU)
	m.Write(ctxV)
	binary.BigEndian.PutUint32(b4[:], bits)
	m.Write(b4[:])
	want := m.Sum(nil)

	got := kdfa(AlgSHA256, key, label, ctxU, ctxV, bits)
	if !bytes.Equal(got, want) {
		t.Fatalf("kdfa = %x, want %x", got, want)
	}
}

func TestKDFaLengthAndDeterminism(t *testing.T) {
	key := []byte("k")
	// 600 bits needs three SHA-256 (256-bit) blocks; output is 75 bytes.
	a := kdfa(AlgSHA256, key, []byte("L"), nil, nil, 600)
	b := kdfa(AlgSHA256, key, []byte("L"), nil, nil, 600)
	if len(a) != (600+7)/8 {
		t.Fatalf("kdfa len = %d, want %d", len(a), (600+7)/8)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("kdfa is not deterministic")
	}
	// A different label must change the output.
	if bytes.Equal(a, kdfa(AlgSHA256, key, []byte("M"), nil, nil, 600)) {
		t.Fatal("kdfa output must depend on the label")
	}
}

// TestKDFaBitMasking verifies that a bit count which is not a byte multiple
// clears the unused most-significant bits of the first output byte.
func TestKDFaBitMasking(t *testing.T) {
	out := kdfa(AlgSHA256, []byte("k"), []byte("L"), nil, nil, 5) // 5 bits → 1 byte
	if len(out) != 1 {
		t.Fatalf("len = %d, want 1", len(out))
	}
	if out[0] & ^byte(0x1F) != 0 {
		t.Fatalf("unused high bits not masked: 0x%02x", out[0])
	}
}

func TestKDFeFirstBlock(t *testing.T) {
	z := []byte("shared")
	out := kdfe(AlgSHA256, z, []byte("DUPLICATE"), []byte("u"), []byte("v"), 256)
	if len(out) != 32 {
		t.Fatalf("kdfe len = %d, want 32", len(out))
	}
	// Independent recomputation: H(BE32(1)‖z‖label‖0x00‖u‖v).
	h := sha256.New()
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], 1)
	h.Write(b4[:])
	h.Write(z)
	h.Write([]byte("DUPLICATE"))
	h.Write([]byte{0x00})
	h.Write([]byte("u"))
	h.Write([]byte("v"))
	if !bytes.Equal(out, h.Sum(nil)) {
		t.Fatal("kdfe first block mismatch")
	}
}

// TestObjectName checks Name = nameAlg ‖ H_nameAlg(publicArea).
func TestObjectName(t *testing.T) {
	p := public{
		Type:    AlgKeyedHash,
		NameAlg: AlgSHA256,
		Scheme:  hashScheme{Scheme: AlgNull},
		Unique:  bytes.Repeat([]byte{0x42}, 32),
	}
	name := p.name()
	if binary.BigEndian.Uint16(name) != AlgSHA256 {
		t.Fatalf("name alg prefix = 0x%x, want SHA256", binary.BigEndian.Uint16(name))
	}
	var w writer
	p.marshal(&w)
	want := sha256.Sum256(w.bytes())
	if !bytes.Equal(name[2:], want[:]) {
		t.Fatalf("name digest mismatch")
	}
	if len(name) != 2+32 {
		t.Fatalf("name len = %d, want 34", len(name))
	}
}
