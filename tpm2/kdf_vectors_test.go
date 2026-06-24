// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// Known-answer vectors for KDFa (SP800-108 counter mode, TPM 2.0 Part 1
// §8.4.10.2) and KDFe (SP800-56A, §8.4.10.3). The expected outputs were
// produced by an independent, spec-faithful reference implementation (the same
// shape go-tpm's KDF tests use), so these pin our kdfa/kdfe to externally-derived
// bytes — not to our own implementation.
func TestKDFaKnownAnswers(t *testing.T) {
	key := bytes.Repeat([]byte{0x0b}, 32)
	ctxU := bytes.Repeat([]byte{0x01}, 16)
	ctxV := bytes.Repeat([]byte{0x02}, 16)

	for _, v := range []struct {
		name  string
		label string
		bits  int
		want  string
	}{
		{"ATH-256", "ATH", 256, "63591fea5c8a26cee98e509a3cd1ba3b4e3c079f7014fc56e5805175d15e292b"},
		{"CFB-128", "CFB", 128, "102d8c3954fd6f1e1decad8fa4cc2180"},
		// 521 bits exercises the multi-block path and the high-bit mask of the
		// first byte (521 mod 8 = 1).
		{"STORAGE-521", "STORAGE", 521, "010daf94829d8540d49264e166574cabb8956388fe1c8c7e494f432dc7057c4b75713e7aac5e6df4630ce6ab7a1cd21539a9c79364b8ba6d2b2b559c33e7b2e87cbc"},
	} {
		got := kdfa(AlgSHA256, key, []byte(v.label), ctxU, ctxV, v.bits)
		if want, _ := hex.DecodeString(v.want); !bytes.Equal(got, want) {
			t.Errorf("KDFa %s = %x, want %s", v.name, got, v.want)
		}
	}
}

func TestKDFeKnownAnswer(t *testing.T) {
	z := bytes.Repeat([]byte{0x0c}, 32)
	pu := bytes.Repeat([]byte{0x03}, 32)
	pv := bytes.Repeat([]byte{0x04}, 32)
	want, _ := hex.DecodeString("792abfa6b8f56534e5cb0baf2492e49c11afe9ce3a2e72968e9db967a01b9d05")
	if got := kdfe(AlgSHA256, z, []byte("SECRET"), pu, pv, 256); !bytes.Equal(got, want) {
		t.Errorf("KDFe = %x, want %x", got, want)
	}
}

// TestKDFaMatchesIndependentReference cross-checks kdfa against a from-scratch
// SP800-108 transcription over random-ish inputs, so a regression in either the
// optimized or the reference path is caught structurally, not just at the pins.
func TestKDFaMatchesIndependentReference(t *testing.T) {
	ref := func(key, label, u, v []byte, bits int) []byte {
		var out []byte
		for i := uint32(1); len(out)*8 < bits; i++ {
			m := hmac.New(sha256.New, key)
			m.Write(be32(i))
			m.Write(label)
			m.Write([]byte{0x00})
			m.Write(u)
			m.Write(v)
			m.Write(be32(uint32(bits)))
			out = append(out, m.Sum(nil)...)
		}
		out = out[:(bits+7)/8]
		if rem := bits % 8; rem != 0 {
			out[0] &= byte(1<<rem) - 1
		}
		return out
	}
	for i, bits := range []int{8, 127, 128, 256, 384, 500, 512, 600} {
		key := bytes.Repeat([]byte{byte(i + 1)}, 20)
		u := bytes.Repeat([]byte{0xa0 ^ byte(i)}, 13)
		v := bytes.Repeat([]byte{0x0f ^ byte(i)}, 29)
		if got, want := kdfa(AlgSHA256, key, []byte("LBL"), u, v, bits), ref(key, []byte("LBL"), u, v, bits); !bytes.Equal(got, want) {
			t.Errorf("bits=%d: kdfa diverges from reference", bits)
		}
	}
}
