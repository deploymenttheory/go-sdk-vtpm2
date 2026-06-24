// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// roundTripPublic marshals p, unmarshals the bytes, re-marshals, and requires the
// two encodings to match — exercising both directions of a tagged-union layout.
func roundTripPublic(t *testing.T, name string, p public) {
	t.Helper()
	var w1 writer
	p.marshal(&w1)
	b1 := w1.bytes()

	r := newReader(b1)
	var got public
	got.unmarshal(r)
	if r.err != nil {
		t.Fatalf("%s: unmarshal error: %v", name, r.err)
	}
	var w2 writer
	got.marshal(&w2)
	if !bytes.Equal(b1, w2.bytes()) {
		t.Fatalf("%s: re-marshal mismatch\n first: %x\nsecond: %x", name, b1, w2.bytes())
	}
	if got.Type != p.Type || got.NameAlg != p.NameAlg || got.Attrs != p.Attrs {
		t.Fatalf("%s: scalar fields lost: %+v vs %+v", name, got, p)
	}
}

func TestPublicRoundTrip(t *testing.T) {
	storageAttrs := ObjFixedTPM | ObjFixedParent | ObjSensitiveDataOrigin |
		ObjUserWithAuth | ObjRestricted | ObjDecrypt | ObjNoDA

	roundTripPublic(t, "RSA-SRK", public{
		Type:    AlgRSA,
		NameAlg: AlgSHA256,
		Attrs:   storageAttrs,
		Sym:     symDef{Alg: AlgAES, KeyBits: 128, Mode: AlgCFB},
		Scheme:  hashScheme{Scheme: AlgNull},
		KeyBits: 2048,
		Exp:     0,
		Unique:  bytes.Repeat([]byte{0xAB}, 256), // 2048-bit modulus
	})

	roundTripPublic(t, "ECC-P256", public{
		Type:    AlgECC,
		NameAlg: AlgSHA256,
		Attrs:   ObjFixedTPM | ObjFixedParent | ObjSensitiveDataOrigin | ObjUserWithAuth | ObjSign,
		Sym:     symDef{Alg: AlgNull},
		Scheme:  hashScheme{Scheme: AlgECDSA, HashAlg: AlgSHA256},
		Curve:   ECCNistP256,
		KDF:     hashScheme{Scheme: AlgNull},
		UniqueX: bytes.Repeat([]byte{0x01}, 32),
		UniqueY: bytes.Repeat([]byte{0x02}, 32),
	})

	roundTripPublic(t, "KeyedHash-seal", public{
		Type:    AlgKeyedHash,
		NameAlg: AlgSHA256,
		Attrs:   ObjFixedTPM | ObjFixedParent | ObjUserWithAuth,
		Scheme:  hashScheme{Scheme: AlgNull}, // a sealed data blob has no scheme
		Unique:  bytes.Repeat([]byte{0x09}, 32),
	})

	roundTripPublic(t, "SymCipher", public{
		Type:    AlgSymCipher,
		NameAlg: AlgSHA256,
		Attrs:   ObjFixedTPM | ObjFixedParent | ObjSensitiveDataOrigin | ObjUserWithAuth | ObjDecrypt | ObjSign,
		Sym:     symDef{Alg: AlgAES, KeyBits: 128, Mode: AlgCFB},
		Unique:  bytes.Repeat([]byte{0x07}, 32),
	})
}

func TestPublic2BSizePrefix(t *testing.T) {
	p := public{Type: AlgKeyedHash, NameAlg: AlgSHA256, Scheme: hashScheme{Scheme: AlgNull}, Unique: []byte{1, 2, 3}}
	var inner writer
	p.marshal(&inner)

	var w writer
	p.marshal2B(&w)
	got := w.bytes()
	if size := binary.BigEndian.Uint16(got); int(size) != len(inner.bytes()) {
		t.Fatalf("TPM2B_PUBLIC size = %d, want %d", size, len(inner.bytes()))
	}
	if !bytes.Equal(got[2:], inner.bytes()) {
		t.Fatalf("TPM2B_PUBLIC body mismatch")
	}

	// Round trip through readPublic2B.
	r := newReader(got)
	back := readPublic2B(r)
	if r.err != nil || back.Type != p.Type {
		t.Fatalf("readPublic2B = %+v, err %v", back, r.err)
	}

	// An empty TPM2B_PUBLIC (size 0) yields the zero public.
	er := newReader([]byte{0x00, 0x00})
	if empty := readPublic2B(er); er.err != nil || empty.Type != 0 {
		t.Fatalf("empty TPM2B_PUBLIC = %+v, err %v", empty, er.err)
	}
}

func TestSensitiveRoundTrip(t *testing.T) {
	s := sensitive{
		Type:      AlgRSA,
		AuthValue: []byte{0xDE, 0xAD},
		SeedValue: bytes.Repeat([]byte{0x5A}, 32),
		Secret:    bytes.Repeat([]byte{0xCC}, 128), // an RSA prime
	}
	var w writer
	s.marshal2B(&w)
	b := w.bytes()
	if size := binary.BigEndian.Uint16(b); int(size) != len(b)-2 {
		t.Fatalf("TPM2B_SENSITIVE size = %d, want %d", size, len(b)-2)
	}

	r := newReader(b)
	_ = r.u16() // outer TPM2B size
	var got sensitive
	got.unmarshal(r)
	if r.err != nil {
		t.Fatalf("unmarshal: %v", r.err)
	}
	if got.Type != s.Type || !bytes.Equal(got.AuthValue, s.AuthValue) ||
		!bytes.Equal(got.SeedValue, s.SeedValue) || !bytes.Equal(got.Secret, s.Secret) {
		t.Fatalf("sensitive round trip mismatch: %+v", got)
	}
}

func TestNVPublicRoundTrip(t *testing.T) {
	n := nvPublic{
		Index:      0x01000001,
		NameAlg:    AlgSHA256,
		Attrs:      NVAuthWrite | NVAuthRead | NVWritten | (2 << NVNTShift), // NT=counter(2)
		AuthPolicy: nil,
		DataSize:   8,
	}
	var w writer
	n.marshal(&w)
	r := newReader(w.bytes())
	var got nvPublic
	got.unmarshal(r)
	if r.err != nil {
		t.Fatalf("unmarshal: %v", r.err)
	}
	if got.Index != n.Index || got.NameAlg != n.NameAlg || got.Attrs != n.Attrs || got.DataSize != n.DataSize {
		t.Fatalf("nvPublic round trip mismatch: %+v vs %+v", got, n)
	}
	if got.nvType() != 2 {
		t.Fatalf("nvType = %d, want 2 (counter)", got.nvType())
	}
}

func TestPublicUnmarshalRejectsUnknownType(t *testing.T) {
	// type=0x00FF is not a valid object type; unmarshal must flag a value error.
	var w writer
	w.u16(0x00FF) // Type
	w.u16(AlgSHA256)
	w.u32(0)
	w.tpm2b(nil) // authPolicy
	r := newReader(w.bytes())
	var p public
	p.unmarshal(r)
	if r.err != errBadValue {
		t.Fatalf("unknown object type err = %v, want errBadValue", r.err)
	}
}
