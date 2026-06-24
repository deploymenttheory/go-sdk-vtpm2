// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import "encoding/binary"

// This file is the typed TPM 2.0 structure layer (TPM 2.0 Part 2). Each type
// marshals/unmarshals itself over the big-endian reader/writer in buf.go, so
// command handlers compose structures instead of hand-rolling wire layout. The
// tagged unions (TPMU_*) are selected by an algorithm/type field that always
// precedes them on the wire, exactly as the spec specifies.

// symDef is a TPMT_SYM_DEF_OBJECT: an algorithm and, unless it is TPM_ALG_NULL,
// its key size and block-cipher mode. Only block ciphers (AES) and NULL are
// modelled — the only forms a key's parameters use here.
type symDef struct {
	Alg     uint16 // TPM_ALG_ID: AES or NULL
	KeyBits uint16 // key size in bits (absent when Alg==NULL)
	Mode    uint16 // TPM_ALG_ID block mode, e.g. CFB (absent when Alg==NULL)
}

func (s symDef) marshal(w *writer) {
	w.u16(s.Alg)
	if s.Alg != AlgNull {
		w.u16(s.KeyBits)
		w.u16(s.Mode)
	}
}

func (s *symDef) unmarshal(r *reader) {
	s.Alg = r.u16()
	if s.Alg != AlgNull {
		s.KeyBits = r.u16()
		s.Mode = r.u16()
	}
}

// hashScheme is a scheme selector plus its single hash algorithm — the shape of
// TPMT_RSA_SCHEME / TPMT_ECC_SCHEME / TPMT_KEYEDHASH_SCHEME / TPMT_KDF_SCHEME for
// every scheme used here (RSASSA, RSAPSS, OAEP, ECDSA, ECDH, HMAC, KDF1, NULL).
// A NULL scheme carries no hash.
type hashScheme struct {
	Scheme  uint16 // TPM_ALG_ID of the scheme (e.g. RSASSA), or NULL
	HashAlg uint16 // hash for the scheme (absent when Scheme==NULL)
}

func (s hashScheme) marshal(w *writer) {
	w.u16(s.Scheme)
	if s.Scheme != AlgNull {
		w.u16(s.HashAlg)
	}
}

func (s *hashScheme) unmarshal(r *reader) {
	s.Scheme = r.u16()
	if s.Scheme != AlgNull {
		s.HashAlg = r.u16()
	}
}

// public is a TPMT_PUBLIC: the public area of a TPM object. The parameters and
// unique fields are tagged unions selected by Type (TPM_ALG_RSA / ECC /
// KEYEDHASH / SYMCIPHER).
type public struct {
	Type       uint16 // TPM_ALG_ID object type
	NameAlg    uint16 // TPM_ALG_ID name hash
	Attrs      uint32 // TPMA_OBJECT
	AuthPolicy []byte // TPM2B_DIGEST

	// TPMU_PUBLIC_PARMS (by Type):
	Sym     symDef     // symmetric (SYMCIPHER parms, or the sym of RSA/ECC parms)
	Scheme  hashScheme // RSA/ECC/KEYEDHASH scheme
	KeyBits uint16     // RSA modulus size in bits
	Exp     uint32     // RSA public exponent (0 ⇒ default 65537)
	Curve   uint16     // ECC curve id
	KDF     hashScheme // ECC KDF scheme

	// TPMU_PUBLIC_ID (by Type):
	Unique  []byte // RSA modulus, or KEYEDHASH/SYMCIPHER digest
	UniqueX []byte // ECC point X
	UniqueY []byte // ECC point Y
}

func (p *public) marshal(w *writer) {
	w.u16(p.Type)
	w.u16(p.NameAlg)
	w.u32(p.Attrs)
	w.tpm2b(p.AuthPolicy)

	switch p.Type { // TPMU_PUBLIC_PARMS
	case AlgKeyedHash:
		p.Scheme.marshal(w)
	case AlgSymCipher:
		p.Sym.marshal(w)
	case AlgRSA:
		p.Sym.marshal(w)
		p.Scheme.marshal(w)
		w.u16(p.KeyBits)
		w.u32(p.Exp)
	case AlgECC:
		p.Sym.marshal(w)
		p.Scheme.marshal(w)
		w.u16(p.Curve)
		p.KDF.marshal(w)
	}

	switch p.Type { // TPMU_PUBLIC_ID
	case AlgRSA, AlgKeyedHash, AlgSymCipher:
		w.tpm2b(p.Unique)
	case AlgECC:
		w.tpm2b(p.UniqueX)
		w.tpm2b(p.UniqueY)
	}
}

func (p *public) unmarshal(r *reader) {
	p.Type = r.u16()
	p.NameAlg = r.u16()
	p.Attrs = r.u32()
	p.AuthPolicy = r.tpm2b()

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
			r.err = errBadValue // unknown object type
		}
		return
	}

	switch p.Type {
	case AlgRSA, AlgKeyedHash, AlgSymCipher:
		p.Unique = r.tpm2b()
	case AlgECC:
		p.UniqueX = r.tpm2b()
		p.UniqueY = r.tpm2b()
	}
}

// marshal2B writes a TPM2B_PUBLIC: the marshalled public area behind a UINT16
// size prefix.
func (p *public) marshal2B(w *writer) {
	var inner writer
	p.marshal(&inner)
	w.tpm2b(inner.bytes())
}

// readPublic2B reads a TPM2B_PUBLIC. A zero-size field yields the zero public
// (the empty template some commands accept).
func readPublic2B(r *reader) public {
	buf := r.tpm2b()
	if r.err != nil || len(buf) == 0 {
		return public{}
	}
	ir := newReader(buf)
	var p public
	p.unmarshal(ir)
	if ir.err != nil {
		r.err = ir.err
	}
	return p
}

// sensitive is a TPMT_SENSITIVE: the secret half of an object. The composite
// secret (TPMU_SENSITIVE_COMPOSITE) is a single TPM2B for every type used here —
// RSA prime, ECC private scalar, keyed-hash data, or symmetric key.
type sensitive struct {
	Type      uint16 // matches the object's public Type
	AuthValue []byte // TPM2B_AUTH
	SeedValue []byte // TPM2B_DIGEST (obfuscation/storage seed)
	Secret    []byte // TPMU_SENSITIVE_COMPOSITE
}

func (s *sensitive) marshal(w *writer) {
	w.u16(s.Type)
	w.tpm2b(s.AuthValue)
	w.tpm2b(s.SeedValue)
	w.tpm2b(s.Secret)
}

func (s *sensitive) unmarshal(r *reader) {
	s.Type = r.u16()
	s.AuthValue = r.tpm2b()
	s.SeedValue = r.tpm2b()
	s.Secret = r.tpm2b()
}

// marshal2B writes a TPM2B_SENSITIVE: the marshalled sensitive area behind a
// UINT16 size prefix.
func (s *sensitive) marshal2B(w *writer) {
	var inner writer
	s.marshal(&inner)
	w.tpm2b(inner.bytes())
}

// nvPublic is a TPMS_NV_PUBLIC: the public definition of an NV index.
type nvPublic struct {
	Index      uint32 // NV index handle (0x01xxxxxx)
	NameAlg    uint16 // TPM_ALG_ID
	Attrs      uint32 // TPMA_NV
	AuthPolicy []byte // TPM2B_DIGEST
	DataSize   uint16
}

func (n *nvPublic) marshal(w *writer) {
	w.u32(n.Index)
	w.u16(n.NameAlg)
	w.u32(n.Attrs)
	w.tpm2b(n.AuthPolicy)
	w.u16(n.DataSize)
}

func (n *nvPublic) unmarshal(r *reader) {
	n.Index = r.u32()
	n.NameAlg = r.u16()
	n.Attrs = r.u32()
	n.AuthPolicy = r.tpm2b()
	n.DataSize = r.u16()
}

// marshal2B writes a TPM2B_NV_PUBLIC: the marshalled NV public behind a UINT16
// size prefix.
func (n *nvPublic) marshal2B(w *writer) {
	var inner writer
	n.marshal(&inner)
	w.tpm2b(inner.bytes())
}

// nvType returns the NT field of a TPMA_NV (ordinary, counter, bits, extend…).
func (n *nvPublic) nvType() uint32 { return (n.Attrs & NVNTMask) >> NVNTShift }

// name returns the NV index Name: nameAlg ‖ H_nameAlg(marshalled TPMS_NV_PUBLIC),
// per TPM 2.0 Part 1 §16. Returns nil if the name algorithm is unsupported.
func (n *nvPublic) name() []byte {
	if _, ok := cryptoHash(n.NameAlg); !ok {
		return nil
	}
	var w writer
	n.marshal(&w)
	sum := hashSum(n.NameAlg, w.bytes())
	out := make([]byte, 2+len(sum))
	binary.BigEndian.PutUint16(out, n.NameAlg)
	copy(out[2:], sum)
	return out
}

// name returns the object Name (TPM2B_NAME contents): the nameAlg identifier
// followed by H_nameAlg(publicArea), per TPM 2.0 Part 1 §16. Returns nil if the
// name algorithm is unsupported.
func (p *public) name() []byte {
	if _, ok := cryptoHash(p.NameAlg); !ok {
		return nil
	}
	var w writer
	p.marshal(&w)
	sum := hashSum(p.NameAlg, w.bytes())
	out := make([]byte, 2+len(sum))
	binary.BigEndian.PutUint16(out, p.NameAlg)
	copy(out[2:], sum)
	return out
}
