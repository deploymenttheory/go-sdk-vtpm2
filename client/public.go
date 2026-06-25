// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package client

// This file holds the typed TPM 2.0 values the client API exposes: handles, the
// constants a caller needs, and the TPMT_PUBLIC structure with marshalling that is
// byte-compatible with the responder.

// Handle is a TPM handle (object, hierarchy, NV, session, …).
type Handle uint32

// Permanent handles and the password-session handle.
const (
	HandleOwner       Handle = 0x40000001
	HandleNull        Handle = 0x40000007
	HandlePassword    Handle = 0x40000009 // TPM_RS_PW
	HandleLockout     Handle = 0x4000000A
	HandleEndorsement Handle = 0x4000000B
	HandlePlatform    Handle = 0x4000000C
)

// Algorithm identifiers (TPM_ALG_ID).
const (
	AlgRSA       uint16 = 0x0001
	AlgHMAC      uint16 = 0x0005
	AlgAES       uint16 = 0x0006
	AlgKeyedHash uint16 = 0x0008
	AlgSHA1      uint16 = 0x0004
	AlgSHA256    uint16 = 0x000B
	AlgSHA384    uint16 = 0x000C
	AlgSHA512    uint16 = 0x000D
	AlgNull      uint16 = 0x0010
	AlgRSASSA    uint16 = 0x0014
	AlgRSAES     uint16 = 0x0015
	AlgRSAPSS    uint16 = 0x0016
	AlgOAEP      uint16 = 0x0017
	AlgECDSA     uint16 = 0x0018
	AlgECDH      uint16 = 0x0019
	AlgECC       uint16 = 0x0023
	AlgSymCipher uint16 = 0x0025
	AlgCFB       uint16 = 0x0043
)

// ECC curve identifiers (TPM_ECC_CURVE).
const (
	ECCNistP256 uint16 = 0x0003
	ECCNistP384 uint16 = 0x0004
	ECCNistP521 uint16 = 0x0005
)

// TPMA_OBJECT attribute bits.
const (
	AttrFixedTPM             uint32 = 1 << 1
	AttrStClear              uint32 = 1 << 2
	AttrFixedParent          uint32 = 1 << 4
	AttrSensitiveDataOrigin  uint32 = 1 << 5
	AttrUserWithAuth         uint32 = 1 << 6
	AttrAdminWithPolicy      uint32 = 1 << 7
	AttrNoDA                 uint32 = 1 << 10
	AttrEncryptedDuplication uint32 = 1 << 11
	AttrRestricted           uint32 = 1 << 16
	AttrDecrypt              uint32 = 1 << 17
	AttrSign                 uint32 = 1 << 18
)

// SymDef is a TPMT_SYM_DEF_OBJECT (symmetric algorithm, key size, block mode).
type SymDef struct {
	Alg     uint16
	KeyBits uint16
	Mode    uint16
}

func (s SymDef) marshal(w *writer) {
	w.u16(s.Alg)
	if s.Alg != AlgNull {
		w.u16(s.KeyBits)
		w.u16(s.Mode)
	}
}

func (s *SymDef) unmarshal(r *reader) {
	s.Alg = r.u16()
	if s.Alg != AlgNull {
		s.KeyBits = r.u16()
		s.Mode = r.u16()
	}
}

// Scheme is a TPMT_*_SCHEME with an optional hash (KDF/sig/keyed-hash schemes).
type Scheme struct {
	Alg  uint16
	Hash uint16
}

func (s Scheme) marshal(w *writer) {
	w.u16(s.Alg)
	if s.Alg != AlgNull {
		w.u16(s.Hash)
	}
}

func (s *Scheme) unmarshal(r *reader) {
	s.Alg = r.u16()
	if s.Alg != AlgNull {
		s.Hash = r.u16()
	}
}

// Public is a TPMT_PUBLIC: an object's public area (template on input, the full
// public area on output). Fields outside the object Type are ignored.
type Public struct {
	Type       uint16
	NameAlg    uint16
	Attrs      uint32
	AuthPolicy []byte

	Sym     SymDef // RSA/ECC parent symmetric, or SYMCIPHER key
	Scheme  Scheme // RSA/ECC/KEYEDHASH scheme
	KeyBits uint16 // RSA modulus size
	Exp     uint32 // RSA exponent (0 ⇒ default 65537)
	Curve   uint16 // ECC curve
	KDF     Scheme // ECC KDF

	Unique  []byte // RSA modulus / KEYEDHASH / SYMCIPHER digest
	UniqueX []byte // ECC point X
	UniqueY []byte // ECC point Y
}

func (p *Public) marshal(w *writer) {
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

func (p *Public) unmarshal(r *reader) {
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
	}

	switch p.Type {
	case AlgRSA, AlgKeyedHash, AlgSymCipher:
		p.Unique = r.tpm2b()
	case AlgECC:
		p.UniqueX = r.tpm2b()
		p.UniqueY = r.tpm2b()
	}
}

// marshal2B writes the Public area as a size-prefixed TPM2B_PUBLIC.
func (p *Public) marshal2B(w *writer) {
	var inner writer
	p.marshal(&inner)
	w.tpm2b(inner.bytes())
}

// readPublic2B reads a TPM2B_PUBLIC.
func readPublic2B(r *reader) Public {
	inner := newReader(r.tpm2b())
	var p Public
	p.unmarshal(inner)
	return p
}
