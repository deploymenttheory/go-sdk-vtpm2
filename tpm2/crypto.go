// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	_ "crypto/sha1"   //nolint:gosec // SHA-1 is a mandated TPM algorithm, not a security control
	_ "crypto/sha256" // register SHA-256
	_ "crypto/sha512" // register SHA-384 / SHA-512
	"encoding/binary"
	"hash"
	"io"
	"math/big"
)

// rsaExponent is the fixed TPM RSA public exponent.
const rsaExponent = 65537

// This file is the cryptographic foundation, drawn entirely from the Go standard
// library: hashing, HMAC, key derivation (KDFa/KDFe), deterministic RSA/ECC key
// generation, and the symmetric primitives the session and object subsystems use.

// cryptoHash maps a TPM_ALG_ID to a registered Go hash, reporting false for an
// unsupported algorithm.
func cryptoHash(alg uint16) (crypto.Hash, bool) {
	switch alg {
	case AlgSHA1:
		return crypto.SHA1, true
	case AlgSHA256:
		return crypto.SHA256, true
	case AlgSHA384:
		return crypto.SHA384, true
	case AlgSHA512:
		return crypto.SHA512, true
	}
	return 0, false
}

// newHash returns a fresh hash.Hash for alg, or nil if unsupported.
func newHash(alg uint16) hash.Hash {
	if h, ok := cryptoHash(alg); ok {
		return h.New()
	}
	return nil
}

// hashSum returns H(parts…) under alg, or nil if alg is unsupported.
func hashSum(alg uint16, parts ...[]byte) []byte {
	h := newHash(alg)
	if h == nil {
		return nil
	}
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// hmacSum returns HMAC(key, parts…) under alg, or nil if alg is unsupported.
func hmacSum(alg uint16, key []byte, parts ...[]byte) []byte {
	h, ok := cryptoHash(alg)
	if !ok {
		return nil
	}
	m := hmac.New(h.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// kdfa implements KDFa (TPM 2.0 Part 1, §11.4.10.2): SP800-108 counter-mode
// HMAC. It derives bits bits of key material; the label is the use string
// (without its terminating null, which kdfa appends). The high bits of the first
// output byte are masked when bits is not a multiple of 8.
func kdfa(alg uint16, key, label, contextU, contextV []byte, bits int) []byte {
	h, ok := cryptoHash(alg)
	if !ok || bits <= 0 {
		return nil
	}
	var sizeBuf [4]byte
	binary.BigEndian.PutUint32(sizeBuf[:], uint32(bits))

	out := make([]byte, 0, (bits+7)/8)
	for i := uint32(1); len(out)*8 < bits; i++ {
		m := hmac.New(h.New, key)
		var ctr [4]byte
		binary.BigEndian.PutUint32(ctr[:], i)
		m.Write(ctr[:])
		m.Write(label)
		m.Write([]byte{0x00}) // terminating null of the label
		m.Write(contextU)
		m.Write(contextV)
		m.Write(sizeBuf[:])
		out = append(out, m.Sum(nil)...)
	}
	out = out[:(bits+7)/8]
	if rem := bits % 8; rem != 0 {
		out[0] &= byte(1<<rem) - 1 // mask the unused most-significant bits
	}
	return out
}

// detReader is a deterministic byte stream H_alg(seed ‖ counter), used to derive
// primary keys reproducibly from a primary seed. The same seed always yields the
// same key, so a recreated primary (e.g. the SRK) can load objects sealed under a
// previous instance of it.
type detReader struct {
	alg  uint16
	seed []byte
	ctr  uint32
	buf  []byte
}

func (d *detReader) Read(p []byte) (int, error) {
	for len(d.buf) < len(p) {
		d.buf = append(d.buf, hashSum(d.alg, d.seed, be32(d.ctr))...)
		d.ctr++
	}
	n := copy(p, d.buf)
	d.buf = d.buf[n:]
	return n, nil
}

// curveFor maps a TPM_ECC_CURVE to a Go elliptic curve, or nil if unsupported.
func curveFor(curveID uint16) elliptic.Curve {
	switch curveID {
	case ECCNistP256:
		return elliptic.P256()
	case ECCNistP384:
		return elliptic.P384()
	}
	return nil
}

// padLeft left-pads b with zeroes to exactly n bytes (a fixed-width TPM2B field).
func padLeft(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// derivePrime draws candidates from r until one is a prime usable with the TPM
// exponent. The top two bits are forced so the product of two such primes has the
// full modulus width. The derivation is fully determined by r — unlike
// crypto/rsa.GenerateKey, which reads an extra random byte to defeat determinism.
func derivePrime(r io.Reader, bits int) (*big.Int, error) {
	n := (bits + 7) / 8
	buf := make([]byte, n)
	one := big.NewInt(1)
	e := big.NewInt(rsaExponent)
	for {
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		buf[0] |= 0xC0   // force the two most-significant bits
		buf[n-1] |= 0x01 // force odd
		p := new(big.Int).SetBytes(buf)
		if !p.ProbablyPrime(20) {
			continue
		}
		pm1 := new(big.Int).Sub(p, one)
		if new(big.Int).GCD(nil, nil, e, pm1).Cmp(one) == 0 { // e must be invertible mod p-1
			return p, nil
		}
	}
}

// deriveRSAKey deterministically derives an RSA key of the given size from r and
// returns the modulus and the first prime (what a TPMT_SENSITIVE stores).
func deriveRSAKey(r io.Reader, bits int) (modulus, prime []byte, err error) {
	for {
		p, err := derivePrime(r, bits/2)
		if err != nil {
			return nil, nil, err
		}
		q, err := derivePrime(r, bits/2)
		if err != nil {
			return nil, nil, err
		}
		if p.Cmp(q) == 0 {
			continue
		}
		modN := new(big.Int).Mul(p, q)
		if modN.BitLen() != bits {
			continue
		}
		return padLeft(modN.Bytes(), bits/8), padLeft(p.Bytes(), bits/16), nil
	}
}

// deriveECCKey deterministically derives an ECC key on curve from r: the private
// scalar is reduced into [1, n-1] and the public point is d·G. ScalarBaseMult is
// deterministic, so the same r yields the same key.
func deriveECCKey(r io.Reader, curve elliptic.Curve) (x, y, d []byte, err error) {
	params := curve.Params()
	n := (params.BitSize + 7) / 8
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, nil, nil, err
	}
	k := new(big.Int).SetBytes(buf)
	k.Mod(k, new(big.Int).Sub(params.N, big.NewInt(1)))
	k.Add(k, big.NewInt(1)) // scalar in [1, n-1]
	// ScalarBaseMult is the deterministic primitive we need here; the crypto/ecdh
	// replacement reintroduces the non-determinism we are specifically avoiding.
	px, py := curve.ScalarBaseMult(k.Bytes()) //nolint:staticcheck // deterministic derivation

	return padLeft(px.Bytes(), n), padLeft(py.Bytes(), n), padLeft(k.Bytes(), n), nil
}

// rsaPrivateKey reconstructs an RSA private key from a TPM object's modulus and
// stored prime (TPMT_SENSITIVE keeps one prime; the other is N/p).
func rsaPrivateKey(modulus, prime []byte, exp uint32) *rsa.PrivateKey {
	if exp == 0 {
		exp = rsaExponent
	}
	n := new(big.Int).SetBytes(modulus)
	p := new(big.Int).SetBytes(prime)
	q := new(big.Int).Div(n, p)
	one := big.NewInt(1)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: n, E: int(exp)},
		D:         new(big.Int).ModInverse(big.NewInt(int64(exp)), phi),
		Primes:    []*big.Int{p, q},
	}
	priv.Precompute()
	return priv
}

// eccPrivateKey reconstructs an ECDSA private key from a TPM object's scalar.
func eccPrivateKey(curve elliptic.Curve, d []byte) *ecdsa.PrivateKey {
	priv := &ecdsa.PrivateKey{D: new(big.Int).SetBytes(d)}
	priv.Curve = curve
	priv.X, priv.Y = curve.ScalarBaseMult(d) //nolint:staticcheck // raw point from scalar
	return priv
}

// kdfe implements KDFe (TPM 2.0 Part 1, §11.4.10.3): the SP800-56A concatenation
// KDF used for ECDH secret derivation. z is the shared secret; the label is
// appended with a terminating null.
func kdfe(alg uint16, z, label, partyU, partyV []byte, bits int) []byte {
	h := newHash(alg)
	if h == nil || bits <= 0 {
		return nil
	}
	out := make([]byte, 0, (bits+7)/8)
	for i := uint32(1); len(out)*8 < bits; i++ {
		h.Reset()
		var ctr [4]byte
		binary.BigEndian.PutUint32(ctr[:], i)
		h.Write(ctr[:])
		h.Write(z)
		h.Write(label)
		h.Write([]byte{0x00})
		h.Write(partyU)
		h.Write(partyV)
		out = append(out, h.Sum(nil)...)
	}
	out = out[:(bits+7)/8]
	if rem := bits % 8; rem != 0 {
		out[0] &= byte(1<<rem) - 1
	}
	return out
}
