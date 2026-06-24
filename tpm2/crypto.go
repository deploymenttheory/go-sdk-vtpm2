// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	_ "crypto/sha1"   //nolint:gosec // SHA-1 is a mandated TPM algorithm, not a security control
	_ "crypto/sha256" // register SHA-256
	_ "crypto/sha512" // register SHA-384 / SHA-512
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"math/big"
)

// rsaExponent is the fixed TPM RSA public exponent.
const rsaExponent = 65537

// errUnsupportedCurve is returned when a TPM_ECC_CURVE has no crypto/ecdh backing.
var errUnsupportedCurve = errors.New("tpm2: unsupported ECC curve")

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

// kdfa implements KDFa (TPM 2.0 Part 1, §8.4.10.2): SP800-108 counter-mode
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

// hashDRBG is a NIST SP800-90A §10.1.1 Hash_DRBG, instantiated deterministically
// (no entropy source, no reseed) from a fixed seed so the same inputs always
// reproduce the same byte stream. It backs primary-key derivation:
// the TPM 2.0 spec (Part 1, §24.6.3) seeds a DRBG with the primary seed, a
// template hash and a use string and reinstantiates it to recreate a Primary. A
// real, FIPS-approved DRBG construction replaces the earlier ad-hoc H(seed‖ctr).
type hashDRBG struct {
	h       func() hash.Hash
	outlen  int // hash output, bytes
	seedlen int // SP800-90A seed length, bytes (55 for ≤256-bit, 111 for >256-bit)
	v       []byte
	c       []byte
	rc      uint64
	buf     []byte
}

// newHashDRBG instantiates a Hash_DRBG over alg's hash, with seedMaterial =
// concatenation of the given parts (entropy ‖ nonce ‖ personalization).
func newHashDRBG(alg uint16, parts ...[]byte) *hashDRBG {
	ch, _ := cryptoHash(alg)
	d := &hashDRBG{h: ch.New, outlen: ch.Size()}
	d.seedlen = 55 // SHA-1/SHA-256
	if ch.Size() > 32 {
		d.seedlen = 111 // SHA-384/SHA-512
	}
	var seedMaterial []byte
	for _, p := range parts {
		seedMaterial = append(seedMaterial, p...)
	}
	// Instantiate (SP800-90A 10.1.1.2): seed = Hash_df(seed_material); V = seed;
	// C = Hash_df(0x00 ‖ V); reseed_counter = 1.
	d.v = d.hashDF(seedMaterial, d.seedlen)
	d.c = d.hashDF(append([]byte{0x00}, d.v...), d.seedlen)
	d.rc = 1
	return d
}

// hashDF is the SP800-90A Hash derivation function (10.3.1).
func (d *hashDRBG) hashDF(input []byte, nbytes int) []byte {
	out := make([]byte, 0, ((nbytes+d.outlen-1)/d.outlen)*d.outlen)
	var nbits [4]byte
	binary.BigEndian.PutUint32(nbits[:], uint32(nbytes*8))
	for counter := byte(1); len(out) < nbytes; counter++ {
		hh := d.h()
		hh.Write([]byte{counter})
		hh.Write(nbits[:])
		hh.Write(input)
		out = hh.Sum(out)
	}
	return out[:nbytes]
}

// addInto computes dst = (dst + add) mod 2^(seedlen*8), big-endian, in place.
func (d *hashDRBG) addInto(dst, add []byte) {
	carry := 0
	for i := len(dst) - 1; i >= 0; i-- {
		j := i - (len(dst) - len(add))
		s := int(dst[i]) + carry
		if j >= 0 {
			s += int(add[j])
		}
		dst[i] = byte(s)
		carry = s >> 8
	}
}

// generate produces nbytes of output and updates the state (SP800-90A 10.1.1.4).
func (d *hashDRBG) generate(nbytes int) []byte {
	// Hashgen: data = V; W = H(data); data++ ; …
	data := append([]byte(nil), d.v...)
	out := make([]byte, 0, nbytes)
	one := []byte{0x01}
	for len(out) < nbytes {
		hh := d.h()
		hh.Write(data)
		out = hh.Sum(out)
		d.addInto(data, one)
	}
	out = out[:nbytes]
	// V = (V + H(0x03 ‖ V) + C + reseed_counter) mod 2^seedlen.
	hh := d.h()
	hh.Write([]byte{0x03})
	hh.Write(d.v)
	d.addInto(d.v, hh.Sum(nil))
	d.addInto(d.v, d.c)
	var rc [8]byte
	binary.BigEndian.PutUint64(rc[:], d.rc)
	d.addInto(d.v, rc[:])
	d.rc++
	return out
}

// Read streams DRBG output, refilling a generate-block at a time so the byte
// stream is independent of the caller's read sizes.
func (d *hashDRBG) Read(p []byte) (int, error) {
	for len(d.buf) < len(p) {
		d.buf = append(d.buf, d.generate(d.seedlen)...)
	}
	n := copy(p, d.buf)
	d.buf = d.buf[n:]
	return n, nil
}

// curveFor maps a TPM_ECC_CURVE to a Go elliptic curve, or nil if unsupported.
// Used for ECDSA, which the crypto/ecdh package cannot do.
func curveFor(curveID uint16) elliptic.Curve {
	switch curveID {
	case ECCNistP256:
		return elliptic.P256()
	case ECCNistP384:
		return elliptic.P384()
	case ECCNistP521:
		return elliptic.P521()
	}
	return nil
}

// ecdhCurveFor maps a TPM_ECC_CURVE to a crypto/ecdh curve, or nil if
// unsupported. crypto/ecdh provides deterministic, constant-time point
// operations (NewPrivateKey is a pure function of the scalar), which is what the
// deterministic key derivation and the salt ECDH need.
func ecdhCurveFor(curveID uint16) ecdh.Curve {
	switch curveID {
	case ECCNistP256:
		return ecdh.P256()
	case ECCNistP384:
		return ecdh.P384()
	case ECCNistP521:
		return ecdh.P521()
	}
	return nil
}

// eccPointFromScalar computes the public point d·G on the curve using crypto/ecdh
// (deterministic), returning fixed-width X and Y. ok is false if d is not a valid
// scalar for the curve.
func eccPointFromScalar(c ecdh.Curve, d []byte, size int) (x, y []byte, ok bool) {
	priv, err := c.NewPrivateKey(padLeft(d, size))
	if err != nil {
		return nil, nil, false
	}
	b := priv.PublicKey().Bytes() // 0x04 ‖ X ‖ Y (uncompressed)
	if len(b) != 1+2*size {
		return nil, nil, false
	}
	return b[1 : 1+size], b[1+size:], true
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
// scalar is reduced into [1, n-1] and the public point is d·G, computed with
// crypto/ecdh's NewPrivateKey (a pure function of the scalar, so the same r yields
// the same key). curveID selects the matching crypto/ecdh curve.
func deriveECCKey(r io.Reader, curve elliptic.Curve, curveID uint16) (x, y, d []byte, err error) {
	params := curve.Params()
	n := (params.BitSize + 7) / 8
	c := ecdhCurveFor(curveID)
	if c == nil {
		return nil, nil, nil, errUnsupportedCurve
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, nil, nil, err
	}
	k := new(big.Int).SetBytes(buf)
	k.Mod(k, new(big.Int).Sub(params.N, big.NewInt(1)))
	k.Add(k, big.NewInt(1)) // scalar in [1, n-1]
	px, py, ok := eccPointFromScalar(c, k.Bytes(), n)
	if !ok {
		return nil, nil, nil, errUnsupportedCurve
	}
	return px, py, padLeft(k.Bytes(), n), nil
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

// decryptSalt recovers the session salt that a caller encrypted to a loaded
// decryption key, for a salted TPM2_StartAuthSession (TPM 2.0 Part 1, §19.6.7 and
// the secret-sharing scheme of §C.6.1 / Part 4 CryptSecretDecrypt). Windows uses
// this to establish a confidential session for the BitLocker VMK. RSA keys carry
// the salt as an RSAES-OAEP blob under the label "SECRET\0"; ECC keys carry an
// ephemeral public point and the salt is KDFe over the one-pass ECDH secret with
// the label "SECRET". The salt length is the key's name-algorithm digest size.
func decryptSalt(o *object, encryptedSecret []byte, rng io.Reader) ([]byte, bool) {
	switch o.public.Type {
	case AlgRSA:
		h := newHash(o.public.NameAlg)
		if h == nil {
			return nil, false
		}
		priv := rsaPrivateKey(o.public.Unique, o.sensitive.Secret, o.public.Exp)
		// The TPM OAEP label is the null-terminated string "SECRET".
		salt, err := rsa.DecryptOAEP(h, rng, priv, encryptedSecret, append([]byte("SECRET"), 0))
		if err != nil {
			return nil, false
		}
		return salt, true
	case AlgECC:
		c := ecdhCurveFor(o.public.Curve)
		ec := curveFor(o.public.Curve)
		if c == nil || ec == nil {
			return nil, false
		}
		n := (ec.Params().BitSize + 7) / 8
		// encryptedSecret is a TPMS_ECC_POINT: the caller's ephemeral public point.
		r := newReader(encryptedSecret)
		qeX := r.tpm2b()
		qeY := r.tpm2b()
		if r.err != nil {
			return nil, false
		}
		// One-pass ECDH: the shared secret is the X coordinate of d_static·Q_ephemeral.
		uncompressed := append(append([]byte{0x04}, padLeft(qeX, n)...), padLeft(qeY, n)...)
		remote, err := c.NewPublicKey(uncompressed)
		if err != nil {
			return nil, false
		}
		priv, err := c.NewPrivateKey(padLeft(o.sensitive.Secret, n))
		if err != nil {
			return nil, false
		}
		z, err := priv.ECDH(remote)
		if err != nil {
			return nil, false
		}
		// salt = KDFe(nameAlg, Z.x, "SECRET", Q_ephemeral.x, Q_static.x, digestBits).
		salt := kdfe(o.public.NameAlg, z, []byte("SECRET"),
			padLeft(qeX, n), padLeft(o.public.UniqueX, n), hashSize(o.public.NameAlg)*8)
		return salt, true
	}
	return nil, false
}

// eccPrivateKey reconstructs an ECDSA private key from a TPM object's scalar. The
// public point comes from crypto/ecdh (deterministic); ECDSA itself still needs an
// *ecdsa.PrivateKey, whose coordinate fields must be set from the derived point.
func eccPrivateKey(curve elliptic.Curve, curveID uint16, d []byte) *ecdsa.PrivateKey {
	priv := &ecdsa.PrivateKey{D: new(big.Int).SetBytes(d)}
	priv.Curve = curve
	if c := ecdhCurveFor(curveID); c != nil {
		if x, y, ok := eccPointFromScalar(c, d, (curve.Params().BitSize+7)/8); ok {
			priv.X = new(big.Int).SetBytes(x) //nolint:staticcheck // building a valid key from a raw scalar
			priv.Y = new(big.Int).SetBytes(y) //nolint:staticcheck // building a valid key from a raw scalar
		}
	}
	return priv
}

// kdfe implements KDFe (TPM 2.0 Part 1, §8.4.10.3): the SP800-56A concatenation
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
