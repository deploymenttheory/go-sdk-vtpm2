// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package client

// Ready-made object templates, so callers never hand-roll a TPMT_PUBLIC. Each
// returns a fresh value you can tweak before use (e.g. change NameAlg or Curve).

const (
	attrPrimary = AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrNoDA
)

// ECCStorageKey is a restricted ECC (P-256) decryption key — the shape of an SRK /
// storage parent (AES-128-CFB inner symmetric).
func ECCStorageKey() Public {
	return Public{
		Type:    AlgECC,
		NameAlg: AlgSHA256,
		Attrs:   attrPrimary | AttrRestricted | AttrDecrypt,
		Sym:     SymDef{Alg: AlgAES, KeyBits: 128, Mode: AlgCFB},
		Scheme:  Scheme{Alg: AlgNull},
		Curve:   ECCNistP256,
		KDF:     Scheme{Alg: AlgNull},
	}
}

// RSAStorageKey is a restricted RSA-2048 decryption key (storage parent shape).
func RSAStorageKey() Public {
	return Public{
		Type:    AlgRSA,
		NameAlg: AlgSHA256,
		Attrs:   attrPrimary | AttrRestricted | AttrDecrypt,
		Sym:     SymDef{Alg: AlgAES, KeyBits: 128, Mode: AlgCFB},
		Scheme:  Scheme{Alg: AlgNull},
		KeyBits: 2048,
	}
}

// ECCSigningKey is an unrestricted ECC (P-256) signing key (ECDSA / SHA-256).
func ECCSigningKey() Public {
	return Public{
		Type:    AlgECC,
		NameAlg: AlgSHA256,
		Attrs:   attrPrimary | AttrSign,
		Sym:     SymDef{Alg: AlgNull},
		Scheme:  Scheme{Alg: AlgECDSA, Hash: AlgSHA256},
		Curve:   ECCNistP256,
		KDF:     Scheme{Alg: AlgNull},
	}
}

// RSASigningKey is an unrestricted RSA-2048 signing key (RSASSA / SHA-256).
func RSASigningKey() Public {
	return Public{
		Type:    AlgRSA,
		NameAlg: AlgSHA256,
		Attrs:   attrPrimary | AttrSign,
		Sym:     SymDef{Alg: AlgNull},
		Scheme:  Scheme{Alg: AlgRSASSA, Hash: AlgSHA256},
		KeyBits: 2048,
	}
}

// HMACKey is a keyed-hash HMAC (SHA-256) key.
func HMACKey() Public {
	return Public{
		Type:    AlgKeyedHash,
		NameAlg: AlgSHA256,
		Attrs:   attrPrimary | AttrSign,
		Scheme:  Scheme{Alg: AlgHMAC, Hash: AlgSHA256},
	}
}
