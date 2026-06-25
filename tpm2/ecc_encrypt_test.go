// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"testing"
)

// eccDecryptTemplate is an unrestricted ECC (P-256) decryption key.
func eccDecryptTemplate() public {
	return public{
		Type:    AlgECC,
		NameAlg: AlgSHA256,
		Attrs:   ObjSensitiveDataOrigin | ObjUserWithAuth | ObjDecrypt | ObjNoDA,
		Sym:     symDef{Alg: AlgNull},
		Scheme:  hashScheme{Scheme: AlgNull},
		Curve:   ECCNistP256,
		KDF:     hashScheme{Scheme: AlgNull},
	}
}

const algKDF1SP80056A = 0x0020 // TPM_ALG_KDF1_SP800_56A

func TestECCEncryptDecrypt(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	keyH := createSigningKey(t, tpm, srk, eccDecryptTemplate())
	msg := []byte("ecc-encrypted-secret-payload")

	// ECC_Encrypt (no authorization).
	var eb writer
	eb.u32(keyH)
	eb.tpm2b(msg)
	eb.u16(algKDF1SP80056A)
	eb.u16(AlgSHA256)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCECCEncrypt, eb.bytes())))
	if rc != RCSuccess {
		t.Fatalf("ECC_Encrypt rc = 0x%x", rc)
	}
	r := newReader(p)
	c1x, c1y := readECCPoint(r)
	c2 := r.tpm2b()
	c3 := r.tpm2b()
	if bytes.Equal(c2, msg) {
		t.Fatal("C2 equals plaintext")
	}

	decryptCmd := func(c3 []byte) (uint32, []byte) {
		var db writer
		db.u32(keyH)
		db.raw(onePasswordAuth())
		writeECCPoint(&db, c1x, c1y)
		db.tpm2b(c2)
		db.tpm2b(c3)
		db.u16(algKDF1SP80056A)
		db.u16(AlgSHA256)
		_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCECCDecrypt, db.bytes())))
		dr := newReader(p)
		if rc == RCSuccess {
			_ = dr.u32()
			return rc, dr.tpm2b()
		}
		return rc, nil
	}

	rc, plain := decryptCmd(c3)
	if rc != RCSuccess {
		t.Fatalf("ECC_Decrypt rc = 0x%x", rc)
	}
	if !bytes.Equal(plain, msg) {
		t.Fatalf("round-trip failed: got %q, want %q", plain, msg)
	}

	// A tampered integrity value C3 is rejected.
	bad := append([]byte(nil), c3...)
	bad[0] ^= 0xFF
	if rc, _ := decryptCmd(bad); baseRC(rc) != RCValue {
		t.Fatalf("tampered-C3 ECC_Decrypt rc = 0x%x, want RC_VALUE", rc)
	}
}
