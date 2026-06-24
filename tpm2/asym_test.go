// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"crypto/elliptic"
	"math/big"
	"testing"
)

// rsaDecryptTemplate is an unrestricted RSA decryption key (caller picks the
// padding scheme) — the kind TPM2_RSA_Decrypt requires.
func rsaDecryptTemplate() public {
	return public{
		Type:    AlgRSA,
		NameAlg: AlgSHA256,
		Attrs:   ObjFixedTPM | ObjFixedParent | ObjSensitiveDataOrigin | ObjUserWithAuth | ObjDecrypt | ObjNoDA,
		Sym:     symDef{Alg: AlgNull},
		Scheme:  hashScheme{Scheme: AlgNull},
		KeyBits: 2048,
	}
}

// eccKeyTemplate is an unrestricted ECC-P256 key usable for ECDH.
func eccKeyTemplate() public {
	return public{
		Type:    AlgECC,
		NameAlg: AlgSHA256,
		Attrs:   ObjFixedTPM | ObjFixedParent | ObjSensitiveDataOrigin | ObjUserWithAuth | ObjDecrypt | ObjNoDA,
		Sym:     symDef{Alg: AlgNull},
		Scheme:  hashScheme{Scheme: AlgNull},
		Curve:   ECCNistP256,
		KDF:     hashScheme{Scheme: AlgNull},
	}
}

func TestRSAEncryptDecrypt(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	keyH, _, _ := createPrimary(t, tpm, RHOwner, rsaDecryptTemplate())
	msg := []byte("BitLocker VMK-ish secret")

	for _, sc := range []struct {
		name   string
		scheme uint16
	}{{"OAEP", AlgOAEP}, {"RSAES", AlgRSAES}} {
		// RSA_Encrypt (no authorization).
		var eb writer
		eb.u32(keyH)
		eb.tpm2b(msg)
		eb.u16(sc.scheme)
		if sc.scheme == AlgOAEP {
			eb.u16(AlgSHA256)
		}
		eb.tpm2b(nil) // label
		_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCRSAEncrypt, eb.bytes())))
		if rc != RCSuccess {
			t.Fatalf("%s RSA_Encrypt rc = 0x%x", sc.name, rc)
		}
		cipher := newReader(p).tpm2b()
		if bytes.Equal(cipher, msg) || len(cipher) != 256 {
			t.Fatalf("%s ciphertext looks wrong (len %d)", sc.name, len(cipher))
		}

		// RSA_Decrypt (object authorization).
		var db writer
		db.tpm2b(cipher)
		db.u16(sc.scheme)
		if sc.scheme == AlgOAEP {
			db.u16(AlgSHA256)
		}
		db.tpm2b(nil)
		_, rc2, p2 := parseResp(t, tpm.Execute(buildHierarchyCmd(CCRSADecrypt, keyH, nil, db.bytes())))
		if rc2 != RCSuccess {
			t.Fatalf("%s RSA_Decrypt rc = 0x%x", sc.name, rc2)
		}
		r := newReader(p2)
		_ = r.u32() // parameterSize
		if got := r.tpm2b(); !bytes.Equal(got, msg) {
			t.Fatalf("%s round-trip recovered %q, want %q", sc.name, got, msg)
		}
	}
}

// TestRSADecryptRejectsRestricted confirms a restricted key cannot be used for
// general decryption (TPM 2.0 Part 3, §14.3).
func TestRSADecryptRejectsRestricted(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	keyH, _, _ := createPrimary(t, tpm, RHOwner, rsaStorageTemplate()) // restricted decrypt
	var db writer
	db.tpm2b(bytes.Repeat([]byte{0}, 256))
	db.u16(AlgOAEP)
	db.u16(AlgSHA256)
	db.tpm2b(nil)
	if _, rc, _ := parseResp(t, tpm.Execute(buildHierarchyCmd(CCRSADecrypt, keyH, nil, db.bytes()))); baseRC(rc) != RCAttributes {
		t.Fatalf("restricted RSA_Decrypt rc = 0x%x, want RC_ATTRIBUTES", rc)
	}
}

// TestECDHKeyGenZGen verifies the ECDH identity: ZGen([ds], pubPoint) reproduces
// the zPoint from KeyGen, since [ds]([de]G) = [de]([ds]G) = [de]Qs.
func TestECDHKeyGenZGen(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	keyH, _, _ := createPrimary(t, tpm, RHOwner, eccKeyTemplate())

	var kb writer
	kb.u32(keyH)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCECDHKeyGen, kb.bytes())))
	if rc != RCSuccess {
		t.Fatalf("ECDH_KeyGen rc = 0x%x", rc)
	}
	r := newReader(p)
	zX, zY := readECCPoint(r)   // zPoint = [de]Qs
	qeX, qeY := readECCPoint(r) // pubPoint = [de]G
	if r.err != nil {
		t.Fatalf("parse KeyGen: %v", r.err)
	}

	var zb writer
	writeECCPoint(&zb, qeX, qeY)
	_, rc2, p2 := parseResp(t, tpm.Execute(buildHierarchyCmd(CCECDHZGen, keyH, nil, zb.bytes())))
	if rc2 != RCSuccess {
		t.Fatalf("ECDH_ZGen rc = 0x%x", rc2)
	}
	rr := newReader(p2)
	_ = rr.u32()
	oX, oY := readECCPoint(rr)
	if !bytes.Equal(oX, zX) || !bytes.Equal(oY, zY) {
		t.Fatal("ECDH_ZGen(pubPoint) does not reproduce KeyGen's zPoint")
	}
}

func TestECCParameters(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	var b writer
	b.u16(ECCNistP256)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCECCParameters, b.bytes())))
	if rc != RCSuccess {
		t.Fatalf("ECC_Parameters rc = 0x%x", rc)
	}
	r := newReader(p)
	if cid := r.u16(); cid != ECCNistP256 {
		t.Fatalf("curveID = 0x%x", cid)
	}
	if ks := r.u16(); ks != 256 {
		t.Fatalf("keySize = %d, want 256", ks)
	}
	_, _ = r.u16(), r.u16() // kdf, sign (NULL)
	p256 := elliptic.P256().Params()
	if got := new(big.Int).SetBytes(r.tpm2b()); got.Cmp(p256.P) != 0 {
		t.Fatal("field prime p does not match NIST P-256")
	}
	_ = r.tpm2b() // a
	if got := new(big.Int).SetBytes(r.tpm2b()); got.Cmp(p256.B) != 0 {
		t.Fatal("coefficient b does not match NIST P-256")
	}

	// Unsupported curve ⇒ TPM_RC_VALUE.
	var bad writer
	bad.u16(0x9999)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCECCParameters, bad.bytes()))); baseRC(rc) != RCValue {
		t.Fatalf("unknown curve rc = 0x%x, want RC_VALUE", rc)
	}
}
