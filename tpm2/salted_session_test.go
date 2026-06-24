// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"testing"
)

// rsaStorageTemplate is a restricted RSA-2048 decryption (storage) key — the
// shape Windows uses for an RSA SRK and the kind of key a salted session targets.
func rsaStorageTemplate() public {
	return public{
		Type:    AlgRSA,
		NameAlg: AlgSHA256,
		Attrs:   ObjFixedTPM | ObjFixedParent | ObjSensitiveDataOrigin | ObjUserWithAuth | ObjRestricted | ObjDecrypt | ObjNoDA,
		Sym:     symDef{Alg: AlgAES, KeyBits: 128, Mode: AlgCFB},
		Scheme:  hashScheme{Scheme: AlgNull},
		KeyBits: 2048,
	}
}

// TestSaltedSessionRSA is the Windows/BitLocker remediation check: a session
// salted to an RSA SRK must decrypt the OAEP-wrapped salt and fold it into the
// session key (TPM 2.0 Part 1, §19.6.7). Previously such a session was rejected.
func TestSaltedSessionRSA(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, pub, _ := createPrimary(t, tpm, RHOwner, rsaStorageTemplate())

	// Caller side (the TSS): encrypt a salt to the SRK public with RSAES-OAEP and
	// the TPM secret-sharing label "SECRET\0".
	salt := bytes.Repeat([]byte{0x3c}, sha256.Size)
	rsaPub := &rsa.PublicKey{N: new(big.Int).SetBytes(pub.Unique), E: 65537}
	encSalt, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, salt, append([]byte("SECRET"), 0))
	if err != nil {
		t.Fatalf("OAEP encrypt salt: %v", err)
	}

	nonceCaller := bytes.Repeat([]byte{0x5a}, 16)
	var w writer
	w.u32(srk)    // tpmKey (salted)
	w.u32(RHNull) // bind (unbound)
	w.tpm2b(nonceCaller)
	w.tpm2b(encSalt) // encryptedSalt
	w.u8(seHMAC)
	w.u16(AlgNull)   // symmetric
	w.u16(AlgSHA256) // authHash
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCStartAuthSession, w.bytes())))
	if rc != RCSuccess {
		t.Fatalf("salted StartAuthSession rc = 0x%x", rc)
	}
	r := newReader(p)
	h := r.u32()
	nonceTPM := r.tpm2b()
	if r.err != nil {
		t.Fatalf("parse response: %v", r.err)
	}

	// The TPM must have recovered the same salt: unbound ⇒ sessionKey =
	// KDFa(authHash, salt, "ATH", nonceTPM, nonceCaller, bits).
	want := kdfa(AlgSHA256, salt, []byte("ATH"), nonceTPM, nonceCaller, sha256.Size*8)
	as, ok := tpm.sessions.get(h)
	if !ok {
		t.Fatal("session not found after StartAuthSession")
	}
	if !bytes.Equal(as.sessionKey, want) {
		t.Fatal("session key does not incorporate the decrypted salt — salt recovery is wrong")
	}
}

// TestSaltedSessionECC validates the ECDH salt path against an ECC SRK (the
// common Windows SRK). The caller does one-pass ECDH to an ephemeral key and
// KDFe-derives the salt; the TPM must arrive at the same value.
func TestSaltedSessionECC(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, pub, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())

	curve := elliptic.P256()
	const n = 32
	de, err := rand.Int(rand.Reader, curve.Params().N) // ephemeral scalar
	if err != nil {
		t.Fatal(err)
	}
	qeX, qeY := curve.ScalarBaseMult(de.Bytes()) // ephemeral public point
	qsX, qsY := new(big.Int).SetBytes(pub.UniqueX), new(big.Int).SetBytes(pub.UniqueY)
	zx, _ := curve.ScalarMult(qsX, qsY, de.Bytes()) // Z = de · Q_static
	salt := kdfe(AlgSHA256, padLeft(zx.Bytes(), n), []byte("SECRET"),
		padLeft(qeX.Bytes(), n), padLeft(pub.UniqueX, n), sha256.Size*8)

	// encryptedSalt = TPMS_ECC_POINT(Q_ephemeral).
	var ep writer
	ep.tpm2b(padLeft(qeX.Bytes(), n))
	ep.tpm2b(padLeft(qeY.Bytes(), n))

	nonceCaller := bytes.Repeat([]byte{0x5a}, 16)
	var w writer
	w.u32(srk)
	w.u32(RHNull)
	w.tpm2b(nonceCaller)
	w.tpm2b(ep.bytes())
	w.u8(seHMAC)
	w.u16(AlgNull)
	w.u16(AlgSHA256)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCStartAuthSession, w.bytes())))
	if rc != RCSuccess {
		t.Fatalf("salted (ECC) StartAuthSession rc = 0x%x", rc)
	}
	r := newReader(p)
	h := r.u32()
	nonceTPM := r.tpm2b()
	if r.err != nil {
		t.Fatalf("parse response: %v", r.err)
	}
	want := kdfa(AlgSHA256, salt, []byte("ATH"), nonceTPM, nonceCaller, sha256.Size*8)
	as, ok := tpm.sessions.get(h)
	if !ok {
		t.Fatal("session not found")
	}
	if !bytes.Equal(as.sessionKey, want) {
		t.Fatal("ECC salt recovery mismatch — KDFe/ECDH path is wrong")
	}
}

// TestSaltedSessionRejectsUnloadedKey keeps the error path honest: a tpmKey that
// is not loaded is RC_HANDLE on the first handle.
func TestSaltedSessionRejectsUnloadedKey(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	var w writer
	w.u32(0x80FFFFFF) // tpmKey: not loaded
	w.u32(RHNull)
	w.tpm2b(bytes.Repeat([]byte{0x5a}, 16))
	w.tpm2b([]byte{0x00, 0x01, 0x02})
	w.u8(seHMAC)
	w.u16(AlgNull)
	w.u16(AlgSHA256)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCStartAuthSession, w.bytes()))); baseRC(rc) != RCHandle {
		t.Fatalf("rc = 0x%x, want RC_HANDLE", rc)
	}
}
