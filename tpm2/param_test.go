// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"testing"
)

// startEncryptSession opens an unbound HMAC session whose symmetric is AES-128-CFB
// (for parameter/response encryption) and returns its handle and nonceTPM.
func startEncryptSession(t *testing.T, tpm *TPM, authHash uint16) (uint32, []byte) {
	t.Helper()
	var w writer
	w.u32(RHNull)
	w.u32(RHNull)
	w.tpm2b(bytes.Repeat([]byte{0x5a}, 16))
	w.tpm2b(nil)
	w.u8(seHMAC)
	w.u16(AlgAES) // symmetric: AES-128-CFB
	w.u16(128)
	w.u16(AlgCFB)
	w.u16(authHash)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCStartAuthSession, w.bytes())))
	if rc != RCSuccess {
		t.Fatalf("StartAuthSession rc = 0x%x", rc)
	}
	r := newReader(p)
	h := r.u32()
	return h, r.tpm2b()
}

// TestCreateWithCommandDecryption drives a decrypt session: the inSensitive (the
// data to seal) is sent AES-CFB-encrypted, and the TPM decrypts it before sealing.
// The command HMAC (and so the test) computes cpHash over the PLAINTEXT params.
func TestCreateWithCommandDecryption(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	parent, _ := tpm.objects.get(srk)

	sh, nonceTPM := startEncryptSession(t, tpm, AlgSHA256)
	nonceCaller := bytes.Repeat([]byte{0x66}, 16)
	attrs := attrDecrypt | attrContinue

	// inSensitive buffer (plaintext): userAuth ‖ data.
	sealData := []byte("seal-me-via-decrypt-session")
	var sensBuf writer
	sensBuf.tpm2b(nil)
	sensBuf.tpm2b(sealData)
	plainBuffer := sensBuf.bytes()

	tmpl := sealedTemplate()
	var pubW writer
	tmpl.marshal2B(&pubW)
	var rest writer
	rest.tpm2b(nil) // outsideInfo
	rest.u32(0)     // creationPCR

	// cpHash is over the plaintext parameters.
	var plainCp writer
	plainCp.tpm2b(plainBuffer)
	plainCp.raw(pubW.bytes())
	plainCp.raw(rest.bytes())
	cph := cpHash(AlgSHA256, CCCreate, [][]byte{parent.name}, plainCp.bytes())
	mac := commandAuthHMAC(AlgSHA256, nil, cph, nonceCaller, nonceTPM, attrs)

	// Encrypt only the first parameter's buffer for transmission.
	ki := kdfa(AlgSHA256, nil, []byte("CFB"), nonceCaller, nonceTPM, 128+128)
	encBuffer := aesCFB(ki[:16], ki[16:32], plainBuffer, true)
	var encCp writer
	encCp.tpm2b(encBuffer)
	encCp.raw(pubW.bytes())
	encCp.raw(rest.bytes())

	var auth writer
	auth.u32(sh)
	auth.tpm2b(nonceCaller)
	auth.u8(attrs)
	auth.tpm2b(mac)
	var body writer
	body.u32(srk)
	body.u32(uint32(len(auth.bytes())))
	body.raw(auth.bytes())
	body.raw(encCp.bytes())
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCCreate, body.bytes())))
	if rc != RCSuccess {
		t.Fatalf("Create(decrypt session) rc = 0x%x", rc)
	}

	// Load the result and confirm the sealed data survived decryption.
	r := newReader(p)
	_ = r.u32() // parameterSize
	priv := r.tpm2b()
	pub := readPublic2B(r)
	h, lrc := loadObject(t, tpm, srk, priv, pub)
	if lrc != RCSuccess {
		t.Fatalf("Load rc = 0x%x", lrc)
	}
	obj, _ := tpm.objects.get(h)
	if !bytes.Equal(obj.sensitive.Secret, sealData) {
		t.Fatalf("decrypted sealed data = %q, want %q", obj.sensitive.Secret, sealData)
	}
}

// TestUnsealWithResponseEncryption drives an encrypt session the way a TSS does:
// the Unseal response (the VMK) comes back AES-CFB-encrypted, and the test derives
// the same key to recover it.
func TestUnsealWithResponseEncryption(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	vmk := []byte("secret-volume-master-key-32byte!")
	priv, pub := createSealed(t, tpm, srk, vmk)
	h, _ := loadObject(t, tpm, srk, priv, pub)
	obj, _ := tpm.objects.get(h)

	sh, nonceTPM := startEncryptSession(t, tpm, AlgSHA256)
	nonceCaller := bytes.Repeat([]byte{0x77}, 16)
	attrs := attrEncrypt | attrContinue

	// Compute the command auth HMAC (sealed object has empty auth → empty key).
	cph := cpHash(AlgSHA256, CCUnseal, [][]byte{obj.name}, nil)
	mac := commandAuthHMAC(AlgSHA256, nil, cph, nonceCaller, nonceTPM, attrs)

	var auth writer
	auth.u32(sh)
	auth.tpm2b(nonceCaller)
	auth.u8(attrs)
	auth.tpm2b(mac)
	var body writer
	body.u32(h)
	body.u32(uint32(len(auth.bytes())))
	body.raw(auth.bytes())
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCUnseal, body.bytes())))
	if rc != RCSuccess {
		t.Fatalf("Unseal(encrypt session) rc = 0x%x", rc)
	}

	r := newReader(p)
	paramArea := r.bytes(int(r.u32())) // outData, with its data encrypted
	respNonce := r.tpm2b()
	if r.err != nil {
		t.Fatalf("parse response: %v", r.err)
	}

	// The plaintext outData must NOT appear; decrypting with the session key must.
	encData := newReader(paramArea).tpm2b()
	if bytes.Equal(encData, vmk) {
		t.Fatal("response parameter was not encrypted")
	}
	ki := kdfa(AlgSHA256, nil, []byte("CFB"), respNonce, nonceCaller, 128+128)
	plain := aesCFB(ki[:16], ki[16:32], encData, false)
	if !bytes.Equal(plain, vmk) {
		t.Fatalf("decrypted response = %q, want %q", plain, vmk)
	}
}
