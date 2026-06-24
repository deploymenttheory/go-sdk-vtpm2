// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"testing"
)

// symCipherTemplate is an AES-128 SYMCIPHER key usable for encrypt and decrypt.
func symCipherTemplate(mode uint16) public {
	return public{
		Type:    AlgSymCipher,
		NameAlg: AlgSHA256,
		Attrs:   ObjSensitiveDataOrigin | ObjUserWithAuth | ObjSign | ObjDecrypt | ObjNoDA,
		Sym:     symDef{Alg: AlgAES, KeyBits: 128, Mode: mode},
	}
}

// encDec runs TPM2_EncryptDecrypt (or _2) and returns outData.
func encDec(t *testing.T, tpm *TPM, cc, keyH uint32, decrypt byte, mode uint16, iv, data []byte) []byte {
	t.Helper()
	var body writer
	body.u32(keyH)
	body.raw(onePasswordAuth())
	if cc == CCEncryptDecrypt2 {
		body.tpm2b(data)
		body.u8(decrypt)
		body.u16(mode)
		body.tpm2b(iv)
	} else {
		body.u8(decrypt)
		body.u16(mode)
		body.tpm2b(iv)
		body.tpm2b(data)
	}
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, cc, body.bytes())))
	if rc != RCSuccess {
		t.Fatalf("EncryptDecrypt(cc=0x%x) rc = 0x%x", cc, rc)
	}
	r := newReader(p)
	_ = r.u32() // parameterSize
	return r.tpm2b()
}

func TestEncryptDecrypt(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	iv := make([]byte, 16)

	for _, tc := range []struct {
		name string
		mode uint16
		data []byte
	}{
		{"CFB", AlgCFB, []byte("a thirteen!!!")},        // partial block (stream)
		{"CTR", AlgCTR, []byte("counter-mode data!")},   // partial block (stream)
		{"CBC", AlgCBC, bytes.Repeat([]byte{0x41}, 32)}, // block-aligned
		{"OFB", AlgOFB, []byte("ofb stream bytes")},
		{"ECB", AlgECB, bytes.Repeat([]byte{0x42}, 16)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyH := createSigningKey(t, tpm, srk, symCipherTemplate(tc.mode))
			enc := encDec(t, tpm, CCEncryptDecrypt, keyH, 0, tc.mode, iv, tc.data)
			if bytes.Equal(enc, tc.data) {
				t.Fatal("ciphertext equals plaintext")
			}
			dec := encDec(t, tpm, CCEncryptDecrypt, keyH, 1, tc.mode, iv, enc)
			if !bytes.Equal(dec, tc.data) {
				t.Fatalf("round-trip failed: got %q, want %q", dec, tc.data)
			}
		})
	}
}

// TestEncryptDecrypt2 confirms the reordered-parameter variant round-trips, and
// that the key's default mode applies when mode is TPM_ALG_NULL.
func TestEncryptDecrypt2(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	keyH := createSigningKey(t, tpm, srk, symCipherTemplate(AlgCFB))
	iv := make([]byte, 16)
	msg := []byte("encrypt-decrypt-2 payload")

	// mode = NULL ⇒ use the key's default (CFB).
	enc := encDec(t, tpm, CCEncryptDecrypt2, keyH, 0, AlgNull, iv, msg)
	dec := encDec(t, tpm, CCEncryptDecrypt2, keyH, 1, AlgNull, iv, enc)
	if !bytes.Equal(dec, msg) {
		t.Fatalf("EncryptDecrypt2 round-trip failed: got %q", dec)
	}
}
