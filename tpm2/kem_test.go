// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"testing"
)

func TestEncapsulateDecapsulate(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	keyH := createSigningKey(t, tpm, srk, eccDecryptTemplate()) // KEM key: decrypt, unrestricted

	// Encapsulate (no authorization).
	var eb writer
	eb.u32(keyH)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCEncapsulate, eb.bytes())))
	if rc != RCSuccess {
		t.Fatalf("Encapsulate rc = 0x%x", rc)
	}
	er := newReader(p)
	sharedSecret := er.tpm2b()
	ciphertext := er.tpm2b()
	if len(sharedSecret) == 0 || len(ciphertext) == 0 {
		t.Fatal("Encapsulate returned empty sharedSecret or ciphertext")
	}

	// Decapsulate recovers the same shared secret.
	var db writer
	db.u32(keyH)
	db.raw(onePasswordAuth())
	db.tpm2b(ciphertext)
	_, rc, p2 := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCDecapsulate, db.bytes())))
	if rc != RCSuccess {
		t.Fatalf("Decapsulate rc = 0x%x", rc)
	}
	dr := newReader(p2)
	_ = dr.u32() // parameterSize
	if got := dr.tpm2b(); !bytes.Equal(got, sharedSecret) {
		t.Fatal("Decapsulate sharedSecret does not match Encapsulate")
	}
}
