// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"testing"
)

// twoPasswordAuth marshals an authorization area of two empty password sessions.
func twoPasswordAuth() []byte {
	var auth writer
	for i := 0; i < 2; i++ {
		auth.u32(RHPW)
		auth.tpm2b(nil)
		auth.u8(1)
		auth.tpm2b(nil)
	}
	var w writer
	w.u32(uint32(len(auth.bytes())))
	w.raw(auth.bytes())
	return w.bytes()
}

// TestMakeActivateCredential round-trips the credential-protection pair against
// both an RSA and an ECC "EK" (TPM 2.0 Part 3, §24).
func TestMakeActivateCredential(t *testing.T) {
	for _, ek := range []struct {
		name string
		tmpl func() public
	}{
		{"ECC", eccStorageTemplate},
		{"RSA", rsaStorageTemplate},
	} {
		t.Run(ek.name, func(t *testing.T) {
			tpm := New()
			startup(t, tpm)
			ekH, _, _ := createPrimary(t, tpm, RHEndorsement, ek.tmpl())
			obj, _, objName := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
			credential := []byte("cred-secret-1234") // ≤ digest size

			// MakeCredential (no authorization).
			var mb writer
			mb.u32(ekH)
			mb.tpm2b(credential)
			mb.tpm2b(objName)
			_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCMakeCredential, mb.bytes())))
			if rc != RCSuccess {
				t.Fatalf("MakeCredential rc = 0x%x", rc)
			}
			mr := newReader(p)
			credBlob := mr.tpm2b()
			secret := mr.tpm2b()

			// ActivateCredential (activateHandle + keyHandle authorized).
			var ab writer
			ab.u32(obj)
			ab.u32(ekH)
			ab.raw(twoPasswordAuth())
			ab.tpm2b(credBlob)
			ab.tpm2b(secret)
			_, rc2, p2 := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCActivateCredential, ab.bytes())))
			if rc2 != RCSuccess {
				t.Fatalf("ActivateCredential rc = 0x%x", rc2)
			}
			ar := newReader(p2)
			_ = ar.u32()
			if certInfo := ar.tpm2b(); !bytes.Equal(certInfo, credential) {
				t.Fatalf("recovered credential = %q, want %q", certInfo, credential)
			}
		})
	}
}

// TestActivateCredentialWrongObject confirms the credential is bound to the named
// object: activating against a different object fails the integrity check.
func TestActivateCredentialWrongObject(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	ekH, _, _ := createPrimary(t, tpm, RHEndorsement, eccStorageTemplate())
	_, _, objName := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	other, _, _ := createPrimary(t, tpm, RHPlatform, eccStorageTemplate()) // a different object

	var mb writer
	mb.u32(ekH)
	mb.tpm2b([]byte("secret"))
	mb.tpm2b(objName)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCMakeCredential, mb.bytes())))
	if rc != RCSuccess {
		t.Fatalf("MakeCredential rc = 0x%x", rc)
	}
	mr := newReader(p)
	credBlob := mr.tpm2b()
	secret := mr.tpm2b()

	// Activate against `other`, whose Name differs from objName ⇒ integrity failure.
	var ab writer
	ab.u32(other)
	ab.u32(ekH)
	ab.raw(twoPasswordAuth())
	ab.tpm2b(credBlob)
	ab.tpm2b(secret)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCActivateCredential, ab.bytes()))); baseRC(rc) != RCIntegrity {
		t.Fatalf("wrong-object ActivateCredential rc = 0x%x, want RC_INTEGRITY", rc)
	}
}
