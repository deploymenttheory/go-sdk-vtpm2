// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"testing"
)

// createLoaded runs TPM2_CreateLoaded under parent (a hierarchy or storage key)
// and returns the transient handle, outPrivate content, and Name.
func createLoaded(t *testing.T, tpm *TPM, parent uint32, tmpl public) (handle uint32, outPrivate, name []byte) {
	t.Helper()
	var inner writer
	inner.tpm2b(nil) // userAuth
	inner.tpm2b(nil) // data
	var body writer
	body.u32(parent)
	body.raw(onePasswordAuth())
	body.tpm2b(inner.bytes()) // inSensitive (TPM2B_SENSITIVE_CREATE)
	tmpl.marshal2B(&body)     // inPublic (TPM2B_TEMPLATE)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCCreateLoaded, body.bytes())))
	if rc != RCSuccess {
		t.Fatalf("CreateLoaded rc = 0x%x", rc)
	}
	r := newReader(p)
	handle = r.u32()
	_ = r.u32() // parameterSize
	outPrivate = r.tpm2b()
	_ = r.bytes(int(r.u16())) // skip outPublic (TPM2B_PUBLIC)
	name = r.tpm2b()
	if r.err != nil {
		t.Fatalf("parse CreateLoaded response: %v", r.err)
	}
	return handle, outPrivate, name
}

func TestCreateLoaded(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())

	// A child signing key under the SRK: outPrivate is the wrapped sensitive.
	h, outPriv, name := createLoaded(t, tpm, srk, eccSigningTemplate())
	if len(outPriv) == 0 {
		t.Fatal("child CreateLoaded returned an empty outPrivate")
	}
	if loaded, ok := tpm.objects.get(h); !ok || !bytes.Equal(loaded.name, name) {
		t.Fatal("loaded child object Name does not match the returned name")
	}
	// The loaded key is functional: it can sign.
	sig := signDigest(t, tpm, h, bytes.Repeat([]byte{0x33}, 32))
	if len(sig) == 0 {
		t.Fatal("CreateLoaded child key could not sign")
	}

	// A primary key under a hierarchy: outPrivate is empty.
	ph, pPriv, pName := createLoaded(t, tpm, RHEndorsement, eccStorageTemplate())
	if len(pPriv) != 0 {
		t.Fatalf("primary CreateLoaded outPrivate = %d bytes, want empty", len(pPriv))
	}
	if loaded, ok := tpm.objects.get(ph); !ok || !bytes.Equal(loaded.name, pName) {
		t.Fatal("loaded primary object Name does not match the returned name")
	}

	// Determinism: the same hierarchy + template reproduces the same primary Name.
	_, _, pName2 := createLoaded(t, tpm, RHEndorsement, eccStorageTemplate())
	if !bytes.Equal(pName, pName2) {
		t.Fatal("CreateLoaded primary is not deterministic across calls")
	}
}
