// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package client

import (
	"bytes"
	"testing"
)

// TestOpenLocalAndRandom drives the in-process responder entirely through the
// typed client — no hand-built blobs, no external TPM stack.
func TestOpenLocalAndRandom(t *testing.T) {
	c, err := OpenLocal()
	if err != nil {
		t.Fatalf("OpenLocal: %v", err)
	}
	r, err := c.GetRandom(16)
	if err != nil {
		t.Fatalf("GetRandom: %v", err)
	}
	if len(r) != 16 {
		t.Fatalf("GetRandom returned %d bytes, want 16", len(r))
	}
	if bytes.Equal(r, make([]byte, 16)) {
		t.Fatal("GetRandom returned all zeros")
	}
}

// TestObjectLifecycle is the provisioning flow a consumer actually wants: an SRK,
// a child signing key created and loaded under it, and ReadPublic round-trips.
func TestObjectLifecycle(t *testing.T) {
	c, err := OpenLocal()
	if err != nil {
		t.Fatal(err)
	}

	srk, err := c.CreatePrimary(HandleOwner, ECCStorageKey(), nil)
	if err != nil {
		t.Fatalf("CreatePrimary: %v", err)
	}
	defer c.FlushContext(srk.Handle)
	if srk.Public.Type != AlgECC || srk.Public.Curve != ECCNistP256 {
		t.Fatalf("SRK public = %+v, want ECC P-256", srk.Public)
	}
	if len(srk.Name) == 0 {
		t.Fatal("SRK has no Name")
	}

	// A child signing key under the SRK.
	child, err := c.CreateAndLoad(srk, ECCSigningKey(), []byte("child-auth"))
	if err != nil {
		t.Fatalf("CreateAndLoad: %v", err)
	}
	defer c.FlushContext(child.Handle)
	if child.Public.Attrs&AttrSign == 0 {
		t.Fatal("child key is not a signing key")
	}

	// ReadPublic of the child matches the Name returned at load time.
	pub, name, err := c.ReadPublic(child.Handle)
	if err != nil {
		t.Fatalf("ReadPublic: %v", err)
	}
	if !bytes.Equal(name, child.Name) {
		t.Fatal("ReadPublic Name does not match the loaded child")
	}
	if pub.Scheme.Alg != AlgECDSA {
		t.Fatalf("child scheme = 0x%x, want ECDSA", pub.Scheme.Alg)
	}
}

// TestPrimaryDeterminism confirms CreatePrimary reproduces the same SRK Name within
// a TPM (the responder derives primaries deterministically from the hierarchy seed,
// so a recreated SRK matches its prior form — across separate TPMs the random seeds
// differ, as they should).
func TestPrimaryDeterminism(t *testing.T) {
	c, err := OpenLocal()
	if err != nil {
		t.Fatal(err)
	}
	first, err := c.CreatePrimary(HandleOwner, ECCStorageKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.FlushContext(first.Handle); err != nil {
		t.Fatal(err)
	}
	second, err := c.CreatePrimary(HandleOwner, ECCStorageKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Name, second.Name) {
		t.Fatal("recreated SRK Name differs from the original")
	}
}

// TestRSAPrimary exercises the RSA template/marshalling path.
func TestRSAPrimary(t *testing.T) {
	c, err := OpenLocal()
	if err != nil {
		t.Fatal(err)
	}
	k, err := c.CreatePrimary(HandleOwner, RSAStorageKey(), nil)
	if err != nil {
		t.Fatalf("RSA CreatePrimary: %v", err)
	}
	defer c.FlushContext(k.Handle)
	if k.Public.Type != AlgRSA || k.Public.KeyBits != 2048 {
		t.Fatalf("RSA SRK public = %+v, want RSA-2048", k.Public)
	}
	if len(k.Public.Unique) != 256 {
		t.Fatalf("RSA modulus length = %d, want 256", len(k.Public.Unique))
	}
}
