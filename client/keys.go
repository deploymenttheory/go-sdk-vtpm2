// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package client

// Object lifecycle: create primary keys, create and load child keys, and read
// public areas. These cover the common provisioning flow (an SRK, then child
// signing/storage keys under it).
//
// Note: this first slice authorizes the parent / hierarchy with an empty
// authorization (the common case for a freshly created SRK and the default
// hierarchies). Per-parent authorization and HMAC/policy sessions are layered on in
// a later phase.

// Key is a loaded TPM object: its transient handle, Name, and public area.
type Key struct {
	Handle Handle
	Name   []byte
	Public Public
}

// sensitiveCreate marshals a TPM2B_SENSITIVE_CREATE carrying the new object's
// authValue (and optional seed data for sealed objects).
func sensitiveCreate(auth, data []byte) []byte {
	var inner writer
	inner.tpm2b(auth)
	inner.tpm2b(data)
	var w writer
	w.tpm2b(inner.bytes())
	return w.bytes()
}

// CreatePrimary derives a primary key under a hierarchy (Owner/Endorsement/
// Platform/Null) from that hierarchy's seed, loads it, and returns the loaded Key.
// objectAuth sets the new key's authorization value (nil for none).
func (c *Conn) CreatePrimary(hierarchy Handle, tmpl Public, objectAuth []byte) (*Key, error) {
	var b writer
	b.u32(uint32(hierarchy))
	b.raw(passwordAuth(nil)) // hierarchy auth (empty)
	b.raw(sensitiveCreate(objectAuth, nil))
	tmpl.marshal2B(&b)
	b.tpm2b(nil) // outsideInfo
	b.u32(0)     // creationPCR: empty selection

	payload, err := c.call(tagSessions, ccCreatePrimary, b.bytes())
	if err != nil {
		return nil, err
	}
	r := newReader(payload)
	h := r.u32()
	_ = r.u32() // parameterSize
	pub := readPublic2B(r)
	_ = r.tpm2b() // creationData
	_ = r.tpm2b() // creationHash
	_ = r.u16()   // ticket: tag
	_ = r.u32()   //         hierarchy
	_ = r.tpm2b() //         digest
	name := r.tpm2b()
	if r.err {
		return nil, errShort
	}
	return &Key{Handle: Handle(h), Name: name, Public: pub}, nil
}

// Create makes a child object under parent, returning its wrapped private blob and
// public area (which Load then turns into a usable handle). objectAuth sets the
// new object's authorization value.
func (c *Conn) Create(parent *Key, tmpl Public, objectAuth []byte) (private, public []byte, err error) {
	var b writer
	b.u32(uint32(parent.Handle))
	b.raw(passwordAuth(nil)) // parent auth (empty)
	b.raw(sensitiveCreate(objectAuth, nil))
	tmpl.marshal2B(&b)
	b.tpm2b(nil) // outsideInfo
	b.u32(0)     // creationPCR

	payload, err := c.call(tagSessions, ccCreate, b.bytes())
	if err != nil {
		return nil, nil, err
	}
	r := newReader(payload)
	_ = r.u32() // parameterSize
	private = r.tpm2b()
	public = r.tpm2b() // outPublic (TPM2B_PUBLIC, kept opaque for Load)
	if r.err {
		return nil, nil, errShort
	}
	return private, public, nil
}

// Load loads a child object (from Create) under its parent and returns the Key.
func (c *Conn) Load(parent *Key, private, public []byte) (*Key, error) {
	var b writer
	b.u32(uint32(parent.Handle))
	b.raw(passwordAuth(nil)) // parent auth (empty)
	b.tpm2b(private)
	b.tpm2b(public) // re-wrap the public area as a TPM2B_PUBLIC

	payload, err := c.call(tagSessions, ccLoad, b.bytes())
	if err != nil {
		return nil, err
	}
	r := newReader(payload)
	h := r.u32()
	_ = r.u32() // parameterSize
	name := r.tpm2b()
	if r.err {
		return nil, errShort
	}
	pub, _, _ := c.ReadPublic(Handle(h))
	return &Key{Handle: Handle(h), Name: name, Public: pub}, nil
}

// CreateAndLoad is the common one-call combination of Create + Load.
func (c *Conn) CreateAndLoad(parent *Key, tmpl Public, objectAuth []byte) (*Key, error) {
	priv, pub, err := c.Create(parent, tmpl, objectAuth)
	if err != nil {
		return nil, err
	}
	return c.Load(parent, priv, pub)
}

// ReadPublic returns the public area and Name of a loaded object.
func (c *Conn) ReadPublic(h Handle) (Public, []byte, error) {
	var b writer
	b.u32(uint32(h))
	payload, err := c.call(tagNoSessions, ccReadPublic, b.bytes())
	if err != nil {
		return Public{}, nil, err
	}
	r := newReader(payload)
	pub := readPublic2B(r)
	name := r.tpm2b()
	if r.err {
		return Public{}, nil, errShort
	}
	return pub, name, nil
}
