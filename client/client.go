// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

// Package client is a typed, in-process-native TPM 2.0 client for the
// go-sdk-vtpm2 responder. It turns the raw `Execute([]byte) []byte` boundary into
// ergonomic Go calls — templates, sessions, and typed commands — so you can drive
// the TPM without hand-building wire blobs or importing a separate TPM stack.
//
// The same typed API works against any transport: an in-process responder
// (client.Local), a remote swtpm socket, or real hardware. The in-process path
// needs no socket, daemon, or second dependency:
//
//	c, _ := client.OpenLocal()           // an in-process TPM, started
//	srk, _ := c.CreatePrimary(client.HandleOwner, client.ECCStorageKey(), nil)
//	defer c.FlushContext(srk.Handle)
package client

import (
	"encoding/binary"
	"fmt"

	"github.com/deploymenttheory/go-sdk-vtpm2/tpm2"
)

// Command codes used by this package (TPM_CC).
const (
	ccStartup       = 0x00000144
	ccShutdown      = 0x00000145
	ccGetRandom     = 0x0000017B
	ccCreatePrimary = 0x00000131
	ccCreate        = 0x00000153
	ccLoad          = 0x00000157
	ccReadPublic    = 0x00000173
	ccFlushContext  = 0x00000165
)

// Structure tags.
const (
	tagNoSessions uint16 = 0x8001
	tagSessions   uint16 = 0x8002
)

// Transport carries a complete TPM 2.0 command blob to a device and returns the
// complete response blob. Implementations may be in-process, a socket, or real
// hardware.
type Transport interface {
	Execute(cmd []byte) ([]byte, error)
}

// localTransport adapts an in-process responder to a Transport.
type localTransport struct{ tpm *tpm2.TPM }

func (l localTransport) Execute(cmd []byte) ([]byte, error) {
	return l.tpm.Execute(cmd), nil // the responder encodes errors as response codes, never Go errors
}

// Local wraps an in-process responder as a Transport.
func Local(tpm *tpm2.TPM) Transport { return localTransport{tpm} }

// Conn is a typed TPM connection over a Transport.
type Conn struct{ t Transport }

// Open returns a typed connection over any transport.
func Open(t Transport) *Conn { return &Conn{t: t} }

// OpenLocal creates a fresh in-process TPM, runs TPM2_Startup, and returns a typed
// connection to it — the quickest way to get a usable TPM in a Go program.
func OpenLocal() (*Conn, error) {
	c := Open(Local(tpm2.New()))
	if err := c.Startup(); err != nil {
		return nil, err
	}
	return c, nil
}

// errShort reports a response that ended before all expected fields were read.
var errShort = fmt.Errorf("tpm: truncated response")

// Error is a non-success TPM response code surfaced as a Go error.
type Error struct{ Code uint32 }

func (e *Error) Error() string { return fmt.Sprintf("tpm: response code 0x%x", e.Code) }

// call frames, sends, and checks a command, returning the response payload (the
// bytes after the 10-byte header).
func (c *Conn) call(tag uint16, cc uint32, body []byte) ([]byte, error) {
	cmd := make([]byte, 10+len(body))
	binary.BigEndian.PutUint16(cmd[0:], tag)
	binary.BigEndian.PutUint32(cmd[2:], uint32(len(cmd)))
	binary.BigEndian.PutUint32(cmd[6:], cc)
	copy(cmd[10:], body)

	resp, err := c.t.Execute(cmd)
	if err != nil {
		return nil, err
	}
	if len(resp) < 10 {
		return nil, fmt.Errorf("tpm: short response (%d bytes)", len(resp))
	}
	if rc := binary.BigEndian.Uint32(resp[6:]); rc != 0 {
		return nil, &Error{Code: rc}
	}
	return resp[10:], nil
}

// passwordAuth marshals a single password authorization area for authValue.
func passwordAuth(authValue []byte) []byte {
	var a writer
	a.u32(uint32(HandlePassword))
	a.tpm2b(nil) // nonce
	a.u8(1)      // continueSession
	a.tpm2b(authValue)
	var w writer
	w.u32(uint32(len(a.bytes())))
	w.raw(a.bytes())
	return w.bytes()
}

// Startup runs TPM2_Startup(TPM_SU_CLEAR).
func (c *Conn) Startup() error {
	var b writer
	b.u16(0x0000) // TPM_SU_CLEAR
	_, err := c.call(tagNoSessions, ccStartup, b.bytes())
	return err
}

// Shutdown runs TPM2_Shutdown(TPM_SU_CLEAR).
func (c *Conn) Shutdown() error {
	var b writer
	b.u16(0x0000)
	_, err := c.call(tagNoSessions, ccShutdown, b.bytes())
	return err
}

// GetRandom returns n bytes of TPM-generated entropy.
func (c *Conn) GetRandom(n uint16) ([]byte, error) {
	var b writer
	b.u16(n)
	payload, err := c.call(tagNoSessions, ccGetRandom, b.bytes())
	if err != nil {
		return nil, err
	}
	return newReader(payload).tpm2b(), nil
}

// FlushContext unloads a transient object or session.
func (c *Conn) FlushContext(h Handle) error {
	var b writer
	b.u32(uint32(h))
	_, err := c.call(tagNoSessions, ccFlushContext, b.bytes())
	return err
}
