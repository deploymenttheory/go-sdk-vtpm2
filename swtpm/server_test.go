// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package swtpm

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// stubDevice records Init calls and echoes Execute input.
type stubDevice struct {
	initCalled     bool
	deleteVolatile bool
}

func (d *stubDevice) Execute(cmd []byte) []byte { return cmd }
func (d *stubDevice) Init(del bool)             { d.initCalled = true; d.deleteVolatile = del }

func newTestServer() (*Server, *stubDevice) {
	dev := &stubDevice{}
	return NewServer("", dev, nil), dev
}

// stateDevice adds the optional state-blob capability to the stub.
type stateDevice struct {
	stubDevice
	blob   []byte
	loaded []byte
}

func (d *stateDevice) StateBlob() ([]byte, error)   { return d.blob, nil }
func (d *stateDevice) LoadStateBlob(b []byte) error { d.loaded = append([]byte(nil), b...); return nil }

// localityFake records SetLocality calls.
type localityFake struct {
	stubDevice
	loc    byte
	called bool
}

func (d *localityFake) SetLocality(loc byte) { d.loc = loc; d.called = true }

func TestSetLocalityPropagates(t *testing.T) {
	dev := &localityFake{}
	s := NewServer("", dev, nil)
	if resp, _ := s.handleControl(cmdSetLocality, []byte{4}, nil); binary.BigEndian.Uint32(resp) != ptmSuccess {
		t.Fatal("SET_LOCALITY should succeed")
	}
	if !dev.called || dev.loc != 4 {
		t.Fatalf("SetLocality not propagated: called=%v loc=%d", dev.called, dev.loc)
	}
}

func TestHandleGetStateBlob(t *testing.T) {
	dev := &stateDevice{blob: []byte("snapshot-bytes")}
	s := NewServer("", dev, nil)
	req := make([]byte, 16) // state_flags, tpm_number, type, offset
	binary.BigEndian.PutUint32(req[8:], blobPermanent)
	resp, _ := s.handleControl(cmdGetStateBlob, req, nil)

	if rc := binary.BigEndian.Uint32(resp[:4]); rc != ptmSuccess {
		t.Fatalf("result = %d", rc)
	}
	totlen := binary.BigEndian.Uint32(resp[8:12])
	length := binary.BigEndian.Uint32(resp[12:16])
	if int(totlen) != len(dev.blob) || int(length) != len(dev.blob) || !bytes.Equal(resp[16:], dev.blob) {
		t.Fatalf("GET_STATEBLOB returned wrong blob (totlen %d, len %d)", totlen, length)
	}
}

func TestHandleSetStateBlob(t *testing.T) {
	dev := &stateDevice{}
	s := NewServer("", dev, nil)
	blob := []byte("new-serialized-state")
	req := make([]byte, 12) // state_flags, type, length
	binary.BigEndian.PutUint32(req[4:], blobPermanent)
	binary.BigEndian.PutUint32(req[8:], uint32(len(blob)))
	req = append(req, blob...)
	resp, _ := s.handleControl(cmdSetStateBlob, req, nil)

	if rc := binary.BigEndian.Uint32(resp); rc != ptmSuccess {
		t.Fatalf("result = %d", rc)
	}
	if !bytes.Equal(dev.loaded, blob) {
		t.Fatalf("SET_STATEBLOB loaded %q, want %q", dev.loaded, blob)
	}
}

func TestStateBlobChunked(t *testing.T) {
	blob := bytes.Repeat([]byte{0xAB}, 10000) // > 2 chunks of maxStateChunk
	dev := &stateDevice{blob: blob}
	s := NewServer("", dev, nil)

	// GET in chunks until the whole totlength is reassembled.
	var got []byte
	for off := 0; ; {
		req := make([]byte, 16)
		binary.BigEndian.PutUint32(req[8:], blobPermanent)
		binary.BigEndian.PutUint32(req[12:], uint32(off))
		resp, _ := s.handleControl(cmdGetStateBlob, req, nil)
		totlen := binary.BigEndian.Uint32(resp[8:12])
		length := binary.BigEndian.Uint32(resp[12:16])
		got = append(got, resp[16:16+length]...)
		off += int(length)
		if length == 0 || off >= int(totlen) {
			break
		}
	}
	if !bytes.Equal(got, blob) {
		t.Fatalf("GET reassembly len %d, want %d", len(got), len(blob))
	}

	// SET the same blob back in chunks; the device must receive the whole thing.
	for off := 0; off < len(blob); off += maxStateChunk {
		end := off + maxStateChunk
		if end > len(blob) {
			end = len(blob)
		}
		chunk := blob[off:end]
		req := make([]byte, 12)
		binary.BigEndian.PutUint32(req[4:], blobPermanent)
		binary.BigEndian.PutUint32(req[8:], uint32(len(chunk)))
		req = append(req, chunk...)
		if resp, _ := s.handleControl(cmdSetStateBlob, req, nil); binary.BigEndian.Uint32(resp) != ptmSuccess {
			t.Fatalf("SET chunk at %d failed", off)
		}
	}
	if !bytes.Equal(dev.loaded, blob) {
		t.Fatalf("SET reassembly len %d, want %d", len(dev.loaded), len(blob))
	}
}

func TestStateBlobUnsupportedDevice(t *testing.T) {
	s, _ := newTestServer() // stubDevice has no state-blob capability
	req := make([]byte, 16)
	binary.BigEndian.PutUint32(req[8:], blobPermanent)
	if resp, _ := s.handleControl(cmdGetStateBlob, req, nil); binary.BigEndian.Uint32(resp) == ptmSuccess {
		t.Fatal("GET_STATEBLOB should fail when the device lacks the capability")
	}
}

func TestHandleSetLocalityTracked(t *testing.T) {
	s, _ := newTestServer()
	if resp, _ := s.handleControl(cmdSetLocality, []byte{3}, nil); binary.BigEndian.Uint32(resp) != ptmSuccess {
		t.Fatal("SET_LOCALITY should succeed")
	}
	if s.locality != 3 {
		t.Fatalf("locality = %d, want 3", s.locality)
	}
}

func TestGetCapabilityAdvertisesStateBlob(t *testing.T) {
	s, _ := newTestServer()
	resp, _ := s.handleControl(cmdGetCapability, nil, nil)
	caps := binary.BigEndian.Uint32(resp[4:8])
	if caps&(capGetStateBlob|capSetStateBlob) != (capGetStateBlob | capSetStateBlob) {
		t.Fatalf("caps 0x%x missing state-blob capabilities", caps)
	}
}

func TestHandleGetCapability(t *testing.T) {
	s, _ := newTestServer()
	resp, fd := s.handleControl(cmdGetCapability, nil, nil)
	if fd != -1 || len(resp) != 8 {
		t.Fatalf("resp len %d, fd %d", len(resp), fd)
	}
	if rc := binary.BigEndian.Uint32(resp[:4]); rc != ptmSuccess {
		t.Fatalf("result = %d", rc)
	}
	caps := binary.BigEndian.Uint32(resp[4:8])
	// QEMU's TPM 2.0 requirement.
	const required = capInit | capShutdown | capGetTPMEstablished | capSetLocality |
		capSetDataFD | capStop | capSetBufferSize | capResetTPMEstablished
	if caps&required != required {
		t.Fatalf("caps 0x%x missing required 0x%x", caps, required)
	}
}

func TestHandleInit(t *testing.T) {
	s, dev := newTestServer()
	payload := binary.BigEndian.AppendUint32(nil, ptmInitFlagDeleteVolatile)
	resp, _ := s.handleControl(cmdInit, payload, nil)
	if rc := binary.BigEndian.Uint32(resp); rc != ptmSuccess {
		t.Fatalf("INIT result = %d", rc)
	}
	if !dev.initCalled || !dev.deleteVolatile {
		t.Fatalf("Init(deleteVolatile) not propagated: called=%v delete=%v", dev.initCalled, dev.deleteVolatile)
	}
}

func TestHandleFixedResponses(t *testing.T) {
	s, _ := newTestServer()
	for _, tc := range []struct {
		name string
		cmd  uint32
		want int
	}{
		{"established", cmdGetTPMEstablished, 8},
		{"config", cmdGetConfig, 8},
		{"buffersize", cmdSetBufferSize, 16},
		{"setlocality", cmdSetLocality, 4},
		{"stop", cmdStop, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, fd := s.handleControl(tc.cmd, make([]byte, 8), nil)
			if fd != -1 || len(resp) != tc.want {
				t.Fatalf("resp len %d (want %d), fd %d", len(resp), tc.want, fd)
			}
			if rc := binary.BigEndian.Uint32(resp[:4]); rc != ptmSuccess {
				t.Fatalf("result = %d", rc)
			}
		})
	}
}

func TestHandleUnknownCommand(t *testing.T) {
	s, _ := newTestServer()
	resp, _ := s.handleControl(0xDEAD, nil, nil)
	if rc := binary.BigEndian.Uint32(resp); rc == ptmSuccess {
		t.Fatal("unknown command should not succeed")
	}
}

func TestHandleSetDataFDNoFD(t *testing.T) {
	s, _ := newTestServer()
	resp, fd := s.handleControl(cmdSetDataFD, nil, nil) // no ancillary fd
	if fd != -1 {
		t.Fatalf("fd = %d, want -1", fd)
	}
	if rc := binary.BigEndian.Uint32(resp); rc == ptmSuccess {
		t.Fatal("SET_DATAFD without an fd should fail")
	}
}

func TestReadTPMCommand(t *testing.T) {
	// A well-formed 12-byte command (10-byte header + 2 params).
	cmd := binary.BigEndian.AppendUint16(nil, 0x8001)
	cmd = binary.BigEndian.AppendUint32(cmd, 12)
	cmd = binary.BigEndian.AppendUint32(cmd, 0x017B)
	cmd = append(cmd, 0x00, 0x08)

	got, err := readTPMCommand(bytes.NewReader(cmd))
	if err != nil || !bytes.Equal(got, cmd) {
		t.Fatalf("readTPMCommand = (%x, %v), want %x", got, err, cmd)
	}

	// A size below the header length is rejected.
	bad := binary.BigEndian.AppendUint16(nil, 0x8001)
	bad = binary.BigEndian.AppendUint32(bad, 4) // < headerLen
	bad = binary.BigEndian.AppendUint32(bad, 0)
	if _, err := readTPMCommand(bytes.NewReader(bad)); err == nil {
		t.Fatal("expected error for undersized command")
	}
}
