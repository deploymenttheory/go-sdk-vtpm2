// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package emulator

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// swtpm control command codes (protocol literals, deliberately not importing the
// unexported constants from package swtpm — this test stands in for QEMU).
const (
	ctrlGetCapability = 1
	ctrlInit          = 2
	ctrlSetDataFD     = 16
)

// TPM 2.0 wire literals.
const (
	stNoSessions = 0x8001
	ccStartup    = 0x00000144
	ccGetRandom  = 0x0000017B
	suClear      = 0x0000
)

func dialControl(t *testing.T, path string) *net.UnixConn {
	t.Helper()
	raddr := &net.UnixAddr{Name: path, Net: "unix"}
	for i := 0; i < 100; i++ {
		if c, err := net.DialUnix("unix", nil, raddr); err == nil {
			return c
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("could not dial control socket %s", path)
	return nil
}

func readN(t *testing.T, r io.Reader, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return b
}

// tpmCmd frames a TPM 2.0 command blob.
func tpmCmd(tag uint16, code uint32, params []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, tag)
	b = binary.BigEndian.AppendUint32(b, uint32(10+len(params)))
	b = binary.BigEndian.AppendUint32(b, code)
	return append(b, params...)
}

// readTPMResp reads a full TPM response off the data channel and returns its
// response code and parameter bytes.
func readTPMResp(t *testing.T, r io.Reader) (uint32, []byte) {
	t.Helper()
	hdr := readN(t, r, 10)
	size := binary.BigEndian.Uint32(hdr[2:6])
	rc := binary.BigEndian.Uint32(hdr[6:10])
	var params []byte
	if size > 10 {
		params = readN(t, r, int(size)-10)
	}
	return rc, params
}

func TestEmulatorHandshakeAndData(t *testing.T) {
	dir := t.TempDir()
	ctrl := filepath.Join(dir, "swtpm.sock")

	emu, err := New(ctrl, dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := emu.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer emu.Close()

	c := dialControl(t, ctrl)
	defer c.Close()

	// 1. GET_CAPABILITY → tpm_result + caps mask.
	if _, err := c.Write(binary.BigEndian.AppendUint32(nil, ctrlGetCapability)); err != nil {
		t.Fatalf("write GET_CAPABILITY: %v", err)
	}
	capResp := readN(t, c, 8)
	if rc := binary.BigEndian.Uint32(capResp[:4]); rc != 0 {
		t.Fatalf("GET_CAPABILITY result = %d", rc)
	}
	caps := binary.BigEndian.Uint32(capResp[4:8])
	const wantBits = 1 /*INIT*/ | (1 << 1) /*SHUTDOWN*/ | (1 << 12) /*SET_DATAFD*/ | (1 << 13) /*SET_BUFFERSIZE*/
	if caps&wantBits != wantBits {
		t.Fatalf("caps 0x%x missing required bits 0x%x", caps, wantBits)
	}

	// 2. SET_DATAFD: pass one end of a socketpair via SCM_RIGHTS.
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	oob := syscall.UnixRights(fds[1])
	if _, _, err := c.WriteMsgUnix(binary.BigEndian.AppendUint32(nil, ctrlSetDataFD), oob, nil); err != nil {
		t.Fatalf("write SET_DATAFD: %v", err)
	}
	_ = syscall.Close(fds[1]) // server dup'd it
	if rc := binary.BigEndian.Uint32(readN(t, c, 4)); rc != 0 {
		t.Fatalf("SET_DATAFD result = %d", rc)
	}

	dataFile := os.NewFile(uintptr(fds[0]), "vtpm2-data-test")
	data, err := net.FileConn(dataFile)
	if err != nil {
		t.Fatalf("FileConn: %v", err)
	}
	_ = dataFile.Close()
	defer data.Close()

	// 3. INIT.
	initReq := binary.BigEndian.AppendUint32(nil, ctrlInit)
	initReq = binary.BigEndian.AppendUint32(initReq, 0) // init_flags
	if _, err := c.Write(initReq); err != nil {
		t.Fatalf("write INIT: %v", err)
	}
	if rc := binary.BigEndian.Uint32(readN(t, c, 4)); rc != 0 {
		t.Fatalf("INIT result = %d", rc)
	}

	// 4. TPM2_Startup(CLEAR) over the data channel.
	suParams := binary.BigEndian.AppendUint16(nil, suClear)
	if _, err := data.Write(tpmCmd(stNoSessions, ccStartup, suParams)); err != nil {
		t.Fatalf("write Startup: %v", err)
	}
	if rc, _ := readTPMResp(t, data); rc != 0 {
		t.Fatalf("Startup rc = 0x%x", rc)
	}

	// 5. TPM2_GetRandom over the data channel returns 8 bytes.
	grParams := binary.BigEndian.AppendUint16(nil, 8)
	if _, err := data.Write(tpmCmd(stNoSessions, ccGetRandom, grParams)); err != nil {
		t.Fatalf("write GetRandom: %v", err)
	}
	rc, params := readTPMResp(t, data)
	if rc != 0 {
		t.Fatalf("GetRandom rc = 0x%x", rc)
	}
	if len(params) < 2 || binary.BigEndian.Uint16(params) != 8 {
		t.Fatalf("GetRandom returned %d-byte body, want a 8-byte digest", len(params))
	}
}

func TestStatePersistsAcrossEmulators(t *testing.T) {
	dir := t.TempDir()
	ctrl := filepath.Join(dir, "swtpm.sock")

	emu, err := New(ctrl, dir)
	if err != nil {
		t.Fatal(err)
	}
	// Drive a Startup directly through the TPM, then close to persist.
	emu.tpm.Execute(tpmCmd(stNoSessions, ccStartup, binary.BigEndian.AppendUint16(nil, suClear)))
	if err := emu.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// A fresh emulator over the same dir must reload the persisted snapshot.
	emu2, err := New(ctrl, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer emu2.Close()
	if !emu2.tpm.Snapshot().Started {
		t.Fatal("expected restored TPM to be started")
	}
}
