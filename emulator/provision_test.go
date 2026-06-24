// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package emulator

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/deploymenttheory/go-sdk-vtpm2/tpm2"
)

// srkName reads the SRK's Name via TPM2_ReadPublic, failing if it is absent.
func srkName(t *testing.T, e *Emulator) []byte {
	t.Helper()
	resp := e.tpm.Execute(buildCmd(tpm2.TPMSTNoSessions, tpm2.CCReadPublic, be32(SRKHandle)))
	if rc := respCode(resp); rc != tpm2.RCSuccess {
		t.Fatalf("ReadPublic(SRK) rc = 0x%x", rc)
	}
	p := resp[10:]
	pubSize := binary.BigEndian.Uint16(p)
	p = p[2+pubSize:]
	nameSize := binary.BigEndian.Uint16(p)
	return p[2 : 2+nameSize]
}

func TestProvisionCreatesSRK(t *testing.T) {
	e, err := New("", "") // ephemeral
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Provision(); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if name := srkName(t, e); len(name) == 0 {
		t.Fatal("SRK has no Name after provisioning")
	}
}

func TestProvisionIdempotent(t *testing.T) {
	e, _ := New("", "")
	if err := e.Provision(); err != nil {
		t.Fatal(err)
	}
	first := srkName(t, e)
	if err := e.Provision(); err != nil { // second call must be a no-op
		t.Fatal(err)
	}
	if !bytes.Equal(first, srkName(t, e)) {
		t.Fatal("re-provisioning changed the SRK")
	}
}

func TestProvisionPersistsAcrossReboot(t *testing.T) {
	dir := t.TempDir()
	e, err := New("", dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Provision(); err != nil {
		t.Fatal(err)
	}
	want := srkName(t, e)

	// A fresh emulator from the same state directory is a reboot.
	rebooted, err := New("", dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := srkName(t, rebooted); !bytes.Equal(got, want) {
		t.Fatal("SRK Name changed across reboot — sealed objects would fail to load")
	}
}

// TestStateBlobRoundTrip exercises the swtpm GET/SET state path end to end through
// the real TPM: the blob from a provisioned TPM restores into a fresh one.
func TestStateBlobRoundTrip(t *testing.T) {
	e, _ := New("", "")
	if err := e.Provision(); err != nil {
		t.Fatal(err)
	}
	blob, err := e.tpm.StateBlob()
	if err != nil {
		t.Fatal(err)
	}

	fresh := tpm2.New()
	if err := fresh.LoadStateBlob(blob); err != nil {
		t.Fatalf("LoadStateBlob: %v", err)
	}
	resp := fresh.Execute(buildCmd(tpm2.TPMSTNoSessions, tpm2.CCReadPublic, be32(SRKHandle)))
	if rc := respCode(resp); rc != tpm2.RCSuccess {
		t.Fatalf("SRK missing after state-blob restore: rc 0x%x", rc)
	}
}
