// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package state

import (
	"encoding/binary"
	"testing"

	"github.com/deploymenttheory/go-sdk-vtpm2/tpm2"
)

func TestLoadMissing(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := store.Load(); err != nil || ok {
		t.Fatalf("Load on empty dir = (ok %v, err %v), want (false, nil)", ok, err)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	// Drive a TPM into a non-default state: startup + one PCR extend.
	src := tpm2.New()
	su := make([]byte, 2)
	binary.BigEndian.PutUint16(su, tpm2.SUClear)
	src.Execute(frame(tpm2.TPMSTNoSessions, tpm2.CCStartup, su))
	extendPCR0(t, src)

	if err := store.Save(src.Snapshot()); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Restore into a fresh TPM and confirm the PCR and counter carried over.
	dst := tpm2.New()
	ok, err := store.LoadInto(dst)
	if err != nil || !ok {
		t.Fatalf("LoadInto = (ok %v, err %v)", ok, err)
	}

	want := src.Snapshot()
	got := dst.Snapshot()
	if got.PCRUpdateCounter != want.PCRUpdateCounter {
		t.Fatalf("update counter %d != %d", got.PCRUpdateCounter, want.PCRUpdateCounter)
	}
	if !got.Started {
		t.Fatal("restored TPM should be started")
	}
	for alg, bank := range want.PCRBanks {
		for i := range bank {
			if string(got.PCRBanks[alg][i]) != string(bank[i]) {
				t.Fatalf("PCR[%d] bank 0x%x differs after round trip", i, alg)
			}
		}
	}
}

// frame builds a command blob (mirrors the tpm2 wire header).
func frame(tag uint16, code uint32, params []byte) []byte {
	out := make([]byte, 10)
	binary.BigEndian.PutUint16(out[0:], tag)
	binary.BigEndian.PutUint32(out[2:], uint32(10+len(params)))
	binary.BigEndian.PutUint32(out[6:], code)
	return append(out, params...)
}

// extendPCR0 extends PCR0/SHA-256 with a fixed digest via a password session.
func extendPCR0(t *testing.T, tpm *tpm2.TPM) {
	t.Helper()
	var p []byte
	be := binary.BigEndian
	// pcrHandle = 0
	p = be.AppendUint32(p, 0)
	// auth area: one empty password session (handle, nonce, attrs, hmac)
	auth := be.AppendUint32(nil, 0x40000009)
	auth = be.AppendUint16(auth, 0)
	auth = append(auth, 0)
	auth = be.AppendUint16(auth, 0)
	p = be.AppendUint32(p, uint32(len(auth)))
	p = append(p, auth...)
	// TPML_DIGEST_VALUES: one SHA-256 digest
	p = be.AppendUint32(p, 1)
	p = be.AppendUint16(p, tpm2.AlgSHA256)
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = 0xCD
	}
	p = append(p, digest...)

	resp := tpm.Execute(frame(tpm2.TPMSTSessions, tpm2.CCPCRExtend, p))
	if rc := be.Uint32(resp[6:]); rc != tpm2.RCSuccess {
		t.Fatalf("PCR_Extend rc = 0x%x", rc)
	}
}
