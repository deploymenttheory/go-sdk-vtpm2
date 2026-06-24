// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"testing"
)

// pwExtArea is an empty password authorization area.
func pwExtArea() []byte {
	var auth writer
	auth.u32(RHPW)
	auth.u16(0)
	auth.u8(0)
	auth.u16(0)
	var w writer
	w.u32(uint32(len(auth.bytes())))
	w.raw(auth.bytes())
	return w.bytes()
}

func extendPCR(t *testing.T, tpm *TPM, index int, digest []byte) uint32 {
	t.Helper()
	var ext writer
	ext.u32(uint32(index)) // pcrHandle
	ext.raw(pwExtArea())
	ext.u32(1) // TPML_DIGEST_VALUES count
	ext.u16(AlgSHA256)
	ext.raw(digest)
	_, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCPCRExtend, ext.bytes())))
	return rc
}

func resetPCR(t *testing.T, tpm *TPM, index int) uint32 {
	t.Helper()
	var rst writer
	rst.u32(uint32(index))
	rst.raw(pwExtArea())
	_, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCPCRReset, rst.bytes())))
	return rc
}

func TestPCRExtendLocality(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	digest := bytes.Repeat([]byte{0xAB}, 32)

	// A boot-measurement PCR extends fine at the default locality 0.
	if rc := extendPCR(t, tpm, 0, digest); rc != RCSuccess {
		t.Fatalf("PCR0 extend rc = 0x%x", rc)
	}
	// A DRTM PCR (17) is restricted to locality 4.
	if rc := extendPCR(t, tpm, 17, digest); rc != RCLocality {
		t.Fatalf("PCR17 @ locality 0 rc = 0x%x, want LOCALITY (0x%x)", rc, RCLocality)
	}
	tpm.SetLocality(4)
	if rc := extendPCR(t, tpm, 17, digest); rc != RCSuccess {
		t.Fatalf("PCR17 @ locality 4 rc = 0x%x", rc)
	}
}

func TestPCRReset(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	digest := bytes.Repeat([]byte{0xCD}, 32)

	// PCR16 is resettable at any locality.
	if rc := extendPCR(t, tpm, 16, digest); rc != RCSuccess {
		t.Fatalf("PCR16 extend rc = 0x%x", rc)
	}
	if rc := resetPCR(t, tpm, 16); rc != RCSuccess {
		t.Fatalf("PCR16 reset rc = 0x%x", rc)
	}
	if d := tpm.pcr.read(AlgSHA256, 16); !bytes.Equal(d, make([]byte, 32)) {
		t.Fatalf("PCR16 not zeroed by reset: %x", d)
	}

	// PCR0 is a boot PCR — not resettable by command at any locality.
	if rc := resetPCR(t, tpm, 0); rc != RCLocality {
		t.Fatalf("PCR0 reset rc = 0x%x, want LOCALITY", rc)
	}
	tpm.SetLocality(4)
	if rc := resetPCR(t, tpm, 0); rc != RCLocality {
		t.Fatalf("PCR0 reset @ locality 4 rc = 0x%x, want LOCALITY", rc)
	}
}
