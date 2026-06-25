// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"testing"
)

// TestCreateRSAChild covers the RSA branch of createChild plus Load of an RSA key.
func TestCreateRSAChild(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	keyH := createSigningKey(t, tpm, srk, rsaSigningTemplate())
	sig := signDigest(t, tpm, keyH, bytes.Repeat([]byte{0x09}, 32))
	if verifySig(t, tpm, keyH, bytes.Repeat([]byte{0x09}, 32), sig) != RCSuccess {
		t.Fatal("RSA child key could not sign/verify")
	}
}

// TestHMACKey covers the keyed-hash HMAC key path (cmdHMAC).
func TestHMACKey(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	keyH := createSigningKey(t, tpm, srk, hmacKeyTemplate())

	var b writer
	b.u32(keyH)
	b.raw(onePasswordAuth())
	b.tpm2b([]byte("message to MAC"))
	b.u16(AlgSHA256)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCHMAC, b.bytes())))
	if rc != RCSuccess {
		t.Fatalf("HMAC rc = 0x%x", rc)
	}
	r := newReader(p)
	_ = r.u32()
	if mac := r.tpm2b(); len(mac) != 32 {
		t.Fatalf("HMAC length = %d, want 32", len(mac))
	}
}

// TestNVIndexTypes covers the counter, bit-field and extend NV index types.
func TestNVIndexTypes(t *testing.T) {
	tpm := New()
	startup(t, tpm)

	// Counter: NV_Increment then read the 8-byte value.
	const counter = 0x01000080
	defineSpace(t, tpm, RHOwner, counter, nvCounter, NVOwnerWrite|NVOwnerRead, 8, nil)
	if _, rc, _ := parseResp(t, tpm.Execute(nvCmd(CCNVIncrement, RHOwner, counter, nil, nil))); rc != RCSuccess {
		t.Fatalf("NV_Increment rc = 0x%x", rc)
	}
	var rp writer
	rp.u16(8)
	rp.u16(0)
	if _, rc, _ := parseResp(t, tpm.Execute(nvCmd(CCNVRead, RHOwner, counter, nil, rp.bytes()))); rc != RCSuccess {
		t.Fatalf("NV_Read(counter) rc = 0x%x", rc)
	}

	// Bit field: NV_SetBits.
	const bits = 0x01000081
	defineSpace(t, tpm, RHOwner, bits, nvBits, NVOwnerWrite|NVOwnerRead, 8, nil)
	var sb writer
	sb.u64(0xF0F0)
	if _, rc, _ := parseResp(t, tpm.Execute(nvCmd(CCNVSetBits, RHOwner, bits, nil, sb.bytes()))); rc != RCSuccess {
		t.Fatalf("NV_SetBits rc = 0x%x", rc)
	}

	// Extend: NV_Extend with a 32-byte buffer.
	const ext = 0x01000082
	defineSpace(t, tpm, RHOwner, ext, nvExtend, NVOwnerWrite|NVOwnerRead, 32, nil)
	var eb writer
	eb.tpm2b(bytes.Repeat([]byte{0x5a}, 16))
	if _, rc, _ := parseResp(t, tpm.Execute(nvCmd(CCNVExtend, RHOwner, ext, nil, eb.bytes()))); rc != RCSuccess {
		t.Fatalf("NV_Extend rc = 0x%x", rc)
	}

	// Write-lock then a failed write; read-lock then a failed read.
	const ord = 0x01000083
	defineSpace(t, tpm, RHOwner, ord, nvOrdinary, NVOwnerWrite|NVOwnerRead|NVWriteDefine|NVReadSTClear, 8, nil)
	var wp writer
	wp.tpm2b([]byte("12345678"))
	wp.u16(0)
	if _, rc, _ := parseResp(t, tpm.Execute(nvCmd(CCNVWrite, RHOwner, ord, nil, wp.bytes()))); rc != RCSuccess {
		t.Fatalf("NV_Write rc = 0x%x", rc)
	}
	if _, rc, _ := parseResp(t, tpm.Execute(nvCmd(CCNVWriteLock, RHOwner, ord, nil, nil))); rc != RCSuccess {
		t.Fatalf("NV_WriteLock rc = 0x%x", rc)
	}
	if _, rc, _ := parseResp(t, tpm.Execute(nvCmd(CCNVWrite, RHOwner, ord, nil, wp.bytes()))); rc == RCSuccess {
		t.Fatal("write to a write-locked index unexpectedly succeeded")
	}
	if _, rc, _ := parseResp(t, tpm.Execute(nvCmd(CCNVReadLock, RHOwner, ord, nil, nil))); rc != RCSuccess {
		t.Fatalf("NV_ReadLock rc = 0x%x", rc)
	}
	var rp2 writer
	rp2.u16(8)
	rp2.u16(0)
	if _, rc, _ := parseResp(t, tpm.Execute(nvCmd(CCNVRead, RHOwner, ord, nil, rp2.bytes()))); rc == RCSuccess {
		t.Fatal("read from a read-locked index unexpectedly succeeded")
	}
}
