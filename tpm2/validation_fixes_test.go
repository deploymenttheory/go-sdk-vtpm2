// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"testing"
)

// TestParamEncryptBoundOmitsAuthValue covers the conformance fix: the parameter
// encryption key is the session value (sessionKey ‖ authValue) with the same
// bound-session exception as the authorization HMAC — when the session is bound to
// the entity, authValue is omitted (TPM 2.0 Part 1, §21).
func TestParamEncryptBoundOmitsAuthValue(t *testing.T) {
	as := &authSession{
		authHash:   AlgSHA256,
		sessionKey: bytes.Repeat([]byte{0xAA}, 16),
		symmetric:  symDef{Alg: AlgAES, KeyBits: 128, Mode: AlgCFB},
	}
	authValue := []byte("entity-auth")
	nNew := bytes.Repeat([]byte{0x01}, 16)
	nOld := bytes.Repeat([]byte{0x02}, 16)
	plain := []byte("0123456789abcdef") // 16 bytes

	enc := func(bound bool) []byte {
		buf := append([]byte{0x00, byte(len(plain))}, plain...) // TPM2B size ‖ data
		cryptParam(as, authValue, nNew, nOld, buf, bound, true)
		return append([]byte(nil), buf[2:]...)
	}
	encBound, encUnbound := enc(true), enc(false)

	if bytes.Equal(encBound, encUnbound) {
		t.Fatal("bound and unbound must differ when authValue is non-empty")
	}
	// Bound: key = sessionKey only.
	ki := kdfa(AlgSHA256, as.sessionKey, []byte("CFB"), nNew, nOld, 128+128)
	if want := aesCFB(ki[:16], ki[16:32], plain, true); !bytes.Equal(encBound, want) {
		t.Fatal("bound encryption must derive the key from sessionKey alone")
	}
	// Unbound: key = sessionKey ‖ authValue.
	k2 := append(append([]byte(nil), as.sessionKey...), authValue...)
	ki2 := kdfa(AlgSHA256, k2, []byte("CFB"), nNew, nOld, 128+128)
	if want := aesCFB(ki2[:16], ki2[16:32], plain, true); !bytes.Equal(encUnbound, want) {
		t.Fatal("unbound encryption must include authValue in the key")
	}
}

// TestTPMANVBitPositions pins the corrected TPMA_NV bit positions (TPM 2.0 Part 2,
// TPMA_NV): GLOBALLOCK is bit 15 (bit 14 is WRITE_STCLEAR) and READLOCKED is bit
// 28 (bit 24 is reserved).
func TestTPMANVBitPositions(t *testing.T) {
	for _, c := range []struct {
		name string
		got  uint32
		want uint32
	}{
		{"WRITE_STCLEAR", NVWriteSTClear, 1 << 14},
		{"GLOBALLOCK", NVGlobalLock, 1 << 15},
		{"READLOCKED", NVReadLocked, 1 << 28},
		{"WRITTEN", NVWritten, 1 << 29},
	} {
		if c.got != c.want {
			t.Errorf("TPMA_NV_%s = 0x%x, want 0x%x", c.name, c.got, c.want)
		}
	}
}

// TestNVReadLockSetsCorrectBit confirms read-locking sets READLOCKED at bit 28 in
// the index's attributes (which feed the NV Name).
func TestNVReadLockSetsCorrectBit(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	const h = 0x0100000B
	defineSpace(t, tpm, RHOwner, h, nvOrdinary, NVOwnerWrite|NVOwnerRead, 8, nil)
	var wp writer
	wp.tpm2b([]byte("12345678"))
	wp.u16(0)
	if _, rc, _ := parseResp(t, tpm.Execute(nvCmd(CCNVWrite, RHOwner, h, nil, wp.bytes()))); rc != RCSuccess {
		t.Fatalf("write rc = 0x%x", rc)
	}
	if _, rc, _ := parseResp(t, tpm.Execute(nvCmd(CCNVReadLock, RHOwner, h, nil, nil))); rc != RCSuccess {
		t.Fatalf("read-lock rc = 0x%x", rc)
	}
	idx, _ := tpm.nv.get(h)
	if idx.public.Attrs&(1<<28) == 0 {
		t.Fatalf("READLOCKED (bit 28) not set after read-lock: attrs 0x%x", idx.public.Attrs)
	}
}
