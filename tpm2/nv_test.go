// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"encoding/binary"
	"encoding/json"
	"testing"
)

// defineSpace runs TPM2_NV_DefineSpace under a hierarchy (empty auth).
func defineSpace(t *testing.T, tpm *TPM, authHi, index, nt, attrs uint32, dataSize uint16, indexAuth []byte) {
	t.Helper()
	public := nvPublic{
		Index:    index,
		NameAlg:  AlgSHA256,
		Attrs:    attrs | (nt << NVNTShift),
		DataSize: dataSize,
	}
	var params writer
	params.tpm2b(indexAuth) // auth
	public.marshal2B(&params)

	var auth writer
	auth.u32(RHPW)
	auth.u16(0)
	auth.u8(0)
	auth.u16(0)
	var body writer
	body.u32(authHi)
	body.u32(uint32(len(auth.bytes())))
	body.raw(auth.bytes())
	body.raw(params.bytes())
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCNVDefineSpace, body.bytes()))); rc != RCSuccess {
		t.Fatalf("NV_DefineSpace rc = 0x%x", rc)
	}
}

// nvCmd frames a two-handle NV command [authHandle, nvIndex] with one password
// session and the given parameters.
func nvCmd(cc, authHandle, nvIndex uint32, password, params []byte) []byte {
	var auth writer
	auth.u32(RHPW)
	auth.u16(0)
	auth.u8(0)
	auth.tpm2b(password)
	var body writer
	body.u32(authHandle)
	body.u32(nvIndex)
	body.u32(uint32(len(auth.bytes())))
	body.raw(auth.bytes())
	body.raw(params)
	return buildCmd(TPMSTSessions, cc, body.bytes())
}

func TestNVOrdinaryWriteRead(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	const h = 0x01000001
	defineSpace(t, tpm, RHOwner, h, nvOrdinary, NVOwnerWrite|NVOwnerRead|NVAuthWrite|NVAuthRead, 16, []byte("idxauth"))

	// Write under owner authorization.
	var wp writer
	wp.tpm2b([]byte("hello"))
	wp.u16(0) // offset
	if _, rc, _ := parseResp(t, tpm.Execute(nvCmd(CCNVWrite, RHOwner, h, nil, wp.bytes()))); rc != RCSuccess {
		t.Fatalf("NV_Write rc = 0x%x", rc)
	}

	// Read under the index's own authorization.
	var rp writer
	rp.u16(5) // size
	rp.u16(0) // offset
	_, rc, p := parseResp(t, tpm.Execute(nvCmd(CCNVRead, h, h, []byte("idxauth"), rp.bytes())))
	if rc != RCSuccess {
		t.Fatalf("NV_Read rc = 0x%x", rc)
	}
	r := newReader(p)
	_ = r.u32() // parameterSize
	if data := r.tpm2b(); string(data) != "hello" {
		t.Fatalf("NV_Read = %q, want hello", data)
	}
}

func TestNVReadUninitialized(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	const h = 0x01000002
	defineSpace(t, tpm, RHOwner, h, nvOrdinary, NVOwnerWrite|NVOwnerRead, 8, nil)
	var rp writer
	rp.u16(8)
	rp.u16(0)
	if _, rc, _ := parseResp(t, tpm.Execute(nvCmd(CCNVRead, RHOwner, h, nil, rp.bytes()))); rc != RCNVUninitialized {
		t.Fatalf("read-before-write rc = 0x%x, want NV_UNINITIALIZED", rc)
	}
}

func TestNVCounter(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	const h = 0x01000003
	defineSpace(t, tpm, RHOwner, h, nvCounter, NVOwnerWrite|NVOwnerRead, 8, nil)
	for i := 0; i < 3; i++ {
		if _, rc, _ := parseResp(t, tpm.Execute(nvCmd(CCNVIncrement, RHOwner, h, nil, nil))); rc != RCSuccess {
			t.Fatalf("NV_Increment rc = 0x%x", rc)
		}
	}
	var rp writer
	rp.u16(8)
	rp.u16(0)
	_, rc, p := parseResp(t, tpm.Execute(nvCmd(CCNVRead, RHOwner, h, nil, rp.bytes())))
	if rc != RCSuccess {
		t.Fatalf("NV_Read counter rc = 0x%x", rc)
	}
	r := newReader(p)
	_ = r.u32()
	data := r.tpm2b()
	if v := binary.BigEndian.Uint64(data); v != 3 {
		t.Fatalf("counter = %d, want 3", v)
	}
}

func TestNVSetBits(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	const h = 0x01000004
	defineSpace(t, tpm, RHOwner, h, nvBits, NVOwnerWrite|NVOwnerRead, 8, nil)
	for _, bits := range []uint64{0x01, 0x80} {
		var sp writer
		sp.u64(bits)
		if _, rc, _ := parseResp(t, tpm.Execute(nvCmd(CCNVSetBits, RHOwner, h, nil, sp.bytes()))); rc != RCSuccess {
			t.Fatalf("NV_SetBits rc = 0x%x", rc)
		}
	}
	var rp writer
	rp.u16(8)
	rp.u16(0)
	_, _, p := parseResp(t, tpm.Execute(nvCmd(CCNVRead, RHOwner, h, nil, rp.bytes())))
	r := newReader(p)
	_ = r.u32()
	if v := binary.BigEndian.Uint64(r.tpm2b()); v != 0x81 {
		t.Fatalf("bits = 0x%x, want 0x81", v)
	}
}

func TestNVExtend(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	const h = 0x0100000A
	defineSpace(t, tpm, RHOwner, h, nvExtend, NVOwnerWrite|NVOwnerRead, 0, nil)
	var ep writer
	ep.tpm2b([]byte("measurement"))
	if _, rc, _ := parseResp(t, tpm.Execute(nvCmd(CCNVExtend, RHOwner, h, nil, ep.bytes()))); rc != RCSuccess {
		t.Fatalf("NV_Extend rc = 0x%x", rc)
	}
	var rp writer
	rp.u16(32)
	rp.u16(0)
	_, rc, p := parseResp(t, tpm.Execute(nvCmd(CCNVRead, RHOwner, h, nil, rp.bytes())))
	if rc != RCSuccess {
		t.Fatalf("read extend rc = 0x%x", rc)
	}
	r := newReader(p)
	_ = r.u32()
	// Expected: H(zero32 ‖ "measurement").
	want := hashSum(AlgSHA256, make([]byte, 32), []byte("measurement"))
	if got := r.tpm2b(); string(got) != string(want) {
		t.Fatalf("NV_Extend digest mismatch")
	}
}

func TestNVWriteLock(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	const h = 0x01000005
	defineSpace(t, tpm, RHOwner, h, nvOrdinary, NVOwnerWrite|NVOwnerRead, 8, nil)
	if _, rc, _ := parseResp(t, tpm.Execute(nvCmd(CCNVWriteLock, RHOwner, h, nil, nil))); rc != RCSuccess {
		t.Fatalf("NV_WriteLock rc = 0x%x", rc)
	}
	var wp writer
	wp.tpm2b([]byte("x"))
	wp.u16(0)
	if _, rc, _ := parseResp(t, tpm.Execute(nvCmd(CCNVWrite, RHOwner, h, nil, wp.bytes()))); rc != RCNVLocked {
		t.Fatalf("write after lock rc = 0x%x, want NV_LOCKED", rc)
	}
}

func TestNVOwnerWriteNotPermitted(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	const h = 0x01000006
	// Only AUTHWRITE — owner authorization must be refused.
	defineSpace(t, tpm, RHOwner, h, nvOrdinary, NVAuthWrite|NVOwnerRead, 8, []byte("a"))
	var wp writer
	wp.tpm2b([]byte("x"))
	wp.u16(0)
	if _, rc, _ := parseResp(t, tpm.Execute(nvCmd(CCNVWrite, RHOwner, h, nil, wp.bytes()))); rc != RCNVAuthorization {
		t.Fatalf("owner write rc = 0x%x, want NV_AUTHORIZATION", rc)
	}
}

func TestNVUndefine(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	const h = 0x01000007
	defineSpace(t, tpm, RHOwner, h, nvOrdinary, NVOwnerWrite|NVOwnerRead, 8, nil)

	// UndefineSpace [owner, nvIndex].
	var auth writer
	auth.u32(RHPW)
	auth.u16(0)
	auth.u8(0)
	auth.u16(0)
	var body writer
	body.u32(RHOwner)
	body.u32(h)
	body.u32(uint32(len(auth.bytes())))
	body.raw(auth.bytes())
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCNVUndefineSpace, body.bytes()))); rc != RCSuccess {
		t.Fatalf("NV_UndefineSpace rc = 0x%x", rc)
	}
	var rp writer
	rp.u32(h)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCNVReadPublic, rp.bytes()))); baseRC(rc) != RCHandle {
		t.Fatalf("ReadPublic after undefine rc = 0x%x, want HANDLE", rc)
	}
}

func TestNVPersistsAcrossReboot(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	const h = 0x01000008
	defineSpace(t, tpm, RHOwner, h, nvOrdinary, NVOwnerWrite|NVOwnerRead, 16, nil)
	var wp writer
	wp.tpm2b([]byte("persist-me"))
	wp.u16(0)
	if _, rc, _ := parseResp(t, tpm.Execute(nvCmd(CCNVWrite, RHOwner, h, nil, wp.bytes()))); rc != RCSuccess {
		t.Fatalf("write rc = 0x%x", rc)
	}

	data, err := json.Marshal(tpm.Snapshot())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Snapshot
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rebooted := New()
	if err := rebooted.Restore(back); err != nil {
		t.Fatalf("restore: %v", err)
	}

	var rp writer
	rp.u16(10)
	rp.u16(0)
	_, rc, p := parseResp(t, rebooted.Execute(nvCmd(CCNVRead, RHOwner, h, nil, rp.bytes())))
	if rc != RCSuccess {
		t.Fatalf("read after reboot rc = 0x%x", rc)
	}
	r := newReader(p)
	_ = r.u32()
	if data := r.tpm2b(); string(data) != "persist-me" {
		t.Fatalf("NV data after reboot = %q, want persist-me", data)
	}
}
