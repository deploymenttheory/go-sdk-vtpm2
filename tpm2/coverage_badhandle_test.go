// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"encoding/binary"
	"testing"
)

// TestBadHandlePaths sends structurally-valid commands that reference a
// non-existent object/key/NV handle, exercising the handle-resolution error
// branches across the handlers. Each must return an error, never success.
func TestBadHandlePaths(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	const bad = 0x80FFFFFF // a non-existent transient handle
	const badNV = 0x01FFFFFF
	z32 := make([]byte, 32)
	pw := onePasswordAuth()
	two := twoPasswordAuth()

	// build assembles handles + (optional) auth area + params.
	build := func(tag uint16, handles []uint32, auth, params []byte) []byte {
		var b writer
		for _, h := range handles {
			b.u32(h)
		}
		b.raw(auth)
		b.raw(params)
		return b.bytes()
	}
	p := func(parts ...[]byte) []byte {
		var b writer
		for _, x := range parts {
			b.raw(x)
		}
		return b.bytes()
	}
	tpm2bz := func(x []byte) []byte { var b writer; b.tpm2b(x); return b.bytes() }
	u16b := func(v uint16) []byte { var b writer; b.u16(v); return b.bytes() }
	u32b := func(v uint32) []byte { var b writer; b.u32(v); return b.bytes() }

	cases := []struct {
		name    string
		cc, tag uint32
		body    []byte
	}{
		{"Sign", CCSign, uint32(TPMSTSessions), build(TPMSTSessions, []uint32{bad}, pw, p(tpm2bz(z32), u16b(AlgNull), u16b(STHashCheck), u32b(RHNull), tpm2bz(nil)))},
		{"Quote", CCQuote, uint32(TPMSTSessions), build(TPMSTSessions, []uint32{bad}, pw, p(tpm2bz(nil), u16b(AlgNull), u32b(0)))},
		{"Unseal", CCUnseal, uint32(TPMSTSessions), build(TPMSTSessions, []uint32{bad}, pw, nil)},
		{"RSADecrypt", CCRSADecrypt, uint32(TPMSTSessions), build(TPMSTSessions, []uint32{bad}, pw, p(tpm2bz(nil), u16b(AlgNull), tpm2bz(nil)))},
		{"ECDHZGen", CCECDHZGen, uint32(TPMSTSessions), build(TPMSTSessions, []uint32{bad}, pw, p(tpm2bz(nil), tpm2bz(nil)))},
		{"ObjectChangeAuth", CCObjectChangeAuth, uint32(TPMSTSessions), build(TPMSTSessions, []uint32{bad, bad}, pw, tpm2bz(nil))},
		{"Certify", CCCertify, uint32(TPMSTSessions), build(TPMSTSessions, []uint32{bad, bad}, two, p(tpm2bz(nil), u16b(AlgNull)))},
		{"Commit", CCCommit, uint32(TPMSTSessions), build(TPMSTSessions, []uint32{bad}, pw, p(tpm2bz(nil), tpm2bz(nil), tpm2bz(nil)))},
		{"ECCDecrypt", CCECCDecrypt, uint32(TPMSTSessions), build(TPMSTSessions, []uint32{bad}, pw, p(tpm2bz(nil), tpm2bz(nil), tpm2bz(nil), tpm2bz(nil), u16b(AlgNull)))},
		{"Decapsulate", CCDecapsulate, uint32(TPMSTSessions), build(TPMSTSessions, []uint32{bad}, pw, tpm2bz(nil))},
		{"SignDigest", CCSignDigest, uint32(TPMSTSessions), build(TPMSTSessions, []uint32{bad}, pw, p(tpm2bz(nil), tpm2bz(z32), u16b(STHashCheck), u32b(RHNull), tpm2bz(nil)))},
		{"EncryptDecrypt", CCEncryptDecrypt, uint32(TPMSTSessions), build(TPMSTSessions, []uint32{bad}, pw, p([]byte{0}, u16b(AlgCFB), tpm2bz(make([]byte, 16)), tpm2bz(nil)))},
		{"EvictControl", CCEvictControl, uint32(TPMSTSessions), build(TPMSTSessions, []uint32{RHOwner, bad}, pw, u32b(0x81000005))},
		{"ContextSave", CCContextSave, uint32(TPMSTNoSessions), build(TPMSTNoSessions, []uint32{bad}, nil, nil)},
		{"ReadPublic", CCReadPublic, uint32(TPMSTNoSessions), build(TPMSTNoSessions, []uint32{bad}, nil, nil)},
		{"RSAEncrypt", CCRSAEncrypt, uint32(TPMSTNoSessions), build(TPMSTNoSessions, []uint32{bad}, nil, p(tpm2bz(nil), u16b(AlgNull), tpm2bz(nil)))},
		{"ECCEncrypt", CCECCEncrypt, uint32(TPMSTNoSessions), build(TPMSTNoSessions, []uint32{bad}, nil, p(tpm2bz(nil), u16b(AlgNull)))},
		{"Encapsulate", CCEncapsulate, uint32(TPMSTNoSessions), build(TPMSTNoSessions, []uint32{bad}, nil, nil)},
		{"MakeCredential", CCMakeCredential, uint32(TPMSTNoSessions), build(TPMSTNoSessions, []uint32{bad}, nil, p(tpm2bz(z32), tpm2bz(z32)))},
		{"NVRead", CCNVRead, uint32(TPMSTSessions), build(TPMSTSessions, []uint32{RHOwner, badNV}, pw, p(u16b(8), u16b(0)))},
		{"NVWrite", CCNVWrite, uint32(TPMSTSessions), build(TPMSTSessions, []uint32{RHOwner, badNV}, pw, p(tpm2bz(z32), u16b(0)))},
		{"NVReadPublic", CCNVReadPublic, uint32(TPMSTNoSessions), build(TPMSTNoSessions, []uint32{badNV}, nil, nil)},
		{"NVChangeAuth", CCNVChangeAuth, uint32(TPMSTSessions), build(TPMSTSessions, []uint32{badNV}, pw, tpm2bz(nil))},
		{"VerifySignature", CCVerifySignature, uint32(TPMSTNoSessions), build(TPMSTNoSessions, []uint32{bad}, nil, p(tpm2bz(z32), u16b(AlgECDSA), u16b(AlgSHA256), tpm2bz(z32), tpm2bz(z32)))},
	}
	for _, c := range cases {
		resp := tpm.Execute(buildCmd(uint16(c.tag), c.cc, c.body))
		if rc := binary.BigEndian.Uint32(resp[6:]); rc == RCSuccess {
			t.Fatalf("%s with a bad handle unexpectedly succeeded", c.name)
		}
	}
}
