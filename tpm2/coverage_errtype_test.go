// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"encoding/binary"
	"testing"
)

// TestWrongTypeAndAuthPaths triggers wrong-key-type and wrong-auth-hierarchy error
// branches across many handlers.
func TestWrongTypeAndAuthPaths(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate()) // ECC restricted decrypt
	rsaKey := createSigningKey(t, tpm, srk, rsaSigningTemplate())     // RSA sign key
	eccSign := createSigningKey(t, tpm, srk, eccSigningTemplate())

	pw := onePasswordAuth()
	tb := func(x []byte) []byte { var b writer; b.tpm2b(x); return b.bytes() }
	u16 := func(v uint16) []byte { var b writer; b.u16(v); return b.bytes() }
	u32 := func(v uint32) []byte { var b writer; b.u32(v); return b.bytes() }
	cat := func(xs ...[]byte) []byte {
		var b writer
		for _, x := range xs {
			b.raw(x)
		}
		return b.bytes()
	}
	handlesNoAuth := func(hs ...uint32) []byte {
		var b writer
		for _, h := range hs {
			b.u32(h)
		}
		return b.bytes()
	}
	withAuth := func(h uint32, params []byte) []byte { return cat(u32(h), pw, params) }
	withAuth2 := func(h1, h2 uint32, params []byte) []byte { return cat(u32(h1), u32(h2), pw, params) }

	cases := []struct {
		name string
		tag  uint16
		cc   uint32
		body []byte
	}{
		// Wrong key type.
		{"RSAEncrypt-ECC", TPMSTNoSessions, CCRSAEncrypt, cat(handlesNoAuth(srk), tb(nil), u16(AlgNull), tb(nil))},
		{"ECCEncrypt-RSA", TPMSTNoSessions, CCECCEncrypt, cat(handlesNoAuth(rsaKey), tb([]byte("x")), u16(AlgNull), u16(AlgSHA256))},
		{"Commit-RSA", TPMSTSessions, CCCommit, withAuth(rsaKey, cat(tb(nil), tb(nil), tb(nil)))},
		{"ZGen2Phase-RSA", TPMSTSessions, CCZGen2Phase, withAuth(rsaKey, cat(tb(nil), tb(nil), u16(AlgECDH), u16(0)))},
		{"EncryptDecrypt-nonsym", TPMSTSessions, CCEncryptDecrypt, withAuth(eccSign, cat([]byte{0}, u16(AlgCFB), tb(make([]byte, 16)), tb(nil)))},
		{"Encapsulate-restricted", TPMSTNoSessions, CCEncapsulate, handlesNoAuth(srk)}, // restricted ⇒ not a KEM key

		// Wrong authorizing hierarchy (must be owner/platform/etc).
		{"ClockSet-endorsement", TPMSTSessions, CCClockSet, withAuth(RHEndorsement, cat(u32(0), u32(0)))},
		{"SetAlgorithmSet-owner", TPMSTSessions, CCSetAlgorithmSet, withAuth(RHOwner, u32(1))},
		{"PPCommands-owner", TPMSTSessions, CCPPCommands, withAuth(RHOwner, cat(u32(0), u32(0)))},
		{"PCRAllocate-owner", TPMSTSessions, CCPCRAllocate, withAuth(RHOwner, u32(0))},
		{"PCRSetAuthPolicy-owner", TPMSTSessions, CCPCRSetAuthPolicy, withAuth(RHOwner, cat(tb(nil), u16(AlgNull), u32(20)))},
		{"NVGlobalWriteLock-endorsement", TPMSTSessions, CCNVGlobalWriteLock, withAuth(RHEndorsement, nil)},
		{"ReadOnlyControl-owner", TPMSTSessions, CCReadOnlyControl, withAuth(RHOwner, []byte{1})},
		{"ACTSetTimeout-badhandle", TPMSTSessions, CCACTSetTimeout, withAuth(0x40000200, u32(1))},
		{"GetTime-notendorsement", TPMSTSessions, CCGetTime, withAuth2(RHOwner, eccSign, cat(tb(nil), u16(AlgNull)))},

		// Invalid parameters.
		{"TestParms-badtype", TPMSTNoSessions, CCTestParms, u16(0x9999)},
		{"PolicyTransportSPDM-badname", TPMSTNoSessions, CCPolicyTransportSPDM, nil},
	}
	for _, c := range cases {
		resp := tpm.Execute(buildCmd(c.tag, c.cc, c.body))
		if rc := binary.BigEndian.Uint32(resp[6:]); rc == RCSuccess {
			t.Fatalf("%s unexpectedly succeeded", c.name)
		}
	}
}
