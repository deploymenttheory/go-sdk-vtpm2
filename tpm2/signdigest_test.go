// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"testing"
)

func TestSignDigestVerifyDigestSignature(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	keyH := createSigningKey(t, tpm, srk, eccSigningTemplate())
	digest := bytes.Repeat([]byte{0x5a}, 32)

	// SignDigest: context, digest, null hashcheck (key is unrestricted).
	var sb writer
	sb.u32(keyH)
	sb.raw(onePasswordAuth())
	sb.tpm2b(nil) // context
	sb.tpm2b(digest)
	sb.u16(STHashCheck)
	sb.u32(RHNull)
	sb.tpm2b(nil)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCSignDigest, sb.bytes())))
	if rc != RCSuccess {
		t.Fatalf("SignDigest rc = 0x%x", rc)
	}
	pr := newReader(p)
	sig := pr.bytes(int(pr.u32())) // signature is the whole parameter area

	// VerifyDigestSignature accepts it (no authorization).
	verify := func(sig []byte) uint32 {
		var vb writer
		vb.u32(keyH)
		vb.tpm2b(nil) // context
		vb.tpm2b(digest)
		vb.raw(sig)
		_, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCVerifyDigestSignature, vb.bytes())))
		return rc
	}
	if rc := verify(sig); rc != RCSuccess {
		t.Fatalf("VerifyDigestSignature rc = 0x%x", rc)
	}

	// A tampered signature is rejected.
	bad := append([]byte(nil), sig...)
	bad[len(bad)-1] ^= 0xFF
	if rc := verify(bad); baseRC(rc) != RCSignature {
		t.Fatalf("tampered VerifyDigestSignature rc = 0x%x, want RC_SIGNATURE", rc)
	}
}
