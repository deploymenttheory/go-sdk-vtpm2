// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import "testing"

func TestSignVerifySequence(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	keyH := createSigningKey(t, tpm, srk, eccSigningTemplate())
	chunk1 := []byte("first part of the message, ")
	chunk2 := []byte("and the second part to sign")

	// SignSequenceStart → Update(chunk1) → SignSequenceComplete(chunk2).
	var sb writer
	sb.u32(keyH)
	sb.tpm2b(nil) // auth
	sb.tpm2b(nil) // context
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCSignSequenceStart, sb.bytes())))
	if rc != RCSuccess {
		t.Fatalf("SignSequenceStart rc = 0x%x", rc)
	}
	signSeq := newReader(p).u32()
	seqUpdate(t, tpm, signSeq, chunk1)

	var cb writer
	cb.u32(signSeq)
	cb.u32(keyH)
	cb.raw(twoPasswordAuth())
	cb.tpm2b(chunk2)
	_, rc, cp := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCSignSequenceComplete, cb.bytes())))
	if rc != RCSuccess {
		t.Fatalf("SignSequenceComplete rc = 0x%x", rc)
	}
	cr := newReader(cp)
	sig := cr.bytes(int(cr.u32()))

	// Verify the signature over the same streamed data via a verify sequence.
	verifySeq := func() uint32 {
		var vb writer
		vb.u32(keyH)
		vb.tpm2b(nil) // auth
		vb.tpm2b(nil) // hint
		vb.tpm2b(nil) // context
		_, rc, vp := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCVerifySequenceStart, vb.bytes())))
		if rc != RCSuccess {
			t.Fatalf("VerifySequenceStart rc = 0x%x", rc)
		}
		h := newReader(vp).u32()
		seqUpdate(t, tpm, h, chunk1)
		seqUpdate(t, tpm, h, chunk2)
		return h
	}
	complete := func(seqH uint32, sig []byte) uint32 {
		var vcb writer
		vcb.u32(seqH)
		vcb.u32(keyH)
		vcb.raw(onePasswordAuth()) // only the sequence handle is authorized
		vcb.raw(sig)
		_, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCVerifySequenceComplete, vcb.bytes())))
		return rc
	}

	if rc := complete(verifySeq(), sig); rc != RCSuccess {
		t.Fatalf("VerifySequenceComplete rc = 0x%x", rc)
	}

	// A tampered signature is rejected.
	bad := append([]byte(nil), sig...)
	bad[len(bad)-1] ^= 0xFF
	if rc := complete(verifySeq(), bad); baseRC(rc) != RCSignature {
		t.Fatalf("tampered VerifySequenceComplete rc = 0x%x, want RC_SIGNATURE", rc)
	}
}
