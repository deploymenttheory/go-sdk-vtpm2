// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"encoding/binary"
	"testing"
)

// TestCommandErrorPaths sends a truncated (empty) parameter area to many commands
// and confirms each returns an error response without panicking — exercising the
// parse/insufficient-data branches across the handlers.
func TestCommandErrorPaths(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	cmds := []struct {
		cc  uint32
		tag uint16
	}{
		{CCSign, TPMSTSessions}, {CCQuote, TPMSTSessions}, {CCUnseal, TPMSTSessions},
		{CCRSAEncrypt, TPMSTNoSessions}, {CCRSADecrypt, TPMSTSessions}, {CCECDHZGen, TPMSTSessions},
		{CCECDHKeyGen, TPMSTNoSessions}, {CCECCEncrypt, TPMSTNoSessions}, {CCECCDecrypt, TPMSTSessions},
		{CCEncapsulate, TPMSTNoSessions}, {CCDecapsulate, TPMSTSessions}, {CCEncryptDecrypt, TPMSTSessions},
		{CCEncryptDecrypt2, TPMSTSessions}, {CCCertify, TPMSTSessions}, {CCCertifyCreation, TPMSTSessions},
		{CCGetTime, TPMSTSessions}, {CCNVCertify, TPMSTSessions}, {CCCertifyX509, TPMSTSessions},
		{CCCommit, TPMSTSessions}, {CCECEphemeral, TPMSTNoSessions}, {CCZGen2Phase, TPMSTSessions},
		{CCMakeCredential, TPMSTNoSessions}, {CCActivateCredential, TPMSTSessions}, {CCDuplicate, TPMSTSessions},
		{CCImport, TPMSTSessions}, {CCRewrap, TPMSTSessions}, {CCCreate, TPMSTSessions},
		{CCCreateLoaded, TPMSTSessions}, {CCLoad, TPMSTSessions}, {CCLoadExternal, TPMSTNoSessions},
		{CCReadPublic, TPMSTNoSessions}, {CCNVWrite, TPMSTSessions}, {CCNVRead, TPMSTSessions},
		{CCNVDefineSpace, TPMSTSessions}, {CCNVIncrement, TPMSTSessions}, {CCNVExtend, TPMSTSessions},
		{CCNVSetBits, TPMSTSessions}, {CCNVReadPublic, TPMSTNoSessions}, {CCObjectChangeAuth, TPMSTSessions},
		{CCPolicyPCR, TPMSTNoSessions}, {CCPolicyOR, TPMSTNoSessions}, {CCPolicyNV, TPMSTSessions},
		{CCPolicySecret, TPMSTSessions}, {CCPolicySigned, TPMSTNoSessions}, {CCSignDigest, TPMSTSessions},
		{CCVerifyDigestSignature, TPMSTNoSessions}, {CCSignSequenceStart, TPMSTNoSessions},
		{CCVerifySequenceStart, TPMSTNoSessions}, {CCSetPrimaryPolicy, TPMSTSessions},
		{CCHierarchyChangeAuth, TPMSTSessions}, {CCClockSet, TPMSTSessions}, {CCClockRateAdjust, TPMSTSessions},
		{CCSetCommandCodeAuditStatus, TPMSTSessions}, {CCPPCommands, TPMSTSessions}, {CCSetAlgorithmSet, TPMSTSessions},
		{CCACTSetTimeout, TPMSTSessions}, {CCReadOnlyControl, TPMSTSessions}, {CCTestParms, TPMSTNoSessions},
		{CCStirRandom, TPMSTNoSessions}, {CCPCREvent, TPMSTSessions}, {CCNVChangeAuth, TPMSTSessions},
		{CCNVGlobalWriteLock, TPMSTSessions}, {CCPCRAllocate, TPMSTSessions}, {CCPCRSetAuthValue, TPMSTSessions},
		{CCPCRSetAuthPolicy, TPMSTSessions}, {CCContextSave, TPMSTNoSessions}, {CCFlushContext, TPMSTNoSessions},
		{CCEvictControl, TPMSTSessions}, {CCStartAuthSession, TPMSTNoSessions}, {CCHMAC, TPMSTSessions},
		{CCVerifySignature, TPMSTNoSessions}, {CCHash, TPMSTNoSessions}, {CCRSADecrypt, TPMSTSessions},
	}
	for _, c := range cmds {
		resp := tpm.Execute(buildCmd(c.tag, c.cc, nil)) // empty parameter area
		if len(resp) < headerLen {
			t.Fatalf("cc=0x%x: short response (%d bytes)", c.cc, len(resp))
		}
		if rc := binary.BigEndian.Uint32(resp[6:]); rc == RCSuccess {
			t.Fatalf("cc=0x%x: empty parameter area unexpectedly succeeded", c.cc)
		}
	}
}

// TestPolicyCounterTimerSigned exercises the signed comparison path (signedBig).
func TestPolicyCounterTimerSigned(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	s := startSession(t, tpm, sePolicy, AlgSHA256)
	// SIGNED_LT (0x0004): clock (a small positive time) < a large operandB whose
	// top bit is set (negative when read as signed) is FALSE → policy fails.
	negative := []byte{0x80, 0, 0, 0, 0, 0, 0, 0}
	if _, rc, _ := parseResp(t, tpm.Execute(policyCmd(CCPolicyCounterTimer, s, counterTimerParams(negative, 0, 0x0004)))); baseRC(rc) != RCPolicyFail {
		t.Fatalf("signed PolicyCounterTimer rc = 0x%x, want RC_POLICY_FAIL", rc)
	}
	// SIGNED_GT (0x0002): clock > a negative operandB is TRUE → succeeds.
	s2 := startSession(t, tpm, sePolicy, AlgSHA256)
	if _, rc, _ := parseResp(t, tpm.Execute(policyCmd(CCPolicyCounterTimer, s2, counterTimerParams(negative, 0, 0x0002)))); rc != RCSuccess {
		t.Fatalf("signed-GT PolicyCounterTimer rc = 0x%x", rc)
	}
}

// TestCommandAuditClear exercises the clear path of the audited-command set.
func TestCommandAuditClear(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	set := func(setCC, clearCC uint32) uint32 {
		var b writer
		b.u32(RHOwner)
		b.raw(onePasswordAuth())
		b.u16(AlgSHA256)
		if setCC != 0 {
			b.u32(1)
			b.u32(setCC)
		} else {
			b.u32(0)
		}
		if clearCC != 0 {
			b.u32(1)
			b.u32(clearCC)
		} else {
			b.u32(0)
		}
		_, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCSetCommandCodeAuditStatus, b.bytes())))
		return rc
	}
	if rc := set(CCNVWrite, 0); rc != RCSuccess {
		t.Fatalf("set rc = 0x%x", rc)
	}
	if !tpm.audit.audited(CCNVWrite) {
		t.Fatal("command not added to audit set")
	}
	if rc := set(0, CCNVWrite); rc != RCSuccess {
		t.Fatalf("clear rc = 0x%x", rc)
	}
	if tpm.audit.audited(CCNVWrite) {
		t.Fatal("command not removed from audit set")
	}
}

// TestSequenceCompleteTicket exercises safeToSign by completing a hash sequence
// under a real hierarchy, which yields a non-NULL hashcheck ticket.
func TestSequenceCompleteTicket(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	h := hashSeqStart(t, tpm, AlgSHA256)
	seqUpdate(t, tpm, h, []byte("safe data that is not TPM-generated"))

	var b writer
	b.tpm2b([]byte(" tail"))
	b.u32(RHOwner) // a real hierarchy ⇒ a usable hashcheck ticket
	_, rc, p := parseResp(t, tpm.Execute(buildHierarchyCmd(CCSequenceComplete, h, nil, b.bytes())))
	if rc != RCSuccess {
		t.Fatalf("SequenceComplete rc = 0x%x", rc)
	}
	r := newReader(p)
	_ = r.u32()     // parameterSize
	_ = r.tpm2b()   // result digest
	tag := r.u16()  // ticket tag
	_ = r.u32()     // hierarchy
	tk := r.tpm2b() // ticket digest
	if tag != STHashCheck || len(tk) == 0 {
		t.Fatal("expected a non-NULL hashcheck ticket for safe data under a real hierarchy")
	}
}

// TestPersistentHandlesCapability exercises persistentHandles via EvictControl +
// GetCapability(TPM_CAP_HANDLES).
func TestPersistentHandlesCapability(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	const persistent = 0x81000001

	var b writer
	b.u32(RHOwner)
	b.u32(srk)
	b.raw(onePasswordAuth())
	b.u32(persistent)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCEvictControl, b.bytes()))); rc != RCSuccess {
		t.Fatalf("EvictControl rc = 0x%x", rc)
	}
	// The persistent handle is now reported by TPM_CAP_HANDLES.
	r := newReader(getCap(t, tpm, CapHandles, htPersistent, 16))
	_ = r.u8()  // moreData
	_ = r.u32() // capability
	n := r.u32()
	found := false
	for i := uint32(0); i < n; i++ {
		if r.u32() == persistent {
			found = true
		}
	}
	if !found {
		t.Fatal("persistent handle not reported by TPM_CAP_HANDLES")
	}
}
