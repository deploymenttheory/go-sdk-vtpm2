// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// startSession opens an unbound, unsalted session of the given type and returns
// its handle.
func startSession(t *testing.T, tpm *TPM, se byte, authHash uint16) uint32 {
	t.Helper()
	var w writer
	w.u32(RHNull)                           // tpmKey (unsalted)
	w.u32(RHNull)                           // bind (unbound)
	w.tpm2b(bytes.Repeat([]byte{0x5a}, 16)) // nonceCaller (>= 16 bytes)
	w.tpm2b(nil)                            // encryptedSalt
	w.u8(se)                                // sessionType
	w.u16(AlgNull)                          // symmetric = TPM_ALG_NULL
	w.u16(authHash)                         // authHash
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCStartAuthSession, w.bytes())))
	if rc != RCSuccess {
		t.Fatalf("StartAuthSession rc = 0x%x", rc)
	}
	r := newReader(p)
	h := r.u32()
	nonceTPM := r.tpm2b()
	if r.err != nil || len(nonceTPM) != hashSize(authHash) {
		t.Fatalf("bad StartAuthSession response (nonceTPM %d bytes, err %v)", len(nonceTPM), r.err)
	}
	if classifyHandle(h) != htHMACSession {
		t.Fatalf("session handle 0x%x not in the session range", h)
	}
	return h
}

// policyCmd frames a policy command: the policy-session handle then params.
func policyCmd(cc, session uint32, params []byte) []byte {
	var w writer
	w.u32(session)
	w.raw(params)
	return buildCmd(TPMSTNoSessions, cc, w.bytes())
}

// policyDigest reads a session's current digest via TPM2_PolicyGetDigest.
func policyDigest(t *testing.T, tpm *TPM, session uint32) []byte {
	t.Helper()
	_, rc, p := parseResp(t, tpm.Execute(policyCmd(CCPolicyGetDigest, session, nil)))
	if rc != RCSuccess {
		t.Fatalf("PolicyGetDigest rc = 0x%x", rc)
	}
	return newReader(p).tpm2b()
}

// sha256Cat hashes the concatenation of parts (the policyDigest reference).
func sha256Cat(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	sum := h.Sum(nil)
	return sum
}

func TestStartAuthSessionRejections(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	mk := func(tpmKey uint32, nonce []byte, salt []byte, se byte) []byte {
		var w writer
		w.u32(tpmKey)
		w.u32(RHNull)
		w.tpm2b(nonce)
		w.tpm2b(salt)
		w.u8(se)
		w.u16(AlgNull)
		w.u16(AlgSHA256)
		return buildCmd(TPMSTNoSessions, CCStartAuthSession, w.bytes())
	}
	good := bytes.Repeat([]byte{1}, 16)
	cases := []struct {
		name string
		cmd  []byte
		want uint32
	}{
		{"bad session type", mk(RHNull, good, nil, 0x09), RCValue},
		{"short nonce", mk(RHNull, []byte{1, 2}, nil, sePolicy), RCSize},
		{"salted not supported", mk(RHOwner, good, nil, sePolicy), RCHandle},
	}
	for _, c := range cases {
		_, rc, _ := parseResp(t, tpm.Execute(c.cmd))
		if baseRC(rc) != c.want {
			t.Errorf("%s: rc = 0x%x, want base 0x%x", c.name, rc, c.want)
		}
	}
}

func TestSessionFlushAndCapability(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	s := startSession(t, tpm, seHMAC, AlgSHA256)

	// The session shows up under TPM_CAP_HANDLES for the session range.
	r := newReader(getCap(t, tpm, CapHandles, htHMACSession, 100))
	_ = r.u8()
	_ = r.u32() // capability
	if n := r.u32(); n != 1 {
		t.Fatalf("session-range handle count = %d, want 1", n)
	}
	if h := r.u32(); h != s {
		t.Fatalf("listed handle 0x%x, want 0x%x", h, s)
	}

	// Flush it.
	var fp writer
	fp.u32(s)
	_, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCFlushContext, fp.bytes())))
	if rc != RCSuccess {
		t.Fatalf("FlushContext rc = 0x%x", rc)
	}
	if _, ok := tpm.sessions.get(s); ok {
		t.Fatal("session not removed after FlushContext")
	}
	// Flushing again is a handle error.
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCFlushContext, fp.bytes()))); baseRC(rc) != RCHandle {
		t.Fatalf("double flush rc = 0x%x, want HANDLE", rc)
	}
}

func TestPolicyCommandCodeDigest(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	s := startSession(t, tpm, sePolicy, AlgSHA256)

	var p writer
	p.u32(CCPCRExtend)
	if _, rc, _ := parseResp(t, tpm.Execute(policyCmd(CCPolicyCommandCode, s, p.bytes()))); rc != RCSuccess {
		t.Fatalf("PolicyCommandCode rc = 0x%x", rc)
	}
	zero := make([]byte, 32)
	want := sha256Cat(zero, be32(CCPolicyCommandCode), be32(CCPCRExtend))
	if got := policyDigest(t, tpm, s); !bytes.Equal(got, want) {
		t.Fatalf("policyDigest = %x, want %x", got, want)
	}
}

func TestPolicyAuthValueDigest(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	s := startSession(t, tpm, sePolicy, AlgSHA256)
	if _, rc, _ := parseResp(t, tpm.Execute(policyCmd(CCPolicyAuthValue, s, nil))); rc != RCSuccess {
		t.Fatalf("PolicyAuthValue rc = 0x%x", rc)
	}
	want := sha256Cat(make([]byte, 32), be32(CCPolicyAuthValue))
	if got := policyDigest(t, tpm, s); !bytes.Equal(got, want) {
		t.Fatalf("policyDigest = %x, want %x", got, want)
	}
	if sess, _ := tpm.sessions.get(s); !sess.policyAuth {
		t.Fatal("policyAuth flag not set")
	}
}

func TestPolicyPCRTrialDigest(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	s := startSession(t, tpm, seTrial, AlgSHA256)

	pcrDigest := bytes.Repeat([]byte{0xAA}, 32)
	sel := oneSHA256Selection(7) // TPML_PCR_SELECTION for PCR7/SHA-256
	var p writer
	p.tpm2b(pcrDigest)
	p.raw(sel)
	if _, rc, _ := parseResp(t, tpm.Execute(policyCmd(CCPolicyPCR, s, p.bytes()))); rc != RCSuccess {
		t.Fatalf("PolicyPCR rc = 0x%x", rc)
	}
	// Trial session folds the caller's pcrDigest directly.
	want := sha256Cat(make([]byte, 32), be32(CCPolicyPCR), sel, pcrDigest)
	if got := policyDigest(t, tpm, s); !bytes.Equal(got, want) {
		t.Fatalf("policyDigest = %x, want %x", got, want)
	}
}

func TestPolicyPCRRealSessionMismatch(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	s := startSession(t, tpm, sePolicy, AlgSHA256)
	// PCR7 is all-zero at start; a non-matching pcrDigest must be rejected.
	var p writer
	p.tpm2b(bytes.Repeat([]byte{0xFF}, 32))
	p.raw(oneSHA256Selection(7))
	if _, rc, _ := parseResp(t, tpm.Execute(policyCmd(CCPolicyPCR, s, p.bytes()))); baseRC(rc) != RCValue {
		t.Fatalf("PolicyPCR mismatch rc = 0x%x, want VALUE", rc)
	}
}

func TestPolicyORDigest(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	s := startSession(t, tpm, seTrial, AlgSHA256)
	d1 := bytes.Repeat([]byte{0x11}, 32)
	d2 := bytes.Repeat([]byte{0x22}, 32)
	var p writer
	p.u32(2) // TPML_DIGEST count
	p.tpm2b(d1)
	p.tpm2b(d2)
	if _, rc, _ := parseResp(t, tpm.Execute(policyCmd(CCPolicyOR, s, p.bytes()))); rc != RCSuccess {
		t.Fatalf("PolicyOR rc = 0x%x", rc)
	}
	// OR resets to a zero digest then folds the concatenated branch digests.
	want := sha256Cat(make([]byte, 32), be32(CCPolicyOR), append(append([]byte{}, d1...), d2...))
	if got := policyDigest(t, tpm, s); !bytes.Equal(got, want) {
		t.Fatalf("policyDigest = %x, want %x", got, want)
	}
}

func TestPolicyRestartResets(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	s := startSession(t, tpm, sePolicy, AlgSHA256)
	if _, rc, _ := parseResp(t, tpm.Execute(policyCmd(CCPolicyAuthValue, s, nil))); rc != RCSuccess {
		t.Fatal("PolicyAuthValue failed")
	}
	if _, rc, _ := parseResp(t, tpm.Execute(policyCmd(CCPolicyRestart, s, nil))); rc != RCSuccess {
		t.Fatalf("PolicyRestart rc = 0x%x", rc)
	}
	if got := policyDigest(t, tpm, s); !bytes.Equal(got, make([]byte, 32)) {
		t.Fatalf("policyDigest after restart = %x, want zero", got)
	}
	if sess, _ := tpm.sessions.get(s); sess.policyAuth {
		t.Fatal("policyAuth not cleared by restart")
	}
}

func TestPolicyOnNonPolicySession(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	s := startSession(t, tpm, seHMAC, AlgSHA256) // an HMAC session, not a policy one
	if _, rc, _ := parseResp(t, tpm.Execute(policyCmd(CCPolicyAuthValue, s, nil))); baseRC(rc) != RCHandle {
		t.Fatalf("policy cmd on HMAC session rc = 0x%x, want HANDLE", rc)
	}
}
