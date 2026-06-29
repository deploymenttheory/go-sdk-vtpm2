// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"testing"
)

// startHMACSession opens an unbound, unsalted HMAC session and returns its handle
// and initial nonceTPM (what a TSS tracks to compute the next command HMAC).
func startHMACSession(t *testing.T, tpm *TPM, authHash uint16) (uint32, []byte) {
	t.Helper()
	var w writer
	w.u32(RHNull)
	w.u32(RHNull)
	w.tpm2b(bytes.Repeat([]byte{0x5a}, 16))
	w.tpm2b(nil)
	w.u8(seHMAC)
	w.u16(AlgNull)
	w.u16(authHash)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCStartAuthSession, w.bytes())))
	if rc != RCSuccess {
		t.Fatalf("StartAuthSession rc = 0x%x", rc)
	}
	r := newReader(p)
	h := r.u32()
	return h, r.tpm2b()
}

// changeAuthCmd frames a TPM2_HierarchyChangeAuth authorized by one session,
// given the already-computed auth HMAC and session nonce/attributes.
func changeAuthCmd(authHandle, sessionHandle uint32, nonceCaller []byte, attrs byte, authHMAC, newAuth []byte) []byte {
	var auth writer
	auth.u32(sessionHandle)
	auth.tpm2b(nonceCaller)
	auth.u8(attrs)
	auth.tpm2b(authHMAC)

	var cp writer
	cp.tpm2b(newAuth)

	var body writer
	body.u32(authHandle)
	body.u32(uint32(len(auth.bytes())))
	body.raw(auth.bytes())
	body.raw(cp.bytes())
	return buildCmd(TPMSTSessions, CCHierarchyChangeAuth, body.bytes())
}

// TestHMACSessionRoundTrip drives a full HMAC-authorized command the way a TSS
// does: compute cpHash and the command HMAC, send it, then verify the response
// HMAC the TPM returns.
func TestHMACSessionRoundTrip(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	tpm.h.owner.authValue = []byte("ownerpw")

	sh, nonceTPM := startHMACSession(t, tpm, AlgSHA256)
	nonceCaller := bytes.Repeat([]byte{0x11}, 16)
	newAuth := []byte("next-auth")

	var cp writer
	cp.tpm2b(newAuth)
	cpParams := cp.bytes()
	cph := cpHash(AlgSHA256, CCHierarchyChangeAuth, [][]byte{permanentName(RHOwner)}, cpParams)
	key := []byte("ownerpw") // empty sessionKey ‖ authValue
	const attrs = attrContinue
	mac := commandAuthHMAC(AlgSHA256, key, cph, nonceCaller, nonceTPM, nil, attrs)

	tag, rc, p := parseResp(t, tpm.Execute(changeAuthCmd(RHOwner, sh, nonceCaller, attrs, mac, newAuth)))
	if rc != RCSuccess {
		t.Fatalf("HMAC-authorized command rc = 0x%x", rc)
	}
	if tag != TPMSTSessions {
		t.Fatalf("response tag = 0x%x, want TPM_ST_SESSIONS", tag)
	}
	if !bytes.Equal(tpm.h.owner.authValue, newAuth) {
		t.Fatal("owner auth not changed by the authorized command")
	}

	// Verify the response authorization HMAC, as a TSS would.
	r := newReader(p)
	rpParams := r.bytes(int(r.u32()))
	respNonceTPM := r.tpm2b()
	respAttrs := r.u8()
	respMAC := r.tpm2b()
	if r.err != nil {
		t.Fatalf("parse response auth: %v", r.err)
	}
	rph := rpHash(AlgSHA256, RCSuccess, CCHierarchyChangeAuth, rpParams)
	wantMAC := responseAuthHMAC(AlgSHA256, key, rph, respNonceTPM, nonceCaller, respAttrs)
	if !bytes.Equal(respMAC, wantMAC) {
		t.Fatalf("response HMAC mismatch\n got:  %x\nwant: %x", respMAC, wantMAC)
	}
}

func TestHMACSessionWrongAuth(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	tpm.h.owner.authValue = []byte("ownerpw")

	sh, nonceTPM := startHMACSession(t, tpm, AlgSHA256)
	nonceCaller := bytes.Repeat([]byte{0x22}, 16)
	newAuth := []byte("x")
	var cp writer
	cp.tpm2b(newAuth)
	cph := cpHash(AlgSHA256, CCHierarchyChangeAuth, [][]byte{permanentName(RHOwner)}, cp.bytes())
	// Wrong key (wrong authValue) → AUTH_FAIL.
	mac := commandAuthHMAC(AlgSHA256, []byte("WRONG"), cph, nonceCaller, nonceTPM, nil, 0)
	_, rc, _ := parseResp(t, tpm.Execute(changeAuthCmd(RHOwner, sh, nonceCaller, 0, mac, newAuth)))
	if baseRC(rc) != RCAuthFail {
		t.Fatalf("wrong HMAC rc = 0x%x, want AUTH_FAIL", rc)
	}
}

// TestPolicySessionAuthorizes builds a PolicyCommandCode policy, sets it as the
// owner's authPolicy, satisfies it in a policy session, and authorizes a command.
func TestPolicySessionAuthorizes(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	tpm.h.owner.authPolicy = sha256Cat(make([]byte, 32), be32(CCPolicyCommandCode), be32(CCHierarchyChangeAuth))

	ps := startSession(t, tpm, sePolicy, AlgSHA256)
	var pc writer
	pc.u32(CCHierarchyChangeAuth)
	if _, rc, _ := parseResp(t, tpm.Execute(policyCmd(CCPolicyCommandCode, ps, pc.bytes()))); rc != RCSuccess {
		t.Fatalf("PolicyCommandCode rc = 0x%x", rc)
	}

	// Authorize with the policy session: empty auth HMAC (no PolicyAuthValue).
	newAuth := []byte("via-policy")
	_, rc, _ := parseResp(t, tpm.Execute(changeAuthCmd(RHOwner, ps, nil, 0, nil, newAuth)))
	if rc != RCSuccess {
		t.Fatalf("policy-authorized command rc = 0x%x", rc)
	}
	if !bytes.Equal(tpm.h.owner.authValue, newAuth) {
		t.Fatal("owner auth not changed via policy authorization")
	}
}

func TestPolicySessionMismatch(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	tpm.h.owner.authPolicy = bytes.Repeat([]byte{0xAB}, 32) // a policy the session won't match

	ps := startSession(t, tpm, sePolicy, AlgSHA256) // digest is all-zero
	_, rc, _ := parseResp(t, tpm.Execute(changeAuthCmd(RHOwner, ps, nil, 0, nil, []byte("x"))))
	if baseRC(rc) != RCPolicyFail {
		t.Fatalf("policy mismatch rc = 0x%x, want POLICY_FAIL", rc)
	}
}

// TestPolicyCommandCodeRestriction checks a policy bound to one command code is
// rejected when used to authorize a different command.
func TestPolicyCommandCodeRestriction(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	// Policy satisfied for PolicyCommandCode(CCClear), but we'll authorize
	// HierarchyChangeAuth — the command-code restriction must reject it.
	tpm.h.owner.authPolicy = sha256Cat(make([]byte, 32), be32(CCPolicyCommandCode), be32(CCClear))
	ps := startSession(t, tpm, sePolicy, AlgSHA256)
	var pc writer
	pc.u32(CCClear)
	if _, rc, _ := parseResp(t, tpm.Execute(policyCmd(CCPolicyCommandCode, ps, pc.bytes()))); rc != RCSuccess {
		t.Fatalf("PolicyCommandCode rc = 0x%x", rc)
	}
	_, rc, _ := parseResp(t, tpm.Execute(changeAuthCmd(RHOwner, ps, nil, 0, nil, []byte("x"))))
	if rc != RCPolicyCC {
		t.Fatalf("command-code restriction rc = 0x%x, want POLICY_CC (0x%x)", rc, RCPolicyCC)
	}
}
