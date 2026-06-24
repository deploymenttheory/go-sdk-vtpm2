// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"crypto/hmac"
	"io"
)

// This file holds the cryptographic core of session authorization (TPM 2.0
// Part 1, §18.7 and §19.6): the command/response parameter hashes, the
// authorization HMACs, and the processor that verifies a command's
// authorizations and signs the response. The hash/HMAC functions must match a
// real TSS byte-for-byte, so they are validated against golden vectors in
// auth_vectors_test.go.

// TPMA_SESSION attribute bits used by the processor.
const (
	attrContinue byte = 0x01 // continueSession: when clear, flush after the command
	attrDecrypt  byte = 0x20 // the first command parameter is encrypted by the caller
	attrEncrypt  byte = 0x40 // the TPM encrypts the first response parameter
)

// commandAuth is the parsed authorization context of a command: its handles, the
// authorization sessions, and the raw command parameter area used for cpHash.
type commandAuth struct {
	cc       uint32
	handles  []uint32
	sessions []session
	cpParams []byte
	cpStart  int            // offset of cpParams within the reader buffer (for in-place decrypt)
	resolved []resolvedAuth // filled in by verifyAuth, in session order
}

// resolvedAuth records what verifyAuth learned about one authorization, so the
// response can be signed with the same key material.
type resolvedAuth struct {
	live      *authSession // nil for a password session
	authValue []byte
	bound     bool
}

// parseCommandAuth reads the handle area, the authorization area, and captures
// the remaining bytes as cpParams. Authorized commands must carry sessions.
func parseCommandAuth(tag uint16, cc uint32, nHandles int, r *reader) (*commandAuth, []byte) {
	handles := make([]uint32, nHandles)
	for i := range handles {
		handles[i] = r.u32()
	}
	if r.err != nil {
		return nil, errorResponse(RCInsufficient)
	}
	if tag != TPMSTSessions {
		return nil, errorResponse(RCAuthMissing)
	}
	sessions, ok := readAuthArea(r)
	if !ok {
		return nil, errorResponse(RCAuthSize)
	}
	return &commandAuth{
		cc:       cc,
		handles:  handles,
		sessions: sessions,
		cpParams: append([]byte(nil), r.b[r.off:]...),
		cpStart:  r.off,
	}, nil
}

// entityAuthValue returns the authValue of the entity a handle names, for
// parameter encryption keys.
func (t *TPM) entityAuthValue(handle uint32) []byte {
	switch classifyHandle(handle) {
	case htPermanent:
		if hi := t.h.byHandle(handle); hi != nil {
			return hi.authValue
		}
	case htTransient, htPersistent:
		if o, ok := t.objects.get(handle); ok {
			return o.sensitive.AuthValue
		}
	case htNVIndex:
		if idx, ok := t.nv.get(handle); ok {
			return idx.authValue
		}
	}
	return nil
}

// decryptCommandParams decrypts the first command parameter in place when a
// session carries the decrypt attribute, so cpHash and the handler both see the
// plaintext (TPM 2.0 Part 1, §21). It must run after parseCommandAuth and before
// the handler reads parameters. The key uses the first handle's authValue.
func (t *TPM) decryptCommandParams(ac *commandAuth, r *reader) {
	for _, s := range ac.sessions {
		if s.handle == RHPW || s.attrs&attrDecrypt == 0 {
			continue
		}
		as, ok := t.sessions.get(s.handle)
		if !ok {
			return
		}
		authValue := t.entityAuthValue(ac.handles[0])
		// Command direction: nonceNewer = nonceCaller, nonceOlder = nonceTPM.
		cryptParam(as, authValue, s.nonce, as.nonceTPM, r.b[ac.cpStart:], false)
		ac.cpParams = append([]byte(nil), r.b[ac.cpStart:]...)
		return // only the first decrypt session applies
	}
}

// handleName returns the Name of a handle for cpHash: the cached Name for a
// loaded object or defined NV index, and the handle value for a permanent handle.
func (t *TPM) handleName(h uint32) []byte {
	switch classifyHandle(h) {
	case htTransient, htPersistent:
		if o, ok := t.objects.get(h); ok {
			return o.name
		}
	case htNVIndex:
		if idx, ok := t.nv.get(h); ok {
			return idx.name
		}
	}
	return permanentName(h)
}

// commandHandleNames returns the Names of all of a command's handles, in order.
func (t *TPM) commandHandleNames(ac *commandAuth) [][]byte {
	ns := make([][]byte, len(ac.handles))
	for i, h := range ac.handles {
		ns[i] = t.handleName(h)
	}
	return ns
}

// verifyAuth checks the sessionIdx'th authorization against an entity (identified
// by its Name, authValue and authPolicy) and records the resolution for response
// signing. daProtected marks the entity as dictionary-attack protected.
func (t *TPM) verifyAuth(ac *commandAuth, sessionIdx int, entityName, authValue, authPolicy []byte, daProtected bool) []byte {
	for len(ac.resolved) <= sessionIdx {
		ac.resolved = append(ac.resolved, resolvedAuth{})
	}
	s := ac.sessions[sessionIdx]

	if daProtected && t.da.inLockout() {
		return errorResponse(RCLockout)
	}
	fail := func() []byte {
		if daProtected {
			t.da.recordFailure()
		}
		return errorResponse(withSession(RCAuthFail, sessionIdx+1))
	}

	switch {
	case s.handle == RHPW:
		if !hmac.Equal(s.hmac, authValue) {
			return fail()
		}
		ac.resolved[sessionIdx] = resolvedAuth{authValue: authValue}

	case classifyHandle(s.handle) == htHMACSession:
		as, ok := t.sessions.get(s.handle)
		if !ok {
			return errorResponse(withSession(RCHandle, sessionIdx+1))
		}
		bound := len(as.bindName) > 0 && hmac.Equal(as.bindName, entityName)
		switch as.kind {
		case seHMAC:
			cph := cpHash(as.authHash, ac.cc, t.commandHandleNames(ac), ac.cpParams)
			key := authHMACKey(as.sessionKey, authValue, bound)
			want := commandAuthHMAC(as.authHash, key, cph, s.nonce, as.nonceTPM, s.attrs)
			if !hmac.Equal(want, s.hmac) {
				return fail()
			}
		case sePolicy:
			if len(authPolicy) == 0 || !hmac.Equal(as.policyDigest, authPolicy) {
				return errorResponse(withSession(RCPolicyFail, sessionIdx+1))
			}
			if as.commandCode != 0 && as.commandCode != ac.cc {
				return errorResponse(RCPolicyCC)
			}
			if as.policyAuth { // PolicyAuthValue: also prove the authValue via HMAC
				cph := cpHash(as.authHash, ac.cc, t.commandHandleNames(ac), ac.cpParams)
				key := authHMACKey(as.sessionKey, authValue, false)
				want := commandAuthHMAC(as.authHash, key, cph, s.nonce, as.nonceTPM, s.attrs)
				if !hmac.Equal(want, s.hmac) {
					return fail()
				}
			}
		default:
			return errorResponse(withSession(RCAuthType, sessionIdx+1))
		}
		ac.resolved[sessionIdx] = resolvedAuth{live: as, authValue: authValue, bound: bound}

	default:
		return errorResponse(withSession(RCHandle, sessionIdx+1))
	}

	if daProtected {
		t.da.recordSuccess()
	}
	return nil
}

// authResponse frames the response for an authorized command: the response
// handle area, parameterSize, the response parameters, then one response
// authorization per session. HMAC (and PolicyAuthValue policy) sessions get a
// fresh nonceTPM and a response HMAC; sessions whose continueSession bit is clear
// are flushed. Response handles precede parameterSize and are not part of rpHash.
func (t *TPM) authResponse(ac *commandAuth, respHandles []uint32, rpParams []byte) []byte {
	type respAuth struct {
		nonce, mac []byte
		cont       byte
	}
	auths := make([]respAuth, len(ac.sessions))

	// First pass: roll each session's nonce and compute its response HMAC over the
	// *plaintext* parameters. Response encryption (below) happens afterwards.
	var encSess *authSession
	var encNonce, encOlder, encAuthVal []byte
	for i, s := range ac.sessions {
		cont := s.attrs & attrContinue
		if s.handle == RHPW {
			auths[i] = respAuth{cont: cont}
			continue
		}
		as := ac.resolved[i].live
		if as == nil {
			auths[i] = respAuth{cont: cont}
			continue
		}
		nonce := make([]byte, len(as.nonceTPM))
		_, _ = io.ReadFull(t.rand, nonce)
		as.nonceTPM = nonce
		var mac []byte
		if as.kind == seHMAC || (as.kind == sePolicy && as.policyAuth) {
			rph := rpHash(as.authHash, RCSuccess, ac.cc, rpParams)
			key := authHMACKey(as.sessionKey, ac.resolved[i].authValue, ac.resolved[i].bound)
			mac = responseAuthHMAC(as.authHash, key, rph, nonce, s.nonce, cont)
		}
		auths[i] = respAuth{nonce: nonce, mac: mac, cont: cont}
		if s.attrs&attrEncrypt != 0 && encSess == nil {
			encSess, encNonce, encOlder, encAuthVal = as, nonce, s.nonce, ac.resolved[i].authValue
		}
		if cont == 0 {
			t.sessions.flush(s.handle)
		}
	}

	// Encrypt the first response parameter for an encrypt session (after the HMACs,
	// which cover the plaintext).
	params := rpParams
	if encSess != nil {
		params = append([]byte(nil), rpParams...)
		cryptParam(encSess, encAuthVal, encNonce, encOlder, params, true)
	}

	var body writer
	for _, h := range respHandles {
		body.u32(h)
	}
	body.u32(uint32(len(params)))
	body.raw(params)
	for _, a := range auths {
		body.u16(uint16(len(a.nonce)))
		body.raw(a.nonce)
		body.u8(a.cont)
		body.u16(uint16(len(a.mac)))
		body.raw(a.mac)
	}

	payload := body.bytes()
	out := make([]byte, headerLen, headerLen+len(payload))
	putHeader(out, TPMSTSessions, uint32(headerLen+len(payload)), RCSuccess)
	return append(out, payload...)
}

// cpHash computes the command-parameter hash (TPM 2.0 Part 1, §18.7):
//
//	cpHash = H_alg(commandCode ‖ name0 ‖ name1 ‖ … ‖ cpParams)
//
// names are the Names of the command's handles, in handle-area order. cpParams is
// the marshalled command parameter area (everything after the handles and the
// authorization area).
func cpHash(alg uint16, cc uint32, names [][]byte, cpParams []byte) []byte {
	h := newHash(alg)
	if h == nil {
		return nil
	}
	h.Write(be32(cc))
	for _, n := range names {
		h.Write(n)
	}
	h.Write(cpParams)
	return h.Sum(nil)
}

// rpHash computes the response-parameter hash (TPM 2.0 Part 1, §18.7):
//
//	rpHash = H_alg(responseCode ‖ commandCode ‖ rpParams)
func rpHash(alg uint16, rc, cc uint32, rpParams []byte) []byte {
	h := newHash(alg)
	if h == nil {
		return nil
	}
	h.Write(be32(rc))
	h.Write(be32(cc))
	h.Write(rpParams)
	return h.Sum(nil)
}

// authHMACKey is the HMAC key for a session authorization: the session key
// concatenated with the entity's authValue. The authValue is omitted when the
// session is bound to the entity being authorized (it is already folded into the
// session key) — bound reports that case.
func authHMACKey(sessionKey, authValue []byte, bound bool) []byte {
	key := append([]byte(nil), sessionKey...)
	if !bound {
		key = append(key, authValue...)
	}
	return key
}

// commandAuthHMAC computes the authorization HMAC a caller must present in a
// command (TPM 2.0 Part 1, §19.6.5):
//
//	HMAC_alg(key, cpHash ‖ nonceCaller ‖ nonceTPM ‖ sessionAttributes)
func commandAuthHMAC(alg uint16, key, cp, nonceCaller, nonceTPM []byte, attrs byte) []byte {
	return hmacSum(alg, key, cp, nonceCaller, nonceTPM, []byte{attrs})
}

// responseAuthHMAC computes the authorization HMAC the TPM returns in a response.
// The nonces swap roles relative to the command (the new nonceTPM is "newer"):
//
//	HMAC_alg(key, rpHash ‖ nonceTPM ‖ nonceCaller ‖ sessionAttributes)
func responseAuthHMAC(alg uint16, key, rp, nonceTPM, nonceCaller []byte, attrs byte) []byte {
	return hmacSum(alg, key, rp, nonceTPM, nonceCaller, []byte{attrs})
}
