// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"io"
	"sort"
)

// This file is the authorization-session subsystem (TPM 2.0 Part 1, §19). It
// holds the live session table and TPM2_StartAuthSession / TPM2_FlushContext.
// Sessions are volatile: they are dropped on any TPM reset and never persisted.

const maxActiveSessions = 64

// authSession is a loaded HMAC, policy, or trial session.
type authSession struct {
	handle      uint32
	kind        byte   // TPM_SE: seHMAC / sePolicy / seTrial
	authHash    uint16 // session hash algorithm
	nonceTPM    []byte // most recent TPM nonce
	nonceCaller []byte // most recent caller nonce
	sessionKey  []byte // KDFa-derived; empty for an unbound, unsalted session
	bindName    []byte // Name of the bound entity (empty if unbound)
	symmetric   symDef // cipher for parameter/response encryption (may be NULL)

	// Policy-session accumulators (TPM 2.0 Part 1, §23.2.3):
	policyDigest   []byte // current policy digest
	commandCode    uint32 // PolicyCommandCode restriction (0 ⇒ unset)
	policyAuth     bool   // PolicyAuthValue / PolicyPassword was invoked
	policyCpHash   []byte // PolicyCpHash restriction (nil ⇒ unset)
	hasLocality    bool   // PolicyLocality was invoked
	policyLocality byte   // PolicyLocality bitmap (localities 0..4)

	auditDigest []byte // running session-audit digest (nil until first audited command)
}

// sessionTable holds the live sessions, keyed by handle (in the 0x02xxxxxx range).
type sessionTable struct {
	m    map[uint32]*authSession
	next uint32
}

func newSessionTable() *sessionTable {
	return &sessionTable{m: make(map[uint32]*authSession), next: htHMACSession + 1}
}

func (st *sessionTable) get(h uint32) (*authSession, bool) { s, ok := st.m[h]; return s, ok }

func (st *sessionTable) flush(h uint32) bool {
	if _, ok := st.m[h]; ok {
		delete(st.m, h)
		return true
	}
	return false
}

// add inserts s under a fresh session handle, or reports false if the session
// table is full.
func (st *sessionTable) add(s *authSession) (uint32, bool) {
	if len(st.m) >= maxActiveSessions {
		return 0, false
	}
	h := st.next
	st.next++
	s.handle = h
	st.m[h] = s
	return h, true
}

// restore reinserts a previously context-saved session under its own handle.
func (st *sessionTable) restore(s *authSession) { st.m[s.handle] = s }

// handles returns the loaded session handles in ascending order.
func (st *sessionTable) handles() []uint32 {
	hs := make([]uint32, 0, len(st.m))
	for h := range st.m {
		hs = append(hs, h)
	}
	sort.Slice(hs, func(i, j int) bool { return hs[i] < hs[j] })
	return hs
}

// permanentName returns the Name of a permanent handle, which for the permanent
// hierarchy is simply the 4-byte handle value (TPM 2.0 Part 1, §16).
func permanentName(handle uint32) []byte {
	return []byte{byte(handle >> 24), byte(handle >> 16), byte(handle >> 8), byte(handle)}
}

// deriveSessionKey computes the session key (TPM 2.0 Part 1, §19.6.8). For an
// unbound, unsalted session both inputs are empty and the key is the Empty
// Buffer; otherwise it is KDFa over the bind authValue concatenated with the salt.
func deriveSessionKey(authHash uint16, bindAuth, salt, nonceTPM, nonceCaller []byte) []byte {
	if len(bindAuth) == 0 && len(salt) == 0 {
		return nil
	}
	key := append(append([]byte(nil), bindAuth...), salt...)
	return kdfa(authHash, key, []byte("ATH"), nonceTPM, nonceCaller, hashSize(authHash)*8)
}

// cmdStartAuthSession implements TPM2_StartAuthSession. A non-NULL tpmKey makes
// the session salted: its private half decrypts the caller's salt (RSA-OAEP or
// ECDH), which is folded into the session key. bind may be NULL or a permanent
// hierarchy handle.
func (t *TPM) cmdStartAuthSession(r *reader) []byte {
	tpmKey := r.u32()
	bind := r.u32()
	nonceCaller := r.tpm2b()
	encSalt := r.tpm2b()
	se := r.u8()
	var sym symDef
	sym.unmarshal(r)
	authHash := r.u16()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}

	if se != seHMAC && se != sePolicy && se != seTrial {
		return errorResponse(withParam(RCValue, 3)) // sessionType is parameter 3
	}
	if _, ok := cryptoHash(authHash); !ok {
		return errorResponse(withParam(RCValue, 5)) // authHash
	}
	if len(nonceCaller) < 16 {
		return errorResponse(withParam(RCSize, 1)) // nonceCaller must be >= 16 bytes
	}
	// Salted session: a non-NULL tpmKey is a loaded decryption key whose private
	// half recovers the caller-supplied salt (TPM 2.0 Part 1, §19.6.7). Windows
	// salts to the SRK to establish a confidential session for the BitLocker VMK.
	var salt []byte
	if tpmKey != RHNull {
		key, ok := t.objects.get(tpmKey)
		if !ok {
			return errorResponse(withHandle(RCHandle, 1)) // tpmKey not loaded
		}
		if key.public.Attrs&ObjDecrypt == 0 {
			return errorResponse(withHandle(RCValue, 1)) // tpmKey must be a decryption key
		}
		s, ok := decryptSalt(key, encSalt, t.rand)
		if !ok {
			return errorResponse(withParam(RCValue, 2)) // salt did not decrypt
		}
		salt = s
	} else if len(encSalt) != 0 {
		return errorResponse(withParam(RCValue, 2)) // no salt without a tpmKey
	}

	var bindAuth, bindName []byte
	if bind != RHNull {
		hi := t.h.byHandle(bind)
		if hi == nil {
			return errorResponse(withHandle(RCHandle, 2))
		}
		bindAuth = hi.authValue
		bindName = permanentName(bind)
	}

	nonceTPM := make([]byte, hashSize(authHash))
	if _, err := io.ReadFull(t.rand, nonceTPM); err != nil {
		return errorResponse(RCFailure)
	}

	s := &authSession{
		kind:        se,
		authHash:    authHash,
		nonceTPM:    nonceTPM,
		nonceCaller: nonceCaller,
		sessionKey:  deriveSessionKey(authHash, bindAuth, salt, nonceTPM, nonceCaller),
		bindName:    bindName,
		symmetric:   sym,
	}
	if se == sePolicy || se == seTrial {
		s.policyDigest = make([]byte, hashSize(authHash)) // starts at all-zero
	}

	h, ok := t.sessions.add(s)
	if !ok {
		return errorResponse(RCSessionMemory)
	}

	var w writer
	w.u32(h)          // sessionHandle (response handle area)
	w.tpm2b(nonceTPM) // nonceTPM
	return successResponse(w.bytes(), 0)
}

// cmdFlushContext implements TPM2_FlushContext. The handle to flush is a
// parameter (TPMI_DH_CONTEXT), not a command handle. Only loaded sessions are
// flushable today; transient objects join in the object subsystem.
func (t *TPM) cmdFlushContext(r *reader) []byte {
	flushHandle := r.u32()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	switch classifyHandle(flushHandle) {
	case htHMACSession, htPolicySession:
		if !t.sessions.flush(flushHandle) {
			return errorResponse(withHandle(RCHandle, 1))
		}
		return successResponse(nil, 0)
	case htTransient:
		if t.objects.flushTransient(flushHandle) || t.sequences.flush(flushHandle) {
			return successResponse(nil, 0)
		}
		return errorResponse(withHandle(RCHandle, 1))
	default:
		return errorResponse(withHandle(RCHandle, 1))
	}
}
