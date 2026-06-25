// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import "sort"

// This file implements the audit subsystem (TPM 2.0 Part 1, §19): session audit
// (a session that accumulates a digest over the commands it authorizes) and
// command audit (a global digest over a configured set of command codes). Both
// extend their digest as auditDigest := H(auditDigest ‖ cpHash ‖ rpHash).

// auditState holds the command-audit configuration and running digest.
type auditState struct {
	hashAlg  uint16   // audit digest hash algorithm
	digest   []byte   // running command-audit digest (nil ⇒ Zero Digest)
	counter  uint64   // monotonic audit counter
	commands []uint32 // sorted, unique set of audited command codes
}

func (a *auditState) audited(cc uint32) bool {
	i := sort.Search(len(a.commands), func(i int) bool { return a.commands[i] >= cc })
	return i < len(a.commands) && a.commands[i] == cc
}

func (a *auditState) add(cc uint32) {
	i := sort.Search(len(a.commands), func(i int) bool { return a.commands[i] >= cc })
	if i < len(a.commands) && a.commands[i] == cc {
		return
	}
	a.commands = append(a.commands, 0)
	copy(a.commands[i+1:], a.commands[i:])
	a.commands[i] = cc
}

func (a *auditState) remove(cc uint32) {
	i := sort.Search(len(a.commands), func(i int) bool { return a.commands[i] >= cc })
	if i < len(a.commands) && a.commands[i] == cc {
		a.commands = append(a.commands[:i], a.commands[i+1:]...)
	}
}

// commandListDigest is H_auditAlg over the audited command codes (commandDigest in
// TPMS_COMMAND_AUDIT_INFO).
func (a *auditState) commandListDigest() []byte {
	var w writer
	for _, cc := range a.commands {
		w.u32(cc)
	}
	return hashSum(a.hashAlg, w.bytes())
}

// extendAudit folds cpHash and rpHash into a running audit digest.
func extendAudit(alg uint16, digest, cpHash, rpHash []byte) []byte {
	if len(digest) == 0 {
		digest = make([]byte, hashSize(alg))
	}
	return hashSum(alg, digest, cpHash, rpHash)
}

// zeroOr returns digest, or an alg-sized Zero Digest when digest is empty.
func zeroOr(alg uint16, digest []byte) []byte {
	if len(digest) == 0 {
		return make([]byte, hashSize(alg))
	}
	return digest
}

// recordAudit updates the session- and command-audit digests for a completed,
// successful command. Called from authResponse with the plaintext response
// parameters (audit covers cpHash/rpHash over plaintext).
func (t *TPM) recordAudit(ac *commandAuth, rpParams []byte) {
	for i, s := range ac.sessions {
		if s.attrs&attrAudit == 0 {
			continue
		}
		as := ac.resolved[i].live
		if as == nil {
			continue
		}
		if s.attrs&attrAuditReset != 0 {
			as.auditDigest = nil
		}
		cph := cpHash(as.authHash, ac.cc, t.commandHandleNames(ac), ac.cpParams)
		rph := rpHash(as.authHash, RCSuccess, ac.cc, rpParams)
		as.auditDigest = extendAudit(as.authHash, as.auditDigest, cph, rph)
		t.exclusiveAudit = as.handle // most-recent audit session holds exclusive status
	}

	// Command audit: extend the global digest for audited, authorized commands.
	if t.audit.hashAlg != AlgNull && t.audit.audited(ac.cc) {
		cph := cpHash(t.audit.hashAlg, ac.cc, t.commandHandleNames(ac), ac.cpParams)
		rph := rpHash(t.audit.hashAlg, RCSuccess, ac.cc, rpParams)
		t.audit.digest = extendAudit(t.audit.hashAlg, t.audit.digest, cph, rph)
	}
}

// readCCList reads a TPML_CC (count followed by command codes).
func readCCList(r *reader) []uint32 {
	n := r.u32()
	if n > 1024 {
		r.err = errShort
		return nil
	}
	out := make([]uint32, 0, n)
	for i := uint32(0); i < n && r.err == nil; i++ {
		out = append(out, r.u32())
	}
	return out
}

// cmdSetCommandCodeAuditStatus implements TPM2_SetCommandCodeAuditStatus (Part 3,
// §22.1): set the command-audit hash algorithm and add/remove audited commands.
func (t *TPM) cmdSetCommandCodeAuditStatus(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCSetCommandCodeAuditStatus, 1, r) // @auth
	if errResp != nil {
		return errResp
	}
	auditAlg := r.u16()
	setList := readCCList(r)
	clearList := readCCList(r)
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	authHandle := ac.handles[0]
	if authHandle != RHOwner && authHandle != RHPlatform {
		return errorResponse(withHandle(RCValue, 1))
	}
	if errResp := t.authorizeHierarchy(ac, authHandle); errResp != nil {
		return errResp
	}
	// Changing the audit algorithm and changing the audited-command lists are
	// mutually exclusive (TPM 2.0 Part 3, §22.1): a different, supported auditAlg
	// resets the digest and requires both lists to be empty; otherwise (NULL or
	// unchanged alg) the lists are processed.
	if auditAlg != AlgNull && auditAlg != t.audit.hashAlg {
		if _, ok := cryptoHash(auditAlg); !ok {
			return errorResponse(withParam(RCHash, 1))
		}
		if len(setList) != 0 || len(clearList) != 0 {
			return errorResponse(withParam(RCValue, 2)) // cannot change alg and lists together
		}
		t.audit.hashAlg = auditAlg
		t.audit.digest = nil
	} else {
		for _, cc := range setList {
			t.audit.add(cc)
		}
		for _, cc := range clearList {
			t.audit.remove(cc)
		}
	}
	return t.authResponse(ac, nil, nil)
}

// cmdGetSessionAuditDigest implements TPM2_GetSessionAuditDigest (Part 3, §22.2):
// sign the audit digest of an audit session. Handles: privacyAdmin (endorsement),
// signHandle (both authorized), sessionHandle (the audit session).
func (t *TPM) cmdGetSessionAuditDigest(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCGetSessionAuditDigest, 3, r)
	if errResp != nil {
		return errResp
	}
	qualifyingData := r.tpm2b()
	scheme, schemeHash := readSigScheme(r)
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if ac.handles[0] != RHEndorsement {
		return errorResponse(withHandle(RCValue, 1))
	}
	if errResp := t.authorizeHierarchyAt(ac, 0, RHEndorsement); errResp != nil {
		return errResp
	}
	key, ok := t.objects.get(ac.handles[1])
	if !ok {
		return errorResponse(withHandle(RCHandle, 2))
	}
	if key.public.Attrs&ObjSign == 0 {
		return errorResponse(withHandle(RCAttributes, 2))
	}
	if errResp := t.authorizeObject(ac, 1, key); errResp != nil {
		return errResp
	}
	sess, ok := t.sessions.get(ac.handles[2])
	if !ok {
		return errorResponse(withHandle(RCHandle, 3))
	}

	// TPMS_SESSION_AUDIT_INFO = exclusiveSession ‖ sessionDigest.
	exclusive := no
	if t.exclusiveAudit == sess.handle {
		exclusive = yes
	}
	var si writer
	si.u8(exclusive)
	si.tpm2b(zeroOr(sess.authHash, sess.auditDigest))

	attest, sig, errResp := t.signAttest(key, scheme, schemeHash, STAttestSessionAudit, qualifyingData, si.bytes())
	if errResp != nil {
		return errResp
	}
	var w writer
	w.tpm2b(attest)
	w.raw(sig)
	return t.authResponse(ac, nil, w.bytes())
}

// cmdGetCommandAuditDigest implements TPM2_GetCommandAuditDigest (Part 3, §22.3):
// sign the command-audit digest, then reset it and bump the counter. Handles:
// privacyHandle (endorsement), signHandle — both authorized.
func (t *TPM) cmdGetCommandAuditDigest(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCGetCommandAuditDigest, 2, r)
	if errResp != nil {
		return errResp
	}
	qualifyingData := r.tpm2b()
	scheme, schemeHash := readSigScheme(r)
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if ac.handles[0] != RHEndorsement {
		return errorResponse(withHandle(RCValue, 1))
	}
	if errResp := t.authorizeHierarchyAt(ac, 0, RHEndorsement); errResp != nil {
		return errResp
	}
	key, ok := t.objects.get(ac.handles[1])
	if !ok {
		return errorResponse(withHandle(RCHandle, 2))
	}
	if key.public.Attrs&ObjSign == 0 {
		return errorResponse(withHandle(RCAttributes, 2))
	}
	if errResp := t.authorizeObject(ac, 1, key); errResp != nil {
		return errResp
	}

	// TPMS_COMMAND_AUDIT_INFO = auditCounter ‖ digestAlg ‖ auditDigest ‖ commandDigest.
	var ci writer
	ci.u64(t.audit.counter)
	ci.u16(t.audit.hashAlg)
	ci.tpm2b(zeroOr(t.audit.hashAlg, t.audit.digest))
	ci.tpm2b(t.audit.commandListDigest())

	attest, sig, errResp := t.signAttest(key, scheme, schemeHash, STAttestCommandAudit, qualifyingData, ci.bytes())
	if errResp != nil {
		return errResp
	}
	// Signing resets the digest and advances the counter (Part 3, §22.3).
	t.audit.digest = nil
	t.audit.counter++

	var w writer
	w.tpm2b(attest)
	w.raw(sig)
	return t.authResponse(ac, nil, w.bytes())
}
