// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import "crypto/hmac"

// This file implements TPM2_ContextSave / TPM2_ContextLoad (TPM 2.0 Part 3, §28):
// swapping a transient object or session out of and back into the TPM as an
// opaque TPMS_CONTEXT. The context blob is encrypted and integrity-protected with
// a volatile per-TPM context key, so a saved context cannot be tampered with and
// does not survive a reboot (the key is regenerated on reset).

// Context payload type markers.
const (
	ctxObject  byte = 0x01
	ctxSession byte = 0x02
)

// writeBlob / readBlob frame a length-prefixed (UINT32) byte field inside a
// context payload.
func writeBlob(w *writer, b []byte) {
	w.u32(uint32(len(b)))
	w.raw(b)
}

func readBlob(r *reader) []byte { return r.bytes(int(r.u32())) }

// protectContext encrypts payload and returns integrity ‖ ciphertext, bound to
// savedHandle and seq by the integrity HMAC.
func (t *TPM) protectContext(payload []byte, savedHandle uint32, seq uint64) []byte {
	iv := make([]byte, 16)
	enc := aesCFB(t.contextKey, iv, payload, true)
	integrity := hmacSum(AlgSHA256, t.contextKey, enc, be32(savedHandle), be64(seq))
	return append(append([]byte(nil), integrity...), enc...)
}

// unprotectContext verifies and decrypts a context blob.
func (t *TPM) unprotectContext(blob []byte, savedHandle uint32, seq uint64) ([]byte, bool) {
	const tagLen = 32 // SHA-256
	if len(blob) < tagLen {
		return nil, false
	}
	integrity, enc := blob[:tagLen], blob[tagLen:]
	want := hmacSum(AlgSHA256, t.contextKey, enc, be32(savedHandle), be64(seq))
	if !hmac.Equal(want, integrity) {
		return nil, false
	}
	iv := make([]byte, 16)
	return aesCFB(t.contextKey, iv, enc, false), true
}

// cmdContextSave implements TPM2_ContextSave.
func (t *TPM) cmdContextSave(r *reader) []byte {
	saveHandle := r.u32()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}

	var payload writer
	hierarchy := uint32(RHNull)
	switch classifyHandle(saveHandle) {
	case htTransient:
		o, ok := t.objects.get(saveHandle)
		if !ok {
			return errorResponse(withHandle(RCHandle, 1))
		}
		payload.u8(ctxObject)
		var pub, sens writer
		o.public.marshal(&pub)
		o.sensitive.marshal(&sens)
		writeBlob(&payload, pub.bytes())
		writeBlob(&payload, sens.bytes())
		writeBlob(&payload, o.name)
	case htHMACSession, htPolicySession:
		s, ok := t.sessions.get(saveHandle)
		if !ok {
			return errorResponse(withHandle(RCHandle, 1))
		}
		payload.u8(ctxSession)
		payload.u32(s.handle)
		payload.u8(s.kind)
		payload.u16(s.authHash)
		payload.u32(s.commandCode)
		boolByte := byte(no)
		if s.policyAuth {
			boolByte = yes
		}
		payload.u8(boolByte)
		writeBlob(&payload, s.nonceTPM)
		writeBlob(&payload, s.nonceCaller)
		writeBlob(&payload, s.sessionKey)
		writeBlob(&payload, s.bindName)
		writeBlob(&payload, s.policyDigest)
	default:
		return errorResponse(withHandle(RCHandle, 1))
	}

	seq := t.contextSeq
	t.contextSeq++
	blob := t.protectContext(payload.bytes(), saveHandle, seq)

	var w writer      // TPMS_CONTEXT
	w.u64(seq)        // sequence
	w.u32(saveHandle) // savedHandle
	w.u32(hierarchy)  // hierarchy
	w.tpm2b(blob)     // contextBlob (TPM2B_CONTEXT_DATA)
	return successResponse(w.bytes(), 0)
}

// cmdContextLoad implements TPM2_ContextLoad.
func (t *TPM) cmdContextLoad(r *reader) []byte {
	seq := r.u64()
	savedHandle := r.u32()
	_ = r.u32() // hierarchy
	blob := r.tpm2b()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}

	payload, ok := t.unprotectContext(blob, savedHandle, seq)
	if !ok {
		return errorResponse(RCIntegrity)
	}
	pr := newReader(payload)
	switch pr.u8() {
	case ctxObject:
		var o object
		o.public.unmarshal(newReader(readBlob(pr)))
		o.sensitive.unmarshal(newReader(readBlob(pr)))
		o.name = readBlob(pr)
		if pr.err != nil {
			return errorResponse(RCIntegrity)
		}
		h, ok := t.objects.loadTransient(&o)
		if !ok {
			return errorResponse(RCObjectMemory)
		}
		var w writer
		w.u32(h) // loadedHandle (response handle area)
		return successResponse(w.bytes(), 0)
	case ctxSession:
		s := &authSession{}
		s.handle = pr.u32()
		s.kind = pr.u8()
		s.authHash = pr.u16()
		s.commandCode = pr.u32()
		s.policyAuth = pr.u8() == yes
		s.nonceTPM = readBlob(pr)
		s.nonceCaller = readBlob(pr)
		s.sessionKey = readBlob(pr)
		s.bindName = readBlob(pr)
		s.policyDigest = readBlob(pr)
		if pr.err != nil {
			return errorResponse(RCIntegrity)
		}
		t.sessions.restore(s)
		var w writer
		w.u32(s.handle) // loadedHandle
		return successResponse(w.bytes(), 0)
	default:
		return errorResponse(RCIntegrity)
	}
}
