// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"crypto/hmac"
	"hash"
)

// This file implements the hash/HMAC sequence commands (TPM 2.0 Part 3, §15–18):
// TPM2_HMAC (one-shot), TPM2_HMAC_Start, TPM2_HashSequenceStart,
// TPM2_SequenceUpdate, TPM2_SequenceComplete and TPM2_EventSequenceComplete. A
// sequence is a memory-resident hashing context held in a transient handle slot.

// seqHandleBase is the start of the sequence handle range. It sits high in the
// transient range so it never collides with loaded objects (which start at
// htTransient+1 and are capped at maxTransientObjects).
const seqHandleBase = htTransient + 0x00C00000

// sequence is a running hash, HMAC or event-hashing context.
type sequence struct {
	auth  []byte
	alg   uint16 // hash algorithm (0 for an event sequence)
	hmac  bool
	event bool
	state hash.Hash            // running hash/HMAC (non-event sequences)
	banks map[uint16]hash.Hash // event sequence: one running hash per PCR bank
	first []byte               // first ≤4 octets seen, to decide hashcheck safety
}

// write feeds data into the sequence, tracking the first 4 octets.
func (s *sequence) write(p []byte) {
	if len(s.first) < 4 {
		n := 4 - len(s.first)
		if n > len(p) {
			n = len(p)
		}
		s.first = append(s.first, p[:n]...)
	}
	if s.event {
		for _, h := range s.banks {
			h.Write(p)
		}
		return
	}
	s.state.Write(p)
}

// safeToSign reports whether a completed hash sequence may be signed by a
// restricted key: the hashed data must not begin with TPM_GENERATED_VALUE
// (TPM 2.0 Part 3, §17.6).
func (s *sequence) safeToSign() bool {
	return !bytes.Equal(s.first, be32(tpmGeneratedValue))
}

// sequenceTable holds the active sequence contexts (volatile, like sessions).
type sequenceTable struct {
	seqs map[uint32]*sequence
	next uint32
}

func newSequenceTable() *sequenceTable {
	return &sequenceTable{seqs: make(map[uint32]*sequence), next: seqHandleBase}
}

func (st *sequenceTable) add(s *sequence) uint32 {
	h := st.next
	st.next++
	st.seqs[h] = s
	return h
}

func (st *sequenceTable) get(h uint32) (*sequence, bool) { s, ok := st.seqs[h]; return s, ok }

func (st *sequenceTable) flush(h uint32) bool {
	if _, ok := st.seqs[h]; ok {
		delete(st.seqs, h)
		return true
	}
	return false
}

func (st *sequenceTable) reset() {
	st.seqs = make(map[uint32]*sequence)
	st.next = seqHandleBase
}

// resolveKeyedHashAlg picks the hash for a keyed-hash (HMAC) signing key: the
// key's own scheme wins (hashAlg must be NULL or match); otherwise hashAlg must
// name a valid hash (TPM 2.0 Part 3, §15.1 Table 71).
func resolveKeyedHashAlg(scheme hashScheme, hashAlg uint16) (uint16, bool) {
	keyAlg := uint16(AlgNull)
	if scheme.Scheme == AlgHMAC {
		keyAlg = scheme.HashAlg
	}
	if keyAlg != AlgNull {
		if hashAlg == AlgNull || hashAlg == keyAlg {
			return keyAlg, true
		}
		return 0, false
	}
	if _, ok := cryptoHash(hashAlg); ok {
		return hashAlg, true
	}
	return 0, false
}

// cmdHMAC implements TPM2_HMAC / TPM2_MAC (Part 3, §15.1): a one-shot HMAC over
// buffer using a loaded keyed-hash signing key.
func (t *TPM) cmdHMAC(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCHMAC, 1, r)
	if errResp != nil {
		return errResp
	}
	t.decryptCommandParams(ac, r)
	buffer := r.tpm2b()
	hashAlg := r.u16()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	key, ok := t.objects.get(ac.handles[0])
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if key.public.Type != AlgKeyedHash {
		return errorResponse(withHandle(RCType, 1))
	}
	if key.public.Attrs&ObjSign == 0 {
		return errorResponse(withHandle(RCAttributes, 1))
	}
	if errResp := t.authorizeObject(ac, 0, key); errResp != nil {
		return errResp
	}
	alg, ok := resolveKeyedHashAlg(key.public.Scheme, hashAlg)
	if !ok {
		return errorResponse(withParam(RCValue, 2))
	}
	var w writer
	w.tpm2b(hmacSum(alg, key.sensitive.Secret, buffer)) // outHMAC
	return t.authResponse(ac, nil, w.bytes())
}

// cmdHMACStart implements TPM2_HMAC_Start / TPM2_MAC_Start (Part 3, §17.2): begin
// an HMAC sequence keyed by a loaded keyed-hash signing key.
func (t *TPM) cmdHMACStart(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCHMACStart, 1, r)
	if errResp != nil {
		return errResp
	}
	auth := r.tpm2b()
	hashAlg := r.u16()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	key, ok := t.objects.get(ac.handles[0])
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if key.public.Type != AlgKeyedHash {
		return errorResponse(withHandle(RCType, 1))
	}
	if key.public.Attrs&ObjSign == 0 {
		return errorResponse(withHandle(RCAttributes, 1))
	}
	if errResp := t.authorizeObject(ac, 0, key); errResp != nil {
		return errResp
	}
	alg, ok := resolveKeyedHashAlg(key.public.Scheme, hashAlg)
	if !ok {
		return errorResponse(withParam(RCValue, 2))
	}
	ch, _ := cryptoHash(alg)
	seq := &sequence{auth: append([]byte(nil), auth...), hmac: true, alg: alg, state: hmac.New(ch.New, key.sensitive.Secret)}
	handle := t.sequences.add(seq)
	return t.authResponse(ac, []uint32{handle}, nil)
}

// cmdHashSequenceStart implements TPM2_HashSequenceStart (Part 3, §17.3): begin a
// hash sequence, or an event sequence when hashAlg is TPM_ALG_NULL. No handle.
func (t *TPM) cmdHashSequenceStart(r *reader) []byte {
	auth := r.tpm2b()
	hashAlg := r.u16()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	seq := &sequence{auth: append([]byte(nil), auth...)}
	if hashAlg == AlgNull {
		seq.event = true
		seq.banks = make(map[uint16]hash.Hash)
		for _, b := range supportedPCRBanks {
			seq.banks[b] = newHash(b)
		}
	} else {
		h := newHash(hashAlg)
		if h == nil {
			return errorResponse(withParam(RCHash, 2))
		}
		seq.alg = hashAlg
		seq.state = h
	}
	var w writer
	w.u32(t.sequences.add(seq)) // sequenceHandle
	return successResponse(w.bytes(), 0)
}

// authorizeSequence verifies the auth session at sessionIdx against the sequence's
// authValue. A sequence object has no public area; its handle stands in as the
// entity Name for HMAC sessions.
func (t *TPM) authorizeSequence(ac *commandAuth, sessionIdx int, handle uint32, seq *sequence) []byte {
	return t.verifyAuth(ac, sessionIdx, be32(handle), seq.auth, nil, false)
}

// cmdSequenceUpdate implements TPM2_SequenceUpdate (Part 3, §17.4): add data to a
// hash, HMAC or event sequence.
func (t *TPM) cmdSequenceUpdate(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCSequenceUpdate, 1, r)
	if errResp != nil {
		return errResp
	}
	t.decryptCommandParams(ac, r)
	buffer := r.tpm2b()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	seq, ok := t.sequences.get(ac.handles[0])
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if errResp := t.authorizeSequence(ac, 0, ac.handles[0], seq); errResp != nil {
		return errResp
	}
	seq.write(buffer)
	return t.authResponse(ac, nil, nil)
}

// cmdSequenceComplete implements TPM2_SequenceComplete (Part 3, §17.5): finish a
// hash or HMAC sequence, returning the result and a validation ticket; the
// sequence is then flushed. Event sequences must use EventSequenceComplete.
func (t *TPM) cmdSequenceComplete(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCSequenceComplete, 1, r)
	if errResp != nil {
		return errResp
	}
	t.decryptCommandParams(ac, r)
	buffer := r.tpm2b()
	tkHierarchy := r.u32()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	seq, ok := t.sequences.get(ac.handles[0])
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if seq.event {
		return errorResponse(RCMode) // an event sequence: use EventSequenceComplete
	}
	if errResp := t.authorizeSequence(ac, 0, ac.handles[0], seq); errResp != nil {
		return errResp
	}
	seq.write(buffer)
	digest := seq.state.Sum(nil)
	t.sequences.flush(ac.handles[0]) // a completed sequence is flushed

	var w writer
	w.tpm2b(digest) // result
	// A valid hashcheck ticket only for a hash sequence whose data is safe to sign
	// and a real hierarchy; HMAC sequences and the NULL hierarchy get a NULL ticket.
	proof := t.hierarchyProof(tkHierarchy)
	if !seq.hmac && tkHierarchy != RHNull && seq.safeToSign() && proof != nil {
		w.u16(STHashCheck)
		w.u32(tkHierarchy)
		w.tpm2b(hmacSum(AlgSHA256, proof, be16(STHashCheck), digest))
	} else {
		w.u16(STHashCheck)
		w.u32(RHNull)
		w.tpm2b(nil)
	}
	return t.authResponse(ac, nil, w.bytes())
}

// cmdEventSequenceComplete implements TPM2_EventSequenceComplete (Part 3, §17.6):
// finish an event sequence, returning the per-bank digests and extending each into
// pcrHandle (when it names a PCR). Two authorizations: pcrHandle then sequenceHandle.
func (t *TPM) cmdEventSequenceComplete(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCEventSequenceComplete, 2, r)
	if errResp != nil {
		return errResp
	}
	t.decryptCommandParams(ac, r)
	buffer := r.tpm2b()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	pcrHandle, seqHandle := ac.handles[0], ac.handles[1]
	seq, ok := t.sequences.get(seqHandle)
	if !ok {
		return errorResponse(withHandle(RCHandle, 2))
	}
	if !seq.event {
		return errorResponse(RCMode) // a hash/HMAC sequence: use SequenceComplete
	}
	// Authorize the PCR (session 0, typically empty auth) and the sequence (session 1).
	if errResp := t.verifyAuth(ac, 0, be32(pcrHandle), nil, nil, false); errResp != nil {
		return errResp
	}
	if errResp := t.authorizeSequence(ac, 1, seqHandle, seq); errResp != nil {
		return errResp
	}
	seq.write(buffer)
	t.sequences.flush(seqHandle)

	pcrIndex := -1
	if classifyHandle(pcrHandle) == htPCR && int(pcrHandle) < numPCR {
		pcrIndex = int(pcrHandle)
	}
	var w writer
	w.u32(uint32(len(supportedPCRBanks))) // TPML_DIGEST_VALUES count
	for _, b := range supportedPCRBanks {
		d := seq.banks[b].Sum(nil)
		w.u16(b) // TPMT_HA hashAlg
		w.raw(d) // TPMT_HA digest (size implied by the algorithm)
		if pcrIndex >= 0 {
			t.pcr.extend(b, pcrIndex, d)
		}
	}
	return t.authResponse(ac, nil, w.bytes())
}
