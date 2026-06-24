// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"crypto/sha1" //nolint:gosec // SHA-1 is a mandated TPM 2.0 PCR bank, not a security control
	"crypto/sha256"
)

// supportedPCRBanks are the hash algorithms for which the emulator maintains PCR
// banks. Windows 11 measured boot uses the SHA-1 and SHA-256 banks.
var supportedPCRBanks = []uint16{AlgSHA1, AlgSHA256}

// pcrSelectMin is TPM_PT_PCR_SELECT_MIN: the minimum sizeofSelect (in bytes) of a
// TPMS_PCR_SELECTION, which must cover numPCR PCRs. TPM 2.0 Part 2 bounds a
// selection's sizeofSelect to PCR_SELECT_MIN..PCR_SELECT_MAX.
const pcrSelectMin = (numPCR + 7) / 8

// pcrSelectMax bounds the upper end of sizeofSelect. With a fixed 24-PCR count
// the minimum and maximum coincide, so a selection must be exactly pcrSelectMin
// bytes; anything else is a TPM_RC_VALUE.
const pcrSelectMax = pcrSelectMin

// pcrState holds every PCR bank plus the monotonic update counter that
// TPM2_PCR_Read returns so callers can detect concurrent extends.
type pcrState struct {
	// banks maps a hash algorithm to its numPCR digests; each digest is a fresh
	// hashSize(alg)-byte slice, zero-initialized as required after TPM_SU_CLEAR.
	banks         map[uint16][][]byte
	updateCounter uint32
	// allocated is the set of bank algorithms a reset rebuilds (TPM2_PCR_Allocate
	// changes it). nil ⇒ the default supportedPCRBanks.
	allocated []uint16
	// authValues / authPolicies hold any per-PCR authorization set by
	// TPM2_PCR_SetAuthValue / TPM2_PCR_SetAuthPolicy.
	authValues   map[uint32][]byte
	authPolicies map[uint32][]byte
}

func newPCRState() *pcrState {
	s := &pcrState{banks: make(map[uint16][][]byte, len(supportedPCRBanks))}
	s.reset()
	return s
}

// reset returns every PCR to its power-on value (all-zero) — the TPM_SU_CLEAR
// behavior for the resettable PCRs the emulator models.
func (s *pcrState) reset() {
	algs := s.allocated
	if algs == nil {
		algs = supportedPCRBanks
	}
	s.banks = make(map[uint16][][]byte, len(algs))
	for _, alg := range algs {
		size := hashSize(alg)
		bank := make([][]byte, numPCR)
		for i := range bank {
			bank[i] = make([]byte, size)
		}
		s.banks[alg] = bank
	}
	s.updateCounter = 0
}

// extend folds digest into PCR[index] of the given bank: PCR := H(PCR || digest).
// digest must be hashSize(alg) bytes. It reports whether the operation applied.
func (s *pcrState) extend(alg uint16, index int, digest []byte) bool {
	bank, ok := s.banks[alg]
	if !ok || index < 0 || index >= numPCR || len(digest) != hashSize(alg) {
		return false
	}
	bank[index] = hashConcat(alg, bank[index], digest)
	s.updateCounter++
	return true
}

// resetAt zeroes PCR[index] across every bank, used by TPM2_PCR_Reset.
func (s *pcrState) resetAt(index int) {
	for alg, bank := range s.banks {
		if index >= 0 && index < numPCR {
			bank[index] = make([]byte, hashSize(alg))
		}
	}
	s.updateCounter++
}

// pcrExtendLocalities returns the bitmap of localities permitted to extend PCR i
// (PC Client: the DRTM PCRs 17..22 are restricted to locality 4).
func pcrExtendLocalities(i int) byte {
	if i >= 17 && i <= 22 {
		return 1 << 4
	}
	return 0x1F // localities 0..4
}

// pcrResetLocalities returns the bitmap of localities permitted to reset PCR i.
// PCRs 0..15 are not resettable by command; 16 and 23 are resettable at any
// locality; the DRTM PCRs 17..22 reset only at locality 4.
func pcrResetLocalities(i int) byte {
	switch {
	case i == 16 || i == 23:
		return 0x1F
	case i >= 17 && i <= 22:
		return 1 << 4
	default:
		return 0
	}
}

// localityAllowed reports whether loc is set in a locality bitmap.
func localityAllowed(bitmap, loc byte) bool {
	return loc <= 4 && bitmap&(1<<loc) != 0
}

// read returns a copy of PCR[index] of the given bank, or nil if absent.
func (s *pcrState) read(alg uint16, index int) []byte {
	bank, ok := s.banks[alg]
	if !ok || index < 0 || index >= numPCR {
		return nil
	}
	out := make([]byte, len(bank[index]))
	copy(out, bank[index])
	return out
}

// hashConcat returns H(a || b) for the given algorithm.
func hashConcat(alg uint16, a, b []byte) []byte {
	switch alg {
	case AlgSHA1:
		h := sha1.New() //nolint:gosec // mandated PCR bank
		h.Write(a)
		h.Write(b)
		return h.Sum(nil)
	case AlgSHA256:
		h := sha256.New()
		h.Write(a)
		h.Write(b)
		return h.Sum(nil)
	default:
		return a
	}
}

// pcrSelection is one TPMS_PCR_SELECTION: a hash algorithm plus a little bitmap
// of selected PCR indices (bit i of byte b selects PCR b*8+i).
type pcrSelection struct {
	hash      uint16
	selectMap []byte
}

// selected reports whether PCR index is set in the bitmap.
func (sel pcrSelection) selected(index int) bool {
	b := index / 8
	if b >= len(sel.selectMap) {
		return false
	}
	return sel.selectMap[b]&(1<<(uint(index)%8)) != 0
}

// readPCRSelectionList reads a TPML_PCR_SELECTION from r.
func readPCRSelectionList(r *reader) []pcrSelection {
	count := r.u32()
	if r.err != nil {
		return nil
	}
	out := make([]pcrSelection, 0, count)
	for i := uint32(0); i < count; i++ {
		hash := r.u16()
		size := int(r.u8())
		if r.err == nil && (size < pcrSelectMin || size > pcrSelectMax) {
			r.err = errBadValue // sizeofSelect out of [PCR_SELECT_MIN, PCR_SELECT_MAX]
			return nil
		}
		sel := r.bytes(size)
		if r.err != nil {
			return nil
		}
		out = append(out, pcrSelection{hash: hash, selectMap: sel})
	}
	return out
}

// writePCRSelectionList writes a TPML_PCR_SELECTION to w.
func writePCRSelectionList(w *writer, sels []pcrSelection) {
	w.u32(uint32(len(sels)))
	for _, sel := range sels {
		w.u16(sel.hash)
		w.u8(byte(len(sel.selectMap)))
		w.raw(sel.selectMap)
	}
}

// digestValue is one TPMT_HA: a hash algorithm tag plus its digest.
type digestValue struct {
	alg    uint16
	digest []byte
}

// readDigestValues reads a TPML_DIGEST_VALUES from r.
func readDigestValues(r *reader) []digestValue {
	count := r.u32()
	if r.err != nil {
		return nil
	}
	out := make([]digestValue, 0, count)
	for i := uint32(0); i < count; i++ {
		alg := r.u16()
		size := hashSize(alg)
		if size == 0 {
			r.err = errShort // unknown alg: cannot determine digest length
			return nil
		}
		out = append(out, digestValue{alg: alg, digest: r.bytes(size)})
		if r.err != nil {
			return nil
		}
	}
	return out
}
