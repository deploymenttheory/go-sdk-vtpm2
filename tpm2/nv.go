// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"encoding/binary"
	"sort"
)

// This file implements NV (non-volatile) storage (TPM 2.0 Part 3, §31). NV
// indices live in the 0x01xxxxxx handle range and persist across reboots; each
// carries a TPMS_NV_PUBLIC, an authValue, and its data. The index type (NT field
// of TPMA_NV) selects ordinary / counter / bits / extend behavior.

// nvIndex is a defined NV index.
type nvIndex struct {
	public      nvPublic
	authValue   []byte
	data        []byte
	name        []byte
	readLocked  bool
	writeLocked bool
}

// nvStore holds all defined NV indices, keyed by handle.
type nvStore struct {
	indices map[uint32]*nvIndex
}

func newNVStore() *nvStore { return &nvStore{indices: make(map[uint32]*nvIndex)} }

func (s *nvStore) get(h uint32) (*nvIndex, bool) { i, ok := s.indices[h]; return i, ok }

func (s *nvStore) handles() []uint32 {
	hs := make([]uint32, 0, len(s.indices))
	for h := range s.indices {
		hs = append(hs, h)
	}
	sort.Slice(hs, func(i, j int) bool { return hs[i] < hs[j] })
	return hs
}

// nvDataSize returns the data length an index of the given type and declared size
// holds: counters and bit-fields are 8 bytes, an extend index is one digest, and
// an ordinary index is its declared dataSize.
func nvDataSize(public nvPublic) int {
	switch public.nvType() {
	case nvCounter, nvBits:
		return 8
	case nvExtend:
		return hashSize(public.NameAlg)
	default:
		return int(public.DataSize)
	}
}

// cmdNVDefineSpace implements TPM2_NV_DefineSpace: define a new NV index under
// Owner or Platform authorization.
func (t *TPM) cmdNVDefineSpace(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCNVDefineSpace, 1, r) // authHandle (owner/platform)
	if errResp != nil {
		return errResp
	}
	auth := r.tpm2b() // auth (TPM2B_AUTH) for the new index
	_ = r.u16()       // publicInfo (TPM2B_NV_PUBLIC) size
	var public nvPublic
	public.unmarshal(r)
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}

	authHandle := ac.handles[0]
	if authHandle != RHOwner && authHandle != RHPlatform {
		return errorResponse(withHandle(RCValue, 1))
	}
	if classifyHandle(public.Index) != htNVIndex {
		return errorResponse(withParam(RCValue, 2))
	}
	if _, ok := cryptoHash(public.NameAlg); !ok {
		return errorResponse(withParam(RCValue, 2))
	}
	if _, exists := t.nv.get(public.Index); exists {
		return errorResponse(RCNVDefined)
	}
	if errResp := t.authorizeHierarchy(ac, authHandle); errResp != nil {
		return errResp
	}

	// Normalize the data size to the index type and start un-written.
	public.DataSize = uint16(nvDataSize(public))
	public.Attrs &^= NVWritten
	idx := &nvIndex{
		public:    public,
		authValue: append([]byte(nil), auth...),
		data:      make([]byte, public.DataSize),
	}
	idx.name = public.name()
	t.nv.indices[public.Index] = idx
	return t.authResponse(ac, nil, nil)
}

// cmdNVUndefineSpace implements TPM2_NV_UndefineSpace: remove an NV index under
// Owner or Platform authorization.
func (t *TPM) cmdNVUndefineSpace(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCNVUndefineSpace, 2, r) // authHandle, nvIndex
	if errResp != nil {
		return errResp
	}
	authHandle := ac.handles[0]
	nvHandle := ac.handles[1]
	if authHandle != RHOwner && authHandle != RHPlatform {
		return errorResponse(withHandle(RCValue, 1))
	}
	if _, ok := t.nv.get(nvHandle); !ok {
		return errorResponse(withHandle(RCHandle, 2))
	}
	if errResp := t.authorizeHierarchy(ac, authHandle); errResp != nil {
		return errResp
	}
	delete(t.nv.indices, nvHandle)
	return t.authResponse(ac, nil, nil)
}

// authorizeNV authorizes an NV access through the unified processor, checking the
// TPMA_NV attributes permit the chosen auth handle (the index itself, Owner, or
// Platform) for the requested direction.
func (t *TPM) authorizeNV(ac *commandAuth, idx *nvIndex, authHandle uint32, write bool) []byte {
	attrs := idx.public.Attrs
	indexAuth, policyAuth, ownerAuth, ppAuth := NVAuthRead, NVPolicyRead, NVOwnerRead, NVPPRead
	if write {
		indexAuth, policyAuth, ownerAuth, ppAuth = NVAuthWrite, NVPolicyWrite, NVOwnerWrite, NVPPWrite
	}
	switch authHandle {
	case idx.public.Index:
		if attrs&indexAuth == 0 && attrs&policyAuth == 0 {
			return errorResponse(RCNVAuthorization)
		}
		return t.verifyAuth(ac, 0, idx.name, idx.authValue, idx.public.AuthPolicy, false)
	case RHOwner:
		if attrs&ownerAuth == 0 {
			return errorResponse(RCNVAuthorization)
		}
		return t.authorizeHierarchy(ac, RHOwner)
	case RHPlatform:
		if attrs&ppAuth == 0 {
			return errorResponse(RCNVAuthorization)
		}
		return t.authorizeHierarchy(ac, RHPlatform)
	}
	return errorResponse(withHandle(RCValue, 1))
}

// nvAccess parses the [authHandle, nvIndex] handles and returns the resolved
// index, or an error response.
func (t *TPM) nvAccess(ac *commandAuth) (*nvIndex, []byte) {
	idx, ok := t.nv.get(ac.handles[1])
	if !ok {
		return nil, errorResponse(withHandle(RCHandle, 2))
	}
	return idx, nil
}

// cmdNVWrite implements TPM2_NV_Write: write data to an ordinary index at offset.
func (t *TPM) cmdNVWrite(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCNVWrite, 2, r)
	if errResp != nil {
		return errResp
	}
	t.decryptCommandParams(ac, r) // data may be encrypted by a decrypt session
	data := r.tpm2b()
	offset := r.u16()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	idx, errResp := t.nvAccess(ac)
	if errResp != nil {
		return errResp
	}
	if idx.public.nvType() != nvOrdinary {
		return errorResponse(RCAttributes) // use Increment/SetBits/Extend for typed indices
	}
	if idx.writeLocked {
		return errorResponse(RCNVLocked)
	}
	if int(offset)+len(data) > len(idx.data) {
		return errorResponse(withParam(RCNVRange, 2))
	}
	if errResp := t.authorizeNV(ac, idx, ac.handles[0], true); errResp != nil {
		return errResp
	}
	copy(idx.data[offset:], data)
	idx.public.Attrs |= NVWritten
	idx.name = idx.public.name()
	return t.authResponse(ac, nil, nil)
}

// cmdNVRead implements TPM2_NV_Read: read size bytes from an index at offset.
func (t *TPM) cmdNVRead(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCNVRead, 2, r)
	if errResp != nil {
		return errResp
	}
	size := r.u16()
	offset := r.u16()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	idx, errResp := t.nvAccess(ac)
	if errResp != nil {
		return errResp
	}
	if idx.readLocked {
		return errorResponse(RCNVLocked)
	}
	if idx.public.Attrs&NVWritten == 0 {
		return errorResponse(RCNVUninitialized)
	}
	if int(offset)+int(size) > len(idx.data) {
		return errorResponse(withParam(RCNVRange, 2))
	}
	if errResp := t.authorizeNV(ac, idx, ac.handles[0], false); errResp != nil {
		return errResp
	}
	var w writer
	w.tpm2b(idx.data[offset : int(offset)+int(size)]) // data (TPM2B_MAX_NV_BUFFER)
	return t.authResponse(ac, nil, w.bytes())
}

// cmdNVIncrement implements TPM2_NV_Increment for a counter index.
func (t *TPM) cmdNVIncrement(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCNVIncrement, 2, r)
	if errResp != nil {
		return errResp
	}
	idx, errResp := t.nvAccess(ac)
	if errResp != nil {
		return errResp
	}
	if idx.public.nvType() != nvCounter {
		return errorResponse(RCAttributes)
	}
	if idx.writeLocked {
		return errorResponse(RCNVLocked)
	}
	if errResp := t.authorizeNV(ac, idx, ac.handles[0], true); errResp != nil {
		return errResp
	}
	binary.BigEndian.PutUint64(idx.data, binary.BigEndian.Uint64(idx.data)+1)
	idx.public.Attrs |= NVWritten
	idx.name = idx.public.name()
	return t.authResponse(ac, nil, nil)
}

// cmdNVExtend implements TPM2_NV_Extend: data := H(old ‖ input) for an extend index.
func (t *TPM) cmdNVExtend(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCNVExtend, 2, r)
	if errResp != nil {
		return errResp
	}
	in := r.tpm2b()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	idx, errResp := t.nvAccess(ac)
	if errResp != nil {
		return errResp
	}
	if idx.public.nvType() != nvExtend {
		return errorResponse(RCAttributes)
	}
	if idx.writeLocked {
		return errorResponse(RCNVLocked)
	}
	if errResp := t.authorizeNV(ac, idx, ac.handles[0], true); errResp != nil {
		return errResp
	}
	idx.data = hashSum(idx.public.NameAlg, idx.data, in)
	idx.public.Attrs |= NVWritten
	idx.name = idx.public.name()
	return t.authResponse(ac, nil, nil)
}

// cmdNVSetBits implements TPM2_NV_SetBits: data |= bits for a bit-field index.
func (t *TPM) cmdNVSetBits(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCNVSetBits, 2, r)
	if errResp != nil {
		return errResp
	}
	bits := r.u64()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	idx, errResp := t.nvAccess(ac)
	if errResp != nil {
		return errResp
	}
	if idx.public.nvType() != nvBits {
		return errorResponse(RCAttributes)
	}
	if idx.writeLocked {
		return errorResponse(RCNVLocked)
	}
	if errResp := t.authorizeNV(ac, idx, ac.handles[0], true); errResp != nil {
		return errResp
	}
	binary.BigEndian.PutUint64(idx.data, binary.BigEndian.Uint64(idx.data)|bits)
	idx.public.Attrs |= NVWritten
	idx.name = idx.public.name()
	return t.authResponse(ac, nil, nil)
}

// cmdNVWriteLock / cmdNVReadLock implement the per-index write/read locks.
func (t *TPM) cmdNVWriteLock(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCNVWriteLock, 2, r)
	if errResp != nil {
		return errResp
	}
	idx, errResp := t.nvAccess(ac)
	if errResp != nil {
		return errResp
	}
	if errResp := t.authorizeNV(ac, idx, ac.handles[0], true); errResp != nil {
		return errResp
	}
	idx.writeLocked = true
	idx.public.Attrs |= NVWriteLocked
	idx.name = idx.public.name()
	return t.authResponse(ac, nil, nil)
}

func (t *TPM) cmdNVReadLock(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCNVReadLock, 2, r)
	if errResp != nil {
		return errResp
	}
	idx, errResp := t.nvAccess(ac)
	if errResp != nil {
		return errResp
	}
	if errResp := t.authorizeNV(ac, idx, ac.handles[0], false); errResp != nil {
		return errResp
	}
	idx.readLocked = true
	idx.public.Attrs |= NVReadLocked
	idx.name = idx.public.name()
	return t.authResponse(ac, nil, nil)
}

// cmdNVReadPublic implements TPM2_NV_ReadPublic: return an index's public area
// and Name. No authorization is required.
func (t *TPM) cmdNVReadPublic(r *reader) []byte {
	nvHandle := r.u32()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	idx, ok := t.nv.get(nvHandle)
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	var w writer
	idx.public.marshal2B(&w) // nvPublic (TPM2B_NV_PUBLIC)
	w.tpm2b(idx.name)        // nvName
	return successResponse(w.bytes(), 0)
}
