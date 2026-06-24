// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

// This file holds the loaded-object table (TPM 2.0 Part 1, §30). Transient
// objects live in the 0x80xxxxxx range and are volatile; persistent objects live
// in 0x81xxxxxx and are saved across reboots (the EK/SRK).

const maxTransientObjects = 64

// object is a loaded TPM object: its public area, its sensitive area, and the
// cached Name (nameAlg ‖ H(public)).
type object struct {
	public    public
	sensitive sensitive
	name      []byte
}

// objectTable holds loaded transient and persistent objects.
type objectTable struct {
	transient  map[uint32]*object
	persistent map[uint32]*object
	nextTrans  uint32
}

func newObjectTable() *objectTable {
	return &objectTable{
		transient:  make(map[uint32]*object),
		persistent: make(map[uint32]*object),
		nextTrans:  htTransient + 1,
	}
}

// loadTransient inserts o under a fresh transient handle, reporting false if the
// transient object table is full.
func (ot *objectTable) loadTransient(o *object) (uint32, bool) {
	if len(ot.transient) >= maxTransientObjects {
		return 0, false
	}
	h := ot.nextTrans
	ot.nextTrans++
	ot.transient[h] = o
	return h, true
}

// get returns the object at handle h (transient or persistent).
func (ot *objectTable) get(h uint32) (*object, bool) {
	switch classifyHandle(h) {
	case htTransient:
		o, ok := ot.transient[h]
		return o, ok
	case htPersistent:
		o, ok := ot.persistent[h]
		return o, ok
	}
	return nil, false
}

// resetTransient drops all transient objects (a TPM reset); persistent objects
// are kept.
func (ot *objectTable) resetTransient() {
	ot.transient = make(map[uint32]*object)
	ot.nextTrans = htTransient + 1
}

// flushTransient removes a transient object, reporting whether it existed.
func (ot *objectTable) flushTransient(h uint32) bool {
	if _, ok := ot.transient[h]; ok {
		delete(ot.transient, h)
		return true
	}
	return false
}

// persist copies a loaded object to a persistent handle.
func (ot *objectTable) persist(persistentHandle uint32, o *object) {
	cp := *o
	ot.persistent[persistentHandle] = &cp
}

// evict removes a persistent object, reporting whether it existed.
func (ot *objectTable) evict(persistentHandle uint32) bool {
	if _, ok := ot.persistent[persistentHandle]; ok {
		delete(ot.persistent, persistentHandle)
		return true
	}
	return false
}

// persistentHandles returns the persistent object handles in ascending order
// from low to high (for TPM_CAP_HANDLES); callers sort if needed.
func (ot *objectTable) persistentHandles() []uint32 {
	hs := make([]uint32, 0, len(ot.persistent))
	for h := range ot.persistent {
		hs = append(hs, h)
	}
	return hs
}
