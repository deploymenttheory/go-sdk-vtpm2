// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import "fmt"

// snapshotVersion is the on-the-wire version of a Snapshot. Bump it whenever the
// serialized shape changes so a loader can reject or migrate older state.
//
//	v1: PCR banks only.
//	v2: + authorization hierarchies (seeds, auth, policy, enables).
//	v3: + dictionary-attack lockout state.
//	v4: + persistent objects (EK/SRK).
//	v5: + NV indices.
//	v6: + clock/reset/restart counters.
//	v7: + persistent-object Qualified Names.
const snapshotVersion = 7

// Snapshot is a serializable copy of a TPM's persistent state. It is the
// boundary between the command processor and the state package, which persists
// it across host restarts (Windows 11 requires its vTPM state to survive
// reboots). All fields are exported and JSON-friendly.
type Snapshot struct {
	Version          int    `json:"version"`
	Started          bool   `json:"started"`
	PCRUpdateCounter uint32 `json:"pcrUpdateCounter"`
	// PCRBanks maps a hash algorithm id to its PCR digests.
	PCRBanks map[uint16][][]byte `json:"pcrBanks"`
	// Hierarchies is the persisted hierarchy state (nil in a v1 snapshot).
	Hierarchies *HierarchiesSnap `json:"hierarchies,omitempty"`
	// DA is the persisted dictionary-attack lockout state (nil before v3).
	DA *DASnap `json:"da,omitempty"`
	// PersistentObjects holds the persistent objects (EK/SRK), nil before v4.
	PersistentObjects []ObjectSnap `json:"persistentObjects,omitempty"`
	// NVIndices holds the defined NV indices, nil before v5.
	NVIndices []NVIndexSnap `json:"nvIndices,omitempty"`
	// Clock is the persisted clock/reset/restart state, nil before v6.
	Clock *ClockSnap `json:"clock,omitempty"`
}

// ClockSnap is the serialized clock state.
type ClockSnap struct {
	Clock        uint64 `json:"clock"`
	ResetCount   uint32 `json:"resetCount"`
	RestartCount uint32 `json:"restartCount"`
	Safe         byte   `json:"safe"`
}

// NVIndexSnap is a serialized NV index.
type NVIndexSnap struct {
	Public      []byte `json:"public"`
	AuthValue   []byte `json:"authValue,omitempty"`
	Data        []byte `json:"data,omitempty"`
	ReadLocked  bool   `json:"readLocked,omitempty"`
	WriteLocked bool   `json:"writeLocked,omitempty"`
}

// ObjectSnap is a serialized persistent object: its handle plus the marshalled
// public and sensitive areas.
type ObjectSnap struct {
	Handle        uint32 `json:"handle"`
	Public        []byte `json:"public"`
	Sensitive     []byte `json:"sensitive"`
	QualifiedName []byte `json:"qualifiedName,omitempty"` // v7+
}

// DASnap is the serialized dictionary-attack lockout state.
type DASnap struct {
	FailedTries     uint32 `json:"failedTries"`
	MaxTries        uint32 `json:"maxTries"`
	RecoveryTime    uint32 `json:"recoveryTime"`
	LockoutRecovery uint32 `json:"lockoutRecovery"`
}

// HierarchySnap is the serialized state of one authorization hierarchy.
type HierarchySnap struct {
	Enabled    bool   `json:"enabled"`
	AuthValue  []byte `json:"authValue,omitempty"`
	AuthPolicy []byte `json:"authPolicy,omitempty"`
	Seed       []byte `json:"seed,omitempty"`
}

// HierarchiesSnap is the serialized set of hierarchies. The null hierarchy is not
// persisted: its seed is volatile and regenerated on every reset.
type HierarchiesSnap struct {
	Owner        HierarchySnap `json:"owner"`
	Endorsement  HierarchySnap `json:"endorsement"`
	Platform     HierarchySnap `json:"platform"`
	Lockout      HierarchySnap `json:"lockout"`
	PHEnableNV   bool          `json:"phEnableNV"`
	DisableClear bool          `json:"disableClear"`
}

func snapHierarchy(h hierarchy) HierarchySnap {
	return HierarchySnap{
		Enabled:    h.enabled,
		AuthValue:  append([]byte(nil), h.authValue...),
		AuthPolicy: append([]byte(nil), h.authPolicy...),
		Seed:       append([]byte(nil), h.seed...),
	}
}

func (s HierarchySnap) restore() hierarchy {
	return hierarchy{
		enabled:    s.Enabled,
		authValue:  append([]byte(nil), s.AuthValue...),
		authPolicy: append([]byte(nil), s.AuthPolicy...),
		seed:       append([]byte(nil), s.Seed...),
	}
}

// Snapshot returns a deep copy of the TPM's persistent state.
func (t *TPM) Snapshot() Snapshot {
	t.mu.Lock()
	defer t.mu.Unlock()

	banks := make(map[uint16][][]byte, len(t.pcr.banks))
	for alg, bank := range t.pcr.banks {
		cp := make([][]byte, len(bank))
		for i, d := range bank {
			cp[i] = append([]byte(nil), d...)
		}
		banks[alg] = cp
	}
	return Snapshot{
		Version:          snapshotVersion,
		Started:          t.started,
		PCRUpdateCounter: t.pcr.updateCounter,
		PCRBanks:         banks,
		Hierarchies: &HierarchiesSnap{
			Owner:        snapHierarchy(t.h.owner),
			Endorsement:  snapHierarchy(t.h.endorsement),
			Platform:     snapHierarchy(t.h.platform),
			Lockout:      snapHierarchy(t.h.lockout),
			PHEnableNV:   t.h.phEnableNV,
			DisableClear: t.h.disableClear,
		},
		DA: &DASnap{
			FailedTries:     t.da.failedTries,
			MaxTries:        t.da.maxTries,
			RecoveryTime:    t.da.recoveryTime,
			LockoutRecovery: t.da.lockoutRecovery,
		},
		PersistentObjects: snapPersistentObjects(t.objects),
		NVIndices:         snapNVIndices(t.nv),
		Clock: &ClockSnap{
			Clock:        t.clock.clock,
			ResetCount:   t.clock.resetCount,
			RestartCount: t.clock.restartCount,
			Safe:         t.clock.safe,
		},
	}
}

// snapNVIndices marshals every NV index for persistence.
func snapNVIndices(nv *nvStore) []NVIndexSnap {
	if len(nv.indices) == 0 {
		return nil
	}
	out := make([]NVIndexSnap, 0, len(nv.indices))
	for _, idx := range nv.indices {
		var pub writer
		idx.public.marshal(&pub)
		out = append(out, NVIndexSnap{
			Public:      pub.bytes(),
			AuthValue:   idx.authValue,
			Data:        idx.data,
			ReadLocked:  idx.readLocked,
			WriteLocked: idx.writeLocked,
		})
	}
	return out
}

// snapPersistentObjects marshals every persistent object for persistence.
func snapPersistentObjects(ot *objectTable) []ObjectSnap {
	if len(ot.persistent) == 0 {
		return nil
	}
	out := make([]ObjectSnap, 0, len(ot.persistent))
	for h, o := range ot.persistent {
		var pub, sens writer
		o.public.marshal(&pub)
		o.sensitive.marshal(&sens)
		out = append(out, ObjectSnap{Handle: h, Public: pub.bytes(), Sensitive: sens.bytes(), QualifiedName: o.qualifiedName})
	}
	return out
}

// Restore replaces the TPM's persistent state with s. Versions up to the current
// snapshotVersion are accepted and migrated forward: a v1 snapshot has no
// hierarchies, so the freshly minted ones from New are kept. Banks absent from
// the snapshot are reset to their power-on (all-zero) value so the supported bank
// set is always complete.
func (t *TPM) Restore(s Snapshot) error {
	if s.Version < 1 || s.Version > snapshotVersion {
		return fmt.Errorf("tpm2: unsupported snapshot version %d (want 1..%d)", s.Version, snapshotVersion)
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	t.pcr.reset()
	t.started = s.Started
	t.pcr.updateCounter = s.PCRUpdateCounter
	for _, alg := range supportedPCRBanks {
		src, ok := s.PCRBanks[alg]
		if !ok {
			continue // leave the reset (zero) bank in place
		}
		size := hashSize(alg)
		for i := 0; i < numPCR && i < len(src); i++ {
			if len(src[i]) != size {
				return fmt.Errorf("tpm2: snapshot PCR[%d] bank 0x%x has %d-byte digest, want %d", i, alg, len(src[i]), size)
			}
			t.pcr.banks[alg][i] = append([]byte(nil), src[i]...)
		}
	}

	// v2+: restore the persisted hierarchies; a v1 snapshot keeps New's fresh set.
	if hs := s.Hierarchies; hs != nil {
		null := t.h.null // preserve the volatile null seed minted by New
		t.h.owner = hs.Owner.restore()
		t.h.endorsement = hs.Endorsement.restore()
		t.h.platform = hs.Platform.restore()
		t.h.lockout = hs.Lockout.restore()
		t.h.null = null
		t.h.phEnableNV = hs.PHEnableNV
		t.h.disableClear = hs.DisableClear
	}

	// v3+: restore the DA lockout state; earlier snapshots keep New's defaults.
	if d := s.DA; d != nil {
		t.da.failedTries = d.FailedTries
		t.da.maxTries = d.MaxTries
		t.da.recoveryTime = d.RecoveryTime
		t.da.lockoutRecovery = d.LockoutRecovery
	}

	// v4+: restore persistent objects (EK/SRK).
	t.objects.persistent = make(map[uint32]*object)
	for _, os := range s.PersistentObjects {
		var o object
		pr := newReader(os.Public)
		o.public.unmarshal(pr)
		sr := newReader(os.Sensitive)
		o.sensitive.unmarshal(sr)
		if pr.err != nil || sr.err != nil {
			return fmt.Errorf("tpm2: corrupt persistent object 0x%x", os.Handle)
		}
		o.name = o.public.name()
		// v7+ carries the Qualified Name; older snapshots fall back to the Name.
		if len(os.QualifiedName) > 0 {
			o.qualifiedName = append([]byte(nil), os.QualifiedName...)
		} else {
			o.qualifiedName = append([]byte(nil), o.name...)
		}
		t.objects.persistent[os.Handle] = &o
	}

	// v5+: restore NV indices.
	t.nv.indices = make(map[uint32]*nvIndex)
	for _, ns := range s.NVIndices {
		var idx nvIndex
		pr := newReader(ns.Public)
		idx.public.unmarshal(pr)
		if pr.err != nil {
			return fmt.Errorf("tpm2: corrupt NV index snapshot")
		}
		idx.authValue = append([]byte(nil), ns.AuthValue...)
		idx.data = append([]byte(nil), ns.Data...)
		idx.readLocked = ns.ReadLocked
		idx.writeLocked = ns.WriteLocked
		idx.name = idx.public.name()
		t.nv.indices[idx.public.Index] = &idx
	}

	// v6+: restore the clock state.
	if c := s.Clock; c != nil {
		t.clock.clock = c.Clock
		t.clock.resetCount = c.ResetCount
		t.clock.restartCount = c.RestartCount
		t.clock.safe = c.Safe
	}
	return nil
}
