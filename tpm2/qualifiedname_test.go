// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"testing"
)

// readPublicNameQN returns an object's Name and Qualified Name from ReadPublic.
func readPublicNameQN(t *testing.T, tpm *TPM, handle uint32) (name, qn []byte) {
	t.Helper()
	var rp writer
	rp.u32(handle)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCReadPublic, rp.bytes())))
	if rc != RCSuccess {
		t.Fatalf("ReadPublic(0x%x) rc = 0x%x", handle, rc)
	}
	r := newReader(p)
	_ = readPublic2B(r)
	name = r.tpm2b()
	qn = r.tpm2b()
	if r.err != nil {
		t.Fatalf("parse ReadPublic: %v", r.err)
	}
	return name, qn
}

// TestQualifiedNameChain verifies the real Qualified-Name chain (TPM 2.0 Part 1,
// §26.5): QN = H_nameAlg(parentQN ‖ Name), with a primary's parentQN being the
// hierarchy handle. Previously ReadPublic returned the Name as the QN.
func TestQualifiedNameChain(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, srkPub, srkName := createPrimary(t, tpm, RHOwner, eccStorageTemplate())

	gotName, srkQN := readPublicNameQN(t, tpm, srk)
	if !bytes.Equal(gotName, srkName) {
		t.Fatal("ReadPublic Name mismatch")
	}
	wantSRKQN := qualifiedNameOf(srkPub.NameAlg, permanentName(RHOwner), srkName)
	if !bytes.Equal(srkQN, wantSRKQN) {
		t.Fatalf("primary QN = %x, want H(nameAlg, hierarchy, Name) = %x", srkQN, wantSRKQN)
	}
	if bytes.Equal(srkQN, srkName) {
		t.Fatal("primary QN must not equal its Name (the old simplification)")
	}

	// A child's QN chains off the parent's QN.
	priv, childPub := createSealed(t, tpm, srk, []byte("vmk"))
	childHandle, rc := loadObject(t, tpm, srk, priv, childPub)
	if rc != RCSuccess {
		t.Fatalf("Load rc = 0x%x", rc)
	}
	childName, childQN := readPublicNameQN(t, tpm, childHandle)
	wantChildQN := qualifiedNameOf(childPub.NameAlg, srkQN, childName)
	if !bytes.Equal(childQN, wantChildQN) {
		t.Fatalf("child QN = %x, want H(nameAlg, parentQN, Name) = %x", childQN, wantChildQN)
	}
}

// TestQualifiedNameSurvivesReboot confirms a persistent object's QN round-trips
// through a snapshot (v7) rather than collapsing to its Name.
func TestQualifiedNameSurvivesReboot(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	const persistent = 0x81000001
	evictControl(t, tpm, RHOwner, srk, persistent)
	_, wantQN := readPublicNameQN(t, tpm, persistent)

	snap := tpm.Snapshot()
	if snap.Version != snapshotVersion {
		t.Fatalf("snapshot version = %d, want %d", snap.Version, snapshotVersion)
	}
	fresh := New()
	if err := fresh.Restore(snap); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	_, gotQN := readPublicNameQN(t, fresh, persistent)
	if !bytes.Equal(gotQN, wantQN) {
		t.Fatalf("QN after reboot = %x, want %x", gotQN, wantQN)
	}
}
