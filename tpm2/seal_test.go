// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"encoding/json"
	"testing"
)

// sealedTemplate is a keyed-hash data object (no sensitiveDataOrigin) — the shape
// BitLocker uses to seal the volume master key under the SRK.
func sealedTemplate() public {
	return public{
		Type:    AlgKeyedHash,
		NameAlg: AlgSHA256,
		Attrs:   ObjFixedTPM | ObjFixedParent | ObjUserWithAuth,
		Scheme:  hashScheme{Scheme: AlgNull},
	}
}

// createSealed seals data under parent and returns the TPM2B_PRIVATE content and
// the public area produced by TPM2_Create.
func createSealed(t *testing.T, tpm *TPM, parent uint32, data []byte) ([]byte, public) {
	t.Helper()
	var inner writer
	inner.tpm2b(nil)  // userAuth
	inner.tpm2b(data) // data to seal
	tmpl := sealedTemplate()
	var params writer
	params.tpm2b(inner.bytes()) // inSensitive
	tmpl.marshal2B(&params)     // inPublic
	params.tpm2b(nil)           // outsideInfo
	params.u32(0)               // creationPCR

	_, rc, p := parseResp(t, tpm.Execute(buildHierarchyCmd(CCCreate, parent, nil, params.bytes())))
	if rc != RCSuccess {
		t.Fatalf("Create rc = 0x%x", rc)
	}
	r := newReader(p)
	_ = r.u32() // parameterSize
	priv := r.tpm2b()
	pub := readPublic2B(r)
	if r.err != nil {
		t.Fatalf("parse Create response: %v", r.err)
	}
	return priv, pub
}

// loadObject loads a (private, public) pair under parent and returns the handle
// and the response code.
func loadObject(t *testing.T, tpm *TPM, parent uint32, priv []byte, pub public) (uint32, uint32) {
	t.Helper()
	var params writer
	params.tpm2b(priv)
	pub.marshal2B(&params)
	_, rc, p := parseResp(t, tpm.Execute(buildHierarchyCmd(CCLoad, parent, nil, params.bytes())))
	if rc != RCSuccess {
		return 0, rc
	}
	r := newReader(p)
	h := r.u32() // objectHandle
	return h, rc
}

func TestSealCreateLoadRoundTrip(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())

	secret := []byte("bitlocker-volume-master-key")
	priv, pub := createSealed(t, tpm, srk, secret)

	h, rc := loadObject(t, tpm, srk, priv, pub)
	if rc != RCSuccess {
		t.Fatalf("Load rc = 0x%x", rc)
	}
	o, ok := tpm.objects.get(h)
	if !ok {
		t.Fatal("loaded object missing")
	}
	if !bytes.Equal(o.sensitive.Secret, secret) {
		t.Fatalf("sealed secret not recovered: got %q", o.sensitive.Secret)
	}
}

func TestLoadWrongParentFailsIntegrity(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk1, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	priv, pub := createSealed(t, tpm, srk1, []byte("secret"))

	// A different storage key cannot unwrap the blob.
	srk2, _, _ := createPrimary(t, tpm, RHEndorsement, eccStorageTemplate())
	if _, rc := loadObject(t, tpm, srk2, priv, pub); rc != RCIntegrity {
		t.Fatalf("wrong-parent Load rc = 0x%x, want INTEGRITY (0x%x)", rc, RCIntegrity)
	}
}

func TestLoadTamperedBlobFailsIntegrity(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	priv, pub := createSealed(t, tpm, srk, []byte("secret"))
	priv[len(priv)-1] ^= 0xFF // flip a ciphertext byte

	if _, rc := loadObject(t, tpm, srk, priv, pub); rc != RCIntegrity {
		t.Fatalf("tampered Load rc = 0x%x, want INTEGRITY", rc)
	}
}

func TestCreateLoadChildKey(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())

	// A child ECC signing key (random, not derived).
	childTmpl := public{
		Type:    AlgECC,
		NameAlg: AlgSHA256,
		Attrs:   ObjFixedTPM | ObjFixedParent | ObjSensitiveDataOrigin | ObjUserWithAuth | ObjSign,
		Sym:     symDef{Alg: AlgNull},
		Scheme:  hashScheme{Scheme: AlgECDSA, HashAlg: AlgSHA256},
		Curve:   ECCNistP256,
		KDF:     hashScheme{Scheme: AlgNull},
	}
	var inner writer
	inner.tpm2b(nil)
	inner.tpm2b(nil)
	var params writer
	params.tpm2b(inner.bytes())
	childTmpl.marshal2B(&params)
	params.tpm2b(nil)
	params.u32(0)
	_, rc, p := parseResp(t, tpm.Execute(buildHierarchyCmd(CCCreate, srk, nil, params.bytes())))
	if rc != RCSuccess {
		t.Fatalf("Create child key rc = 0x%x", rc)
	}
	r := newReader(p)
	_ = r.u32()
	priv := r.tpm2b()
	pub := readPublic2B(r)

	h, rc := loadObject(t, tpm, srk, priv, pub)
	if rc != RCSuccess {
		t.Fatalf("Load child rc = 0x%x", rc)
	}
	o, _ := tpm.objects.get(h)
	if o.public.Type != AlgECC || len(o.sensitive.Secret) != 32 {
		t.Fatalf("loaded child key malformed: type=0x%x |d|=%d", o.public.Type, len(o.sensitive.Secret))
	}
}

// TestSealedObjectSurvivesReboot is the BitLocker scenario end to end: seal a
// secret under a persistent SRK, reboot (snapshot → restore), and load it back.
func TestSealedObjectSurvivesReboot(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	const persistent = 0x81000001
	if rc := evictControl(t, tpm, RHOwner, srk, persistent); rc != RCSuccess {
		t.Fatalf("EvictControl rc = 0x%x", rc)
	}

	vmk := []byte("volume-master-key-32-bytes-long!")
	priv, pub := createSealed(t, tpm, persistent, vmk)

	// Reboot via snapshot/restore into a fresh TPM.
	data, err := json.Marshal(tpm.Snapshot())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Snapshot
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rebooted := New()
	if err := rebooted.Restore(back); err != nil {
		t.Fatalf("restore: %v", err)
	}

	// Load the sealed blob under the restored persistent SRK.
	h, rc := loadObject(t, rebooted, persistent, priv, pub)
	if rc != RCSuccess {
		t.Fatalf("Load after reboot rc = 0x%x", rc)
	}
	o, _ := rebooted.objects.get(h)
	if !bytes.Equal(o.sensitive.Secret, vmk) {
		t.Fatal("sealed VMK not recovered after reboot — BitLocker would fail to unlock")
	}
}
