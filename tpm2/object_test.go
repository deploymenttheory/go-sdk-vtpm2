// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"encoding/json"
	"testing"
)

// evictControl runs TPM2_EvictControl (empty hierarchy auth) and returns the rc.
func evictControl(t *testing.T, tpm *TPM, authHi, objHandle, persistentHandle uint32) uint32 {
	t.Helper()
	var auth writer
	auth.u32(RHPW)
	auth.u16(0)
	auth.u8(0)
	auth.u16(0)
	var body writer
	body.u32(authHi)
	body.u32(objHandle)
	body.u32(uint32(len(auth.bytes())))
	body.raw(auth.bytes())
	body.u32(persistentHandle)
	_, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCEvictControl, body.bytes())))
	return rc
}

// readPublicName returns the Name reported by TPM2_ReadPublic for a handle.
func readPublicName(t *testing.T, tpm *TPM, handle uint32) []byte {
	t.Helper()
	var rp writer
	rp.u32(handle)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCReadPublic, rp.bytes())))
	if rc != RCSuccess {
		t.Fatalf("ReadPublic(0x%x) rc = 0x%x", handle, rc)
	}
	r := newReader(p)
	_ = readPublic2B(r)
	return r.tpm2b()
}

// eccStorageTemplate is a restricted ECC-P256 decryption (storage) key template,
// the shape of a typical SRK.
func eccStorageTemplate() public {
	return public{
		Type:    AlgECC,
		NameAlg: AlgSHA256,
		Attrs:   ObjFixedTPM | ObjFixedParent | ObjSensitiveDataOrigin | ObjUserWithAuth | ObjRestricted | ObjDecrypt | ObjNoDA,
		Sym:     symDef{Alg: AlgAES, KeyBits: 128, Mode: AlgCFB},
		Scheme:  hashScheme{Scheme: AlgNull},
		Curve:   ECCNistP256,
		KDF:     hashScheme{Scheme: AlgNull},
	}
}

// createPrimary runs TPM2_CreatePrimary under a hierarchy (empty auth) and returns
// the object handle, its public area, and its Name.
func createPrimary(t *testing.T, tpm *TPM, hierarchy uint32, tmpl public) (uint32, public, []byte) {
	t.Helper()
	// inSensitive (TPM2B_SENSITIVE_CREATE): outer TPM2B wrapping userAuth + data.
	var inner writer
	inner.tpm2b(nil) // userAuth
	inner.tpm2b(nil) // data
	var params writer
	params.tpm2b(inner.bytes()) // TPM2B_SENSITIVE_CREATE
	tmpl.marshal2B(&params)     // inPublic
	params.tpm2b(nil)           // outsideInfo
	params.u32(0)               // creationPCR (empty TPML_PCR_SELECTION)

	tag, rc, p := parseResp(t, tpm.Execute(buildHierarchyCmd(CCCreatePrimary, hierarchy, nil, params.bytes())))
	if rc != RCSuccess {
		t.Fatalf("CreatePrimary rc = 0x%x", rc)
	}
	if tag != TPMSTSessions {
		t.Fatalf("response tag = 0x%x, want sessions", tag)
	}
	r := newReader(p)
	handle := r.u32()
	_ = r.u32() // parameterSize
	outPub := readPublic2B(r)
	_ = r.tpm2b() // creationData
	_ = r.tpm2b() // creationHash
	_ = r.u16()   // ticket tag
	_ = r.u32()   // ticket hierarchy
	_ = r.tpm2b() // ticket digest
	name := r.tpm2b()
	if r.err != nil {
		t.Fatalf("parse CreatePrimary response: %v", r.err)
	}
	if classifyHandle(handle) != htTransient {
		t.Fatalf("object handle 0x%x not transient", handle)
	}
	return handle, outPub, name
}

func TestCreatePrimaryECCAndReadPublic(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	h, pub, name := createPrimary(t, tpm, RHOwner, eccStorageTemplate())

	if pub.Type != AlgECC || len(pub.UniqueX) != 32 || len(pub.UniqueY) != 32 {
		t.Fatalf("unexpected ECC public: type=0x%x |X|=%d |Y|=%d", pub.Type, len(pub.UniqueX), len(pub.UniqueY))
	}
	if !bytes.Equal(name, pub.name()) {
		t.Fatal("returned Name does not match H(public)")
	}

	// ReadPublic must return the same public area and Name.
	var rp writer
	rp.u32(h)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCReadPublic, rp.bytes())))
	if rc != RCSuccess {
		t.Fatalf("ReadPublic rc = 0x%x", rc)
	}
	r := newReader(p)
	got := readPublic2B(r)
	gotName := r.tpm2b()
	if !bytes.Equal(gotName, name) || got.Type != pub.Type || !bytes.Equal(got.UniqueX, pub.UniqueX) {
		t.Fatal("ReadPublic does not match the created object")
	}
}

func TestCreatePrimaryRSA(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	tmpl := public{
		Type:    AlgRSA,
		NameAlg: AlgSHA256,
		Attrs:   ObjFixedTPM | ObjFixedParent | ObjSensitiveDataOrigin | ObjUserWithAuth | ObjRestricted | ObjDecrypt | ObjNoDA,
		Sym:     symDef{Alg: AlgAES, KeyBits: 128, Mode: AlgCFB},
		Scheme:  hashScheme{Scheme: AlgNull},
		KeyBits: 2048,
	}
	_, pub, _ := createPrimary(t, tpm, RHOwner, tmpl)
	if pub.Type != AlgRSA || len(pub.Unique) != 256 {
		t.Fatalf("RSA primary modulus = %d bytes, want 256", len(pub.Unique))
	}
}

// TestPrimaryDeterministicFromSeed is the property BitLocker depends on: the same
// hierarchy seed and template always derive the same key, so a recreated SRK can
// load objects sealed under it before a reboot.
func TestPrimaryDeterministicFromSeed(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, seedSize)

	tpmA := New()
	startup(t, tpmA)
	tpmA.h.owner.seed = seed
	_, pubA, nameA := createPrimary(t, tpmA, RHOwner, eccStorageTemplate())

	tpmB := New()
	startup(t, tpmB)
	tpmB.h.owner.seed = seed
	_, pubB, nameB := createPrimary(t, tpmB, RHOwner, eccStorageTemplate())

	if !bytes.Equal(nameA, nameB) {
		t.Fatal("same seed+template produced different primary keys (SRK would be unstable)")
	}
	if !bytes.Equal(pubA.UniqueX, pubB.UniqueX) || !bytes.Equal(pubA.UniqueY, pubB.UniqueY) {
		t.Fatal("derived ECC point differs across instances with the same seed")
	}
}

// TestPrimaryDiffersByHierarchy: the same template under different hierarchy seeds
// must yield different keys.
func TestPrimaryDiffersByHierarchy(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	_, ownerPub, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	_, endoPub, _ := createPrimary(t, tpm, RHEndorsement, eccStorageTemplate())
	if bytes.Equal(ownerPub.UniqueX, endoPub.UniqueX) {
		t.Fatal("owner and endorsement primaries must differ")
	}
}

func TestEvictControlPersistAndReload(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	h, _, name := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	const persistent = 0x81000001

	if rc := evictControl(t, tpm, RHOwner, h, persistent); rc != RCSuccess {
		t.Fatalf("EvictControl persist rc = 0x%x", rc)
	}
	if got := readPublicName(t, tpm, persistent); !bytes.Equal(got, name) {
		t.Fatal("ReadPublic of the persistent handle does not match the SRK")
	}

	// Persist via snapshot/JSON and reload into a fresh TPM — the SRK must survive
	// even though the new TPM has a different (random) owner seed.
	data, err := json.Marshal(tpm.Snapshot())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Snapshot
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	reloaded := New()
	if err := reloaded.Restore(back); err != nil {
		t.Fatalf("restore: %v", err)
	}
	o, ok := reloaded.objects.get(persistent)
	if !ok {
		t.Fatal("persistent SRK not restored after reboot")
	}
	if !bytes.Equal(o.name, name) {
		t.Fatal("restored SRK Name differs — sealed objects would fail to load")
	}
	// The restored object must carry its private key, not just the public area.
	if len(o.sensitive.Secret) == 0 {
		t.Fatal("restored persistent object lost its sensitive material")
	}
}

func TestEvictControlEvict(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	h, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	const persistent = 0x81000002
	if rc := evictControl(t, tpm, RHOwner, h, persistent); rc != RCSuccess {
		t.Fatalf("persist rc = 0x%x", rc)
	}
	// Evicting references the persistent handle as the object handle.
	if rc := evictControl(t, tpm, RHOwner, persistent, persistent); rc != RCSuccess {
		t.Fatalf("evict rc = 0x%x", rc)
	}
	if _, ok := tpm.objects.get(persistent); ok {
		t.Fatal("persistent object not evicted")
	}
}

func TestEvictControlWrongRange(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	h, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	// Owner auth cannot persist into the platform range.
	if rc := evictControl(t, tpm, RHOwner, h, platformPersistentBase+1); baseRC(rc) != RCValue {
		t.Fatalf("owner→platform-range rc = 0x%x, want VALUE", rc)
	}
}

func TestFlushTransientObject(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	h, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	var fp writer
	fp.u32(h)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCFlushContext, fp.bytes()))); rc != RCSuccess {
		t.Fatalf("FlushContext rc = 0x%x", rc)
	}
	if _, ok := tpm.objects.get(h); ok {
		t.Fatal("transient object not flushed")
	}
}

func TestReadPublicUnknownHandle(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	var rp writer
	rp.u32(htTransient + 99)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCReadPublic, rp.bytes()))); baseRC(rc) != RCHandle {
		t.Fatalf("ReadPublic of unknown handle rc = 0x%x, want HANDLE", rc)
	}
}
