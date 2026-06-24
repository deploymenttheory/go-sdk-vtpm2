// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import "testing"

// eccParms / rsaParms build a minimal TPMT_PUBLIC_PARMS with NULL symmetric,
// scheme and KDF selectors.
func eccParms(curve uint16) []byte {
	var w writer
	w.u16(AlgECC)
	w.u16(AlgNull) // symmetric
	w.u16(AlgNull) // scheme
	w.u16(curve)
	w.u16(AlgNull) // kdf
	return w.bytes()
}

func rsaParms(keyBits uint16) []byte {
	var w writer
	w.u16(AlgRSA)
	w.u16(AlgNull) // symmetric
	w.u16(AlgNull) // scheme
	w.u16(keyBits)
	w.u32(0) // exponent (default)
	return w.bytes()
}

func TestIncrementalSelfTest(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	var w writer
	w.u32(2)
	w.u16(AlgSHA256)
	w.u16(AlgSHA1)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCIncrementalSelfTest, w.bytes())))
	if rc != RCSuccess {
		t.Fatalf("IncrementalSelfTest rc = 0x%x", rc)
	}
	if n := newReader(p).u32(); n != 0 {
		t.Fatalf("toDoList count = %d, want 0 (all algorithms tested)", n)
	}
}

func TestTestParms(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	cases := []struct {
		name   string
		parms  []byte
		baseRC uint32
	}{
		{"ECC P256", eccParms(ECCNistP256), RCSuccess},
		{"ECC bad curve", eccParms(0x9999), RCCurve},
		{"RSA 2048", rsaParms(2048), RCSuccess},
		{"RSA bad size", rsaParms(999), RCValue},
	}
	for _, c := range cases {
		_, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCTestParms, c.parms)))
		if baseRC(rc) != c.baseRC {
			t.Fatalf("TestParms(%s) rc = 0x%x, want base 0x%x", c.name, rc, c.baseRC)
		}
	}
}

func TestSetAlgorithmSet(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	var b writer
	b.u32(RHPlatform)
	b.raw(onePasswordAuth())
	b.u32(0xCAFE)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCSetAlgorithmSet, b.bytes()))); rc != RCSuccess {
		t.Fatalf("SetAlgorithmSet rc = 0x%x", rc)
	}
	if tpm.algorithmSet != 0xCAFE {
		t.Fatalf("algorithmSet = 0x%x, want 0xCAFE", tpm.algorithmSet)
	}
	// Only the platform hierarchy may set it.
	var bb writer
	bb.u32(RHOwner)
	bb.raw(onePasswordAuth())
	bb.u32(1)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCSetAlgorithmSet, bb.bytes()))); baseRC(rc) != RCValue {
		t.Fatalf("owner SetAlgorithmSet rc = 0x%x, want RC_VALUE", rc)
	}
}

func TestPPCommands(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	var b writer
	b.u32(RHPlatform)
	b.raw(onePasswordAuth())
	b.u32(1)
	b.u32(CCClear) // setList
	b.u32(0)       // clearList
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCPPCommands, b.bytes()))); rc != RCSuccess {
		t.Fatalf("PP_Commands rc = 0x%x", rc)
	}
	if !tpm.ppRequired[CCClear] {
		t.Fatal("TPM2_Clear was not marked physical-presence-required")
	}
	// Clear it again.
	var bb writer
	bb.u32(RHPlatform)
	bb.raw(onePasswordAuth())
	bb.u32(0)
	bb.u32(1)
	bb.u32(CCClear) // clearList
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCPPCommands, bb.bytes()))); rc != RCSuccess {
		t.Fatalf("PP_Commands clear rc = 0x%x", rc)
	}
	if tpm.ppRequired[CCClear] {
		t.Fatal("TPM2_Clear PP requirement was not cleared")
	}
}
