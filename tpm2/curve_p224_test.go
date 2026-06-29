// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import "testing"

// TestECCParametersP224 confirms TPM2_ECC_Parameters answers for NIST P-224: the
// curve is known to crypto/elliptic, so its algorithm detail is returned with the
// curveID echoed back.
func TestECCParametersP224(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	var p writer
	p.u16(ECCNistP224)
	_, rc, body := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCECCParameters, p.bytes())))
	if rc != RCSuccess {
		t.Fatalf("ECC_Parameters(P-224) rc = 0x%x, want success", rc)
	}
	if got := newReader(body).u16(); got != ECCNistP224 {
		t.Fatalf("returned curveID = 0x%x, want 0x%x", got, ECCNistP224)
	}
}

// TestCreatePrimaryP224Rejected confirms that P-224 key *generation* is rejected:
// deterministic key derivation uses crypto/ecdh (deriveECCKey), which has no P-224,
// so CreatePrimary on a P-224 template fails with TPM_RC_KEY rather than producing
// an unusable key or panicking.
func TestCreatePrimaryP224Rejected(t *testing.T) {
	tpm := New()
	startup(t, tpm)

	tmpl := eccSigningTemplate()
	tmpl.Curve = ECCNistP224

	var inner writer
	inner.tpm2b(nil) // userAuth
	inner.tpm2b(nil) // data
	var params writer
	params.tpm2b(inner.bytes()) // TPM2B_SENSITIVE_CREATE
	tmpl.marshal2B(&params)     // inPublic
	params.tpm2b(nil)           // outsideInfo
	params.u32(0)               // creationPCR

	_, rc, _ := parseResp(t, tpm.Execute(buildHierarchyCmd(CCCreatePrimary, RHOwner, nil, params.bytes())))
	if baseRC(rc) != RCKey {
		t.Fatalf("CreatePrimary(P-224) rc = 0x%x, want TPM_RC_KEY", rc)
	}
}
