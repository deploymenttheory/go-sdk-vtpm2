// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"crypto/sha256"
	"encoding/json"
	"testing"
)

func TestQuote(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	keyH := createSigningKey(t, tpm, srk, eccSigningTemplate())

	var params writer
	params.tpm2b([]byte("nonce")) // qualifyingData
	params.u16(AlgNull)           // inScheme NULL → key scheme
	params.raw(oneSHA256Selection(0))
	_, rc, p := parseResp(t, tpm.Execute(buildHierarchyCmd(CCQuote, keyH, nil, params.bytes())))
	if rc != RCSuccess {
		t.Fatalf("Quote rc = 0x%x", rc)
	}
	r := newReader(p)
	paramArea := r.bytes(int(r.u32())) // quoted ‖ signature
	pr := newReader(paramArea)
	quoted := pr.tpm2b()
	sig := pr.bytes(pr.remaining())
	if pr.err != nil {
		t.Fatalf("parse quote response: %v", pr.err)
	}

	// The attestation must be a well-formed, TPM-generated quote.
	ar := newReader(quoted)
	if magic := ar.u32(); magic != tpmGeneratedValue {
		t.Fatalf("attest magic = 0x%x, want TPM_GENERATED_VALUE", magic)
	}
	if at := ar.u16(); at != STAttestQuote {
		t.Fatalf("attest type = 0x%x, want ATTEST_QUOTE", at)
	}

	// The signature must verify over the quoted bytes.
	digest := sha256.Sum256(quoted)
	if rc := verifySig(t, tpm, keyH, digest[:], sig); rc != RCSuccess {
		t.Fatalf("quote signature verify rc = 0x%x", rc)
	}
}

func TestReadClock(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCReadClock, nil)))
	if rc != RCSuccess {
		t.Fatalf("ReadClock rc = 0x%x", rc)
	}
	r := newReader(p)
	_ = r.u64() // time
	_ = r.u64() // clock
	_ = r.u32() // resetCount
	restartCount := r.u32()
	safe := r.u8()
	if r.err != nil {
		t.Fatalf("parse TPMS_TIME_INFO: %v", r.err)
	}
	if restartCount < 1 {
		t.Fatal("restartCount should be incremented by Startup")
	}
	if safe != 1 {
		t.Fatalf("safe = %d, want 1", safe)
	}
}

func TestClockPersists(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	tpm.clock.clock = 12345
	tpm.clock.resetCount = 7

	data, err := json.Marshal(tpm.Snapshot())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Snapshot
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	restored := New()
	if err := restored.Restore(back); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if restored.clock.clock != 12345 || restored.clock.resetCount != 7 {
		t.Fatalf("clock not persisted: %+v", restored.clock)
	}
}
