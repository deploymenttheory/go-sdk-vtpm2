// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import "testing"

// TestListCountBounds verifies that a wire-supplied list count far larger than the
// available data is rejected (errBadValue) instead of driving a multi-gigabyte
// allocation or panicking. Every element occupies at least one byte, so a count of
// ~4 billion against an empty body is unambiguously malformed.
func TestListCountBounds(t *testing.T) {
	t.Run("pcr_selection", func(t *testing.T) {
		var w writer
		w.u32(0xFFFFFFFF) // count, no selections follow
		r := newReader(w.bytes())
		if got := readPCRSelectionList(r); got != nil {
			t.Fatalf("readPCRSelectionList = %v, want nil on bogus count", got)
		}
		if r.err != errBadValue {
			t.Fatalf("err = %v, want errBadValue", r.err)
		}
	})

	t.Run("digest_values", func(t *testing.T) {
		var w writer
		w.u32(0xFFFFFFFF) // count, no digests follow
		r := newReader(w.bytes())
		if got := readDigestValues(r); got != nil {
			t.Fatalf("readDigestValues = %v, want nil on bogus count", got)
		}
		if r.err != errBadValue {
			t.Fatalf("err = %v, want errBadValue", r.err)
		}
	})
}

// TestPCRReadHugeCountErrors confirms the bound surfaces as a clean error response
// (not a panic) when reached through the command dispatcher.
func TestPCRReadHugeCountErrors(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	var p writer
	p.u32(0xFFFFFFFF) // TPML_PCR_SELECTION count with no body
	_, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCPCRRead, p.bytes())))
	if rc == RCSuccess {
		t.Fatal("PCR_Read with bogus selection count unexpectedly succeeded")
	}
}
