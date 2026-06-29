// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"
	"os"
	"testing"
)

// authVector is one golden vector for the cpHash / authorization-HMAC path. See
// testdata/README.md for the schema and how to capture tss-captured vectors.
type authVector struct {
	Name           string   `json:"name"`
	Source         string   `json:"source"`
	HashAlg        string   `json:"hashAlg"`
	CommandCode    uint32   `json:"commandCode"`
	HandleNames    []string `json:"handleNames"`
	CpParams       string   `json:"cpParams"`
	SessionKey     string   `json:"sessionKey"`
	AuthValue      string   `json:"authValue"`
	NonceCaller    string   `json:"nonceCaller"`
	NonceTPM       string   `json:"nonceTPM"`
	Attributes     byte     `json:"attributes"`
	Bound          bool     `json:"bound"`
	ExpectedCpHash string   `json:"expectedCpHash"`
	ExpectedHMAC   string   `json:"expectedAuthHMAC"`
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// refNewHash is an independent hash factory (NOT auth.go) used as the oracle.
func refNewHash(alg string) func() hash.Hash {
	switch alg {
	case "sha256":
		return sha256.New
	}
	return nil
}

// refCpHash independently recomputes cpHash = H(cc ‖ names ‖ cpParams).
func refCpHash(newHash func() hash.Hash, cc uint32, names [][]byte, cp []byte) []byte {
	h := newHash()
	h.Write(be32(cc))
	for _, n := range names {
		h.Write(n)
	}
	h.Write(cp)
	return h.Sum(nil)
}

// refCommandHMAC independently recomputes the command authorization HMAC.
func refCommandHMAC(newHash func() hash.Hash, sessionKey, authValue []byte, bound bool, cph, nonceCaller, nonceTPM []byte, attrs byte) []byte {
	key := append([]byte{}, sessionKey...)
	if !bound {
		key = append(key, authValue...)
	}
	m := hmac.New(newHash, key)
	m.Write(cph)
	m.Write(nonceCaller)
	m.Write(nonceTPM)
	m.Write([]byte{attrs})
	return m.Sum(nil)
}

func TestAuthGoldenVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/auth_vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vectors []authVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("no golden vectors loaded")
	}

	algIDs := map[string]uint16{"sha256": AlgSHA256}

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			newHashFn := refNewHash(v.HashAlg)
			alg, ok := algIDs[v.HashAlg]
			if newHashFn == nil || !ok {
				t.Skipf("hash %q not supported by the harness", v.HashAlg)
			}
			var names [][]byte
			for _, n := range v.HandleNames {
				names = append(names, mustHex(t, n))
			}
			cp := mustHex(t, v.CpParams)
			sessionKey := mustHex(t, v.SessionKey)
			authValue := mustHex(t, v.AuthValue)
			nonceCaller := mustHex(t, v.NonceCaller)
			nonceTPM := mustHex(t, v.NonceTPM)

			// cpHash: auth.go must equal the independent reference.
			gotCp := cpHash(alg, v.CommandCode, names, cp)
			refCp := refCpHash(newHashFn, v.CommandCode, names, cp)
			if !bytes.Equal(gotCp, refCp) {
				t.Fatalf("cpHash mismatch vs reference\n auth.go: %x\nref:     %x", gotCp, refCp)
			}
			if v.ExpectedCpHash != "" && !bytes.Equal(gotCp, mustHex(t, v.ExpectedCpHash)) {
				t.Fatalf("cpHash mismatch vs golden\n got:    %x\ngolden: %s", gotCp, v.ExpectedCpHash)
			}

			// Authorization HMAC: auth.go must equal the independent reference.
			key := authHMACKey(sessionKey, authValue, v.Bound)
			gotMAC := commandAuthHMAC(alg, key, gotCp, nonceCaller, nonceTPM, nil, v.Attributes)
			refMAC := refCommandHMAC(newHashFn, sessionKey, authValue, v.Bound, gotCp, nonceCaller, nonceTPM, v.Attributes)
			if !bytes.Equal(gotMAC, refMAC) {
				t.Fatalf("authHMAC mismatch vs reference\n auth.go: %x\nref:     %x", gotMAC, refMAC)
			}
			if v.ExpectedHMAC != "" && !bytes.Equal(gotMAC, mustHex(t, v.ExpectedHMAC)) {
				t.Fatalf("authHMAC mismatch vs golden\n got:    %x\ngolden: %s", gotMAC, v.ExpectedHMAC)
			}
		})
	}
}

// TestResponseHMACSymmetry checks that the response HMAC uses the swapped nonce
// order (nonceTPM newer, nonceCaller older) relative to the command.
func TestResponseHMACSymmetry(t *testing.T) {
	key := []byte("session-key")
	rp := bytes.Repeat([]byte{0x33}, 32)
	nc := bytes.Repeat([]byte{0x01}, 16)
	nt := bytes.Repeat([]byte{0x02}, 16)

	got := responseAuthHMAC(AlgSHA256, key, rp, nt, nc, 1)
	m := hmac.New(sha256.New, key)
	m.Write(rp)
	m.Write(nt) // newer (response nonceTPM) first
	m.Write(nc) // older (command nonceCaller)
	m.Write([]byte{1})
	if !bytes.Equal(got, m.Sum(nil)) {
		t.Fatal("responseAuthHMAC does not match the spec nonce order")
	}
}
