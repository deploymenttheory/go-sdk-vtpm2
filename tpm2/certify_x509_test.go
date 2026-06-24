// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"encoding/asn1"
	"testing"
	"time"
)

// buildPartialCert assembles a DER partial certificate (no signature algorithm):
// issuer ‖ validity ‖ subject ‖ extensions[3], the extensions carrying a Key Usage
// with the given bits.
func buildPartialCert(t *testing.T, kuByte byte, kuBits int) []byte {
	t.Helper()
	ku := asn1.BitString{Bytes: []byte{kuByte}, BitLength: kuBits}
	kuVal, err := asn1.Marshal(ku)
	if err != nil {
		t.Fatal(err)
	}
	extSeq, err := asn1.Marshal([]x509Extension{{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 15}, // Key Usage
		Critical: true,
		Value:    kuVal,
	}})
	if err != nil {
		t.Fatal(err)
	}
	extsField, err := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 3, IsCompound: true, Bytes: extSeq})
	if err != nil {
		t.Fatal(err)
	}
	valDER, err := asn1.Marshal(struct{ NotBefore, NotAfter time.Time }{
		time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	name := derSeq(nil) // empty RDNSequence
	var content []byte
	content = append(content, name...)      // issuer
	content = append(content, valDER...)    // validity
	content = append(content, name...)      // subject
	content = append(content, extsField...) // extensions [3]
	return derSeq(content)
}

func TestCertifyX509(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	signKey := createSigningKey(t, tpm, srk, eccSigningTemplate())
	obj := createSigningKey(t, tpm, srk, eccSigningTemplate()) // certified object (has sign)
	partial := buildPartialCert(t, 0x80, 1)                    // digitalSignature

	var b writer
	b.u32(obj)
	b.u32(signKey)
	b.raw(twoPasswordAuth())
	b.tpm2b(nil)   // reserved
	b.u16(AlgNull) // inScheme ⇒ key's scheme
	b.tpm2b(partial)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCCertifyX509, b.bytes())))
	if rc != RCSuccess {
		t.Fatalf("CertifyX509 rc = 0x%x", rc)
	}
	r := newReader(p)
	params := r.bytes(int(r.u32()))
	pr := newReader(params)
	added := pr.tpm2b()
	tbsDigest := pr.tpm2b()
	sig := pr.bytes(pr.remaining())

	// The signature is over tbsDigest.
	var v writer
	v.u32(signKey)
	v.tpm2b(tbsDigest)
	v.raw(sig)
	if _, vrc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCVerifySignature, v.bytes()))); vrc != RCSuccess {
		t.Fatalf("X509 signature did not verify: rc = 0x%x", vrc)
	}

	// Reconstruct the full TBSCertificate from addedToCertificate + the partial
	// certificate and confirm it hashes to tbsDigest (RFC 5280 §4.1 field order).
	var addedElems, partialElems []asn1.RawValue
	if _, err := asn1.Unmarshal(added, &addedElems); err != nil {
		t.Fatalf("parse addedToCertificate: %v", err)
	}
	if _, err := asn1.Unmarshal(partial, &partialElems); err != nil {
		t.Fatal(err)
	}
	if len(addedElems) != 4 { // version, serial, signatureAlg (TPM-created), SPKI
		t.Fatalf("addedToCertificate has %d elements, want 4", len(addedElems))
	}
	var tbs []byte
	tbs = append(tbs, addedElems[0].FullBytes...)   // version
	tbs = append(tbs, addedElems[1].FullBytes...)   // serialNumber
	tbs = append(tbs, addedElems[2].FullBytes...)   // signatureAlgorithm
	tbs = append(tbs, partialElems[0].FullBytes...) // issuer
	tbs = append(tbs, partialElems[1].FullBytes...) // validity
	tbs = append(tbs, partialElems[2].FullBytes...) // subject
	tbs = append(tbs, addedElems[3].FullBytes...)   // subjectPublicKeyInfo
	tbs = append(tbs, partialElems[3].FullBytes...) // extensions
	if d := hashSum(AlgSHA256, derSeq(tbs)); !bytes.Equal(d, tbsDigest) {
		t.Fatal("reconstructed TBSCertificate digest does not match tbsDigest")
	}
}

// TestCertifyX509KeyUsageMismatch confirms the Key Usage consistency check: a
// digitalSignature usage against a non-signing object is rejected.
func TestCertifyX509KeyUsageMismatch(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	signKey := createSigningKey(t, tpm, srk, eccSigningTemplate())
	obj, _, _ := createPrimary(t, tpm, RHEndorsement, eccStorageTemplate()) // storage key: no sign
	partial := buildPartialCert(t, 0x80, 1)                                 // digitalSignature

	var b writer
	b.u32(obj)
	b.u32(signKey)
	b.raw(twoPasswordAuth())
	b.tpm2b(nil)
	b.u16(AlgNull)
	b.tpm2b(partial)
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCCertifyX509, b.bytes()))); baseRC(rc) != RCAttributes {
		t.Fatalf("Key-Usage-mismatch CertifyX509 rc = 0x%x, want RC_ATTRIBUTES", rc)
	}
}
