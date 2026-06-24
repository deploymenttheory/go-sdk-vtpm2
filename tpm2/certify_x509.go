// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
)

// This file implements TPM2_CertifyX509 (TPM 2.0 Part 3, §18.8) — deprecated in
// spec version 184 but still defined. Unlike TPM2_Certify, the attestation is
// encoded as an RFC 5280 X.509 TBSCertificate: the caller supplies a partial
// certificate (issuer/validity/subject/extensions, optionally the signature
// algorithm) and the TPM fills in the version, serial number, subjectPublicKeyInfo
// and (if absent) signature algorithm, then signs the assembled TBSCertificate.

// x509Extension mirrors the RFC 5280 Extension SEQUENCE.
type x509Extension struct {
	Id       asn1.ObjectIdentifier
	Critical bool `asn1:"optional"`
	Value    []byte
}

// objectPublicKey builds a crypto public key from an object's public area for
// x509.MarshalPKIXPublicKey.
func objectPublicKey(o *object) (any, bool) {
	switch o.public.Type {
	case AlgRSA:
		return &rsa.PublicKey{N: new(big.Int).SetBytes(o.public.Unique), E: rsaExp(o.public.Exp)}, true
	case AlgECC:
		c := curveFor(o.public.Curve)
		if c == nil {
			return nil, false
		}
		return &ecdsa.PublicKey{Curve: c, X: new(big.Int).SetBytes(o.public.UniqueX), Y: new(big.Int).SetBytes(o.public.UniqueY)}, true
	}
	return nil, false
}

// sigAlgIdentifier returns the DER AlgorithmIdentifier for a signing scheme, or
// false if the TPM has no OID for it (TPM_RC_SCHEME when the caller omits it).
func sigAlgIdentifier(sigAlg, hashAlg uint16) ([]byte, bool) {
	switch sigAlg {
	case AlgECDSA: // ecdsa-with-SHAn (1.2.840.10045.4.3.{2,3,4})
		switch hashAlg {
		case AlgSHA256:
			return []byte{0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02}, true
		case AlgSHA384:
			return []byte{0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03}, true
		case AlgSHA512:
			return []byte{0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04}, true
		}
	case AlgRSASSA: // sha-nWithRSAEncryption (1.2.840.113549.1.1.{11,12,13})
		switch hashAlg {
		case AlgSHA256:
			return []byte{0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00}, true
		case AlgSHA384:
			return []byte{0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C, 0x05, 0x00}, true
		case AlgSHA512:
			return []byte{0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D, 0x05, 0x00}, true
		}
	}
	return nil, false
}

// derSeq wraps content in a DER SEQUENCE.
func derSeq(content []byte) []byte {
	out, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: content})
	return out
}

// checkKeyUsage verifies the X.509 Key Usage bits are consistent with an object's
// attributes (TPM 2.0 Part 2, Table 45 TPMA_X509_KEY_USAGE).
func checkKeyUsage(ku asn1.BitString, attrs uint32) []byte {
	sign := attrs&ObjSign != 0
	decrypt := attrs&ObjDecrypt != 0
	restricted := attrs&ObjRestricted != 0
	fixedTPM := attrs&ObjFixedTPM != 0
	// X.509 KeyUsage bit (0=digitalSignature … 8=decipherOnly) → required attribute.
	reqs := []struct {
		bit int
		ok  bool
	}{
		{0, sign},                  // digitalSignature
		{1, fixedTPM},              // nonRepudiation / contentCommitment
		{2, decrypt && restricted}, // keyEncipherment (parent key)
		{3, decrypt},               // dataEncipherment
		{4, decrypt},               // keyAgreement
		{5, sign},                  // keyCertSign
		{6, sign},                  // cRLSign
		{7, decrypt},               // encipherOnly
		{8, decrypt},               // decipherOnly
	}
	for _, rq := range reqs {
		if ku.At(rq.bit) == 1 && !rq.ok {
			return errorResponse(withHandle(RCAttributes, 1))
		}
	}
	return nil
}

// validateX509Extensions enforces the mandatory Key Usage extension and, if a
// TPMA_OBJECT extension is present, that it matches the object exactly.
func validateX509Extensions(exts asn1.RawValue, obj *object) []byte {
	var extList []x509Extension
	if _, err := asn1.Unmarshal(exts.Bytes, &extList); err != nil {
		return errorResponse(withParam(RCValue, 4))
	}
	keyUsageOID := asn1.ObjectIdentifier{2, 5, 29, 15}
	tpmaObjectOID := asn1.ObjectIdentifier{2, 23, 133, 10, 1, 1, 1}
	foundKU := false
	for _, ext := range extList {
		switch {
		case ext.Id.Equal(keyUsageOID):
			foundKU = true
			var ku asn1.BitString
			if _, err := asn1.Unmarshal(ext.Value, &ku); err != nil {
				return errorResponse(withParam(RCValue, 4))
			}
			if errResp := checkKeyUsage(ku, obj.public.Attrs); errResp != nil {
				return errResp
			}
		case ext.Id.Equal(tpmaObjectOID):
			var bs asn1.BitString
			if _, err := asn1.Unmarshal(ext.Value, &bs); err != nil {
				return errorResponse(withParam(RCValue, 4))
			}
			if len(bs.Bytes) != 4 || binary.BigEndian.Uint32(bs.Bytes) != obj.public.Attrs {
				return errorResponse(withHandle(RCAttributes, 1))
			}
		}
	}
	if !foundKU {
		return errorResponse(withParam(RCValue, 4)) // Key Usage is mandatory
	}
	return nil
}

// cmdCertifyX509 implements TPM2_CertifyX509. Handles: objectHandle (certified),
// signHandle (signer) — both authorized.
func (t *TPM) cmdCertifyX509(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCCertifyX509, 2, r)
	if errResp != nil {
		return errResp
	}
	reserved := r.tpm2b()
	scheme, schemeHash := readSigScheme(r)
	partialCert := r.tpm2b()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if len(reserved) != 0 {
		return errorResponse(withParam(RCValue, 1)) // reserved must be an Empty Buffer
	}
	obj, ok := t.objects.get(ac.handles[0])
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	key, ok := t.objects.get(ac.handles[1])
	if !ok {
		return errorResponse(withHandle(RCHandle, 2))
	}
	if key.public.Attrs&ObjSign == 0 {
		return errorResponse(withHandle(RCKey, 2))
	}
	if errResp := t.authorizeObject(ac, 0, obj); errResp != nil {
		return errResp
	}
	if errResp := t.authorizeObject(ac, 1, key); errResp != nil {
		return errResp
	}
	sigAlg, hashAlg := key.public.Scheme.Scheme, key.public.Scheme.HashAlg
	if sigAlg == AlgNull {
		sigAlg, hashAlg = scheme, schemeHash
	}
	if _, ok := cryptoHash(hashAlg); !ok {
		return errorResponse(withParam(RCValue, 2))
	}

	// Parse the partial certificate into its DER elements (4 = no signature
	// algorithm, 5 = caller-supplied signature algorithm).
	var elements []asn1.RawValue
	if _, err := asn1.Unmarshal(partialCert, &elements); err != nil {
		return errorResponse(withParam(RCValue, 4))
	}
	if len(elements) != 4 && len(elements) != 5 {
		return errorResponse(withParam(RCValue, 4))
	}
	hasSigAlg := len(elements) == 5
	var callerSigAlg, issuer, validity, subject, exts asn1.RawValue
	if hasSigAlg {
		callerSigAlg, issuer, validity, subject, exts = elements[0], elements[1], elements[2], elements[3], elements[4]
	} else {
		issuer, validity, subject, exts = elements[0], elements[1], elements[2], elements[3]
	}
	if errResp := validateX509Extensions(exts, obj); errResp != nil {
		return errResp
	}

	// TPM-created fields: version [0]=v3, serial number, subjectPublicKeyInfo,
	// and the signature algorithm when the caller did not supply it.
	pub, ok := objectPublicKey(obj)
	if !ok {
		return errorResponse(withHandle(RCType, 1))
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return errorResponse(withHandle(RCType, 1))
	}
	version := []byte{0xA0, 0x03, 0x02, 0x01, 0x02} // [0] EXPLICIT INTEGER 2 (v3)
	serial, _ := asn1.Marshal(new(big.Int).SetBytes(hashSum(AlgSHA256, obj.name)[:16]))

	sigAlgDER := callerSigAlg.FullBytes
	if !hasSigAlg {
		sigAlgDER, ok = sigAlgIdentifier(sigAlg, hashAlg)
		if !ok {
			return errorResponse(RCScheme)
		}
	}

	// Assemble the full TBSCertificate in RFC 5280 §4.1 order and sign it.
	var tbs []byte
	tbs = append(tbs, version...)
	tbs = append(tbs, serial...)
	tbs = append(tbs, sigAlgDER...)
	tbs = append(tbs, issuer.FullBytes...)
	tbs = append(tbs, validity.FullBytes...)
	tbs = append(tbs, subject.FullBytes...)
	tbs = append(tbs, spki...)
	tbs = append(tbs, exts.FullBytes...)
	tbsCert := derSeq(tbs)
	tbsDigest := hashSum(hashAlg, tbsCert)

	sig, errResp := t.signWith(key, sigAlg, hashAlg, tbsDigest)
	if errResp != nil {
		return errResp
	}

	// addedToCertificate: version, serial, [signature algorithm if TPM-created],
	// subjectPublicKeyInfo (Part 3, §18.8).
	var added []byte
	added = append(added, version...)
	added = append(added, serial...)
	if !hasSigAlg {
		added = append(added, sigAlgDER...)
	}
	added = append(added, spki...)

	var w writer
	w.tpm2b(derSeq(added)) // addedToCertificate (TPM2B_MAX_BUFFER)
	w.tpm2b(tbsDigest)     // tbsDigest (TPM2B_DIGEST)
	w.raw(sig)             // signature (TPMT_SIGNATURE)
	return t.authResponse(ac, nil, w.bytes())
}
