// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package emulator

import (
	"encoding/binary"
	"fmt"

	"github.com/deploymenttheory/go-sdk-vtpm2/tpm2"
)

// SRKHandle is the conventional persistent handle of the Storage Root Key.
const SRKHandle uint32 = 0x81000001

// Provision pre-creates and persists a Storage Root Key at SRKHandle, the way a
// platform manufacturer provisions a TPM before first OS boot. A guest that
// expects the SRK to already exist (rather than creating its own) finds it ready.
// Provisioning is idempotent: if the SRK handle is already populated it is left
// in place. Persisted state is saved if a state directory was configured.
func (e *Emulator) Provision() error {
	if err := e.startup(); err != nil {
		return err
	}
	if e.handlePopulated(SRKHandle) {
		return nil // already provisioned
	}
	transient, err := e.createPrimarySRK()
	if err != nil {
		return err
	}
	if err := e.evict(transient, SRKHandle); err != nil {
		return err
	}
	e.flush(transient)
	e.persist()
	return nil
}

// startup issues TPM2_Startup(CLEAR) and ignores an already-started TPM.
func (e *Emulator) startup() error {
	su := binary.BigEndian.AppendUint16(nil, tpm2.SUClear)
	resp := e.tpm.Execute(buildCmd(tpm2.TPMSTNoSessions, tpm2.CCStartup, su))
	if rc := respCode(resp); rc != tpm2.RCSuccess && rc != tpm2.RCInitialize {
		return fmt.Errorf("emulator: Startup failed: rc 0x%x", rc)
	}
	return nil
}

// handlePopulated reports whether TPM2_ReadPublic succeeds for a handle.
func (e *Emulator) handlePopulated(handle uint32) bool {
	resp := e.tpm.Execute(buildCmd(tpm2.TPMSTNoSessions, tpm2.CCReadPublic, be32(handle)))
	return respCode(resp) == tpm2.RCSuccess
}

// createPrimarySRK runs TPM2_CreatePrimary under the owner hierarchy with the
// standard ECC-P256 storage template and returns the transient object handle.
func (e *Emulator) createPrimarySRK() (uint32, error) {
	inSensitive := append(tpm2b(nil), tpm2b(nil)...) // userAuth ‖ data, both empty

	var params []byte
	params = append(params, tpm2b(inSensitive)...)   // inSensitive (TPM2B_SENSITIVE_CREATE)
	params = append(params, tpm2b(srkTemplate())...) // inPublic
	params = append(params, tpm2b(nil)...)           // outsideInfo
	params = append(params, be32(0)...)              // creationPCR (empty)

	resp := e.tpm.Execute(buildAuthCmd(tpm2.CCCreatePrimary, tpm2.RHOwner, params))
	if rc := respCode(resp); rc != tpm2.RCSuccess {
		return 0, fmt.Errorf("emulator: CreatePrimary failed: rc 0x%x", rc)
	}
	if len(resp) < 14 {
		return 0, fmt.Errorf("emulator: short CreatePrimary response")
	}
	return binary.BigEndian.Uint32(resp[10:14]), nil // objectHandle in the response handle area
}

// evict runs TPM2_EvictControl to persist a transient object at persistentHandle.
func (e *Emulator) evict(transient, persistentHandle uint32) error {
	var body []byte
	body = append(body, be32(tpm2.RHOwner)...) // authHandle
	body = append(body, be32(transient)...)    // objectHandle
	body = append(body, pwAuthArea()...)
	body = append(body, be32(persistentHandle)...)
	resp := e.tpm.Execute(buildCmd(tpm2.TPMSTSessions, tpm2.CCEvictControl, body))
	if rc := respCode(resp); rc != tpm2.RCSuccess {
		return fmt.Errorf("emulator: EvictControl failed: rc 0x%x", rc)
	}
	return nil
}

// flush runs TPM2_FlushContext for a transient handle (best effort).
func (e *Emulator) flush(handle uint32) {
	e.tpm.Execute(buildCmd(tpm2.TPMSTNoSessions, tpm2.CCFlushContext, be32(handle)))
}

// srkTemplate is the TPMT_PUBLIC of a restricted ECC-P256 storage (root) key.
func srkTemplate() []byte {
	attrs := tpm2.ObjFixedTPM | tpm2.ObjFixedParent | tpm2.ObjSensitiveDataOrigin |
		tpm2.ObjUserWithAuth | tpm2.ObjNoDA | tpm2.ObjRestricted | tpm2.ObjDecrypt
	var b []byte
	b = append(b, be16(tpm2.AlgECC)...)
	b = append(b, be16(tpm2.AlgSHA256)...)
	b = append(b, be32(attrs)...)
	b = append(b, tpm2b(nil)...)         // authPolicy
	b = append(b, be16(tpm2.AlgAES)...)  // symmetric.algorithm
	b = append(b, be16(128)...)          // symmetric.keyBits
	b = append(b, be16(tpm2.AlgCFB)...)  // symmetric.mode
	b = append(b, be16(tpm2.AlgNull)...) // scheme
	b = append(b, be16(tpm2.ECCNistP256)...)
	b = append(b, be16(tpm2.AlgNull)...) // kdf
	b = append(b, tpm2b(nil)...)         // unique.x
	b = append(b, tpm2b(nil)...)         // unique.y
	return b
}

// --- small command-building helpers ---

func buildCmd(tag uint16, code uint32, params []byte) []byte {
	out := make([]byte, 10)
	binary.BigEndian.PutUint16(out[0:], tag)
	binary.BigEndian.PutUint32(out[2:], uint32(10+len(params)))
	binary.BigEndian.PutUint32(out[6:], code)
	return append(out, params...)
}

// buildAuthCmd frames a single-handle command with one empty password session.
func buildAuthCmd(code, handle uint32, params []byte) []byte {
	body := append(be32(handle), pwAuthArea()...)
	body = append(body, params...)
	return buildCmd(tpm2.TPMSTSessions, code, body)
}

// pwAuthArea is an authorization area with one empty TPM_RS_PW session.
func pwAuthArea() []byte {
	var sess []byte
	sess = append(sess, be32(tpm2.RHPW)...) // sessionHandle
	sess = append(sess, be16(0)...)         // nonce
	sess = append(sess, 0x00)               // attributes
	sess = append(sess, be16(0)...)         // hmac
	return append(be32(uint32(len(sess))), sess...)
}

func be16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }
func be32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

// tpm2b wraps b in a UINT16 size prefix (a marshalled TPM2B_* field).
func tpm2b(b []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...)
}

func respCode(resp []byte) uint32 {
	if len(resp) < 10 {
		return tpm2.RCFailure
	}
	return binary.BigEndian.Uint32(resp[6:10])
}
