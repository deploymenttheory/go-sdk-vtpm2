// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

// Package swtpm implements the swtpm control + data channel protocol that
// QEMU's tpm-emulator backend speaks, backed by an in-process TPM 2.0 command
// processor. It is wire-compatible with stefanberger/swtpm's socket interface
// (see QEMU backends/tpm/tpm_emulator.c and swtpm include/swtpm/tpm_ioctl.h):
// the control channel is a Unix stream socket carrying a 4-byte big-endian
// command code followed by that command's request struct; the data channel —
// whose fd QEMU passes via SCM_RIGHTS in CMD_SET_DATAFD — carries raw TPM 2.0
// command and response blobs.
package swtpm

// Control command codes (CMD_*), sent as the first 4 bytes (big-endian) of each
// control request. Values match swtpm's tpm_ioctl.h.
const (
	cmdGetCapability       uint32 = 1
	cmdInit                uint32 = 2
	cmdShutdown            uint32 = 3
	cmdGetTPMEstablished   uint32 = 4
	cmdSetLocality         uint32 = 5
	cmdHashStart           uint32 = 6
	cmdHashData            uint32 = 7
	cmdHashEnd             uint32 = 8
	cmdCancelTPMCmd        uint32 = 9
	cmdStoreVolatile       uint32 = 10
	cmdResetTPMEstablished uint32 = 11
	cmdGetStateBlob        uint32 = 12
	cmdSetStateBlob        uint32 = 13
	cmdStop                uint32 = 14
	cmdGetConfig           uint32 = 15
	cmdSetDataFD           uint32 = 16
	cmdSetBufferSize       uint32 = 17
	cmdGetInfo             uint32 = 18
	cmdLockStorage         uint32 = 19
)

// Capability bits (PTM_CAP_*) reported by CMD_GET_CAPABILITY.
const (
	capInit                uint32 = 1
	capShutdown            uint32 = 1 << 1
	capGetTPMEstablished   uint32 = 1 << 2
	capSetLocality         uint32 = 1 << 3
	capHashing             uint32 = 1 << 4
	capCancelTPMCmd        uint32 = 1 << 5
	capStoreVolatile       uint32 = 1 << 6
	capResetTPMEstablished uint32 = 1 << 7
	capGetStateBlob        uint32 = 1 << 8
	capSetStateBlob        uint32 = 1 << 9
	capStop                uint32 = 1 << 10
	capGetConfig           uint32 = 1 << 11
	capSetDataFD           uint32 = 1 << 12
	capSetBufferSize       uint32 = 1 << 13
	capGetInfo             uint32 = 1 << 14
)

// advertisedCaps is the capability mask the server reports. It covers every
// control command the server implements and is a superset of QEMU's TPM 2.0
// requirement (INIT, SHUTDOWN, GET_TPMESTABLISHED, SET_LOCALITY, SET_DATAFD,
// STOP, SET_BUFFERSIZE, RESET_TPMESTABLISHED). It also advertises state-blob
// save/restore so QEMU can persist and migrate the vTPM.
const advertisedCaps = capInit | capShutdown | capGetTPMEstablished |
	capSetLocality | capCancelTPMCmd | capStoreVolatile | capResetTPMEstablished |
	capGetStateBlob | capSetStateBlob |
	capStop | capGetConfig | capSetDataFD | capSetBufferSize | capGetInfo

// State-blob types (PTM_BLOB_TYPE) in CMD_GET_STATEBLOB / CMD_SET_STATEBLOB. The
// emulator keeps a single combined snapshot, returned as the "permanent" blob.
const (
	blobPermanent uint32 = 1
	blobVolatile  uint32 = 2
	blobSaveState uint32 = 3
)

// maxStateChunk caps a single GET/SET_STATEBLOB chunk so a large state blob can
// be transferred over several control messages. A SET chunk shorter than this is
// the final one, so the accumulated blob is then loaded.
const maxStateChunk = 4096

// ptm result codes. ptmSuccess (0) means the control command succeeded;
// ptmBadInput flags a malformed request.
const (
	ptmSuccess  uint32 = 0
	ptmBadInput uint32 = 0x00000003 // TPM_RC_BAD_PARAMETER-ish; nonzero = failure
)

// ptmInitFlagDeleteVolatile is PTM_INIT_FLAG_DELETE_VOLATILE in a CMD_INIT
// request's init_flags.
const ptmInitFlagDeleteVolatile uint32 = 1

// tpmCmdHeaderLen is the fixed TPM 2.0 command/response header length
// (tag 2 + size 4 + code 4); the size field at offset 2 delimits a data-channel
// frame.
const tpmCmdHeaderLen = 10
