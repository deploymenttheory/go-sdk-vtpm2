// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

// Package vtpm2 is a software TPM 2.0 device implemented from scratch in Go,
// built directly from the TCG TPM 2.0 Library Specification with no external
// (non-Go) dependencies and no cgo — in particular no swtpm, libtpms, or
// Homebrew. It gives a hypervisor a virtual TPM that a Windows 11 guest can use
// for measured boot, BitLocker sealing, and attestation, shipped as a single
// static binary.
//
// The command processor is transport-agnostic: tpm2.TPM.Execute([]byte) []byte
// turns a raw TPM 2.0 command blob into a raw response blob. It implements the
// Windows 11 / BitLocker command set — hierarchies, password/HMAC/policy
// sessions with parameter encryption, dictionary-attack lockout, object and key
// management (RSA/ECC), sealing/unsealing, NV storage, signing and attestation,
// PCR/measured boot, and the clock — with all cryptography drawn from the Go
// standard library (crypto/rsa, crypto/ecdsa, crypto/aes, crypto/hmac,
// crypto/sha*, crypto/rand). State is snapshotted so the TPM, and everything
// sealed against it, survives guest reboots.
//
// Layout:
//
//   - tpm2/     the TPM 2.0 command processor: wire types, marshalling, command
//     dispatch, handlers, cryptography, the session/authorization engine, and
//     versioned state snapshots. Execute([]byte) []byte.
//   - state/    atomic, per-VM persistence of a snapshot to disk.
//   - swtpm/    the swtpm control + data channel protocol QEMU's tpm-emulator
//     backend speaks (Unix sockets, fd passing, state blobs, locality).
//   - emulator/ top-level wiring of the TPM, persistence, and transport into one
//     runnable device, plus Provision().
//   - cmd/vtpm/ a runnable vTPM server to point QEMU at.
//
// The intended consumer is a hypervisor frontend (e.g. guestweave's QEMU
// backend) that needs a TPM 2.0 device for Windows 11 guests without shipping a
// native swtpm binary.
package vtpm2
