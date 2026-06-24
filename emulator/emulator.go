// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

// Package emulator ties the TPM 2.0 command processor, on-disk state, and the
// swtpm control/data channels into a single object a hypervisor can start
// alongside a VM. It is the package weave's QEMU backend consumes.
package emulator

import (
	"github.com/deploymenttheory/go-sdk-vtpm2/state"
	"github.com/deploymenttheory/go-sdk-vtpm2/swtpm"
	"github.com/deploymenttheory/go-sdk-vtpm2/tpm2"
)

// Emulator is a running (or runnable) software TPM 2.0 exposed on a swtpm
// control socket. Construct one with New, then Start it before launching QEMU
// against ControlSocket, and Close it when the VM stops.
type Emulator struct {
	ctrlPath string
	tpm      *tpm2.TPM
	store    *state.Store // nil when no state directory was given
	srv      *swtpm.Server
}

// New builds an emulator that will host its swtpm control socket at ctrlPath.
// When stateDir is non-empty the TPM's state is loaded from (and persisted to)
// that directory, so the vTPM — and anything sealed against it — survives guest
// reboots; an empty stateDir yields an ephemeral TPM.
func New(ctrlPath, stateDir string) (*Emulator, error) {
	e := &Emulator{ctrlPath: ctrlPath, tpm: tpm2.New()}

	if stateDir != "" {
		store, err := state.NewStore(stateDir)
		if err != nil {
			return nil, err
		}
		if _, err := store.LoadInto(e.tpm); err != nil {
			return nil, err
		}
		e.store = store
	}

	e.srv = swtpm.NewServer(ctrlPath, e.tpm, e.persist)
	return e, nil
}

// Start binds the control socket and begins serving in the background.
func (e *Emulator) Start() error { return e.srv.Start() }

// Close persists state (if a state directory was configured) and tears down the
// control and data channels.
func (e *Emulator) Close() error {
	e.persist()
	return e.srv.Close()
}

// ControlSocket is the path QEMU's tpm-emulator chardev connects to.
func (e *Emulator) ControlSocket() string { return e.ctrlPath }

// persist snapshots the TPM to disk when state persistence is enabled. Errors
// are intentionally swallowed: a failed snapshot must not abort guest shutdown.
func (e *Emulator) persist() {
	if e.store == nil {
		return
	}
	_ = e.store.Save(e.tpm.Snapshot())
}
