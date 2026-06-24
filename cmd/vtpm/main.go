// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

// Command vtpm runs the software TPM 2.0 emulator on a swtpm-compatible control
// socket, the way a hypervisor frontend would host it alongside a VM. Point
// QEMU's tpm-emulator chardev at the control socket (see docs/windows11-qemu.md).
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/deploymenttheory/go-sdk-vtpm2/emulator"
)

func main() {
	ctrl := flag.String("ctrl", "/tmp/vtpm-ctrl.sock", "swtpm control socket path")
	stateDir := flag.String("state", "", "state directory (empty = ephemeral, no persistence)")
	provision := flag.Bool("provision", false, "pre-create and persist a Storage Root Key (0x81000001)")
	flag.Parse()

	e, err := emulator.New(*ctrl, *stateDir)
	if err != nil {
		log.Fatalf("vtpm: %v", err)
	}
	if *provision {
		if err := e.Provision(); err != nil {
			log.Fatalf("vtpm: provision: %v", err)
		}
		log.Printf("vtpm: provisioned SRK at 0x%08x", emulator.SRKHandle)
	}
	if err := e.Start(); err != nil {
		log.Fatalf("vtpm: start: %v", err)
	}
	log.Printf("vtpm: control socket %s (state=%q)", e.ControlSocket(), *stateDir)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Printf("vtpm: shutting down, persisting state")
	_ = e.Close()
}
