#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# boot-windows11.sh — launch a Windows 11 guest under QEMU backed by the go-sdk
# vTPM, for the Phase 6 end-to-end validation (provision → measured boot →
# BitLocker seal → reboot → auto-unlock).
#
# STATUS: UNVERIFIED. This has not been run against a real QEMU + Windows 11
# environment yet. It is the harness to execute once that environment exists.
# Treat every step as "expected", not "confirmed".
#
# Requirements on the host:
#   - qemu-system-x86_64 (>= 8.x), with UEFI (OVMF) + Secure Boot firmware
#   - a Windows 11 install ISO (Win11_*.iso)
#   - this module built: `go build -o ./vtpm ./cmd/vtpm`
set -euo pipefail

VTPM_BIN=${VTPM_BIN:-./vtpm}
CTRL_SOCK=${CTRL_SOCK:-/tmp/vtpm-ctrl.sock}
STATE_DIR=${STATE_DIR:-./vtpm-state}
DISK=${DISK:-./win11.qcow2}
ISO=${ISO:?set ISO=/path/to/Win11.iso}
OVMF_CODE=${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE.secboot.fd}
OVMF_VARS_SRC=${OVMF_VARS_SRC:-/usr/share/OVMF/OVMF_VARS.fd}
OVMF_VARS=${OVMF_VARS:-./OVMF_VARS.local.fd}

mkdir -p "$STATE_DIR"
[ -f "$DISK" ]      || qemu-img create -f qcow2 "$DISK" 64G
[ -f "$OVMF_VARS" ] || cp "$OVMF_VARS_SRC" "$OVMF_VARS"

# 1. Start the vTPM (provisions an SRK on first run; state persists in STATE_DIR).
"$VTPM_BIN" -ctrl "$CTRL_SOCK" -state "$STATE_DIR" -provision &
VTPM_PID=$!
trap 'kill "$VTPM_PID" 2>/dev/null || true' EXIT
# Wait for the control socket to appear.
for _ in $(seq 1 50); do [ -S "$CTRL_SOCK" ] && break; sleep 0.1; done

# 2. Boot Windows 11. Q35 + SMM + Secure Boot + the emulator-backed TPM 2.0.
qemu-system-x86_64 \
  -machine q35,smm=on,accel=kvm \
  -cpu host -smp 4 -m 8192 \
  -global driver=cfi.pflash01,property=secure,value=on \
  -drive if=pflash,format=raw,unit=0,file="$OVMF_CODE",readonly=on \
  -drive if=pflash,format=raw,unit=1,file="$OVMF_VARS" \
  -chardev socket,id=chrtpm,path="$CTRL_SOCK" \
  -tpmdev emulator,id=tpm0,chardev=chrtpm \
  -device tpm-tis,tpmdev=tpm0 \
  -drive file="$DISK",if=virtio,format=qcow2 \
  -drive file="$ISO",media=cdrom \
  -boot menu=on \
  -device virtio-net,netdev=n0 -netdev user,id=n0 \
  -vga virtio -display gtk

# 3. (Manual, inside Windows) Install Windows 11; it will report a TPM 2.0
#    present. Then enable BitLocker with a TPM-only protector:
#      manage-bde -on C: -TPMAndPIN-  (or the BitLocker control panel)
#
# 4. Reboot the guest (re-run this script — STATE_DIR persists the vTPM).
#    PASS criterion: the volume auto-unlocks without a recovery key, proving the
#    sealed VMK survived the reboot (deterministic SRK + persistent state +
#    seed-keyed wrapping all holding across a power cycle).
#
# To capture the command trace the guest issues (to close any remaining gaps),
# run the vTPM under a logger or add tracing around tpm2.TPM.Execute.
