# Phase 6 — Windows 11 on QEMU end-to-end harness

> **Status: UNVERIFIED.** Steps 1–3 of Phase 6 (the in-repo transport,
> provisioning, and unit tests) are implemented and passing. Step 4 — actually
> booting Windows 11 — has **not** been run, because a working QEMU + Windows 11
> environment is not available yet. Everything below is the harness to execute
> once it is. Treat each step as *expected*, not *confirmed*.

## What's in the repo (tested)

| Piece | Location | Tested |
|---|---|---|
| swtpm `GET/SET_STATEBLOB`, locality tracking | `swtpm/server.go` | ✅ control round-trip |
| State serialization | `tpm2/stateblob.go` (`StateBlob`/`LoadStateBlob`) | ✅ round-trip via real TPM |
| SRK provisioning | `emulator/provision.go` (`Emulator.Provision`) | ✅ create + persist + reboot |
| Runnable vTPM server | `cmd/vtpm` | builds |
| QEMU launch script | `scripts/boot-windows11.sh` | — (needs the environment) |

## Run it

```sh
go build -o ./vtpm ./cmd/vtpm
ISO=/path/to/Win11.iso ./scripts/boot-windows11.sh
```

The script starts `cmd/vtpm` (which provisions an SRK and persists state under
`./vtpm-state`), waits for its control socket, then launches QEMU with
`-tpmdev emulator,chardev=...` pointed at that socket and a Q35 + Secure-Boot
machine Windows 11 requires.

## How QEMU talks to this vTPM

QEMU's `tpm-emulator` backend speaks the swtpm control/data protocol:

1. Connects to the control socket (`-chardev socket,path=…`).
2. Probes with `CMD_GET_CAPABILITY`, sizes with `CMD_SET_BUFFERSIZE`,
   `CMD_INIT`s the device.
3. Passes a data-channel fd via `CMD_SET_DATAFD` (SCM_RIGHTS); raw TPM 2.0
   command/response blobs flow over it (`swtpm.Server.serveData` →
   `tpm2.TPM.Execute`).
4. On save/migrate, pulls the full state via `CMD_GET_STATEBLOB` and pushes it
   back with `CMD_SET_STATEBLOB` — these now map to `tpm2.TPM.StateBlob` /
   `LoadStateBlob`.

## The validation, end to end

1. **Provision** — `Provision()` creates the SRK at `0x81000001` and persists it.
2. **Measured boot** — Windows/UEFI extends PCRs (`TPM2_PCR_Extend`); the vTPM
   keeps the SHA-1/SHA-256 banks.
3. **Seal** — BitLocker seals the Volume Master Key under the SRK to a PCR policy
   (`TPM2_Create` → `TPM2_Load`), bound to the boot measurements.
4. **Reboot** — re-run the script. `STATE_DIR` reloads the persisted snapshot
   (SRK + NV + PCRs + clock).
5. **Unseal** — BitLocker satisfies its policy and `TPM2_Unseal`s the VMK; the
   volume auto-unlocks.

**PASS** = the volume unlocks after reboot without a recovery key.

This works only because three things compose, all unit-tested in this repo:
deterministic SRK derivation from the persisted seed, full persistent-object
persistence (the SRK survives reboot with its private key), and seed-keyed object
wrapping (the sealed blob unwraps under the recreated/persisted parent). See
`tpm2/seal_test.go:TestSealedObjectSurvivesReboot`.

## When it doesn't work

Add tracing around `tpm2.TPM.Execute` to log every `(commandCode, responseCode)`
the guest issues — the first non-success response pinpoints the gap. Likely
suspects, in order:

- A command the guest needs that isn't dispatched yet (returns
  `TPM_RC_COMMAND_CODE`) — check against the `commandTable` in `tpm2/capability.go`.
- A `TPM_PT` property Windows reads at startup that we don't report.

Parameter encryption (both directions), state-blob chunking, and PCR locality
enforcement (`TPM_RC_LOCALITY`, plus `TPM2_PCR_Reset`) are now implemented, so
those are no longer expected gaps. The one place chunking is best-effort is a
state blob whose size is an exact multiple of the 4 KiB chunk — a trailing short
or zero-length `SET_STATEBLOB` chunk is then relied on to finalize the transfer.
