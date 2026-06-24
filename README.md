# go-sdk-vtpm2

**A pure-Go TPM 2.0 — no cgo, no `swtpm`, no `libtpms`.**

`go-sdk-vtpm2` is a TPM 2.0 device implemented from scratch in Go: the command
processor, the cryptography, the state persistence, and the QEMU transport — all
built directly from the [TCG TPM 2.0 Library
Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/),
with no external (non-Go) dependencies and no cgo.

It gives a hypervisor a **virtual TPM for Windows 11 guests** — measured boot,
BitLocker sealing, and attestation — that you `go build` into a single static
binary, instead of shipping and managing a native service like `swtpm` or
`libtpms`. It speaks the swtpm control/data protocol, so QEMU's `tpm-emulator`
backend connects to it unmodified.

This is the **TPM itself** (the responder that executes commands), not a client
library, driver, or set of bindings. The entire public surface of the core is:

```go
func (t *tpm2.TPM) Execute(command []byte) (response []byte)
```

Raw TPM command blob in, raw response blob out.

## Why it exists / design targets

| Target | What it means |
|---|---|
| **Zero native dependencies** | Pure Go. No cgo, no `swtpm`/`libtpms` binaries, no Homebrew. One `go build` produces a static, cross-compilable binary. |
| **Embeddable, transport-agnostic core** | The command processor is just `Execute([]byte) []byte`. Drop it behind QEMU, a unit test, a fuzzer, or your own transport. |
| **swtpm / QEMU wire-compatible** | Implements the swtpm control + data channels (incl. `SET_DATAFD`, state-blob save/restore, locality), so QEMU's `-tpmdev emulator` is a drop-in. |
| **Reboot-persistent** | Versioned snapshots persist the EK/SRK, NV, PCRs, and clock. Sealed secrets (the BitLocker VMK) survive guest reboots — the requirement that makes a vTPM actually usable. |
| **Spec-correct** | Every command code and response code is checked against the reference implementation. The HMAC/`cpHash` authorization path is validated against golden vectors. Format-one response codes are encoded correctly (a class of bug a lot of toy TPMs get wrong). |

The whole build is sequenced toward one concrete goal: **a real Windows 11 guest
booting with BitLocker** against this vTPM under QEMU.

## What it implements

**52 TPM 2.0 commands**, covering the full Windows 11 / BitLocker path:

| Area | Commands |
|---|---|
| **Boot & test** | `Startup`, `Shutdown`, `SelfTest`, `GetTestResult`, `GetRandom`, `StirRandom` |
| **Capabilities** | `GetCapability` (algorithms, commands, handles, PCRs, TPM properties) |
| **Measured boot (PCR)** | `PCR_Read`, `PCR_Extend`, `PCR_Reset` — SHA-1 + SHA-256 banks, 24 PCRs, locality-enforced |
| **Hierarchies** | `Clear`, `ClearControl`, `HierarchyChangeAuth`, `HierarchyControl`, `SetPrimaryPolicy`, `ChangeEPS`, `ChangePPS` |
| **Sessions & policy** | `StartAuthSession`, `FlushContext`, `PolicyPCR`, `PolicyCommandCode`, `PolicyAuthValue`, `PolicyOR`, `PolicyGetDigest`, `PolicyRestart` |
| **Dictionary attack** | `DictionaryAttackLockReset`, `DictionaryAttackParameters` |
| **Objects & keys** | `CreatePrimary`, `Create`, `Load`, `LoadExternal`, `ReadPublic`, `EvictControl`, `ObjectChangeAuth`, `ContextSave`, `ContextLoad` |
| **Sealing & signing** | `Unseal`, `Sign`, `VerifySignature`, `Hash`, `Quote` |
| **NV storage** | `NV_DefineSpace`, `NV_UndefineSpace`, `NV_ReadPublic`, `NV_Read`, `NV_Write`, `NV_Increment`, `NV_Extend`, `NV_SetBits`, `NV_ReadLock`, `NV_WriteLock` |
| **Clock** | `ReadClock` |

**Authorization:** password, HMAC, and policy sessions, with real HMAC
verify/respond and **parameter encryption in both directions** (XOR and AES-CFB).

**Cryptography (Go standard library only):** RSA (2048-bit; RSASSA / RSA-PSS),
ECC (NIST P-256 / P-384; ECDSA / ECDH), AES-CFB, HMAC, SHA-1/256/384/512, and the
TPM key-derivation functions KDFa / KDFe. Primary keys (EK/SRK) are **derived
deterministically** from the hierarchy seed, so a recreated SRK matches its
persisted form and previously sealed blobs still load.

## Architecture

| Package | Responsibility |
|---|---|
| `tpm2/` | The TPM 2.0 command processor: wire types & marshalling, the command dispatch, the crypto, the auth/session engine, and versioned state snapshots. `Execute([]byte) []byte`. |
| `state/` | Atomic, per-VM persistence of a snapshot to disk (JSON, crash-safe temp-file + rename). |
| `swtpm/` | The swtpm control + data channel protocol QEMU's `tpm-emulator` backend speaks (Unix sockets, fd passing, state blobs, locality). |
| `emulator/` | Top-level wiring: TPM + persistence + transport into one runnable device, plus `Provision()`. |
| `cmd/vtpm/` | A runnable vTPM server you point QEMU at. |

## Usage

### Embed the core

```go
tpm := tpm2.New()
response := tpm.Execute(command) // raw TPM 2.0 command → raw response
```

### Run it for QEMU

```sh
go build -o ./vtpm ./cmd/vtpm
./vtpm -ctrl /tmp/vtpm-ctrl.sock -state ./vtpm-state -provision
```

Then point QEMU at the control socket:

```sh
qemu-system-x86_64 \
  -chardev socket,id=chrtpm,path=/tmp/vtpm-ctrl.sock \
  -tpmdev emulator,id=tpm0,chardev=chrtpm \
  -device tpm-tis,tpmdev=tpm0 \
  ...
```

See [`docs/windows11-qemu.md`](docs/windows11-qemu.md) for the full Windows 11 +
BitLocker boot harness.

## Persistence

State is snapshotted to a per-VM directory and reloaded on the next boot, so the
vTPM — and everything sealed against it — survives guest reboots. The snapshot is
versioned and migrates forward; it currently carries PCR banks, the authorization
hierarchies and their primary seeds, dictionary-attack lockout state, persistent
objects (EK/SRK), NV indices, and the clock.

## Correctness

- Command and response codes are validated against a maintained reference TPM 2.0
  implementation.
- The `cpHash` / authorization-HMAC path — the most interoperability-sensitive
  part — is checked two ways: against an independent in-test reimplementation, and
  against optional golden vectors captured from a real TPM stack (see
  `tpm2/testdata/`).
- The headline reboot guarantee is tested end to end
  (`tpm2/seal_test.go:TestSealedObjectSurvivesReboot`): seal a secret under a
  persistent SRK, snapshot, restore into a fresh TPM, and unseal it.

`go test ./...` exercises the full surface.

## Status & limitations

The TPM core, the swtpm/QEMU transport, and provisioning are implemented and
tested. Honest caveats:

- **Software TPM, not a hardware security boundary.** State lives in host memory
  and on-disk snapshots. This provides the TPM 2.0 *protocol and semantics*, not
  hardware-grade isolation or tamper resistance.
- **The live Windows-11-on-QEMU boot is not yet verified** — that step needs a
  real QEMU + Windows 11 environment. The runner, launch script, and harness are
  ready for it (`cmd/vtpm`, `scripts/`, `docs/windows11-qemu.md`).
- **A focused subset of the spec**, not 100% of TPM 2.0 — the boot/BitLocker path
  is complete; areas like duplication/migration of keys, audit sessions, and the
  full algorithm set are out of scope for now.

## License

MIT — see [`LICENSE`](LICENSE). This is a clean-room implementation written from
the public TCG TPM 2.0 Library Specification; it contains no code from, and is not
derived from, any GPL-licensed TPM implementation.
