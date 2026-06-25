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

**125 TPM 2.0 commands** — essentially the full v1.85 surface a software TPM can
meaningfully implement (the 11 unimplemented are firmware-upgrade, Attached-Component
and a couple of v2 NV/capability variants that need physical hardware; the dispatcher
returns `TPM_RC_COMMAND_CODE` for those, as the spec prescribes):

| Area | Commands |
|---|---|
| **Boot & test** | `Startup`, `Shutdown`, `SelfTest`, `IncrementalSelfTest`, `GetTestResult`, `GetRandom`, `StirRandom`, `TestParms` |
| **Capabilities & management** | `GetCapability`, `SetAlgorithmSet`, `PP_Commands`, `SetCommandCodeAuditStatus`, `ReadOnlyControl`, `ACT_SetTimeout` |
| **Measured boot (PCR)** | `PCR_Read`, `PCR_Extend`, `PCR_Event`, `PCR_Reset`, `PCR_Allocate`, `PCR_SetAuthValue`, `PCR_SetAuthPolicy` |
| **Hierarchies & clock** | `Clear`, `ClearControl`, `HierarchyChangeAuth`, `HierarchyControl`, `SetPrimaryPolicy`, `ChangeEPS`, `ChangePPS`, `ReadClock`, `ClockSet`, `ClockRateAdjust` |
| **Sessions & DA** | `StartAuthSession`, `FlushContext`, `DictionaryAttackLockReset`, `DictionaryAttackParameters` |
| **Policy (full set)** | all ~23 assertions — `PolicyPCR`, `PolicyOR`, `PolicyAuthValue`/`Password`, `PolicySecret`, `PolicySigned`, `PolicyAuthorize`(`NV`), `PolicyCommandCode`, `PolicyCpHash`, `PolicyNameHash`, `PolicyNV`, `PolicyCounterTimer`, `PolicyTicket`, `PolicyDuplicationSelect`, `PolicyTemplate`, `PolicyParameters`, `PolicyCapability`, `PolicyTransportSPDM`, … |
| **Objects & key lifecycle** | `CreatePrimary`, `Create`, `CreateLoaded`, `Load`, `LoadExternal`, `ReadPublic`, `EvictControl`, `ObjectChangeAuth`, `ContextSave`, `ContextLoad` |
| **Duplication & credentials** | `Duplicate`, `Import`, `Rewrap`, `MakeCredential`, `ActivateCredential` |
| **Signing, hashing & attestation** | `Sign`, `SignDigest`, `VerifySignature`, `VerifyDigestSignature`, sign/verify **sequences**, `Hash`, `HMAC`, hash sequences, `Quote`, `Certify`, `CertifyCreation`, `CertifyX509`, `GetTime`, `NV_Certify`, `GetSessionAuditDigest`, `GetCommandAuditDigest`, `Unseal` |
| **Asymmetric & symmetric crypto** | `RSA_Encrypt`/`Decrypt`, `ECC_Encrypt`/`Decrypt`, `ECDH_KeyGen`/`ZGen`, `ZGen_2Phase`, `Commit`, `EC_Ephemeral`, `Encapsulate`/`Decapsulate`, `EncryptDecrypt`/`2`, `ECC_Parameters` |
| **NV storage** | `NV_DefineSpace`, `NV_UndefineSpace`(`Special`), `NV_ReadPublic`, `NV_Read`, `NV_Write`, `NV_Increment`, `NV_Extend`, `NV_SetBits`, `NV_ReadLock`/`WriteLock`, `NV_GlobalWriteLock`, `NV_ChangeAuth` |

**Authorization:** password, HMAC, and policy sessions with real HMAC
verify/respond, salted and bound sessions, **parameter encryption in both
directions** (XOR and AES-CFB), and session + command **audit**.

**Cryptography (Go standard library only):** RSA (RSASSA / RSA-PSS / OAEP),
ECC (NIST P-256 / P-384 / P-521; ECDSA / ECDH / ECDAA commit / SM2-style
encryption / KEM), AES in CFB/OFB/CTR/CBC/ECB, HMAC, SHA-1/256/384/512, and the
TPM key-derivation functions KDFa / KDFe, with the SP800-90A Hash_DRBG used for
deterministic primary derivation. Primary keys (EK/SRK) are **derived
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

### Guides

- **[Getting started](docs/getting-started.md)** — install, build, run, and send
  your first command in a few minutes.
- **[Usage guide](docs/usage-guide.md)** — embedding the core, driving it from a
  TPM stack, persistence, sessions/auth, and the QEMU integration in depth.

## Persistence

State is snapshotted to a per-VM directory and reloaded on the next boot, so the
vTPM — and everything sealed against it — survives guest reboots. The snapshot is
versioned and migrates forward; it currently carries PCR banks, the authorization
hierarchies and their primary seeds, dictionary-attack lockout state, persistent
objects (EK/SRK), NV indices, and the clock.

## Correctness

The implementation is reconciled against the vendored spec
(`docs/spec/v185/`, Parts 1–3) in [`VALIDATION.md`](VALIDATION.md): a
**261-point accuracy sweep** (constants, attribute bitfields, structure wire
layouts, crypto constructions, the authorization/policy engine, and per-command
semantics), each row carrying a Part + page citation. The sweep found and fixed
four conformance bugs and documents seven by-design deviations.

- The `cpHash` / authorization-HMAC path — the most interoperability-sensitive
  part — is checked two ways: against an independent in-test reimplementation, and
  against optional golden vectors captured from a real TPM stack (see
  `tpm2/testdata/`).
- The reboot guarantee is tested end to end
  (`tpm2/seal_test.go`): seal a secret under a persistent SRK, snapshot, restore
  into a fresh TPM, and unseal it.

`go test ./...` exercises the full surface (200+ tests in the `tpm2` package).

## Status & limitations

The TPM core, the swtpm/QEMU transport, and provisioning are implemented and
tested. Honest caveats:

- **Software TPM, not a hardware security boundary.** State lives in host memory
  and on-disk snapshots. This provides the TPM 2.0 *protocol and semantics*, not
  hardware-grade isolation or tamper resistance.
- **The live Windows-11-on-QEMU boot is not yet verified** — that step needs a
  real QEMU + Windows 11 environment. The runner, launch script, and harness are
  ready for it (`cmd/vtpm`, `scripts/`).
- **11 of 136 spec commands are unimplemented** — firmware upgrade, Attached
  Components, and a few v2 NV/capability variants that require physical hardware a
  software TPM cannot provide; the dispatcher returns `TPM_RC_COMMAND_CODE` for
  them, which is the spec-faithful response.

## License

MIT — see [`LICENSE`](LICENSE). This is a clean-room implementation written from
the public TCG TPM 2.0 Library Specification; it contains no code from, and is not
derived from, any GPL-licensed TPM implementation.
