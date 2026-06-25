# Usage guide

How to use `go-sdk-vtpm2` in anger: the integration models, the command/response
boundary, sessions and authorization, persistence and migration, and the QEMU
transport. New here? Start with [getting started](getting-started.md).

## Two ways to use it

| Model | When | Entry point |
|---|---|---|
| **Embed the core** | unit tests, fuzzers, a custom transport, a TPM inside your own process | `tpm2.New()` → `Execute([]byte) []byte` |
| **Run as a vTPM server** | give QEMU/a VM a virtual TPM over the swtpm protocol | `cmd/vtpm`, or the `emulator` package |

Both wrap the same core. The server packages add the on-disk persistence and the
swtpm control/data channels around `Execute`.

## The command/response boundary

The core is transport-agnostic. You hand `Execute` a complete TPM 2.0 command blob
and get a complete response blob back. It never returns a Go error — protocol
problems come back as TPM **response codes**, exactly as a hardware TPM does.

```
Command:   tag(UINT16) ‖ commandSize(UINT32) ‖ commandCode(UINT32) ‖ [handles] ‖ [auth area] ‖ [params]
Response:  tag(UINT16) ‖ responseSize(UINT32) ‖ responseCode(UINT32) ‖ [handles] ‖ [params] ‖ [auth area]
```

- `tag` is `0x8001` (`TPM_ST_NO_SESSIONS`) or `0x8002` (`TPM_ST_SESSIONS`).
- A `responseCode` of `0x00000000` is success; anything else is an error (the
  format-zero / format-one / warning encodings of TPM_RC).
- The TPM must be brought up with `TPM2_Startup` before it answers other commands;
  before that it returns `TPM_RC_INITIALIZE`.

```go
t := tpm2.New()
resp := t.Execute(startupClear) // TPM2_Startup(TPM_SU_CLEAR)
if rc := binary.BigEndian.Uint32(resp[6:10]); rc != 0 {
    log.Fatalf("startup failed: 0x%x", rc)
}
```

## The typed client

Hand-building command blobs is fine for a command or two, but for real use the
repo ships a typed, in-process-native client in the **`client`** package — so you
don't need to build wire bytes *or* import a separate TPM stack.

```go
import "github.com/deploymenttheory/go-sdk-vtpm2/client"

c, _ := client.OpenLocal()                 // an in-process TPM, started
srk, _ := c.CreatePrimary(client.HandleOwner, client.ECCStorageKey(), nil)
defer c.FlushContext(srk.Handle)

key, _ := c.CreateAndLoad(srk, client.ECCSigningKey(), []byte("auth"))
defer c.FlushContext(key.Handle)
pub, name, _ := c.ReadPublic(key.Handle)
```

Typed templates (`ECCStorageKey`, `RSAStorageKey`, `ECCSigningKey`,
`RSASigningKey`, `HMACKey`) mean nobody hand-rolls a `TPMT_PUBLIC`, and the loaded
`*Key` carries its handle, Name, and public area.

### Same API, any transport

The client talks to a `Transport`, so the identical typed API drives an in-process
responder, a remote swtpm socket, or real hardware:

```go
type Transport interface {
    Execute(cmd []byte) ([]byte, error)
}

c := client.Open(client.Local(tpm2.New())) // in-process (no socket, no daemon)
// c := client.Open(yourSocketTransport)   // or a swtpm socket / hardware
```

The in-process path (`client.Local`) is the differentiator: a fully typed TPM in
your own process with no second dependency — ideal for tests, tooling, and fuzzing.

The `client` package is being built out command-by-command (object lifecycle and
templates first; sessions/auth, signing/attestation, and NV next). Until a
particular command has a typed method, you can always drop to the raw boundary
(`Execute`) or implement a transport for it.

## Sessions and authorization

The auth engine implements the full TPM 2.0 model, so a stack's session code works
against it unchanged:

- **Password** sessions (`TPM_RS_PW`) — the plaintext authValue.
- **HMAC** sessions — real `cpHash`/`rpHash` computation and HMAC verify/respond,
  including **salted** (RSA-OAEP / ECDH) and **bound** sessions.
- **Policy** sessions — the full set of policy assertions (`PolicyPCR`,
  `PolicyOR`, `PolicySigned`/`Secret`/`Authorize`, `PolicyNV`, `PolicyCommandCode`,
  …) accumulating a `policyDigest` checked at use.
- **Parameter encryption** in both directions (XOR and AES-CFB), and session +
  command **audit**.

The authorization-HMAC path is the most interoperability-sensitive part of a TPM;
it is validated against an independent reimplementation and optional golden vectors
(`tpm2/testdata/`). See [VALIDATION.md](../VALIDATION.md) for the conformance
detail.

## Persistence and migration

State is a single versioned **snapshot** carrying the hierarchy seeds and auth, the
persistent objects (EK/SRK), NV indices, PCR banks, the DA lockout, and the clock.
Primary keys are derived deterministically from the hierarchy seed, so a recreated
SRK matches its persisted form and previously sealed blobs still load.

```go
// Save / restore the full persistent state as an opaque, self-describing blob.
blob, _ := t.StateBlob()       // serialize (JSON Snapshot, carries its own version)
fresh := tpm2.New()
_ = fresh.LoadStateBlob(blob)  // restore into a new TPM; migrates forward
```

`StateBlob` / `LoadStateBlob` back the swtpm `GET_STATEBLOB` / `SET_STATEBLOB`
control commands that QEMU uses for save/restore and live migration. The
`state` package (`state.NewStore`) provides crash-safe on-disk persistence
(temp-file + atomic rename) for the server model.

`Init(deleteVolatile bool)` models a TPM reset: it drops volatile state (sessions,
transient objects, the volatile null-hierarchy seed) while keeping persistent
state; `deleteVolatile` also resets the PCRs (a `TPM_SU_CLEAR` boot).
`SetLocality(loc)` records the locality of subsequent commands (the transport calls
this), which PCR operations enforce.

## Running as a vTPM server

The `emulator` package wires the TPM, persistence, and the swtpm transport into one
runnable device:

```go
e, err := emulator.New("/tmp/vtpm-ctrl.sock", "./vtpm-state") // stateDir "" = ephemeral
if err != nil { log.Fatal(err) }
if err := e.Provision(); err != nil { log.Fatal(err) } // pre-create the SRK (0x81000001)
if err := e.Start(); err != nil { log.Fatal(err) }
defer e.Close() // persists state on shutdown
```

`cmd/vtpm` is a thin `main` around exactly this:

```sh
go build -o ./vtpm ./cmd/vtpm
./vtpm -ctrl /tmp/vtpm-ctrl.sock -state ./vtpm-state -provision
```

| Flag | Meaning |
|---|---|
| `-ctrl` | swtpm control socket path (default `/tmp/vtpm-ctrl.sock`) |
| `-state` | state directory; empty = ephemeral (no persistence) |
| `-provision` | pre-create and persist a Storage Root Key at `0x81000001` |

## QEMU integration

QEMU's `tpm-emulator` backend speaks the swtpm control + data protocol this server
implements (control socket, `SET_DATAFD` fd passing, state-blob save/restore,
locality). Point it at the control socket:

```sh
qemu-system-x86_64 \
  -chardev socket,id=chrtpm,path=/tmp/vtpm-ctrl.sock \
  -tpmdev emulator,id=tpm0,chardev=chrtpm \
  -device tpm-tis,tpmdev=tpm0 \
  ...
```

The intended end state is a Windows 11 guest doing measured boot and BitLocker
sealing against this vTPM, with the sealed VMK surviving reboots via the persisted
snapshot.

## Notes & limits

- **Software TPM, not a hardware boundary.** It provides the TPM 2.0 protocol and
  semantics, not hardware isolation or tamper resistance; state lives in host
  memory and on-disk snapshots.
- **Stdlib crypto only.** RSA, ECC (P-256/384/521), AES, HMAC, SHA-1/256/384/512,
  and the TPM KDFs come from the Go standard library — no cgo, no external deps.
- **125 of 136 commands** are implemented; the rest are firmware-upgrade /
  Attached-Component / v2 variants that need physical hardware, and return
  `TPM_RC_COMMAND_CODE`.
