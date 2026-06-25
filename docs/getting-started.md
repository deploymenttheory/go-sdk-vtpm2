# Getting started

This walks you from a fresh checkout to a running TPM and your first command, in a
few minutes. `go-sdk-vtpm2` is a **pure-Go TPM 2.0 device** — no cgo, no native
`swtpm`/`libtpms`, one `go build`.

For deeper usage (sessions, persistence, QEMU), see the
[usage guide](usage-guide.md).

## Prerequisites

- **Go 1.26 or newer** (`go version`). That's the only requirement — there are no
  C toolchain, system libraries, or external services to install.
- A POSIX-y host for the QEMU/swtpm transport (Linux or macOS). The core `tpm2`
  package itself is platform-independent.

## Get the code

```sh
git clone https://github.com/deploymenttheory/go-sdk-vtpm2
cd go-sdk-vtpm2
go build ./...
go test ./...        # the full suite should pass
```

Or add it to your own module:

```sh
go get github.com/deploymenttheory/go-sdk-vtpm2/tpm2
```

## Hello, TPM — embed the core

The entire core is one method: `func (t *tpm2.TPM) Execute(cmd []byte) []byte` —
a raw TPM 2.0 command blob in, a raw response blob out. A TPM must be **started**
(`TPM2_Startup`) before it answers other commands.

```go
package main

import (
	"encoding/binary"
	"fmt"

	"github.com/deploymenttheory/go-sdk-vtpm2/tpm2"
)

// cmd frames a TPM command: tag(2) ‖ size(4) ‖ commandCode(4) ‖ params.
func cmd(tag uint16, code uint32, params []byte) []byte {
	b := make([]byte, 10+len(params))
	binary.BigEndian.PutUint16(b[0:], tag)
	binary.BigEndian.PutUint32(b[2:], uint32(len(b)))
	binary.BigEndian.PutUint32(b[6:], code)
	copy(b[10:], params)
	return b
}

func main() {
	t := tpm2.New()

	// TPM2_Startup(TPM_SU_CLEAR) — bring the TPM up.
	t.Execute(cmd(0x8001 /*NO_SESSIONS*/, 0x00000144 /*Startup*/, []byte{0x00, 0x00}))

	// TPM2_GetRandom(16) — ask for 16 bytes of entropy.
	resp := t.Execute(cmd(0x8001, 0x0000017B /*GetRandom*/, []byte{0x00, 0x10}))

	rc := binary.BigEndian.Uint32(resp[6:10]) // responseCode at bytes 6..10
	random := resp[12:]                        // after header(10) + TPM2B size(2)
	fmt.Printf("rc=0x%x  random=%x\n", rc, random)
}
```

```sh
go run .
# rc=0x0  random=<16 random bytes>
```

In real use you would build command blobs with a TPM stack (e.g. `google/go-tpm`)
rather than by hand — see the [usage guide](usage-guide.md#driving-it-with-a-tpm-stack).

## Run it as a vTPM for QEMU

The `cmd/vtpm` binary hosts the TPM on a swtpm-compatible control socket that
QEMU's `tpm-emulator` backend speaks unmodified:

```sh
go build -o ./vtpm ./cmd/vtpm

# -state gives reboot-persistent storage; -provision pre-creates an SRK.
./vtpm -ctrl /tmp/vtpm-ctrl.sock -state ./vtpm-state -provision
```

Point QEMU at the control socket:

```sh
qemu-system-x86_64 \
  -chardev socket,id=chrtpm,path=/tmp/vtpm-ctrl.sock \
  -tpmdev emulator,id=tpm0,chardev=chrtpm \
  -device tpm-tis,tpmdev=tpm0 \
  ...
```

Without `-state` the TPM is ephemeral (nothing persists across restarts); with it,
the EK/SRK, NV, PCRs and clock — and anything sealed against them — survive a guest
reboot.

## What next

- **[Usage guide](usage-guide.md)** — the two integration models, the wire format,
  sessions and authorization, persistence/migration, and the emulator/QEMU path.
- **[VALIDATION.md](../VALIDATION.md)** — how the implementation is reconciled
  against the TCG spec (a 261-point, page-cited accuracy sweep).
- **[docs/ROADMAP.md](ROADMAP.md)** — what is implemented and what remains.
