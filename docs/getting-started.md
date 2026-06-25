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

## Hello, TPM — the typed client

The easiest way to drive the TPM from Go is the in-repo **`client`** package: a
typed, in-process TPM with no socket, no daemon, and no second dependency.

```go
package main

import (
	"fmt"

	"github.com/deploymenttheory/go-sdk-vtpm2/client"
)

func main() {
	c, err := client.OpenLocal() // a fresh in-process TPM, started
	if err != nil {
		panic(err)
	}

	r, _ := c.GetRandom(16)
	fmt.Printf("random: %x\n", r)

	// Provision a Storage Root Key and a child signing key under it.
	srk, _ := c.CreatePrimary(client.HandleOwner, client.ECCStorageKey(), nil)
	defer c.FlushContext(srk.Handle)

	key, _ := c.CreateAndLoad(srk, client.ECCSigningKey(), []byte("auth"))
	defer c.FlushContext(key.Handle)
	fmt.Printf("signing key name: %x\n", key.Name)
}
```

```sh
go run .
```

No hand-built command blobs, no external TPM stack. See the
[usage guide](usage-guide.md#the-typed-client) for templates, transports, and
where the typed API is heading.

## Under the hood — the raw boundary

The typed client is a thin layer over the one method that *is* the TPM:
`func (t *tpm2.TPM) Execute(cmd []byte) []byte` — a raw command blob in, a raw
response blob out. You can use it directly when you need to:

```go
import "encoding/binary"

// cmd frames a TPM command: tag(2) ‖ size(4) ‖ commandCode(4) ‖ params.
func cmd(tag uint16, code uint32, params []byte) []byte {
	b := make([]byte, 10+len(params))
	binary.BigEndian.PutUint16(b[0:], tag)
	binary.BigEndian.PutUint32(b[2:], uint32(len(b)))
	binary.BigEndian.PutUint32(b[6:], code)
	copy(b[10:], params)
	return b
}

t := tpm2.New()
t.Execute(cmd(0x8001, 0x00000144, []byte{0x00, 0x00}))      // TPM2_Startup(CLEAR)
resp := t.Execute(cmd(0x8001, 0x0000017B, []byte{0x00, 0x10})) // TPM2_GetRandom(16)
// responseCode is resp[6:10]; success is 0x00000000.
```

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
