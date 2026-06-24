# go-sdk-vtpm2 — working notes

A pure-Go TPM 2.0 device built from the TCG TPM 2.0 Library Specification (MIT,
no cgo, no swtpm/libtpms). The transport-agnostic core is
`func (t *tpm2.TPM) Execute(command []byte) (response []byte)`.

## Authoritative reference — the TCG spec (read this before claiming conformance)

The TCG TPM 2.0 Library Specification, **revision 1.85**, is vendored in this repo:

```
docs/spec/v185/
  Trusted-Platform-Module-2.0-Library-Part-0-Introduction_Version-185_pub.pdf
  Trusted-Platform-Module-2.0-Library-Part-1-Architecture_Version-185_pub.pdf
  Trusted-Platform-Module-2.0-Library-Part-2-Structures_Version-185_pub.pdf
  Trusted-Platform-Module-2.0-Library-Part-3-Commands_Version-185_pub.pdf
  Eratta-...-185_pub.pdf
  Part-0.txt … Part-3.txt, Errata.txt   # pdftotext -layout exports (searchable)
```

- **This is the primary source.** Cite Part + section/page from these files for any
  conformance claim — do **not** cite the spec from memory.
- The TCG website (`trustedcomputinggroup.org`) is **Cloudflare-gated**; automated
  fetch returns a JS challenge / HTTP 403, so the PDFs cannot be pulled by tooling.
  They are provided here on disk instead. If a newer revision is needed, drop the
  PDFs into a sibling `docs/spec/vNNN/` folder.
- Search the text exports page-aware:
  ```sh
  awk 'BEGIN{p=1} /\f/{p++} {print p"\t"$0}' docs/spec/v185/Part-1.txt | grep -i '<term>'
  ```
  The page number printed matches the PDF page (use `Read` with `pages:` to quote).
- `google/go-tpm` (raw GitHub) is a useful secondary cross-check for constant
  *values* only — not for architecture/semantics.

`VALIDATION.md` is the conformance report; every row should carry a Part+page
citation into `docs/spec/v185/`.

## Conventions

- **Zero non-Go deps.** Crypto is Go stdlib only (`crypto/rsa`, `crypto/ecdsa`,
  `crypto/ecdh`, `crypto/aes`, `crypto/hmac`, `crypto/sha*`, `crypto/rand`).
- **Green every change:** `go build ./... && go vet ./... && go test ./...`.
- **Determinism is load-bearing:** primary keys (EK/SRK) derive deterministically
  from a hierarchy seed so sealed objects survive reboots. Don't introduce
  randomness into key derivation; verify with the reboot/seal tests.
- **State shape changes** bump `tpm2.snapshotVersion` with forward migration in
  `Restore`.
- Commit/push only when asked; branch off `main` first.
