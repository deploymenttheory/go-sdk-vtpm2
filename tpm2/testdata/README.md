# Authorization golden vectors

`auth_vectors.json` drives `TestAuthGoldenVectors` in `auth_vectors_test.go`,
which validates the `cpHash` / authorization-HMAC implementation in `auth.go`
against the TPM 2.0 Library Specification (Part 1, §18.7 and §19.6).

Each vector is checked two ways:

1. **Against an independent reference** re-implemented in the test from raw
   `crypto/sha256` + `crypto/hmac`. This catches implementation bugs in
   `auth.go` (wrong field order, missing input, etc.).
2. **Against `expectedCpHash` / `expectedAuthHMAC`** when those fields are
   present. These are authoritative bytes captured from a real TPM 2.0 stack and
   catch *spec-misreading* (where `auth.go` and the in-test reference agree but
   both diverge from a real TPM).

The seed vectors here are `source: "spec-derived"` (inputs only — validated by
the reference). To raise confidence to byte-for-byte conformance, add
`source: "tss-captured"` vectors with the `expected*` fields filled in.

## Capturing `tss-captured` vectors

Run a known command through a real TPM 2.0 stack with a trace, e.g. with
`tpm2-tools` against a hardware TPM or the Microsoft/IBM simulator:

```
# Start an HMAC session and run a command, capturing the raw command/response
# (TPM2_HierarchyChangeAuth shown).
tpm2_startauthsession --hmac-session -S session.ctx
TPM2_TOOLS_TCTI=tabrmd tpm2 ... # with --trace or a sniffer (e.g. tpm2-abrmd log)
```

For each captured command record into a vector:

| Field          | Source in the captured command/response                         |
|----------------|-----------------------------------------------------------------|
| `commandCode`  | the command header `commandCode` (decimal)                      |
| `handleNames`  | the Name of each handle in the handle area (hex)                |
| `cpParams`     | the command parameter area after handles+auth (hex)             |
| `sessionKey`   | the session key (empty for unbound+unsalted)                    |
| `authValue`    | the entity authValue (hex)                                      |
| `nonceCaller`  | the caller nonce in the command auth area (hex)                 |
| `nonceTPM`     | the session's current TPM nonce (hex)                           |
| `attributes`   | the sessionAttributes byte (decimal)                            |
| `bound`        | true if the session is bound to the authorized entity           |
| `expectedAuthHMAC` | the authorization HMAC field from the command auth area (hex) |

`expectedCpHash` is optional (most traces expose the HMAC, not the intermediate
`cpHash`); the reference still validates `cpHash` structurally.
