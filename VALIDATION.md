# TPM 2.0 Specification Conformance Validation

**Subject:** `github.com/deploymenttheory/go-sdk-vtpm2` — a software TPM 2.0
device implemented in Go from the TCG TPM 2.0 Library Specification, used as a
vTPM for QEMU / Windows 11 guests.

**Validated against:** TCG *TPM 2.0 Library Specification* — Part 1 Architecture,
Part 2 Structures, Part 3 Commands, Part 4 Supporting Routines
(<https://trustedcomputinggroup.org/resource/tpm-library-specification/>), and
cross-checked against the reference implementation tracked at
<https://github.com/TrustedComputingGroup/TPM>. Constant values were confirmed
against a maintained TPM 2.0 codebase (google/go-tpm). The emulator advertises
`TPM_PT_REVISION = 164` (revision 1.64); findings are written against that level.

**Date:** 2026-06-23  ·  **Method:** static audit of the wire protocol, command
semantics, and response codes for every implemented command, plus a completeness
gap analysis. Fixes for the unambiguous bugs have been applied and are noted
inline; see [Fixes applied](#fixes-applied).

---

## 1. Scope of the implementation

The emulator implements a deliberate **boot-critical subset of 9 commands**, two
PCR banks (SHA-1, SHA-256 × 24 PCRs), password-only authorization, and JSON state
persistence. It is **not** a full TPM 2.0 stack: no object/key management, NV
storage, hierarchies, HMAC/policy sessions, or asymmetric/symmetric crypto. This
report evaluates **conformance of what is implemented** (Sections 2–4) and the
**roadmap to completeness** (Section 5).

| Command | Code | Verdict |
|---|---|---|
| `TPM2_Startup` | 0x144 | Conformant (after fix) |
| `TPM2_Shutdown` | 0x145 | Conformant |
| `TPM2_SelfTest` | 0x143 | Conformant (after fix) |
| `TPM2_GetTestResult` | 0x17C | Conformant |
| `TPM2_GetRandom` | 0x17B | Conformant (note R-3) |
| `TPM2_StirRandom` | 0x146 | Conformant |
| `TPM2_GetCapability` | 0x17A | Conformant (after fixes) |
| `TPM2_PCR_Read` | 0x17E | Conformant (after fix) |
| `TPM2_PCR_Extend` | 0x182 | Conformant (after fixes) |

---

## 2. Findings

Severity: **[H]** wrong on a path a real stack hits on the happy/common flow ·
**[M]** wrong on an error/edge path · **[L]** acceptable but noted · **[Doc]**
documentation accuracy. All "after fix" items are addressed in this branch.

### [H] F-1 — `TPM_RC_VALUE` / `TPM_RC_INSUFFICIENT` were not valid response codes

`tpm2/const.go` (pre-fix) defined these format-**one** codes on the format-**zero**
base `RC_VER1` (0x100):

```
RCInsufficient = rcVer1 + 0x09A  // = 0x19A  (wrong)
RCValue        = rcVer1 + 0x004  // = 0x104  (wrong)
```

Per TPM 2.0 Part 2 (*Response Code Details*), `TPM_RC_VALUE` and
`TPM_RC_INSUFFICIENT` are **format-one** codes built on `RC_FMT1` (0x080):
`TPM_RC_VALUE = 0x084`, `TPM_RC_INSUFFICIENT = 0x09A`. The emitted values 0x104
and 0x19A are not decodable TPM response codes — `0x19A` even sets the format bit
(0x080) by accident, so a strict client decodes it as a garbled format-one code.
These were returned on **common** paths: every truncated/short command
(`RCInsufficient`) and every invalid parameter value (`RCValue`, e.g. bad
`TPM_SU`, out-of-range PCR index). The in-code comment ("RC_FMT1 space is not yet
applied") masked the bug — the base, not just the decoration, was wrong.
**Fixed**: codes rebased on `rcFmt1`; regression test `TestFormatOneResponseCodeValues`.

### [H] F-2 — `TPM2_PCR_Read` echoed the request as `pcrSelectionOut`

`tpm2/commands.go` (pre-fix) wrote the **input** selection back as
`pcrSelectionOut`. Part 3 (`TPM2_PCR_Read`) requires `pcrSelectionOut` to be the
selection the TPM **actually read back**. When a request named a bank the
emulator does not implement (e.g. SHA-384) or an unreadable index, no digest was
produced, yet the bank's bits remained set in `pcrSelectionOut` — so
`pcrSelectionOut` and the `pcrValues` count disagreed, which conformant callers
reject. **Fixed**: the response now reflects only PCR actually read (unsupported
banks come back with a cleared bitmap); tests
`TestPCRReadUnsupportedBankClearsSelection`, `TestPCRReadMixedBanksConsistent`.

### [M] F-3 — Wrong response code for `PCR_Extend` sent without a session

`cmdPCRExtend` returned `TPM_RC_FAILURE` when the command tag was
`TPM_ST_NO_SESSIONS`. A command that requires authorization but carries no
sessions is `TPM_RC_AUTH_MISSING` (0x125) per Part 3. `TPM_RC_FAILURE` wrongly
implies the TPM entered failure mode. **Fixed** → `RCAuthMissing`; test
`TestPCRExtendWithoutSession`.

### [M] F-4 — Wrong response code for a malformed authorization area

`cmdPCRExtend` returned `TPM_RC_FAILURE` when `readAuthArea` rejected the auth
area. A bad `authorizationSize` is `TPM_RC_AUTHSIZE` (0x144). **Fixed** →
`RCAuthSize`; test `TestPCRExtendBadAuthSize`.

### [M] F-5 — `GetCapability` accepted unknown capability selectors silently

`cmdGetCapability`'s `default` arm returned success with an empty list for **any**
capability value, including undefined selectors. Part 3 (`TPM2_GetCapability`)
returns `TPM_RC_VALUE` for a capability that is not a defined `TPM_CAP`. **Fixed**:
selectors outside the defined `TPM_CAP` block (0x00–0x0A) and the vendor selector
(0x100) now return `RCValue`; defined-but-unenumerated capabilities still return a
correctly-typed empty `TPML_*`. Tests `TestGetCapabilityUnknownCapability`,
`TestGetCapabilityKnownEmpty`.

### [M] F-6 — `GetCapability` ignored `propertyCount == 0`

`writeProperties` only truncated when `count > 0`, so a request with
`propertyCount = 0` returned **all** properties instead of none. Part 3:
`propertyCount` bounds the count returned; `0` yields an empty list with
`moreData = YES` when properties exist. **Fixed**; test
`TestGetCapabilityPropertyCountZero`.

### [L] F-7 — `TPMI_YES_NO` values were not range-checked

`TPM2_SelfTest.fullTest` accepted any byte; `TPMI_YES_NO` admits only {0,1} →
`TPM_RC_VALUE` (Part 2). **Fixed** for `SelfTest`; test
`TestSelfTestRejectsNonBoolean`. The session/response `sessionAttributes` bytes
are still not validated (acceptable for password auth — see F-9).

### [L] F-8 — No format-one parameter/handle/session decoration

Format-one codes are returned **bare** (no P bit, no N field identifying the
offending parameter/handle/session). This is decodable but less precise than a
real TPM, which pinpoints the faulting item. Acceptable for the boot subset;
listed in the roadmap (Section 5) for when richer error reporting is needed.

### [L] F-9 — Authorization is parsed but not verified

`PCR_Extend` accepts any well-formed session without checking the session handle
type or HMAC. This is **spec-acceptable for the PCR auth group**, whose auth value
is empty by default, but it is not real authorization. When commands with
non-empty auth (keys, NV, hierarchies) are added, HMAC/policy verification per
Part 1 §19–21 becomes mandatory.

### [L] F-10 — PCR select bitmap size and per-call value cap not bounded

`readPCRSelectionList` accepts any `sizeofSelect` (Part 2 bounds it by
`PCR_SELECT_MIN`/`MAX`), and `PCR_Read` returns **all** selected PCR in one call,
whereas a hardware TPM caps the number of digests per call and requires the caller
to loop using `pcrUpdateCounter`. Neither breaks the QEMU/Windows path (callers
loop anyway), but both are out-of-spec bounds worth tightening.

### [Doc] F-11 — `doc.go` overstated the crypto port

`doc.go` listed `crypto/rsa`, `crypto/ecdsa`, `crypto/aes`, `crypto/hmac` as
mapped, but only `crypto/sha1`, `crypto/sha256` and `crypto/rand` are used today.
**Fixed**: wording now distinguishes what is wired in from what is planned.

---

## 3. Confirmed conformant (validated, no change needed)

- **Command/response header** — 10-byte `tag‖size‖code`, big-endian; `size`
  validated against the actual length (`tpm.go:50-62`).
- **Error responses** — always `TPM_ST_NO_SESSIONS` with only the header, per
  Part 1 (`tpm.go:147-155`).
- **Response with sessions** — `parameterSize` (UINT32) precedes the parameter
  area, followed by one acknowledgment session, tag `TPM_ST_SESSIONS`
  (`tpm.go:161-185`). Correct for password authorizations.
- **`Startup` sequencing** — a second `TPM2_Startup` returns `TPM_RC_INITIALIZE`;
  commands before `Startup` return `TPM_RC_INITIALIZE` (`commands.go:22-24`,
  `tpm.go:112-117`). Matches Part 3.
- **Failure mode gating** — only `GetTestResult` and `GetCapability` answer in
  failure mode (`tpm.go:66-69`), per Part 1.
- **PCR extend semantics** — `PCR[i] := H(PCR[i] ‖ digest)`, digest length
  enforced against the bank's hash size (`pcr.go:44-54`). Verified against a
  hand-computed `SHA256(zeros‖digest)` (`tpm_test.go:197-202`).
- **PCR power-on / `SU_CLEAR` reset** — banks zero-initialized to the hash size
  (`pcr.go:30-42`).
- **`TPMS_CAPABILITY_DATA`** — `moreData` (TPMI_YES_NO) ‖ `capability` (UINT32) ‖
  typed `TPML_*`; properties emitted in ascending tag order (`capability.go`).
- **Fixed properties** — family `"2.0\0"` (0x322E3000), `TPM_PT_REVISION = 164`
  (rev × 100), manufacturer/vendor as packed 4-char ASCII (`capability.go:15-23`).
  Correct per Part 2.
- **TPM2B framing** — every sized buffer is a UINT16 length prefix + bytes
  (`buf.go`, `commands.go`).
- **Command codes & algorithm IDs** — the 9 `TPM_CC` and the `TPM_ALG_ID` hash
  identifiers match Part 2 (`const.go`).

---

## 4. Per-command notes

- **`Startup` / `Shutdown`** — both validate `TPM_SU ∈ {CLEAR, STATE}`.
  `Shutdown(STATE)` state-save is a no-op today (persistence is handled out-of-band
  by the `state` package); acceptable, but a true `SU_STATE`/`SU_CLEAR` resume
  distinction is a roadmap item.
- **`GetRandom` (R-3)** — silently caps at 64 bytes (`maxRandomBytes`). Part 3
  permits returning fewer bytes than requested, so this is conformant; document
  that callers must loop to obtain more than 64 bytes.
- **`GetTestResult`** — returns empty `outData` + a `TPM_RC` testResult, and
  answers before `Startup`/in failure mode, per Part 3.
- **`StirRandom`** — consumes and discards entropy (Go's CSPRNG cannot be seeded)
  and succeeds. Conformant: the spec does not mandate a observable effect.

---

## 5. Completeness roadmap

The emulator covers measured-boot PCR operations. To grow toward a general-purpose
TPM 2.0, the missing subsystems below are ordered by dependency. Each maps to its
spec home so the work can be scoped against the standard.

1. **Response-code precision (F-8).** Add `RC_FMT1` parameter/handle/session
   decoration and the full `TPM_RC` warning/severity bits (Part 2, Response Code
   Details). Low effort, improves every error path.
2. **Full `TPM_CAP` coverage.** Implement `TPM_CAP_ALGS`, `TPM_CAP_COMMANDS`,
   `TPM_CAP_HANDLES`, `TPM_CAP_PCR_PROPERTIES`, `TPM_CAP_ECC_CURVES`
   (Part 3, `TPM2_GetCapability`; Part 2 for the `TPML_*` payloads). Tools that
   enumerate the TPM depend on these.
3. **Hierarchies & the handle space** (Part 1 §9, Part 2 handle ranges).
   `TPM_RH_OWNER / ENDORSEMENT / PLATFORM / NULL`, transient (0x80…), persistent
   (0x81…), NV (0x01…) and session (0x02…/0x03…) handle ranges, plus
   hierarchy enable/auth state. Prerequisite for keys, NV and sessions.
4. **Sessions** (Part 1 §19 *Authorizations and Acknowledgments*, §21 *Sessions*).
   HMAC sessions (real auth verification — see F-9), policy sessions
   (`PolicyPCR`, `PolicyAuthValue`, …), salt/bind, and parameter/response
   encryption. Requires `crypto/hmac` and KDFa (Part 1 §11.4.10).
5. **Object & key management** (Part 3 §27–31; Part 2 `TPMT_PUBLIC`,
   `TPMT_SENSITIVE`, `TPM2B_PRIVATE`). `CreatePrimary`, `Create`, `Load`,
   `LoadExternal`, `ContextSave/Load`, `EvictControl`. Pulls in `crypto/rsa`,
   `crypto/ecdsa`, `crypto/aes`, KDFs and the credential-protection routines
   (Part 4). This is the largest block.
6. **NV storage** (Part 3 §31; Part 2 `TPMS_NV_PUBLIC`). `NV_DefineSpace`,
   `NV_Read`, `NV_Write`, `NV_UndefineSpace`, attributes/locks. Needed for
   BitLocker-style sealed state beyond raw PCR snapshots.
7. **Signing / attestation & sealing** (Part 3): `Sign`, `VerifySignature`,
   `Quote`, `Certify`, `RSA_Decrypt`, `Unseal`, `ActivateCredential`. The payoff
   for a "real" vTPM (remote attestation, key sealing).
8. **PCR completeness** — per-call value cap and `sizeofSelect` bounds (F-10);
   `PCR_Allocate`, `PCR_Reset`, `PCR_SetAuthValue`, the platform PCR auth/reset
   policy (Part 3 PCR section; Part 1 §17).

A pragmatic next milestone for the Windows-11 vTPM goal is **3 → 4 → 6**
(hierarchies, sessions, NV), which is what BitLocker and measured-boot sealing
actually exercise, deferring the full key/attestation surface (5, 7) until needed.

---

## Fixes applied

All changes are minimal and reuse existing `reader`/`writer` primitives.

| ID | Files | Change |
|---|---|---|
| F-1 | `tpm2/const.go` | Rebased `RCValue`/`RCInsufficient` on `RC_FMT1`; added `RCSize`, `RCAuthMissing`, `RCAuthSize`; documented the two code formats. |
| F-2 | `tpm2/commands.go` | `cmdPCRRead` now builds `pcrSelectionOut` from PCR actually read. |
| F-3 | `tpm2/commands.go` | `cmdPCRExtend` no-session → `RCAuthMissing`. |
| F-4 | `tpm2/commands.go` | `cmdPCRExtend` bad auth area → `RCAuthSize`. |
| F-5 | `tpm2/capability.go`, `tpm2/const.go` | Unknown capability → `RCValue`; added the defined `TPM_CAP` set + vendor selector. |
| F-6 | `tpm2/capability.go` | `writeProperties` honors `propertyCount == 0`. |
| F-7 | `tpm2/commands.go` | `cmdSelfTest` validates `TPMI_YES_NO`. |
| F-11 | `doc.go` | Corrected the crypto-port description. |
| tests | `tpm2/conformance_test.go` | 11 regression tests, one per fix. |

**Verification:** `go build ./...`, `go vet ./...`, `go test ./...` all pass; the
new conformance tests and the existing suite (including the `emulator`
end-to-end QEMU handshake) are green. Items F-8, F-9, F-10 and the Section 5
roadmap are intentionally **not** changed — they are larger design work, recorded
here for tracking.
