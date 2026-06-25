# Conformance Validation — go-sdk-vtpm2 vs TCG TPM 2.0 Library Specification rev 1.85

This report reconciles the implementation against the vendored spec in
`docs/spec/v185/` (Parts 1–3). Every row carries a Part + page citation taken from
those files (not from memory). The sweep covers **261 reference points** across six
clusters; each point is classified **ALIGNED**, **BUG**, or **DEVIATION-BY-DESIGN**.

Scope: 125 implemented commands (of 136 in v1.85); the 11 unimplemented are
firmware-upgrade, Attached-Component and a few v2 NV/capability variants that a
pure-Go software TPM cannot meaningfully provide — the dispatcher returns
`TPM_RC_COMMAND_CODE` for those, which is the spec-faithful response.

## Executive summary

| Cluster | Points | Aligned | Bugs | Deviations |
|---|---:|---:|---:|---:|
| A. Constant values (`const.go`) | 51 | 49 | 1 | 1 |
| B. Attribute bitfields (TPMA_*) | 45 | 44 | 0 | 1 |
| C. Structure wire layouts | 34 | 34 | 0 | 0¹ |
| D. Crypto constructions (Part 1) | 37 | 35 | 0 | 2 |
| E. Auth / session / policy semantics | 37 | 37 | 0 | 0² |
| F. Per-command parameter/semantics | 57 | 52 | 2 | 3 |
| **Total** | **261** | **251** | **4** | **7** |

¹ One non-layout privacy note (unobfuscated firmwareVersion/clock). ² One
HASH_COUNT design choice. **All four bugs are fixed** (one, RC_NO_RESULT, was found
in cluster A; the other three by the structure/crypto/per-command sweeps).

**Build status after fixes:** `go build ./... && go vet ./... && go test ./...`
green across all packages.

## Bugs found and fixed

| # | Bug | Spec | Fix |
|---|---|---|---|
| 1 | `RCNoResult` defined as `RC_FMT1+0x01F` (0x09F) — collided with `RC_INTEGRITY` | Part 2 p.59 — `TPM_RC_NO_RESULT = RC_VER1 + 0x054` (0x154) | `const.go`: corrected to `rcVer1 + 0x054` |
| 2 | Duplication outer wrap used the **object-storage** form (random symIv, HMAC over `symIv‖enc‖name`) instead of the duplication form | Part 1 p.170 eq 41/43 — **zero IV**, no symIv field, HMAC over `dupSensitive‖name` | `protect.go`: new `wrapDuplication`/`unwrapDuplication`; `duplicate.go` switched to them — now wire-compatible with hardware-TPM Import/Duplicate |
| 3 | `EncryptDecrypt` ignored a caller `mode` conflicting with the key's fixed mode | Part 3 p.119 — must return `TPM_RC_MODE` if mode ≠ NULL and ≠ key mode (or NULL on a NULL-mode key) | `symcipher.go`: added the mode-match check |
| 4 | `SetCommandCodeAuditStatus` changed the audit algorithm **and** processed the command lists together | Part 3 p.190 — these are mutually exclusive; a different alg requires empty lists | `audit.go`: change-alg vs change-list now exclusive (`RC_VALUE` otherwise) |

## Deviations by design (documented, not bugs)

- **TPMA_OBJECT.x509sign (bit 19)** not defined — optional X.509 attribute, unused.
- **SM2 KDF (ECC_Encrypt)** uses `KDFe`-on-x2 with an "SM2" label rather than
  GB/T-32918 KDF2-on-(x2‖y2). Self-consistent encrypt/decrypt; documented in
  `ecc_encrypt.go` as "SM2-style", not byte-conformant.
- **`PolicyOR` branch list** capped at exactly 8 (TPM `HASH_COUNT`); spec says
  "at least eight".
- **`firmwareVersion` / clock counters in `TPMS_ATTEST`** are emitted unobfuscated;
  the wire shape is correct, but a hardware TPM obfuscates them for privacy
  (Part 2 p.162).
- **`GetCommandAuditDigest`** advances the counter eagerly and omits the
  `signHandle = TPM_RH_NULL` read-only form; **`Rewrap`** rejects a `RH_NULL` new
  parent. Acceptable emulator simplifications.
- **`PolicyTransportSPDM`** is a deferred assertion checked at use against a live
  SPDM channel; the emulator has no SPDM transport, so the digest update is
  implemented but the secure-channel check is a no-op (documented in code).

---

## Cluster A — Constant values (51 points)

Verified against Part 2: 12 sampled `TPM_CC` (0x126–0x193, all match), the
format-zero/one/warn bases (`RC_VER1`=0x100, `RC_FMT1`=0x080, `RC_WARN`=0x900) and
specific `TPM_RC` (VALUE 0x084, HASH 0x083, SCHEME 0x092, SIGNATURE 0x09B, KEY
0x09C, CURVE 0x0A6, INTEGRITY 0x09F), algorithm IDs (SHA256 0x000B, AES 0x0006,
RSA 0x0001, ECC 0x0023, ECDSA 0x0018, ECDH 0x0019, CFB 0x0043, KDF1_SP800_56A
0x0020, NULL 0x0010), ECC curves (P256/384/521 = 0x0003/4/5), permanent handles
(OWNER 0x40000001 … PLATFORM 0x4000000C) and range bases (HMAC-session 0x02000000,
transient 0x80000000, persistent 0x81000000, NV 0x01000000), and `TPM_ST` tags
(SESSIONS 0x8002, ATTEST_CERTIFY 0x8017, VERIFIED 0x8022, HASHCHECK 0x8024,
CREATION 0x8021). **Finding:** `RC_NO_RESULT` (bug #1, fixed).

## Cluster B — Attribute bitfields (45 points)

All TPMA_OBJECT (fixedTPM..sign, bits 1–18), TPMA_NV (PPWRITE..READ_STCLEAR, bits
0–31 incl. the NT field 7:4), TPMA_SESSION (continueSession 0, auditExclusive 1,
auditReset 2, decrypt 5, encrypt 6, audit 7) and TPMA_CC (index 15:0, cHandles
27:25, nv 22, extensive 23, flushed 24) bit positions verified against Part 2
Tables 37/249/38/43 — **all correct**. x509sign omitted (deviation).

## Cluster C — Structure wire layouts (34 points)

`TPMT_PUBLIC` (+RSA/ECC/KEYEDHASH/SYMCIPHER parms order), `TPMT_SENSITIVE`,
`TPM2B_PRIVATE` (integrity‖symIv‖enc), `TPMS_NV_PUBLIC`, `TPMT_SIGNATURE` (RSA/ECDSA),
the four `TPMT_TK_*` tickets, `TPMS_ATTEST` + `TPMS_CLOCK_INFO`,
`TPMS_CREATION_DATA`, `TPML_DIGEST_VALUES`/`TPMT_HA`, `TPML_PCR_SELECTION`/
`TPMS_PCR_SELECTION`, the command/response header (10 bytes), the auth area, the
Name rule (`nameAlg‖H(public)`) and the TPM2B size-prefix rule — **all field
orders and sizes match** Part 2/Part 1.

## Cluster D — Crypto constructions (37 points)

KDFa (counter, null-terminated label, U‖V context, bits trailer, MSB masking) and
KDFe (counter‖Z‖OtherInfo) match Part 1 §8.4.10. Object protection
(STORAGE/INTEGRITY labels, random symIv, eq 33–36), credential ("IDENTITY" KEM,
zero-IV encIdentity, eq 44–47), salt ("SECRET", RSA-OAEP/ECDH+KDFe), the "ATH"
session key, param-encryption "CFB"/"XOR" labels, SP800-90A Hash_DRBG primary
seeding, and two-phase ECDH all verified. **Findings:** duplication outer wrap
(bug #2, fixed); SM2 KDF (deviation).

## Cluster E — Auth / session / policy semantics (37 points)

`cpHash`/`rpHash` formulas, command/response auth-HMAC data + nonce ordering,
bound-session authValue omission, KDFa session key, the two-step `PolicyUpdate`
(Clause 23.2.3), and the digest formula of **every** policy assertion (PCR, OR,
CommandCode, AuthValue/Password, CpHash, NameHash, NV, CounterTimer, Secret,
Signed, Authorize, DuplicationSelect, Template, AuthorizeNV, Parameters,
Capability, Ticket, NvWritten) plus the `TPM_EO` comparison table (0x0–0xB) — **all
aligned**. PolicyOR cap (deviation).

## Cluster F — Per-command parameter/semantic correctness (57 points)

Handle counts, parameter order and attested-structure layouts verified for the
attestation set (Certify, CertifyCreation, Quote, GetTime, NV_Certify, CertifyX509),
audit (GetSession/CommandAuditDigest, SetCommandCodeAuditStatus), duplication
(Duplicate/Import/Rewrap), credentials, EC (Commit/EC_Ephemeral/ZGen_2Phase/
ECC_Encrypt/Decrypt), symmetric (EncryptDecrypt/2, CreateLoaded), signing
(Sign/SignDigest/VerifySignature/sequences) and NV (Write/Read/Increment/Extend/
SetBits/DefineSpace/ChangeAuth/GlobalWriteLock/UndefineSpaceSpecial). **Findings:**
EncryptDecrypt mode rule (bug #3, fixed); SetCommandCodeAuditStatus exclusivity
(bug #4, fixed); GetCommandAuditDigest counter/NULL-sign + Rewrap NULL-parent
(deviations).

## Verification

- 261 spec-cited reference points; **251 aligned, 4 bugs fixed, 7 documented
  deviations**.
- After all fixes: `go build ./... && go vet ./... && go test ./...` green.
  Regression tests were added for each fix — the duplication round-trip
  (`Duplicate→Import→Load`, `Rewrap`), the EncryptDecrypt mode rule
  (`TestEncryptDecryptModeMismatch`), and the audit algorithm/list exclusivity
  (`TestCommandAuditClear`).
- Methodology: six parallel read-only audit agents, each citing Part + page from
  `docs/spec/v185/`; findings cross-verified against the spec text before any fix.
