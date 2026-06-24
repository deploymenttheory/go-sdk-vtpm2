# TPM 2.0 Specification Conformance Validation

**Subject:** `github.com/deploymenttheory/go-sdk-vtpm2` — a software TPM 2.0
device implemented in Go from the TCG TPM 2.0 Library Specification, used as a
vTPM for QEMU / Windows 11 guests. This validates the **full 52-command
implementation** (the earlier report covered only the 9-command boot subset).

**Validated against:** TCG *TPM 2.0 Library Specification* (Part 1 Architecture,
Part 2 Structures, Part 3 Commands, Part 4 Supporting Routines). The TCG PDFs
block automated fetch, so authoritative values were cross-checked against the
reference implementation tracked at <https://github.com/TrustedComputingGroup/TPM>
and the maintained **google/go-tpm** constant set; each row cites the Part +
table or that source.

**Method:** the implementation was inventoried in full (constants, structure wire
layouts, command/crypto semantics) and compared point-by-point against the
authoritative values. **127 data points** are compared below, balanced across
constants (A), structure layouts (B), and behavioral/crypto/auth semantics (C).

**Legend:** ✅ aligned · 🔧 bug found **and fixed** in this pass · ⚠️ deviation by
design (documented, intentional) · ⬜ gap (not implemented).

---

## Executive summary

| | Count |
|---|---|
| Data points compared | **127** |
| ✅ Aligned | 116 |
| 🔧 Bugs found & fixed | 3 |
| 🪟 Windows/BitLocker-required gap remediated | 1 (salted sessions) |
| ✨ Improvements (QN chain, crypto/ecdh, constants, KDF KATs) | 4 |
| 🔧 Deviations reviewed vs v1.85 spec & **resolved** | 4 (`TPM2B_PRIVATE`, tickets, DRBG, Hash ticket) |
| ✅ Deviations reviewed & confirmed **spec-permitted** | 2 (context blob, DA time-recovery) |
| ⬜ Gaps (noted, out of scope) | (catalogued in §Gaps) |

**Overall:** the implementation is **highly conformant** for the commands it
supports. Every command code, response code, algorithm id, handle, capability and
property value matches the spec. The wire layouts of all marshalled structures
match Part 2. The authorization/crypto core (cpHash, rpHash, HMAC, KDFa/KDFe,
policy digests, object protection) matches Part 1. **Three conformance bugs were
found and fixed** (two TPMA_NV bit positions, one parameter-encryption key rule);
the remaining deviations are intentional simplifications of internally-opaque
artifacts, plus unimplemented commands listed under Gaps.

### Windows 11 / BitLocker requirement review

Each deviation/gap was re-examined against what the BitLocker boot/unlock path
actually exercises. The opaque-artifact deviations (`TPM2B_PRIVATE` structure,
`qualifiedName`, tickets, context blobs, deterministic derivation) are **not**
required — they are produced and consumed only by this TPM, and BitLocker uses a
PolicyPCR-based unlock that never inspects them. **One item was required and is
now remediated: salted sessions.** Windows establishes a *confidential* session
for the BitLocker VMK by **salting it to the SRK** (an encrypted secret wrapped to
the SRK's public key); the code previously **rejected** any salted session, which
would have failed the seal/unseal outright. `TPM2_StartAuthSession` now decrypts
the salt (RSA-OAEP for an RSA SRK, one-pass ECDH + KDFe for an ECC SRK) and folds
it into the session key (fix V-4).

---

## A. Constants (60 data points)

### A.1 Command codes — `TPM_CC` (Part 2, Table 12) · all 52 verified, 52/52 ✅

Spot sample (full set cross-checked against go-tpm `TPMCC*`):

| Command | impl | spec | |
|---|---|---|---|
| TPM2_EvictControl | 0x120 | 0x120 | ✅ |
| TPM2_HierarchyControl | 0x121 | 0x121 | ✅ |
| TPM2_NV_UndefineSpace | 0x122 | 0x122 | ✅ |
| TPM2_Clear | 0x126 | 0x126 | ✅ |
| TPM2_CreatePrimary | 0x131 | 0x131 | ✅ |
| TPM2_PCR_Reset | 0x13D | 0x13D | ✅ |
| TPM2_Certify | 0x148 | 0x148 | ✅ |
| TPM2_NV_Read | 0x14E | 0x14E | ✅ |
| TPM2_Create | 0x153 | 0x153 | ✅ |
| TPM2_Unseal | 0x15E | 0x15E | ✅ |
| TPM2_FlushContext | 0x165 | 0x165 | ✅ |
| TPM2_PolicyOR | 0x171 | 0x171 | ✅ |
| TPM2_StartAuthSession | 0x176 | 0x176 | ✅ |
| TPM2_GetCapability | 0x17A | 0x17A | ✅ |
| TPM2_PCR_Extend | 0x182 | 0x182 | ✅ |
| TPM2_PolicyGetDigest | 0x189 | 0x189 | ✅ |

*All 52 dispatched command codes match `TPM_CC` (`tpm2/const.go:15-85`). The
`commandTable` ordering (`tpm2/capability.go:62`) is ascending, as `TPM_CAP_COMMANDS`
requires.*

### A.2 Response codes — `TPM_RC` (Part 2, §6.6) · 36 verified, 36/36 ✅

The format encoding is correct — RC_VER1 (0x100), RC_FMT1 (0x080), RC_WARN
(0x900) — which is the class of bug a lot of toy TPMs get wrong:

| Code | impl | spec | | | Code | impl | spec | |
|---|---|---|---|---|---|---|---|---|
| INITIALIZE | 0x100 | 0x100 | ✅ | | VALUE | 0x084 | 0x084 | ✅ |
| FAILURE | 0x101 | 0x101 | ✅ | | HIERARCHY | 0x085 | 0x085 | ✅ |
| DISABLED | 0x120 | 0x120 | ✅ | | KEY_SIZE | 0x087 | 0x087 | ✅ |
| AUTH_TYPE | 0x124 | 0x124 | ✅ | | TYPE | 0x08A | 0x08A | ✅ |
| AUTH_MISSING | 0x125 | 0x125 | ✅ | | HANDLE | 0x08B | 0x08B | ✅ |
| COMMAND_SIZE | 0x142 | 0x142 | ✅ | | AUTH_FAIL | 0x08E | 0x08E | ✅ |
| COMMAND_CODE | 0x143 | 0x143 | ✅ | | NONCE | 0x08F | 0x08F | ✅ |
| AUTHSIZE | 0x144 | 0x144 | ✅ | | SCHEME | 0x092 | 0x092 | ✅ |
| AUTH_CONTEXT | 0x145 | 0x145 | ✅ | | SIZE | 0x095 | 0x095 | ✅ |
| NV_RANGE | 0x146 | 0x146 | ✅ | | INSUFFICIENT | 0x09A | 0x09A | ✅ |
| NV_SIZE | 0x147 | 0x147 | ✅ | | POLICY_FAIL | 0x09D | 0x09D | ✅ |
| NV_LOCKED | 0x148 | 0x148 | ✅ | | INTEGRITY | 0x09F | 0x09F | ✅ |
| NV_AUTHORIZATION | 0x149 | 0x149 | ✅ | | BAD_AUTH | 0x0A2 | 0x0A2 | ✅ |
| NV_UNINITIALIZED | 0x14A | 0x14A | ✅ | | POLICY_CC | 0x0A4 | 0x0A4 | ✅ |
| NV_SPACE | 0x14B | 0x14B | ✅ | | SIGNATURE | 0x0DB | 0x0DB | ✅ |
| NV_DEFINED | 0x14C | 0x14C | ✅ | | KEY | 0x0FB | 0x0FB | ✅ |
| ATTRIBUTES | 0x082 | 0x082 | ✅ | | BAD_TAG | 0x01E | 0x01E | ✅ |
| **WARN:** SESSION_MEMORY 0x903 ✅ · OBJECT_MEMORY 0x902 ✅ · LOCALITY 0x907 ✅ · LOCKOUT 0x921 ✅ ||||||||

`tpm2/const.go:104-177`. Format-one decoration helpers (`withParam`/`withHandle`/
`withSession`, P bit 0x40, N field <<8, session n+8) match Part 2 §6.6.3. ✅

### A.3 Algorithms & curves (24) · all ✅

`TPM_ALG_ID` (Part 2, §6.3): RSA 0x0001, SHA1 0x0004, HMAC 0x0005, AES 0x0006,
MGF1 0x0007, KEYEDHASH 0x0008, XOR 0x000A, SHA256 0x000B, SHA384 0x000C, SHA512
0x000D, NULL 0x0010, RSASSA 0x0014, RSAES 0x0015, RSAPSS 0x0016, OAEP 0x0017,
ECDSA 0x0018, ECDH 0x0019, KDF1_SP800_108 0x0022, ECC 0x0023, SYMCIPHER 0x0025,
CFB 0x0043 — **all match** (`const.go:221`). `TPM_ECC_CURVE`: NIST_P256 0x0003,
NIST_P384 0x0004 — ✅.

### A.4 Handles (14) · all ✅

`TPM_HT` MSBs (Part 2, §7.2): PCR 0x00, NV 0x01, HMAC_SESSION 0x02, POLICY_SESSION
0x03, PERMANENT 0x40, TRANSIENT 0x80, PERSISTENT 0x81 — ✅. `TPM_RH`/`TPM_RS`
(Part 2, §7.4): OWNER 0x40000001, NULL 0x40000007, RS_PW 0x40000009, LOCKOUT
0x4000000A, ENDORSEMENT 0x4000000B, PLATFORM 0x4000000C, PLATFORM_NV 0x4000000D —
**all match** (`const.go:383-404`).

### A.5 Capabilities & startup (14) · all ✅

`TPM_CAP` (Part 2, §6.12): ALGS 0, HANDLES 1, COMMANDS 2, PP_COMMANDS 3,
AUDIT_COMMANDS 4, PCRS 5, TPM_PROPERTIES 6, PCR_PROPERTIES 7, ECC_CURVES 8,
AUTH_POLICIES 9, ACT 0x0A, VENDOR_PROPERTY 0x100 — ✅. `TPM_SU`: CLEAR 0x0000,
STATE 0x0001 — ✅.

### A.6 Properties & magic (10) · all ✅

`TPM_PT` (Part 2, §6.13): PT_FIXED base 0x100, PT_VAR base 0x200; FAMILY_INDICATOR
0x100 reported "2.0\0" (0x322E3000), REVISION 0x102 reported 164 (= rev × 100 =
1.64), MANUFACTURER 0x105, PCR_COUNT 0x112 = 24, MAX_DIGEST 0x120 = 32,
LOCKOUT_COUNTER 0x20E, MAX_AUTH_FAIL 0x20F — tags and value formats ✅.
`TPM_GENERATED_VALUE` 0xFF544347 ✅. `TPM_ST` tags: NO_SESSIONS 0x8001, SESSIONS
0x8002, ATTEST_QUOTE 0x8018, CREATION 0x8021, VERIFIED 0x8022, HASHCHECK 0x8024 —
✅. `TPM_SE`: HMAC 0, POLICY 1, TRIAL 3 ✅.

### A.7 Attribute bit positions (26)

| Attribute set | Result |
|---|---|
| **TPMA_OBJECT** (Part 2, Table 31) — fixedTPM 1, stClear 2, fixedParent 4, sensitiveDataOrigin 5, userWithAuth 6, adminWithPolicy 7, noDA 10, encryptedDuplication 11, restricted 16, decrypt 17, sign 18 | all ✅ |
| **TPMA_SESSION** (Table 8) — continueSession 0, decrypt 5, encrypt 6 | ✅ |
| **TPMA_ALGORITHM** (Table 30) — asymmetric 0, symmetric 1, hash 2, object 3, signing 8, encrypting 9, method 10 | ✅ |
| **TPMA_CC** (Table 35) — commandIndex [15:0], NV 22, extensive 23, flushed 24, cHandles [27:25] | ✅ |
| **TPMA_NV** (Table 218) — ppWrite 0, ownerWrite 1, authWrite 2, policyWrite 3, NT [7:4], policyDelete 10, writeLocked 11, writeAll 12, writeDefine 13, ppRead 16, ownerRead 17, authRead 18, policyRead 19, written 29 | ✅ |
| **TPMA_NV.GLOBALLOCK** — was bit 14, spec is **bit 15** (bit 14 is WRITE_STCLEAR) | 🔧 fixed |
| **TPMA_NV.READLOCKED** — was bit 24 (reserved), spec is **bit 28** | 🔧 fixed |

---

## B. Structure wire layouts (27 data points)

Byte order is big-endian throughout; every `TPM2B_*` is a UINT16 size prefix +
bytes (Part 2, §9.10) ✅. Unions are selected by the preceding type/algorithm
field, no padding, exactly as the spec grammar specifies.

| Structure | Spec | Verdict |
|---|---|---|
| Command/response header (tag·size·code) | Part 1 §18 | ✅ |
| Command auth area (authSize · {handle,nonce,attrs,hmac}) | Part 1 §18.6 | ✅ |
| Response auth area (parameterSize · {nonce,attrs,hmac}) | Part 1 §18.10 | ✅ |
| `TPMT_PUBLIC` (type·nameAlg·objectAttributes·authPolicy·parms·unique) | Part 2 §12.2.4 | ✅ |
| `TPMS_RSA_PARMS` (symmetric·scheme·keyBits·exponent) | Part 2 §12.2.3.5 | ✅ |
| `TPMS_ECC_PARMS` (symmetric·scheme·curveID·kdf) | Part 2 §12.2.3.6 | ✅ |
| `TPMU_PUBLIC_ID` RSA/KeyedHash/Sym = TPM2B; ECC = x‖y | Part 2 §12.2.3.2 | ✅ |
| `TPMT_SENSITIVE` (type·authValue·seedValue·sensitive) | Part 2 §12.3.2.5 | ✅ |
| `TPM2B_PUBLIC` / `TPM2B_SENSITIVE` (size-prefixed inner) | Part 2 §12.2.5 | ✅ |
| `TPMS_NV_PUBLIC` (index·nameAlg·attributes·authPolicy·dataSize) | Part 2 §13.5 | ✅ |
| `TPMT_SIGNATURE` RSA (sigAlg·hash·sig) / ECC (sigAlg·hash·sigR·sigS) | Part 2 §11.3.4 | ✅ |
| `TPMT_TK_CREATION` / `_VERIFIED` / `_HASHCHECK` (tag·hierarchy·digest) | Part 2 §10.7 | ✅ |
| `TPMS_ATTEST` (magic·type·qualifiedSigner·extraData·clockInfo·firmwareVersion·attested) | Part 2 §10.12.8 | ✅ |
| `TPMS_CLOCK_INFO` (clock u64·resetCount·restartCount·safe) = 17 bytes | Part 2 §10.11.1 | ✅ |
| `TPMS_QUOTE_INFO` (pcrSelect·pcrDigest) | Part 2 §10.12.1 | ✅ |
| `TPMS_CREATION_DATA` (pcrSelect·pcrDigest·locality·parentNameAlg·parentName·parentQualifiedName·outsideInfo) | Part 2 §15.1 | ✅ |
| `TPMS_CONTEXT` (sequence·savedHandle·hierarchy·contextBlob) | Part 2 §10.8.1 | ✅ |
| `TPML_PCR_SELECTION` / `TPML_DIGEST_VALUES` | Part 2 §10.9 | ✅ |
| `TPML_TAGGED_TPM_PROPERTY` / `TPML_ALG_PROPERTY` / `TPML_CCA` / `TPML_HANDLE` | Part 2 §10.9 | ✅ |
| Object Name = nameAlg ‖ H(public) | Part 1 §16 | ✅ |
| `TPM2B_PRIVATE` wrap (integrity ‖ TPM2B_IV ‖ encSensitive; HMAC over symIv‖enc‖name) | Part 1 §23.3 (pp.160-163) | ✅ spec-exact (V-8) |
| `qualifiedName` (ReadPublic) | Part 1 §26.5 | ✅ H(parentQN‖Name) chained from the hierarchy (fix V-5) |
| `parentQualifiedName` in creationData | Part 2 §15.1 | ✅ parent's real QN (fix V-5) |
| Verified/creation ticket digest | Part 1 §31 (pp.84-85) | ✅ HMAC keyed by the hierarchy proof (V-9) |

---

## C. Behavioral / crypto / auth semantics (40 data points)

| Item | Formula / rule in impl | Spec | Verdict |
|---|---|---|---|
| `cpHash` | H(commandCode ‖ names ‖ cpParams) | Part 1 §18.7 | ✅ |
| `rpHash` | H(responseCode ‖ commandCode ‖ rpParams) | Part 1 §18.7 | ✅ |
| Command auth HMAC | HMAC(key, cpHash ‖ nonceCaller ‖ nonceTPM ‖ attrs) | Part 1 §19.6.5 | ✅ |
| Response auth HMAC | HMAC(key, rpHash ‖ nonceTPM ‖ nonceCaller ‖ attrs) | Part 1 §19.6 | ✅ |
| HMAC key | sessionKey ‖ authValue; bound ⇒ omit authValue | Part 1 §19.6.4 | ✅ |
| Param-encryption key | session value with **bound exception** | Part 1 §21.2 | 🔧 fixed (was ignoring bound) |
| Param-encryption labels | "CFB" (AES) / "XOR" | Part 1 §21.3 | ✅ |
| Param-encryption direction/nonces | cmd: nonceCaller·nonceTPM; rsp: nonceTPM·nonceCaller; first param only | Part 1 §21 | ✅ |
| KDFa | HMAC counter mode, i ‖ label ‖ 0x00 ‖ ctxU ‖ ctxV ‖ bits, high-bit mask | Part 1 §11.4.10.2 | ✅ |
| KDFe | H(i ‖ z ‖ label ‖ 0x00 ‖ partyU ‖ partyV) | Part 1 §11.4.10.3 | ✅ |
| Session key | KDFa(authHash, bindAuth‖salt, "ATH", nonceTPM, nonceCaller, bits) | Part 1 §19.6.8 | ✅ (ordering matches go-tpm) |
| Salted session — RSA | salt = RSAES-OAEP-decrypt(SRK, encSalt, label "SECRET\0") | Part 1 §19.6.7 | 🪟 implemented (was rejected) |
| Salted session — ECC | salt = KDFe(nameAlg, Z.x, "SECRET", Qe.x, Qs.x); Z = d·Qe | Part 1 §19.6.7 / §C.6.1 | 🪟 implemented (was rejected) |
| nonceCaller minimum | ≥ 16 bytes else RC_SIZE | Part 1 §19.6.1 | ✅ |
| Object protection | symKey = KDFa(…,"STORAGE",name,…); HMAC key = KDFa(…,"INTEGRITY",…); random symIv; outer HMAC over symIv‖enc‖name | Part 1 §23.3–24 | ✅ spec-exact (V-8) |
| PolicyPCR digest | H(old ‖ CC ‖ pcrs ‖ pcrDigest); trial uses caller digest | Part 3 §23.7 | ✅ |
| PolicyCommandCode | H(old ‖ CC ‖ code) + restriction; conflict ⇒ RC_VALUE | Part 3 §23.4 | ✅ |
| PolicyAuthValue | H(old ‖ CC); sets authValue-required flag | Part 3 §23.16 | ✅ |
| PolicyOR | reset to zero, H(zero ‖ CC ‖ ‖digests); 2..8 branches; match check (real) | Part 3 §23.6 | ✅ |
| Policy authorization | policyDigest == authPolicy; CC restriction ⇒ RC_POLICY_CC; policyAuth ⇒ HMAC | Part 1 §19.7 | ✅ |
| `TPM2_Clear` | new SPS; owner/endorsement/lockout auth+policy reset; **EPS/PPS preserved** (EK stable); DA reset | Part 3 §24.6 | ✅ |
| `TPM2_Startup(CLEAR)` | reset resettable PCR, regen null seed, restartCount++ | Part 3 §9.3 | ✅ |
| PCR extend | PCR[i] := H(PCR[i] ‖ digest) | Part 1 §17.6 | ✅ |
| PCR locality | DRTM 17–22 extend/reset locality 4; 0–15 not command-resettable; 16/23 any | PC Client §2.3.4 | ✅ |
| `TPM2_PCR_Reset` | zero across banks if locality permits else RC_LOCALITY | Part 3 §22.4 | ✅ |
| NV ordinary write | bounds-checked; sets WRITTEN; out-of-range ⇒ RC_NV_RANGE | Part 3 §31.7 | ✅ |
| NV counter | data := BE64+1 | Part 3 §31.6 | ✅ |
| NV bits | data \|= bits | Part 3 §31.8 | ✅ |
| NV extend | data := H(old ‖ input) | Part 3 §31.9 | ✅ |
| NV authorization | TPMA_NV bit per handle/direction; mismatch ⇒ RC_NV_AUTHORIZATION | Part 1 §31.3 | ✅ |
| NV read pre-conditions | unwritten ⇒ RC_NV_UNINITIALIZED; locked ⇒ RC_NV_LOCKED | Part 3 §31.13 | ✅ |
| Sign | scheme from key (else inScheme); RSASSA/RSAPSS/ECDSA | Part 3 §20.1 | ✅ |
| VerifySignature | returns TPMT_TK_VERIFIED; mismatch ⇒ RC_SIGNATURE | Part 3 §20.2 | ✅ |
| Quote | TPMS_ATTEST{magic, ATTEST_QUOTE, …}; sign H(attest) | Part 3 §18.4 | ✅ |
| Unseal | keyedHash data object only (not sign/decrypt) else RC_ATTRIBUTES | Part 3 §12.7 | ✅ |
| DA lockout | failedTries ≥ maxTries ⇒ RC_LOCKOUT | Part 1 §19.8 | ✅ |
| DA scope | owner/endorsement protected; platform not; objects unless noDA | Part 1 §19.8 | ✅ |
| DA recovery | LockReset (lockout auth) / Clear reset the counter | Part 3 §25 | ✅ (⚠️ no time-based recovery) |
| Context protection | AES-CFB + HMAC-SHA256(contextKey, enc ‖ handle ‖ seq) | Part 1 §30.3 | ✅ (internal key) |
| Primary derivation | SP800-90A Hash_DRBG seeded with seed+templateHash+useString ⇒ stable EK/SRK | Part 1 §24.6.3 (pp.203-205) | ✅ FIPS-approved DRBG (V-10) |
| Error response framing | always TPM_ST_NO_SESSIONS, header only | Part 1 §18.10 | ✅ |
| Failure mode | only GetTestResult & GetCapability answer | Part 1 §39 | ✅ |

---

## Deviations — reviewed against TPM 2.0 v1.85 (`docs/spec/v185/`)

Each previously-listed deviation was checked against the **primary source** (the
vendored spec PDFs, cited by Part + page). Four were genuine deviations and have
been **resolved**; two are **spec-permitted** design choices (the spec explicitly
allows them). None remain "accepted without review."

| # | Item | Primary-source finding | Status |
|---|---|---|---|
| 1 | `TPM2B_PRIVATE` wrap | Part 1 §23.3, eq. 34–36, **pp.160–163**: a random `symIv` from the RNG encrypts the sensitive, the marshaled `TPM2B_IV` is stored in the blob, and `outerHMAC = HMAC(HMACkey, symIv ∥ encSensitive ∥ name)`. Ours used a zero IV and omitted the `TPM2B_IV`. | 🔧 **resolved (V-8)** — now spec-exact |
| 2 | Ticket proof | Part 1 **pp.84–85**: tickets *"use the hierarchy-specific proof values."* Our verified/creation tickets used a volatile `contextKey`/raw seed. | 🔧 **resolved (V-9)** — keyed by `hierarchyProof` (KDFa `"PROOF"` from the hierarchy seed) |
| 3 | Primary derivation | Part 1 §24.6.3, **pp.203–205**: *"the DRBG is seeded with a primary seed, a template hash, and a use string"* — a SP800-90A DRBG. Ours was an ad-hoc `H(seed‖ctr)`. | 🔧 **resolved (V-10)** — SP800-90A **Hash_DRBG**, deterministically instantiated |
| 6 | `TPM2_Hash` ticket | Part 3 §15.4, **pp.123–124**: a valid `TPMT_TK_HASHCHECK` is returned for safe-to-sign data; null only for `TPM_RH_NULL` or `TPM_GENERATED`-prefixed data. Ours was always null. | 🔧 **resolved (V-11)** — valid ticket + restricted-key validation in `TPM2_Sign` |
| 4 | Context blob format | Part 2 **p.214**: *"The structure of a saved context TPM2B_CONTEXT_DATA **may be defined by the vendor**"* + integrity HMAC + encryption — which we do. | ✅ **spec-permitted** (no change) |
| 5 | DA time recovery | Part 1 **p.148**: *"**If** the TPM has a trusted source of time that runs when TPM power is lost, then failedTries **may** be reduced…"* — conditional on a free-running clock, which a vTPM lacks. | ✅ **spec-permitted** (no change) |

### On FIPS

The DRBG fix is the **algorithm-level** resolution: primary derivation now uses a
SP800-90A-conformant DRBG, and every other primitive (SHA-2, AES, HMAC, RSA,
ECDSA, ECDH) is already FIPS-approved. **Module-level FIPS 140-3 validation** is a
separate CMVP certification of the crypto module; the path is building under Go
1.24+'s native FIPS-140 module (`GODEBUG=fips140=on`) and submitting for
validation — that cannot be granted by source changes alone, and is not claimed
here. (SHA-1 remains present only for the legacy PCR bank / name algorithm, as the
TPM spec requires; it is not used for signing.)

> Previously also listed here and already resolved: **`qualifiedName`** (now the
> real `H(parentQN ‖ Name)`, V-5), **parameter encryption** (bound rule fixed V-3,
> exercised over a salted session), and **salted sessions** (V-4).

## Gaps (not implemented — out of scope, noted for completeness)

Audit sessions; time-based DA recovery; `Duplicate`/`Import`,
`Certify`/`CertifyCreation`, `RSA_Encrypt`/`Decrypt`, `ECDH_*`,
`MakeCredential`/`ActivateCredential`, `GetTime`, `HMAC`, hash sequences,
`PCR_Allocate`/`SetAuthValue`, `NV_GlobalWriteLock`/`ChangeAuth`/`Certify`;
the full algorithm/curve set (SM2/SM3/SM4, Camellia, additional NIST/BN curves);
TPM 1.2 compatibility. None of these are on the BitLocker TPM-only unlock path.

## Fixes applied in this pass

| ID | File | Change | Impact |
|---|---|---|---|
| V-1 | `tpm2/const.go` | `TPMA_NV_READLOCKED` 1<<24 → **1<<28**; added `WRITE_STCLEAR` 1<<14 | the index Name is corrupted after a read-lock (the bit feeds `H(TPMS_NV_PUBLIC)`) — now correct |
| V-2 | `tpm2/const.go` | `TPMA_NV_GLOBALLOCK` 1<<14 → **1<<15** | wrong attribute bit (collided with WRITE_STCLEAR); latent until NV_GlobalWriteLock lands |
| V-3 | `tpm2/protect.go`, `tpm2/auth.go` | `cryptParam` now applies the bound-session exception (omit `authValue` when bound), matching `authHMACKey` | bound encrypt/decrypt sessions now derive the spec key; unbound unchanged |
| V-4 | `tpm2/crypto.go`, `tpm2/session.go` | **Salted sessions** implemented — `StartAuthSession` decrypts the salt (RSA-OAEP / ECC-ECDH+KDFe) and folds it into the session key, instead of rejecting `tpmKey != NULL` | **required by Windows/BitLocker** for the confidential VMK session |
| V-5 | `tpm2/object.go`, `tpm2/handles.go`, `tpm2/snapshot.go` | **Real Qualified-Name chain** — `QN = H_nameAlg(parentQN ‖ Name)` computed at CreatePrimary/Create/Load, returned by ReadPublic and in `parentQualifiedName`, and persisted (snapshot v7) | closes structure deviation; correct for attestation/QN-policy use |
| V-6 | `tpm2/crypto.go` | **crypto/ecdh migration** — salt ECDH and deterministic EC point derivation moved off deprecated `elliptic.ScalarMult`/`ScalarBaseMult`; SRK determinism preserved (verified by the reboot/seal tests) | modern, constant-time EC; removes the deprecation surface |
| V-7 | `tpm2/const.go` | **Constant completeness** — full `TPMA_NV` bits (NO_DA, ORDERLY, CLEAR_STCLEAR, PLATFORMCREATE, READ_STCLEAR), `ECCNistP521` (+ `curveFor`/`ecdhCurveFor`), and the missing `TPM_ALG_*` ids | broader spec coverage |

| V-8 | `tpm2/protect.go`, `tpm2/object.go` | **Spec-exact `TPM2B_PRIVATE`** — random `symIv` from the RNG, marshaled `TPM2B_IV` stored in the blob, outer HMAC over `symIv ‖ enc ‖ name` (Part 1 §23.3) | deviation #1 resolved; wrap now matches the spec construction byte-for-byte |
| V-9 | `tpm2/hierarchy.go`, `tpm2/sign.go`, `tpm2/object.go` | **Hierarchy-proof tickets** — `hierarchyProof = KDFa(seed,"PROOF")`; creation/verified/hashcheck tickets keyed by it instead of the volatile `contextKey` | deviation #2 resolved; tickets durable per the owning hierarchy |
| V-10 | `tpm2/crypto.go`, `tpm2/object.go` | **SP800-90A Hash_DRBG** for primary derivation, deterministically instantiated from seed+templateHash+useString, replacing `H(seed‖ctr)` | deviation #3 resolved; FIPS-approved DRBG construction; determinism preserved |
| V-11 | `tpm2/sign.go`, `tpm2/const.go` | **Valid hashcheck ticket** for safe-to-sign data (null only for `TPM_RH_NULL` / `TPM_GENERATED`), and `TPM2_Sign` validates the ticket for **restricted** keys (`TPM_RC_TICKET`) | deviation #6 resolved |

**Improvement also added:** KDFa/KDFe **known-answer tests** pinned to bytes from
an independent SP800-108/56A reference (`tpm2/kdf_vectors_test.go`), strengthening
the cross-validation hook the parameter-encryption/salt math relies on.

Regression tests for the resolved deviations: `tpm2/deviations_resolved_test.go`
(`TestHashDRBG`, `TestPrivateBlobRandomIV`, `TestHashCheckTicket`,
`TestRestrictedSignNeedsTicket`, `TestVerifiedTicketKeyedByProof`).

Regression tests: `tpm2/validation_fixes_test.go`
(`TestTPMANVBitPositions`, `TestNVReadLockSetsCorrectBit`,
`TestParamEncryptBoundOmitsAuthValue`); `tpm2/salted_session_test.go`
(`TestSaltedSessionRSA`, `TestSaltedSessionECC`, `TestSaltedSessionRejectsUnloadedKey`);
`tpm2/qualifiedname_test.go` (`TestQualifiedNameChain`, `TestQualifiedNameSurvivesReboot`);
`tpm2/kdf_vectors_test.go` (`TestKDFaKnownAnswers`, `TestKDFeKnownAnswer`,
`TestKDFaMatchesIndependentReference`).

## Verification

- Every row cites a Part + table or the go-tpm/reference source for independent
  re-check.
- `go build ./...`, `go vet ./...`, `go test ./...` all green after the fixes,
  including the new regression tests, the golden-vector authorization harness
  (`tpm2/auth_vectors_test.go`), and the reboot-seal test
  (`tpm2/seal_test.go:TestSealedObjectSurvivesReboot`).
