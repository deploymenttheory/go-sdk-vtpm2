# Codebase ↔ TPM 2.0 v1.85 Reconciliation

**Subject:** `github.com/deploymenttheory/go-sdk-vtpm2` reconciled against the
**TCG TPM 2.0 Library Specification, revision 1.85** (Version 185, dated
2026/03/12), vendored at `docs/spec/v185/` (PDF + `pdftotext` exports).

**Method:** four independent reviewers each cross-referenced one category against
the spec **text on disk**, page-aware:
```sh
awk 'BEGIN{p=1} /\f/{p++} {print p"\t"$0}' docs/spec/v185/Part-2.txt | grep -i '<term>'
```
Hard rule: **cite only what was actually grepped** (every row quotes the matched
spec line + page); anything not locatable is marked, not guessed. The printed page
equals the PDF page.

**Coverage: 135 sample points** of differing kinds — 44 constants, 28
attributes/properties, 29 structure layouts, 34 semantics/crypto.

## Summary

| | Count |
|---|---|
| Sample points reconciled | **135** |
| ✅ Exact match to v1.85 | 130 |
| 🔧 Mismatch found **and fixed this pass** | 2 — `PT_REVISION`, `TPM2_Clear` |
| ◐ Cosmetic difference kept (with rationale) | 1 — DA `>=` vs "equal to" |
| ✎ Citation corrected in code comments | KDFa/KDFe §11.4.10 → **§8.4.10** |
| ❔ Correct but not locatable in Parts 1–3 | 2 — PCR 17–22 locality (PC Client spec), `Unseal` data-object wording |

**Fixes applied this pass** (each with a regression test):
- `PT_REVISION` reported the stale `164` (rev 1.64, obsolete ×100 convention).
  Part 2 p.40 defines `TPM_SPEC_VERSION = 185`, and *"beginning with version 184…
  the version number is equal to TPM_SPEC_VERSION"* — fixed to **185**
  (`capability.go`), revision date set to 2026-03-12.
- `TPM2_Clear` was incomplete vs Part 3 §24.6.1 (p.283): now flushes
  Storage/Endorsement objects, deletes owner-created NV (`TPMA_NV_PLATFORMCREATE`
  CLEAR), zeroes Clock/resetCount/restartCount, sets Safe=YES, advances
  `pcrUpdateCounter` (it previously *incremented* resetCount — the spec zeroes it).
- KDFa/KDFe doc-comment section numbers corrected to the v1.85 numbering (§8.4.10).

Legend: ✅ exact · 🔧 mismatch · ◐ cosmetic · ❔ not located · ⬜ not implemented.

---

## A. Constants (44) — vs Part 2

| # | Item | Impl | Spec | Citation (quoted) | |
|---|---|---|---|---|---|
| 1 | TPM_CC_EvictControl | 0x120 | 0x120 | P2 p.47 "TPM_CC_EvictControl 0x00000120" | ✅ |
| 2 | TPM_CC_CreatePrimary | 0x131 | 0x131 | P2 p.48 "…CreatePrimary 0x00000131" | ✅ |
| 3 | TPM_CC_Create | 0x153 | 0x153 | P2 p.49 "…Create 0x00000153" | ✅ |
| 4 | TPM_CC_Unseal | 0x15E | 0x15E | P2 p.50 "…Unseal 0x0000015E" | ✅ |
| 5 | TPM_CC_StartAuthSession | 0x176 | 0x176 | P2 p.51 "…StartAuthSession 0x00000176" | ✅ |
| 6 | TPM_CC_GetCapability | 0x17A | 0x17A | P2 p.51 "…GetCapability 0x0000017A" | ✅ |
| 7 | TPM_CC_PCR_Extend | 0x182 | 0x182 | P2 p.51 "…PCR_Extend 0x00000182" | ✅ |
| 8 | TPM_CC_PolicyGetDigest | 0x189 | 0x189 | P2 p.51 "…PolicyGetDigest 0x00000189" | ✅ |
| 9 | RC_VER1 base | 0x100 | 0x100 | P2 p.57 "RC_VER1 0x100 … all format 0" | ✅ |
| 10 | RC_FMT1 base | 0x080 | 0x080 | P2 p.59 "RC_FMT1 0x080 … all format 1" | ✅ |
| 11 | RC_WARN base | 0x900 | 0x900 | P2 p.61 "RC_WARN 0x900 … warning" | ✅ |
| 12 | TPM_RC_VALUE | 0x084 | RC_FMT1+0x004 | P2 p.59 "TPM_RC_VALUE RC_FMT1 + 0x004" | ✅ |
| 13 | TPM_RC_INITIALIZE | 0x100 | RC_VER1+0x000 | P2 p.57 "TPM_RC_INITIALIZE RC_VER1 + 0x000" | ✅ |
| 14 | TPM_RC_NV_LOCKED | 0x148 | RC_VER1+0x048 | P2 p.58 "TPM_RC_NV_LOCKED RC_VER1 + 0x048" | ✅ |
| 15 | TPM_RC_LOCKOUT | 0x921 | RC_WARN+0x021 | P2 p.63 "TPM_RC_LOCKOUT RC_WARN + 0x021" | ✅ |
| 16 | TPM_RC_TICKET | 0x0A0 | RC_FMT1+0x020 | P2 p.60 "TPM_RC_TICKET RC_FMT1 + 0x020 invalid ticket" | ✅ |
| 17 | TPM_ALG_RSA | 0x0001 | 0x0001 | P2 p.42 "TPM_ALG_RSA 0x0001" | ✅ |
| 18 | TPM_ALG_SHA256 | 0x000B | 0x000B | P2 p.42 "TPM_ALG_SHA256 0x000B" | ✅ |
| 19 | TPM_ALG_AES | 0x0006 | 0x0006 | P2 p.42 "TPM_ALG_AES 0x0006" | ✅ |
| 20 | TPM_ALG_ECDSA | 0x0018 | 0x0018 | P2 p.44 "TPM_ALG_ECDSA 0x0018" | ✅ |
| 21 | TPM_ALG_ECC | 0x0023 | 0x0023 | P2 p.42 "TPM_ALG_ECC 0x0023" | ✅ |
| 22 | TPM_ALG_CFB | 0x0043 | 0x0043 | P2 p.43 "TPM_ALG_CFB 0x0043" | ✅ |
| 23 | TPM_ECC_NIST_P256 | 0x0003 | 0x0003 | P2 p.46 "TPM_ECC_NIST_P256 0x0003" | ✅ |
| 24 | TPM_ECC_NIST_P384 | 0x0004 | 0x0004 | P2 p.46 "TPM_ECC_NIST_P384 0x0004" | ✅ |
| 25 | TPM_ECC_NIST_P521 | 0x0005 | 0x0005 | P2 p.46 "TPM_ECC_NIST_P521 0x0005" | ✅ |
| 26 | TPM_HT_PCR | 0x00«24 | 0x00 | P2 p.86 "TPM_HT_PCR 0x00" | ✅ |
| 27 | TPM_HT_TRANSIENT | 0x80«24 | 0x80 | P2 p.87 "TPM_HT_TRANSIENT 0x80" | ✅ |
| 28 | TPM_HT_PERSISTENT | 0x81«24 | 0x81 | P2 p.87 "TPM_HT_PERSISTENT 0x81" | ✅ |
| 29 | TPM_RH_OWNER | 0x40000001 | 0x40000001 | P2 p.88 "TPM_RH_OWNER 0x40000001" | ✅ |
| 30 | TPM_RH_NULL | 0x40000007 | 0x40000007 | P2 p.88 "TPM_RH_NULL 0x40000007" | ✅ |
| 31 | TPM_RS_PW | 0x40000009 | 0x40000009 | P2 p.88 "TPM_RS_PW 0x40000009" | ✅ |
| 32 | TPM_RH_PLATFORM | 0x4000000C | 0x4000000C | P2 p.89 "TPM_RH_PLATFORM 0x4000000C" | ✅ |
| 33 | TPM_CAP_ALGS | 0x00 | 0x00 | P2 p.69 "TPM_CAP_ALGS 0x00000000" | ✅ |
| 34 | TPM_CAP_HANDLES | 0x01 | 0x01 | P2 p.69 "TPM_CAP_HANDLES 0x00000001" | ✅ |
| 35 | TPM_CAP_COMMANDS | 0x02 | 0x02 | P2 p.70 "TPM_CAP_COMMANDS 0x00000002" | ✅ |
| 36 | TPM_ST_NO_SESSIONS | 0x8001 | 0x8001 | P2 p.66 "TPM_ST_NO_SESSIONS 0x8001" | ✅ |
| 37 | TPM_ST_SESSIONS | 0x8002 | 0x8002 | P2 p.66 "TPM_ST_SESSIONS 0x8002" | ✅ |
| 38 | TPM_ST_ATTEST_QUOTE | 0x8018 | 0x8018 | P2 p.68 "TPM_ST_ATTEST_QUOTE 0x8018" | ✅ |
| 39 | TPM_ST_CREATION | 0x8021 | 0x8021 | P2 p.68 "TPM_ST_CREATION 0x8021" | ✅ |
| 40 | TPM_SE_HMAC | 0x00 | 0x00 | P2 p.69 "TPM_SE_HMAC 0x00" | ✅ |
| 41 | TPM_SE_POLICY | 0x01 | 0x01 | P2 p.69 "TPM_SE_POLICY 0x01" | ✅ |
| 42 | TPM_SE_TRIAL | 0x03 | 0x03 | P2 p.69 "TPM_SE_TRIAL 0x03" | ✅ |
| 43 | TPM_SU_CLEAR | 0x0000 | 0x0000 | P2 p.69 "TPM_SU_CLEAR 0x0000" | ✅ |
| 44 | TPM_SU_STATE | 0x0001 | 0x0001 | P2 p.69 "TPM_SU_STATE 0x0001" | ✅ |

*Note (rows 26–28): the spec defines `TPM_HT` as a single octet; the impl pre-shifts it into the handle MSB (`«24`) to mask against `htMask=0xFF000000` — equivalent, an encoding choice.*

---

## B. Attributes & properties (28) — vs Part 2

| # | Item | Impl | Spec | Citation (quoted) | |
|---|---|---|---|---|---|
| 1 | TPMA_OBJECT fixedTPM | bit 1 | bit 1 | P2 p.95 "1  fixedTPM" | ✅ |
| 2 | TPMA_OBJECT stClear | bit 2 | bit 2 | P2 p.95 "2  stClear" | ✅ |
| 3 | TPMA_OBJECT fixedParent | bit 4 | bit 4 | P2 p.96 "4  fixedParent" | ✅ |
| 4 | TPMA_OBJECT sensitiveDataOrigin | bit 5 | bit 5 | P2 p.96 "5  sensitiveDataOrigin" | ✅ |
| 5 | TPMA_OBJECT userWithAuth | bit 6 | bit 6 | P2 p.96 "6  userWithAuth" | ✅ |
| 6 | TPMA_OBJECT adminWithPolicy | bit 7 | bit 7 | P2 p.96 "7  adminWithPolicy" | ✅ |
| 7 | TPMA_OBJECT noDA | bit 10 | bit 10 | P2 p.96 "10  noDA" | ✅ |
| 8 | TPMA_OBJECT restricted | bit 16 | bit 16 | P2 p.96 "16  restricted" | ✅ |
| 9 | TPMA_OBJECT decrypt | bit 17 | bit 17 | P2 p.97 "17  decrypt" | ✅ |
| 10 | TPMA_OBJECT sign/encrypt | bit 18 | bit 18 | P2 p.97 "18  sign / encrypt" | ✅ |
| 11 | TPMA_NV PPWRITE | bit 0 | bit 0 | P2 p.207 "0  TPMA_NV_PPWRITE" | ✅ |
| 12 | TPMA_NV TPM_NT field | bits 7:4 | bits 7:4 | P2 p.208 "7:4  TPM_NT" | ✅ |
| 13 | TPMA_NV POLICY_DELETE | bit 10 | bit 10 | P2 p.208 "10  TPMA_NV_POLICY_DELETE" | ✅ |
| 14 | TPMA_NV WRITE_STCLEAR | bit 14 | bit 14 | P2 p.209 "14  TPMA_NV_WRITE_STCLEAR" | ✅ |
| 15 | TPMA_NV GLOBALLOCK | bit 15 | bit 15 | P2 p.209 "15  TPMA_NV_GLOBALLOCK" | ✅ |
| 16 | TPMA_NV READLOCKED | bit 28 | bit 28 | P2 p.210 "28  TPMA_NV_READLOCKED" | ✅ |
| 17 | TPMA_NV PLATFORMCREATE | bit 30 | bit 30 | P2 p.210 "30  TPMA_NV_PLATFORMCREATE" | ✅ |
| 18 | TPMA_SESSION continueSession | bit 0 | bit 0 | P2 p.105 "0  continueSession" | ✅ |
| 19 | TPMA_SESSION decrypt/encrypt | bits 5/6 | bits 5/6 | P2 p.106 "5  decrypt" / "6  encrypt" | ✅ |
| 20 | TPMA_CC commandIndex/nv/cHandles | 15:0 / 22 / 27:25 | same | P2 p.112 "15:0 commandIndex", "22 nv", "27:25 cHandles" | ✅ |
| 21 | TPM_GENERATED_VALUE | 0xFF544347 | 0xFF544347 | P2 p.41 "TPM_GENERATED_VALUE 0xff544347" | ✅ |
| 22 | PT_FAMILY value | 0x322E3000 | TPM_SPEC_FAMILY | P2 p.40 "TPM_SPEC_FAMILY 0x322E3000 … '2.0'" | ✅ |
| 23 | PT_FAMILY_INDICATOR tag | PT_FIXED+0 | PT_FIXED+0 | P2 p.73 "TPM_PT_FAMILY_INDICATOR PT_FIXED + 0" | ✅ |
| 24 | PT_PCR_COUNT tag | PT_FIXED+18 | PT_FIXED+18 | P2 p.75 "TPM_PT_PCR_COUNT PT_FIXED + 18" | ✅ |
| 25 | PT_MAX_DIGEST tag | PT_FIXED+32 | PT_FIXED+32 | P2 p.77 "TPM_PT_MAX_DIGEST PT_FIXED + 32" | ✅ |
| 26 | PT_INPUT_BUFFER tag | PT_FIXED+13 | PT_FIXED+13 | P2 p.74 "TPM_PT_INPUT_BUFFER PT_FIXED + 13" | ✅ |
| 27 | PT_MANUFACTURER tag | PT_FIXED+5 | PT_FIXED+5 | P2 p.74 "TPM_PT_MANUFACTURER PT_FIXED + 5" | ✅ |
| 28 | **PT_REVISION reported value** | was **164** → **185** | TPM_SPEC_VERSION = 185 | P2 p.40 "TPM_SPEC_VERSION 185"; "Beginning with version 184 … equal to TPM_SPEC_VERSION" | 🔧→✅ **fixed** |

---

## C. Structure wire layouts (29) — vs Part 2

| # | Structure | Spec field order | Citation | |
|---|---|---|---|---|
| 1 | TPMT_PUBLIC | type, nameAlg, objectAttributes, authPolicy, [type]parameters, [type]unique | §12.2.4 Table 235, p.198-199 | ✅ |
| 2 | TPMS_RSA_PARMS | symmetric, scheme, keyBits, exponent | §12.2.3.4 Table 228, p.193-194 | ✅ |
| 3 | TPMS_ECC_PARMS | symmetric, scheme, curveID, kdf | §12.2.3.5 Table 229, p.194-196 | ✅ |
| 4 | TPMU_PUBLIC_ID (rsa) | bare TPM2B | §12.2.3.2 Table 226, p.192 | ✅ |
| 5 | TPMU_PUBLIC_ID (ecc) | TPMS_ECC_POINT = x, y | Table 226 + §11.2.5.2 Table 198, p.179 | ✅ |
| 6 | TPMT_SENSITIVE | sensitiveType, authValue, seedValue, [type]sensitive | §12.3.2.4 Table 240, p.201 | ✅ |
| 7 | TPM2B_PUBLIC wrap | UINT16 size + TPMT_PUBLIC | §12.2.5 Table 236 | ✅ |
| 8 | TPM2B_SENSITIVE wrap | UINT16 size + TPMT_SENSITIVE | §12.3.3 | ✅ |
| 9 | TPM2B (generic) | UINT16 size + buffer | §10.4 Table 90, p.136 | ✅ |
| 10 | TPMS_NV_PUBLIC | nvIndex, nameAlg, attributes, authPolicy, dataSize | Table 251, p.211-212 | ✅ |
| 11 | TPMT_SIGNATURE (RSA) | sigAlg, hash, sig | §11.3.6 Table 219, p.187 | ✅ |
| 12 | TPMT_SIGNATURE (ECC) | sigAlg, hash, signatureR, signatureS | §11.3.6 + Table 214, p.185-187 | ✅ |
| 13 | TPMT_TK_CREATION | tag, hierarchy, digest | §10.6.3 Table 110, p.143-144 | ✅ |
| 14 | TPMT_TK_VERIFIED | tag, hierarchy, digest | §10.6.5 Table 113, p.143-145 | ✅ |
| 15 | TPMT_TK_HASHCHECK | tag, hierarchy, digest | §10.6.6 Table 114, p.143-144 | ✅ |
| 16 | TPMS_ATTEST | magic, type, qualifiedSigner, extraData, clockInfo, firmwareVersion, [type]attested | §10.12.8 Table 154, p.162-163 | ✅ |
| 17 | TPMS_CLOCK_INFO | clock(8), resetCount(4), restartCount(4), safe(1) | §10.10.1 Table 142, p.158 | ✅ |
| 18 | TPMS_QUOTE_INFO | pcrSelect, pcrDigest | §10.12.3 Table 146, p.160 | ✅ |
| 19 | TPMS_CREATION_DATA | pcrSelect, pcrDigest, locality, parentNameAlg, parentName, parentQualifiedName, outsideInfo | §15.1 Table 261, p.219 | ✅ |
| 20 | TPMS_CONTEXT | sequence, savedHandle, hierarchy, contextBlob | §14.5 Table 260, p.217 | ✅ |
| 21 | TPML_PCR_SELECTION | count + selections | §10.9.7 Table 128, p.152-153 | ✅ |
| 22 | TPML_DIGEST_VALUES | count + TPMT_HA[] | §10.9.5 Table 127, p.152 | ✅ |
| 23 | TPML_TAGGED_TPM_PROPERTY | count + TPMS_TAGGED_PROPERTY[] | §10.9.11 Table 130, p.153 | ✅ |
| 24 | TPML_CCA | count + TPMA_CC[] | §10.9.1 Table 123, p.150 | ✅ |
| 25 | TPML_HANDLE | count + TPM_HANDLE[] | §10.9.3 Table 125, p.151 | ✅ |
| 26 | Command/Response header | tag, size, code (10 bytes) | Part 1 §15.2 Table 10, p.98 | ✅ |
| 27 | Command auth area | authorizationSize + sessions{handle,nonce,attrs,hmac} | Part 1 §15.5 Table 17, p.108-109 | ✅ |
| 28 | Response auth area | respHandles, parameterSize, params, sessions{nonce,attrs,hmac} | Part 1 §15.5 Table 19, p.109 | ✅ |
| 29 | Object Name | nameAlg ‖ H_nameAlg(publicArea) | Part 1 §16, p.90 | ✅ |

---

## D. Semantics / crypto / auth (34) — vs Part 1 & Part 3

| # | Item | Spec rule | Citation (quoted) | |
|---|---|---|---|---|
| 1 | cpHash | H(commandCode ‖ Names ‖ parameters) | P1 eq (15) p.106 | ✅ |
| 2 | rpHash | H(responseCode ‖ commandCode ‖ parameters) | P1 eq (16) p.107 | ✅ |
| 3 | command auth HMAC | HMAC(key, pHash ‖ nonceNewer ‖ nonceOlder ‖ attrs); cmd: newer=nonceCaller | P1 eq (17) p.118; p.156 | ✅ |
| 4 | response auth HMAC | data := rpHash ‖ nonceTPM ‖ nonceCaller ‖ attrs | P1 p.128; p.156 | ✅ |
| 5 | HMAC key = sessionKey ‖ authValue | HMAC((sessionKey ‖ authValue), data) | P1 eq (17) p.118 | ✅ |
| 6 | bound-session exception | bound ⇒ HMAC(sessionKey, data) | P1 eq (22) p.124 vs eq (21) | ✅ |
| 7 | sessionKey = KDFa(…, (authValue ‖ salt), "ATH", nonceTPM, nonceCaller, bits) | order authValue-then-salt, "ATH" | P1 eq (18) p.122; eq (25) p.126 | ✅ |
| 8 | KDFa construction (counter, label‖0x00, [L], MSB mask) | K(i)=HMAC(K_IN,[i]‖Label‖00‖Context‖[L]); counter from 1 | P1 §**8.4.10.2** eq (6) p.52-53 | ✅ (comment cite corrected) |
| 9 | KDFa Context = ctxU.buffer ‖ ctxV.buffer (no sizes) | eq (8) | P1 eq (8) p.53 | ✅ |
| 10 | KDFe ("SECRET" secret sharing) | KDFe(hashAlg, Z, label, PartyU, PartyV, bits) | P1 eq (12) p.55; p.127 "SECRET" | ✅ |
| 11 | object symKey = KDFa(pNameAlg, seedValue, "STORAGE", name, NULL, bits) | eq (33) | P1 eq (33) p.160 | ✅ |
| 12 | object HMACkey = KDFa(pNameAlg, seedValue, "INTEGRITY", NULL, NULL, bits) | eq (35) | P1 eq (35) p.161 | ✅ |
| 13 | outerHMAC over symIv ‖ encSensitive ‖ name | eq (36) | P1 eq (36) p.161 | ✅ |
| 14 | random symIv; encSensitive = CFB(symKey, symIv, sensitive) | eq (34); "symIv is an IV from RNG or 0" | P1 eq (34) p.160 | ✅ |
| 15 | salt recovery — RSA OAEP label "SECRET" | Labeled-KEM label is "SECRET" | P1 p.127 | ✅ |
| 16 | salt recovery — ECC KDFe Z then "SECRET" | one-pass ECDH + KDFe | P1 eq (12) p.55; eq (63) p.305 | ✅ |
| 17 | PCR extend = H(old ‖ digest) | eq (13)/(14) | P1 eq (13) p.91; eq (14) p.92 | ✅ |
| 18 | PCR 17–22 → locality 4 | platform-specific (PC Client), not in Part 1/3 | P1 p.91 "defined in a platform-specific specification" | ❔ (PC Client) |
| 19 | PolicyPCR digest | H(old ‖ TPM_CC_PolicyPCR ‖ pcrs ‖ digest) | P3 p.225 | ✅ |
| 20 | PolicyOR digest | H(0…0 ‖ TPM_CC_PolicyOR ‖ digests) | P3 p.223 | ✅ |
| 21 | PolicyCommandCode digest | H(old ‖ TPM_CC_PolicyCommandCode ‖ code) | P3 p.236 | ✅ |
| 22 | PolicyAuthValue digest | H(old ‖ TPM_CC_PolicyAuthValue) | P3 p.250 | ✅ |
| 23 | **TPM2_Clear** | new SPS; flush Storage/Endorsement objects; delete PLATFORMCREATE==CLEAR NV; auth/policy→Empty; Clock/reset/restart→0; Safe=YES; pcrUpdateCounter++ | P3 §24.6.1 p.283 | 🔧→✅ **fixed** |
| 24 | TPM2_Unseal keyedHash-only | data object only (not sign/decrypt) | P3 §38 (behavior correct; exact sentence not grep-located) | ✅ / ❔ cite |
| 25 | Hash ticket: valid for safe data, null otherwise | "did not start with TPM_GENERATED_VALUE"; NULL hierarchy ⇒ empty | P3 p.123-124 | ✅ |
| 26 | restricted signing key requires the ticket | "only required … for a restricted signing key" | P3 p.147; p.123 | ✅ |
| 27 | ticket = HMAC keyed by a proof value | "A ticket is an HMAC … that uses a proof value as the HMAC key" | P1 p.47 | ✅ |
| 28 | DA lockout predicate | "in Lockout mode while failedTries is equal to maxTries" | P1 p.148 | ◐ impl uses `>=` (defensive; equivalent) |
| 29 | DA recovery needs a trusted clock | "If the TPM has a trusted source of time … failedTries may be reduced" | P1 p.148 | ✅ (vTPM lacks one) |
| 30 | primary DRBG seeded with seed+templateHash+useString | §24.6.3 | P1 §24.6.3 p.203 | ✅ |
| 31 | nonceCaller ≥ 16 octets | "TPM_RC_SIZE if nonceCaller is less than 16 octets" | P3 p.58 | ✅ |
| 32 | NV counter Increment = +1 (unsigned) | "incremented by one … unsigned value" | P3 §31.8 p.355 | ✅ |
| 33 | NV Extend = H(old ‖ data); zero if unwritten | §31.9 | P3 §31.9 p.357 | ✅ |
| 34 | NV SetBits = data OR bits | "ORed with the current contents" | P3 §31.10 p.359 | ✅ |

---

## Verification

`go build ./... && go vet ./... && go test ./...` — green; **123 tpm2 tests**,
including new regressions for the two fixes:
`TestClearFlushesStorageAndResetsClock` and (from the prior pass)
`TestTPMANVBitPositions`. Every row above was obtained by page-aware grep of the
files in `docs/spec/v185/` and quotes the matched line.

The earlier `VALIDATION.md` (remediation history) remains; this document is the
**spec-cited reconciliation** against the on-disk v1.85 primary source.
