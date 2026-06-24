# Roadmap to a complete TPM 2.0 implementation

**Goal:** a complete TPM 2.0 device per the TCG Library Specification v1.85
(`docs/spec/v185/`). Today **52** of the spec's ~117 distinct commands are
implemented and spec-reconciled (see `docs/spec/v185-reconciliation.md`). This
roadmap closes the remaining ~65 commands plus algorithm/capability breadth.

**Working rules (unchanged):** pure-Go stdlib crypto only; every command reconciled
against the spec with a Part+page citation and a test; `go build/vet/test` green
after each phase; state-shape changes bump `snapshotVersion`.

## Phases (dependency-ordered)

- **Phase 1 — Asymmetric primitives** ✅ *(done)*
  `RSA_Encrypt`, `RSA_Decrypt`, `ECDH_KeyGen`, `ECDH_ZGen`, `ECC_Parameters`.
  *Deferred to a symmetric sub-phase:* `EncryptDecrypt`, `EncryptDecrypt2`,
  `TestParms`, symcipher key objects.
- **Phase 2 — Hash/MAC sequences** ✅ *(done)*
  `HMAC`, `HMAC_Start`, `HashSequenceStart`, `SequenceUpdate`,
  `SequenceComplete`, `EventSequenceComplete` (memory-resident sequence table;
  `TPM2_MAC`/`MAC_Start` served by the same handlers).
- **Phase 3 — Full policy command set (~17).**
  - **3a ✅ *(done)*** — simple digest-extend assertions: `PolicyCpHash`,
    `PolicyLocality`, `PolicyNameHash`, `PolicyPhysicalPresence`,
    `PolicyPassword`, `PolicyNvWritten`, `PolicyTemplate` (locality + cpHash also
    enforced at use).
  - **3b** — auth/verification assertions: `PolicySigned`, `PolicySecret`,
    `PolicyTicket`, `PolicyNV`, `PolicyAuthorize`, `PolicyAuthorizeNV`,
    `PolicyCounterTimer`, `PolicyDuplicationSelect`, `PolicyCapability`,
    `PolicyParameters`.
- **Phase 4 — Credentials & duplication.** `MakeCredential`,
  `ActivateCredential`, `Duplicate`, `Import`, `Rewrap` (adds the inner/outer
  duplication wrapper).
- **Phase 5 — Attestation & audit.** `Certify`, `CertifyCreation`, `CertifyX509`,
  `NV_Certify`, `GetSessionAuditDigest`, `GetCommandAuditDigest`,
  `SetCommandCodeAuditStatus`, audit sessions.
- **Phase 6 — Clock, PCR, NV extras.** `ClockSet`, `ClockRateAdjust`,
  `PCR_Allocate`, `PCR_Event`, `PCR_SetAuthValue`, `PCR_SetAuthPolicy`,
  `NV_UndefineSpaceSpecial`, `NV_GlobalWriteLock`, `NV_ChangeAuth`.
- **Phase 7 — EC/ECDAA & advanced.** `Commit`, `EC_Ephemeral`, `ZGen_2Phase`,
  `ECC_Encrypt`, `ECC_Decrypt`.
- **Phase 8 — Management & test.** `IncrementalSelfTest`, `SetAlgorithmSet`,
  `Vendor_TCG_Test`, `PP_Commands`, `SetPrimaryPolicy` (done), `ChangeEPS/PPS`
  (done).
- **Phase 9 — Field upgrade & ACT.** `FieldUpgradeStart`, `FieldUpgradeData`,
  `FirmwareRead`, `ACT_SetTimeout` (largely "unsupported"/stubbed per a software
  TPM, returning the spec-correct codes).
- **Phase 10 — Algorithm & capability breadth.** SHA-3 PCR banks; symmetric
  modes CTR/OFB/CBC/ECB; additional curves; complete `GetCapability` selectors
  (`ECC_CURVES`, `PCR_PROPERTIES`, `ALGS`, `AUTH_POLICIES`, `ACT`,
  `PP_COMMANDS`); full `TPM_PT_VAR` set.

## Tracking

Each phase updates `docs/spec/v185-reconciliation.md` (new cited rows) and adds
tests. "Complete" = every Part 3 command dispatched and reconciled, every Part 2
structure/constant covered, and the mandatory algorithm set advertised.
