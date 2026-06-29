// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

// Structure tags (TPM_ST). The tag of a command/response selects whether an
// authorization (session) area is present.
const (
	TPMSTNoSessions uint16 = 0x8001 // TPM_ST_NO_SESSIONS
	TPMSTSessions   uint16 = 0x8002 // TPM_ST_SESSIONS
)

// Command codes (TPM_CC) — the subset the emulator currently dispatches.
// Values are from the TCG TPM 2.0 spec, Part 2.
const (
	CCSelfTest      uint32 = 0x00000143 // TPM2_SelfTest
	CCStartup       uint32 = 0x00000144 // TPM2_Startup
	CCShutdown      uint32 = 0x00000145 // TPM2_Shutdown
	CCGetTestResult uint32 = 0x0000017C // TPM2_GetTestResult
	CCGetCapability uint32 = 0x0000017A // TPM2_GetCapability
	CCGetRandom     uint32 = 0x0000017B // TPM2_GetRandom
	CCStirRandom    uint32 = 0x00000146 // TPM2_StirRandom
	CCPCRRead       uint32 = 0x0000017E // TPM2_PCR_Read
	CCPCRExtend     uint32 = 0x00000182 // TPM2_PCR_Extend
	CCPCRReset      uint32 = 0x0000013D // TPM2_PCR_Reset

	// Hierarchy administration (Phase 1).
	CCHierarchyControl    uint32 = 0x00000121 // TPM2_HierarchyControl
	CCChangeEPS           uint32 = 0x00000124 // TPM2_ChangeEPS
	CCChangePPS           uint32 = 0x00000125 // TPM2_ChangePPS
	CCClear               uint32 = 0x00000126 // TPM2_Clear
	CCClearControl        uint32 = 0x00000127 // TPM2_ClearControl
	CCHierarchyChangeAuth uint32 = 0x00000129 // TPM2_HierarchyChangeAuth
	CCSetPrimaryPolicy    uint32 = 0x0000012E // TPM2_SetPrimaryPolicy

	// Sessions and policy (Phase 2).
	CCStartAuthSession  uint32 = 0x00000176 // TPM2_StartAuthSession
	CCFlushContext      uint32 = 0x00000165 // TPM2_FlushContext
	CCPolicyAuthValue   uint32 = 0x0000016B // TPM2_PolicyAuthValue
	CCPolicyCommandCode uint32 = 0x0000016C // TPM2_PolicyCommandCode
	CCPolicyOR          uint32 = 0x00000171 // TPM2_PolicyOR
	CCPolicyPCR         uint32 = 0x0000017F // TPM2_PolicyPCR
	CCPolicyRestart     uint32 = 0x00000180 // TPM2_PolicyRestart
	CCPolicyGetDigest   uint32 = 0x00000189 // TPM2_PolicyGetDigest

	// Dictionary-attack protection (Phase 2c).
	CCDictionaryAttackLockReset  uint32 = 0x00000139 // TPM2_DictionaryAttackLockReset
	CCDictionaryAttackParameters uint32 = 0x0000013A // TPM2_DictionaryAttackParameters

	// Objects and keys (Phase 3).
	CCEvictControl     uint32 = 0x00000120 // TPM2_EvictControl
	CCCreatePrimary    uint32 = 0x00000131 // TPM2_CreatePrimary
	CCObjectChangeAuth uint32 = 0x00000150 // TPM2_ObjectChangeAuth
	CCCreate           uint32 = 0x00000153 // TPM2_Create
	CCLoad             uint32 = 0x00000157 // TPM2_Load
	CCContextLoad      uint32 = 0x00000161 // TPM2_ContextLoad
	CCContextSave      uint32 = 0x00000162 // TPM2_ContextSave
	CCLoadExternal     uint32 = 0x00000167 // TPM2_LoadExternal
	CCReadPublic       uint32 = 0x00000173 // TPM2_ReadPublic

	// NV storage (Phase 4).
	CCNVUndefineSpace   uint32 = 0x00000122 // TPM2_NV_UndefineSpace
	CCNVDefineSpace     uint32 = 0x0000012A // TPM2_NV_DefineSpace
	CCNVGlobalWriteLock uint32 = 0x00000132 // TPM2_NV_GlobalWriteLock
	CCNVIncrement       uint32 = 0x00000134 // TPM2_NV_Increment
	CCNVSetBits         uint32 = 0x00000135 // TPM2_NV_SetBits
	CCNVExtend          uint32 = 0x00000136 // TPM2_NV_Extend
	CCNVWrite           uint32 = 0x00000137 // TPM2_NV_Write
	CCNVWriteLock       uint32 = 0x00000138 // TPM2_NV_WriteLock
	CCNVChangeAuth      uint32 = 0x0000013B // TPM2_NV_ChangeAuth
	CCNVRead            uint32 = 0x0000014E // TPM2_NV_Read
	CCNVReadLock        uint32 = 0x0000014F // TPM2_NV_ReadLock
	CCNVReadPublic      uint32 = 0x00000169 // TPM2_NV_ReadPublic

	// Signing, sealing and attestation (Phase 5).
	CCCertify         uint32 = 0x00000148 // TPM2_Certify
	CCCertifyCreation uint32 = 0x0000014A // TPM2_CertifyCreation
	CCCertifyX509     uint32 = 0x00000197 // TPM2_CertifyX509

	// Clock / PCR extras (Phase 6).
	CCClockSet        uint32 = 0x00000128 // TPM2_ClockSet
	CCClockRateAdjust uint32 = 0x00000130 // TPM2_ClockRateAdjust
	CCPCREvent        uint32 = 0x0000013C // TPM2_PCR_Event

	// PCR/NV structural commands (Phase 6b).
	CCNVUndefineSpaceSpecial uint32 = 0x0000011F // TPM2_NV_UndefineSpaceSpecial
	CCPCRAllocate            uint32 = 0x0000012B // TPM2_PCR_Allocate
	CCPCRSetAuthPolicy       uint32 = 0x0000012C // TPM2_PCR_SetAuthPolicy
	CCPCRSetAuthValue        uint32 = 0x00000183 // TPM2_PCR_SetAuthValue
	CCGetTime                uint32 = 0x0000014C // TPM2_GetTime
	CCHMAC                   uint32 = 0x00000155 // TPM2_HMAC
	CCQuote                  uint32 = 0x00000158 // TPM2_Quote
	CCSign                   uint32 = 0x0000015D // TPM2_Sign
	CCUnseal                 uint32 = 0x0000015E // TPM2_Unseal
	CCVerifySignature        uint32 = 0x00000177 // TPM2_VerifySignature
	CCVerifyDigestSignature  uint32 = 0x000001A5 // TPM2_VerifyDigestSignature
	CCSignDigest             uint32 = 0x000001A6 // TPM2_SignDigest
	CCHash                   uint32 = 0x0000017D // TPM2_Hash
	CCReadClock              uint32 = 0x00000181 // TPM2_ReadClock
	CCNVCertify              uint32 = 0x00000184 // TPM2_NV_Certify

	// Audit (Phase 5c).
	CCGetCommandAuditDigest     uint32 = 0x00000133 // TPM2_GetCommandAuditDigest
	CCSetCommandCodeAuditStatus uint32 = 0x00000140 // TPM2_SetCommandCodeAuditStatus
	CCGetSessionAuditDigest     uint32 = 0x0000014D // TPM2_GetSessionAuditDigest

	// Asymmetric primitives (Phase 1).
	CCRSAEncrypt    uint32 = 0x00000174 // TPM2_RSA_Encrypt
	CCRSADecrypt    uint32 = 0x00000159 // TPM2_RSA_Decrypt
	CCECDHKeyGen    uint32 = 0x00000163 // TPM2_ECDH_KeyGen
	CCECDHZGen      uint32 = 0x00000154 // TPM2_ECDH_ZGen
	CCECCParameters uint32 = 0x00000178 // TPM2_ECC_Parameters
	CCECCEncrypt    uint32 = 0x00000199 // TPM2_ECC_Encrypt
	CCECCDecrypt    uint32 = 0x0000019A // TPM2_ECC_Decrypt
	CCEncapsulate   uint32 = 0x000001A7 // TPM2_Encapsulate
	CCDecapsulate   uint32 = 0x000001A8 // TPM2_Decapsulate

	// EC commit / ECDAA / two-phase ECDH (Phase 7).
	CCCommit      uint32 = 0x0000018B // TPM2_Commit
	CCZGen2Phase  uint32 = 0x0000018D // TPM2_ZGen_2Phase
	CCECEphemeral uint32 = 0x0000018E // TPM2_EC_Ephemeral

	// Symmetric cipher + object lifecycle (Phase 9).
	CCEncryptDecrypt  uint32 = 0x00000164 // TPM2_EncryptDecrypt
	CCEncryptDecrypt2 uint32 = 0x00000193 // TPM2_EncryptDecrypt2
	CCCreateLoaded    uint32 = 0x00000191 // TPM2_CreateLoaded

	// ACT and read-only control.
	CCACTSetTimeout   uint32 = 0x00000198 // TPM2_ACT_SetTimeout
	CCReadOnlyControl uint32 = 0x000001A0 // TPM2_ReadOnlyControl

	// Management / test (Phase 8).
	CCPPCommands          uint32 = 0x0000012D // TPM2_PP_Commands
	CCSetAlgorithmSet     uint32 = 0x0000013F // TPM2_SetAlgorithmSet
	CCIncrementalSelfTest uint32 = 0x00000142 // TPM2_IncrementalSelfTest
	CCTestParms           uint32 = 0x0000018A // TPM2_TestParms

	// Hash/HMAC sequences (Phase 2). TPM_CC_HMAC/TPM_CC_MAC and HMAC_Start/MAC_Start
	// share a code; the same handlers serve both names.
	CCHMACStart             uint32 = 0x0000015B // TPM2_HMAC_Start (= TPM2_MAC_Start)
	CCHashSequenceStart     uint32 = 0x00000186 // TPM2_HashSequenceStart
	CCSequenceUpdate        uint32 = 0x0000015C // TPM2_SequenceUpdate
	CCSequenceComplete      uint32 = 0x0000013E // TPM2_SequenceComplete
	CCEventSequenceComplete uint32 = 0x00000185 // TPM2_EventSequenceComplete

	// Sign/verify sequences (streamed data → digest → sign/verify).
	CCVerifySequenceComplete uint32 = 0x000001A3 // TPM2_VerifySequenceComplete
	CCSignSequenceComplete   uint32 = 0x000001A4 // TPM2_SignSequenceComplete
	CCVerifySequenceStart    uint32 = 0x000001A9 // TPM2_VerifySequenceStart
	CCSignSequenceStart      uint32 = 0x000001AA // TPM2_SignSequenceStart

	// Policy assertions (Phase 3a — simple digest-extend assertions).
	CCPolicyCpHash           uint32 = 0x0000016E // TPM2_PolicyCpHash
	CCPolicyLocality         uint32 = 0x0000016F // TPM2_PolicyLocality
	CCPolicyNameHash         uint32 = 0x00000170 // TPM2_PolicyNameHash
	CCPolicyPhysicalPresence uint32 = 0x00000187 // TPM2_PolicyPhysicalPresence
	CCPolicyPassword         uint32 = 0x0000018C // TPM2_PolicyPassword
	CCPolicyNvWritten        uint32 = 0x0000018F // TPM2_PolicyNvWritten
	CCPolicyTemplate         uint32 = 0x00000190 // TPM2_PolicyTemplate

	// Policy comparison assertions (Phase 3b).
	CCPolicyNV           uint32 = 0x00000149 // TPM2_PolicyNV
	CCPolicyCounterTimer uint32 = 0x0000016D // TPM2_PolicyCounterTimer

	// Policy auth/verification assertions (Phase 3c).
	CCPolicySecret    uint32 = 0x00000151 // TPM2_PolicySecret
	CCPolicySigned    uint32 = 0x00000160 // TPM2_PolicySigned
	CCPolicyAuthorize uint32 = 0x0000016A // TPM2_PolicyAuthorize

	// Remaining policy assertions (Phase 3d).
	CCPolicyTicket            uint32 = 0x00000172 // TPM2_PolicyTicket
	CCPolicyDuplicationSelect uint32 = 0x00000188 // TPM2_PolicyDuplicationSelect
	CCPolicyAuthorizeNV       uint32 = 0x00000192 // TPM2_PolicyAuthorizeNV
	CCPolicyCapability        uint32 = 0x0000019B // TPM2_PolicyCapability
	CCPolicyParameters        uint32 = 0x0000019C // TPM2_PolicyParameters
	CCPolicyTransportSPDM     uint32 = 0x000001A1 // TPM2_PolicyTransportSPDM

	// TPM2_Duplicate (Phase 4) — referenced now by PolicyDuplicationSelect's
	// implicit command-code restriction.
	CCDuplicate uint32 = 0x0000014B // TPM2_Duplicate

	// Credentials (Phase 4).
	CCMakeCredential     uint32 = 0x00000168 // TPM2_MakeCredential
	CCActivateCredential uint32 = 0x00000147 // TPM2_ActivateCredential

	// Duplication / migration (Phase 4b).
	CCImport uint32 = 0x00000156 // TPM2_Import
	CCRewrap uint32 = 0x00000152 // TPM2_Rewrap
)

// TPM_GENERATED_VALUE prefixes a TPM-produced attestation structure.
const tpmGeneratedValue uint32 = 0xFF544347

// Attestation structure tags (TPM_ST).
const (
	STAttestNV           uint16 = 0x8014 // TPM_ST_ATTEST_NV
	STAttestCommandAudit uint16 = 0x8015 // TPM_ST_ATTEST_COMMAND_AUDIT
	STAttestSessionAudit uint16 = 0x8016 // TPM_ST_ATTEST_SESSION_AUDIT
	STAttestCertify      uint16 = 0x8017 // TPM_ST_ATTEST_CERTIFY
	STAttestQuote        uint16 = 0x8018 // TPM_ST_ATTEST_QUOTE
	STAttestTime         uint16 = 0x8019 // TPM_ST_ATTEST_TIME
	STAttestCreation     uint16 = 0x801A // TPM_ST_ATTEST_CREATION
)

// TPMA_NV NT field values (the NV index type).
const (
	nvOrdinary uint32 = 0x0
	nvCounter  uint32 = 0x1
	nvBits     uint32 = 0x2
	nvExtend   uint32 = 0x4
)

// Structure tags (TPM_ST) for tickets.
const (
	STCreation   uint16 = 0x8021 // TPM_ST_CREATION
	STVerified   uint16 = 0x8022 // TPM_ST_VERIFIED
	STAuthSecret uint16 = 0x8023 // TPM_ST_AUTH_SECRET
	STHashCheck  uint16 = 0x8024 // TPM_ST_HASHCHECK
	STAuthSigned uint16 = 0x8025 // TPM_ST_AUTH_SIGNED
)

// Session types (TPM_SE), the sessionType parameter of TPM2_StartAuthSession.
const (
	seHMAC   byte = 0x00 // TPM_SE_HMAC
	sePolicy byte = 0x01 // TPM_SE_POLICY
	seTrial  byte = 0x03 // TPM_SE_TRIAL
)

// Response codes (TPM_RC). TPM 2.0 has two code formats (TPM 2.0 Part 2,
// "Response Code Details"): format-zero codes are RC_VER1 (0x100) + number, and
// format-one codes are RC_FMT1 (0x080) + number. TPM_RC_VALUE, TPM_RC_SIZE and
// TPM_RC_INSUFFICIENT are format-one codes and MUST be built on RC_FMT1 — not
// RC_VER1 — or the resulting value (e.g. 0x104, 0x19A) is not a decodable
// response code. The parameter/handle/session number (the P and N fields a real
// TPM sets on a format-one code) is not yet applied; codes are returned bare.
const (
	RCSuccess uint32 = 0x000 // TPM_RC_SUCCESS
	RCBadTag  uint32 = 0x01E // TPM_RC_BAD_TAG (TPM 1.2 compatibility value)

	// Format-zero codes: RC_VER1 + number.
	rcVer1            uint32 = 0x100          // RC_VER1 base
	RCInitialize      uint32 = rcVer1 + 0x000 // TPM_RC_INITIALIZE
	RCFailure         uint32 = rcVer1 + 0x001 // TPM_RC_FAILURE
	RCSequence        uint32 = rcVer1 + 0x003 // TPM_RC_SEQUENCE
	RCDisabled        uint32 = rcVer1 + 0x020 // TPM_RC_DISABLED
	RCAuthType        uint32 = rcVer1 + 0x024 // TPM_RC_AUTH_TYPE
	RCAuthMissing     uint32 = rcVer1 + 0x025 // TPM_RC_AUTH_MISSING
	RCCommandSize     uint32 = rcVer1 + 0x042 // TPM_RC_COMMAND_SIZE
	RCCommandCode     uint32 = rcVer1 + 0x043 // TPM_RC_COMMAND_CODE
	RCAuthSize        uint32 = rcVer1 + 0x044 // TPM_RC_AUTHSIZE
	RCAuthContext     uint32 = rcVer1 + 0x045 // TPM_RC_AUTH_CONTEXT
	RCAuthUnavailable uint32 = rcVer1 + 0x02F // TPM_RC_AUTH_UNAVAILABLE (0x12F)
	RCNVRange         uint32 = rcVer1 + 0x046 // TPM_RC_NV_RANGE (0x146)
	RCNVSize          uint32 = rcVer1 + 0x047 // TPM_RC_NV_SIZE (0x147)
	RCNVLocked        uint32 = rcVer1 + 0x048 // TPM_RC_NV_LOCKED (0x148)
	RCNVAuthorization uint32 = rcVer1 + 0x049 // TPM_RC_NV_AUTHORIZATION (0x149)
	RCNVUninitialized uint32 = rcVer1 + 0x04A // TPM_RC_NV_UNINITIALIZED (0x14A)
	RCNVSpace         uint32 = rcVer1 + 0x04B // TPM_RC_NV_SPACE (0x14B)
	RCNVDefined       uint32 = rcVer1 + 0x04C // TPM_RC_NV_DEFINED (0x14C)

	// Format-one codes: RC_FMT1 + number.
	rcFmt1         uint32 = 0x080          // RC_FMT1 base
	RCHash         uint32 = rcFmt1 + 0x003 // TPM_RC_HASH (0x083)
	RCMode         uint32 = rcFmt1 + 0x009 // TPM_RC_MODE (0x089)
	RCAttributes   uint32 = rcFmt1 + 0x002 // TPM_RC_ATTRIBUTES (0x082)
	RCValue        uint32 = rcFmt1 + 0x004 // TPM_RC_VALUE  (0x084)
	RCHierarchy    uint32 = rcFmt1 + 0x005 // TPM_RC_HIERARCHY (0x085)
	RCHandle       uint32 = rcFmt1 + 0x00B // TPM_RC_HANDLE (0x08B)
	RCAuthFail     uint32 = rcFmt1 + 0x00E // TPM_RC_AUTH_FAIL (0x08E)
	RCNonce        uint32 = rcFmt1 + 0x00F // TPM_RC_NONCE (0x08F)
	RCKeySize      uint32 = rcFmt1 + 0x007 // TPM_RC_KEY_SIZE (0x087)
	RCType         uint32 = rcFmt1 + 0x00A // TPM_RC_TYPE (0x08A)
	RCScheme       uint32 = rcFmt1 + 0x012 // TPM_RC_SCHEME (0x092)
	RCSize         uint32 = rcFmt1 + 0x015 // TPM_RC_SIZE   (0x095)
	RCInsufficient uint32 = rcFmt1 + 0x01A // TPM_RC_INSUFFICIENT (0x09A)
	RCPolicyFail   uint32 = rcFmt1 + 0x01D // TPM_RC_POLICY_FAIL (0x09D)
	RCIntegrity    uint32 = rcFmt1 + 0x01F // TPM_RC_INTEGRITY (0x09F)
	RCBadAuth      uint32 = rcFmt1 + 0x022 // TPM_RC_BAD_AUTH (0x0A2)
	RCTicket       uint32 = rcFmt1 + 0x020 // TPM_RC_TICKET (0x0A0)
	RCECCPoint     uint32 = rcFmt1 + 0x027 // TPM_RC_ECC_POINT (0x0A7)
	RCNoResult     uint32 = rcVer1 + 0x054 // TPM_RC_NO_RESULT (0x154)
	RCCurve        uint32 = rcFmt1 + 0x026 // TPM_RC_CURVE (0x0A6)
	RCPolicyCC     uint32 = rcFmt1 + 0x024 // TPM_RC_POLICY_CC (0x0A4)
	RCSignature    uint32 = rcFmt1 + 0x01B // TPM_RC_SIGNATURE (0x09B)
	RCKey          uint32 = rcFmt1 + 0x01C // TPM_RC_KEY (0x09C)

	// Warning codes: RC_WARN + number.
	rcWarn           uint32 = 0x900          // RC_WARN base
	RCContextGap     uint32 = rcWarn + 0x001 // TPM_RC_CONTEXT_GAP
	RCObjectMemory   uint32 = rcWarn + 0x002 // TPM_RC_OBJECT_MEMORY
	RCSessionMemory  uint32 = rcWarn + 0x003 // TPM_RC_SESSION_MEMORY (0x903)
	RCSessionHandles uint32 = rcWarn + 0x005 // TPM_RC_SESSION_HANDLES
	RCLocality       uint32 = rcWarn + 0x007 // TPM_RC_LOCALITY (0x907)
	RCLockout        uint32 = rcWarn + 0x021 // TPM_RC_LOCKOUT (0x921)
)

// Format-one decoration (TPM 2.0 Part 2, Response Code Details). A format-one
// code may identify the faulting item via the P bit and the 4-bit N field: a
// parameter (P=1, number 1..15), a handle (P=0, number 1..7), or a session
// (P=0, number carried as n+8). Decoration applies only to RC_FMT1 codes.
const (
	rcFmt1P       uint32 = 0x040 // P: the error relates to a parameter
	rcFmt1NShift  uint32 = 8     // position of the N (number) field
	rcFmt1Session uint32 = 0x800 // with P=0, marks N as a session number (n+8)
	rcFmt1ErrMask uint32 = 0x03F // the bare error number (bits 0..5)
)

// withParam decorates a format-one code with a 1-based parameter number.
func withParam(rc uint32, n int) uint32 { return rc | rcFmt1P | uint32(n)<<rcFmt1NShift }

// withHandle decorates a format-one code with a 1-based handle number.
func withHandle(rc uint32, n int) uint32 { return rc | uint32(n)<<rcFmt1NShift }

// withSession decorates a format-one code with a 1-based session number (encoded
// as n+8 in the N field, per TPM 2.0 Part 2).
func withSession(rc uint32, n int) uint32 { return rc | rcFmt1Session | uint32(n)<<rcFmt1NShift }

// baseRC strips any parameter/handle/session decoration from a format-one code,
// yielding the canonical constant (e.g. a decorated TPM_RC_VALUE back to 0x084).
// Format-zero codes are returned unchanged.
func baseRC(rc uint32) uint32 {
	// Bit 7 (RC_FMT1) is the format selector: format-zero (VER1/WARN) codes never
	// set it. A decorated format-one code sets N bits that overlap RC_VER1, so the
	// format test must look at bit 7 alone.
	if rc&rcFmt1 != 0 {
		return rc&rcFmt1ErrMask | rcFmt1
	}
	return rc
}

// Startup / Shutdown types (TPM_SU).
const (
	SUClear uint16 = 0x0000 // TPM_SU_CLEAR
	SUState uint16 = 0x0001 // TPM_SU_STATE
)

// Algorithm identifiers (TPM_ALG_ID). Hash primitives plus the object, scheme,
// symmetric and KDF algorithms the structure layer needs.
const (
	AlgError        uint16 = 0x0000 // TPM_ALG_ERROR
	AlgRSA          uint16 = 0x0001 // TPM_ALG_RSA
	AlgSHA1         uint16 = 0x0004 // TPM_ALG_SHA1
	AlgHMAC         uint16 = 0x0005 // TPM_ALG_HMAC
	AlgAES          uint16 = 0x0006 // TPM_ALG_AES
	AlgMGF1         uint16 = 0x0007 // TPM_ALG_MGF1
	AlgKeyedHash    uint16 = 0x0008 // TPM_ALG_KEYEDHASH
	AlgXOR          uint16 = 0x000A // TPM_ALG_XOR
	AlgSHA256       uint16 = 0x000B // TPM_ALG_SHA256
	AlgSHA384       uint16 = 0x000C // TPM_ALG_SHA384
	AlgSHA512       uint16 = 0x000D // TPM_ALG_SHA512
	AlgNull         uint16 = 0x0010 // TPM_ALG_NULL
	AlgRSASSA       uint16 = 0x0014 // TPM_ALG_RSASSA
	AlgRSAES        uint16 = 0x0015 // TPM_ALG_RSAES
	AlgRSAPSS       uint16 = 0x0016 // TPM_ALG_RSAPSS
	AlgOAEP         uint16 = 0x0017 // TPM_ALG_OAEP
	AlgECDSA        uint16 = 0x0018 // TPM_ALG_ECDSA
	AlgECDH         uint16 = 0x0019 // TPM_ALG_ECDH
	AlgSHA3256      uint16 = 0x0027 // TPM_ALG_SHA3_256
	AlgSHA3384      uint16 = 0x0028 // TPM_ALG_SHA3_384
	AlgSHA3512      uint16 = 0x0029 // TPM_ALG_SHA3_512
	AlgKDF1SP800108 uint16 = 0x0022 // TPM_ALG_KDF1_SP800_108
	AlgKDF1SP80056A uint16 = 0x0020 // TPM_ALG_KDF1_SP800_56A
	AlgKDF2         uint16 = 0x0021 // TPM_ALG_KDF2
	AlgECC          uint16 = 0x0023 // TPM_ALG_ECC
	AlgSymCipher    uint16 = 0x0025 // TPM_ALG_SYMCIPHER
	AlgCMAC         uint16 = 0x003F // TPM_ALG_CMAC
	AlgCTR          uint16 = 0x0040 // TPM_ALG_CTR
	AlgOFB          uint16 = 0x0041 // TPM_ALG_OFB
	AlgCBC          uint16 = 0x0042 // TPM_ALG_CBC
	AlgCFB          uint16 = 0x0043 // TPM_ALG_CFB
	AlgECB          uint16 = 0x0044 // TPM_ALG_ECB
)

// ECC curve identifiers (TPM_ECC_CURVE). NIST P-256/P-384/P-521 are backed by the
// Go standard library; the SM2 and Barreto-Naehrig curves the spec also defines
// are intentionally absent (no pure-Go stdlib support). P-224 is supported for
// curve queries (TPM2_ECC_Parameters) and point operations on externally-loaded
// keys via crypto/elliptic, but P-224 keys cannot be generated: deterministic key
// derivation requires crypto/ecdh, which has no P-224 (see deriveECCKey).
const (
	ECCNistP224 uint16 = 0x0002 // TPM_ECC_NIST_P224 (queries / external keys only)
	ECCNistP256 uint16 = 0x0003 // TPM_ECC_NIST_P256
	ECCNistP384 uint16 = 0x0004 // TPM_ECC_NIST_P384
	ECCNistP521 uint16 = 0x0005 // TPM_ECC_NIST_P521
)

// TPMA_OBJECT attribute bits (object attributes in a TPMT_PUBLIC).
const (
	ObjFixedTPM             uint32 = 1 << 1
	ObjStClear              uint32 = 1 << 2
	ObjFixedParent          uint32 = 1 << 4
	ObjSensitiveDataOrigin  uint32 = 1 << 5
	ObjUserWithAuth         uint32 = 1 << 6
	ObjAdminWithPolicy      uint32 = 1 << 7
	ObjNoDA                 uint32 = 1 << 10
	ObjEncryptedDuplication uint32 = 1 << 11
	ObjRestricted           uint32 = 1 << 16
	ObjDecrypt              uint32 = 1 << 17
	ObjSign                 uint32 = 1 << 18
)

// TPMA_NV attribute bits (NV index attributes in a TPMS_NV_PUBLIC). The NT field
// (bits 4..7) selects the index type (ordinary, counter, bits, extend, pin).
const (
	NVPPWrite        uint32 = 1 << 0
	NVOwnerWrite     uint32 = 1 << 1
	NVAuthWrite      uint32 = 1 << 2
	NVPolicyWrite    uint32 = 1 << 3
	NVNTShift        uint32 = 4
	NVNTMask         uint32 = 0xF << NVNTShift
	NVPolicyDelete   uint32 = 1 << 10
	NVWriteLocked    uint32 = 1 << 11
	NVWriteAll       uint32 = 1 << 12
	NVWriteDefine    uint32 = 1 << 13
	NVWriteSTClear   uint32 = 1 << 14
	NVGlobalLock     uint32 = 1 << 15
	NVPPRead         uint32 = 1 << 16
	NVOwnerRead      uint32 = 1 << 17
	NVAuthRead       uint32 = 1 << 18
	NVPolicyRead     uint32 = 1 << 19
	NVNoDA           uint32 = 1 << 25
	NVOrderly        uint32 = 1 << 26
	NVClearSTClear   uint32 = 1 << 27
	NVReadLocked     uint32 = 1 << 28
	NVWritten        uint32 = 1 << 29
	NVPlatformCreate uint32 = 1 << 30
	NVReadSTClear    uint32 = 1 << 31
)

// Capability identifiers (TPM_CAP). The defined selectors form a contiguous
// block 0x00000000..capLast plus the vendor selector; values outside that set
// are a TPM_RC_VALUE error in TPM2_GetCapability (TPM 2.0 Part 2, TPM_CAP).
const (
	CapAlgs           uint32 = 0x00000000 // TPM_CAP_ALGS
	CapHandles        uint32 = 0x00000001 // TPM_CAP_HANDLES
	CapCommands       uint32 = 0x00000002 // TPM_CAP_COMMANDS
	CapPPCommands     uint32 = 0x00000003 // TPM_CAP_PP_COMMANDS
	CapAuditCommands  uint32 = 0x00000004 // TPM_CAP_AUDIT_COMMANDS
	CapPCRs           uint32 = 0x00000005 // TPM_CAP_PCRS
	CapTPMProperties  uint32 = 0x00000006 // TPM_CAP_TPM_PROPERTIES
	CapPCRProperties  uint32 = 0x00000007 // TPM_CAP_PCR_PROPERTIES
	CapECCCurves      uint32 = 0x00000008 // TPM_CAP_ECC_CURVES
	CapAuthPolicies   uint32 = 0x00000009 // TPM_CAP_AUTH_POLICIES
	CapACT            uint32 = 0x0000000A // TPM_CAP_ACT
	capLast           uint32 = CapACT     // highest defined non-vendor selector
	CapVendorProperty uint32 = 0x00000100 // TPM_CAP_VENDOR_PROPERTY
)

// TPM properties (TPM_PT). The PT_FIXED group is based at 0x100; the run-time
// PT_VAR group (permanent/startup/lockout/handle counts) is based at 0x200 and is
// reported from live subsystem state as those subsystems land (hierarchies,
// sessions). The constants below cover the fixed identity and capacity values
// Windows reads during TPM startup.
const (
	ptFixed uint32 = 0x100 // PT_FIXED group base

	PTFamilyIndicator  uint32 = ptFixed + 0x000 // "2.0\0"
	PTLevel            uint32 = ptFixed + 0x001
	PTRevision         uint32 = ptFixed + 0x002 // reports TPM_SPEC_VERSION (= 185 for v1.85; since v184 not ×100)
	PTDayOfYear        uint32 = ptFixed + 0x003
	PTYear             uint32 = ptFixed + 0x004
	PTManufacturer     uint32 = ptFixed + 0x005
	PTVendorString1    uint32 = ptFixed + 0x006
	PTVendorString2    uint32 = ptFixed + 0x007
	PTVendorString3    uint32 = ptFixed + 0x008
	PTVendorString4    uint32 = ptFixed + 0x009
	PTVendorTPMType    uint32 = ptFixed + 0x00A
	PTFirmwareVersion1 uint32 = ptFixed + 0x00B
	PTFirmwareVersion2 uint32 = ptFixed + 0x00C
	PTInputBuffer      uint32 = ptFixed + 0x00D
	PTHRTransientMin   uint32 = ptFixed + 0x00E
	PTHRPersistentMin  uint32 = ptFixed + 0x00F
	PTHRLoadedMin      uint32 = ptFixed + 0x010
	PTActiveSessionMax uint32 = ptFixed + 0x011
	PTPCRCount         uint32 = ptFixed + 0x012 // TPM_PT_PCR_COUNT
	PTPCRSelectMin     uint32 = ptFixed + 0x013
	PTMaxCommandSize   uint32 = ptFixed + 0x01E
	PTMaxResponseSize  uint32 = ptFixed + 0x01F
	PTMaxDigest        uint32 = ptFixed + 0x020 // TPM_PT_MAX_DIGEST
	PTTotalCommands    uint32 = ptFixed + 0x029
	PTLibraryCommands  uint32 = ptFixed + 0x02A
	PTVendorCommands   uint32 = ptFixed + 0x02B
	PTModes            uint32 = ptFixed + 0x02D

	// PT_VAR group (run-time state), reported from live values.
	ptVar             uint32 = 0x200
	PTPermanent       uint32 = ptVar + 0x000 // TPMA_PERMANENT
	PTStartupClear    uint32 = ptVar + 0x001 // TPMA_STARTUP_CLEAR
	PTLockoutCounter  uint32 = ptVar + 0x00E // failed-tries counter
	PTMaxAuthFail     uint32 = ptVar + 0x00F // maxTries
	PTLockoutInterval uint32 = ptVar + 0x010 // recoveryTime
	PTLockoutRecovery uint32 = ptVar + 0x011 // lockoutRecovery
)

// TPMA_ALGORITHM attribute bits (TPM_CAP_ALGS).
const (
	algAttrAsymmetric uint32 = 0x001
	algAttrSymmetric  uint32 = 0x002
	algAttrHash       uint32 = 0x004
	algAttrObject     uint32 = 0x008
	algAttrSigning    uint32 = 0x100
	algAttrEncrypting uint32 = 0x200
	algAttrMethod     uint32 = 0x400
)

// TPMA_CC attribute bits (TPM_CAP_COMMANDS). Bits [15:0] hold the command index;
// bits [27:25] hold the number of command handles (cHandles).
const (
	ccAttrIndexMask uint32 = 0x0000FFFF
	ccAttrCHandleSh uint32 = 25
	ccAttrNV        uint32 = 1 << 22
	ccAttrExtensive uint32 = 1 << 23
	ccAttrFlushed   uint32 = 1 << 24
)

// Yes/no encodings (TPMI_YES_NO).
const (
	yes byte = 1
	no  byte = 0
)

// Handle ranges (TPM_HT, the most-significant octet of a handle) and the
// permanent handles. classifyHandle returns the range octet shifted into place.
const (
	htPCR           uint32 = 0x00000000 // PCR
	htNVIndex       uint32 = 0x01000000 // NV index
	htHMACSession   uint32 = 0x02000000 // loaded HMAC/policy session
	htPolicySession uint32 = 0x03000000 // saved policy session
	htPermanent     uint32 = 0x40000000 // permanent (hierarchies, RS_PW)
	htTransient     uint32 = 0x80000000 // loaded transient object
	htPersistent    uint32 = 0x81000000 // persistent object

	htMask uint32 = 0xFF000000
)

// Permanent handles (TPM_RH_*).
const (
	RHOwner       uint32 = 0x40000001 // TPM_RH_OWNER (storage hierarchy)
	RHNull        uint32 = 0x40000007 // TPM_RH_NULL
	RHPW          uint32 = 0x40000009 // TPM_RS_PW (password authorization)
	RHLockout     uint32 = 0x4000000A // TPM_RH_LOCKOUT
	RHEndorsement uint32 = 0x4000000B // TPM_RH_ENDORSEMENT
	RHPlatform    uint32 = 0x4000000C // TPM_RH_PLATFORM
	RHPlatformNV  uint32 = 0x4000000D // TPM_RH_PLATFORM_NV
)

// classifyHandle returns the handle-range octet (htPCR, htTransient, …).
func classifyHandle(h uint32) uint32 { return h & htMask }

// numPCR is the number of PCRs per bank (TPM 2.0 platforms define 24).
const numPCR = 24

// hashSize returns the digest length in bytes for a supported hash algorithm,
// or 0 if the algorithm is unknown/unsupported.
func hashSize(alg uint16) int {
	switch alg {
	case AlgSHA1:
		return 20
	case AlgSHA256:
		return 32
	case AlgSHA384:
		return 48
	case AlgSHA512:
		return 64
	default:
		return 0
	}
}
