// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"sync"
)

// headerLen is the fixed size of a TPM 2.0 command/response header:
// tag (2) + size (4) + code/responseCode (4).
const headerLen = 10

// TPM is a software TPM 2.0 command processor. It is transport-agnostic: feed it
// raw command blobs via Execute and it returns raw response blobs. A TPM is safe
// for concurrent Execute calls (the TPM model is single-threaded, so calls are
// serialized internally).
type TPM struct {
	mu       sync.Mutex
	pcr      *pcrState
	h        *hierarchies
	sessions *sessionTable
	objects  *objectTable
	nv       *nvStore
	da       *daState
	clock    *clockState
	locality byte // locality of the current command (set via the transport)
	rand     io.Reader
	// contextKey protects saved contexts (TPM2_ContextSave); it is volatile and
	// regenerated on reset, so saved contexts do not survive a reboot.
	contextKey []byte
	contextSeq uint64
	started    bool // TPM2_Startup has completed
	failed     bool // entered failure mode; only diagnostic commands answer
}

// New returns a powered-on but not-yet-started TPM (TPM2_Startup is still
// required, mirroring real hardware). It uses crypto/rand as its entropy source.
// A fresh TPM mints new primary seeds; they are persisted on first save.
func New() *TPM {
	return &TPM{
		pcr:        newPCRState(),
		h:          newHierarchies(),
		sessions:   newSessionTable(),
		objects:    newObjectTable(),
		nv:         newNVStore(),
		da:         newDAState(),
		clock:      newClockState(),
		rand:       rand.Reader,
		contextKey: randomSeed(),
	}
}

// session is a parsed command authorization (TPMS_AUTH_COMMAND).
type session struct {
	handle uint32
	nonce  []byte
	attrs  byte
	hmac   []byte
}

// Execute processes one command blob and returns one response blob. It never
// returns a Go error: protocol problems are encoded as TPM response codes, as a
// real TPM does.
func (t *TPM) Execute(cmd []byte) []byte {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(cmd) < headerLen {
		return errorResponse(RCCommandSize)
	}
	tag := binary.BigEndian.Uint16(cmd[0:])
	size := binary.BigEndian.Uint32(cmd[2:])
	code := binary.BigEndian.Uint32(cmd[6:])

	if tag != TPMSTNoSessions && tag != TPMSTSessions {
		return errorResponse(RCBadTag)
	}
	if int(size) != len(cmd) {
		return errorResponse(RCCommandSize)
	}

	r := newReader(cmd[headerLen:])

	// In failure mode only GetTestResult and GetCapability are answered.
	if t.failed && code != CCGetTestResult && code != CCGetCapability {
		return errorResponse(RCFailure)
	}

	switch code {
	case CCStartup:
		return t.cmdStartup(r)
	case CCShutdown:
		return t.cmdShutdown(r)
	case CCSelfTest:
		return t.cmdSelfTest(r)
	case CCGetTestResult:
		return t.cmdGetTestResult(r)
	case CCGetRandom:
		return t.cmdGetRandom(r)
	case CCStirRandom:
		return t.cmdStirRandom(r)
	case CCGetCapability:
		return t.cmdGetCapability(r)
	case CCPCRRead:
		return t.cmdPCRRead(r)
	case CCPCRExtend:
		return t.cmdPCRExtend(tag, r)
	case CCPCRReset:
		return t.cmdPCRReset(tag, r)
	case CCClear:
		return t.cmdClear(tag, r)
	case CCClearControl:
		return t.cmdClearControl(tag, r)
	case CCHierarchyChangeAuth:
		return t.cmdHierarchyChangeAuth(tag, r)
	case CCSetPrimaryPolicy:
		return t.cmdSetPrimaryPolicy(tag, r)
	case CCHierarchyControl:
		return t.cmdHierarchyControl(tag, r)
	case CCChangeEPS:
		return t.cmdChangeSeed(tag, CCChangeEPS, r, &t.h.endorsement)
	case CCChangePPS:
		return t.cmdChangeSeed(tag, CCChangePPS, r, &t.h.platform)
	case CCStartAuthSession:
		return t.cmdStartAuthSession(r)
	case CCFlushContext:
		return t.cmdFlushContext(r)
	case CCPolicyPCR:
		return t.cmdPolicyPCR(r)
	case CCPolicyCommandCode:
		return t.cmdPolicyCommandCode(r)
	case CCPolicyAuthValue:
		return t.cmdPolicyAuthValue(r)
	case CCPolicyOR:
		return t.cmdPolicyOR(r)
	case CCPolicyGetDigest:
		return t.cmdPolicyGetDigest(r)
	case CCPolicyRestart:
		return t.cmdPolicyRestart(r)
	case CCDictionaryAttackLockReset:
		return t.cmdDictionaryAttackLockReset(tag, r)
	case CCDictionaryAttackParameters:
		return t.cmdDictionaryAttackParameters(tag, r)
	case CCCreatePrimary:
		return t.cmdCreatePrimary(tag, r)
	case CCEvictControl:
		return t.cmdEvictControl(tag, r)
	case CCCreate:
		return t.cmdCreate(tag, r)
	case CCLoad:
		return t.cmdLoad(tag, r)
	case CCLoadExternal:
		return t.cmdLoadExternal(r)
	case CCObjectChangeAuth:
		return t.cmdObjectChangeAuth(tag, r)
	case CCContextSave:
		return t.cmdContextSave(r)
	case CCContextLoad:
		return t.cmdContextLoad(r)
	case CCReadPublic:
		return t.cmdReadPublic(r)
	case CCNVDefineSpace:
		return t.cmdNVDefineSpace(tag, r)
	case CCNVUndefineSpace:
		return t.cmdNVUndefineSpace(tag, r)
	case CCNVReadPublic:
		return t.cmdNVReadPublic(r)
	case CCNVWrite:
		return t.cmdNVWrite(tag, r)
	case CCNVRead:
		return t.cmdNVRead(tag, r)
	case CCNVIncrement:
		return t.cmdNVIncrement(tag, r)
	case CCNVExtend:
		return t.cmdNVExtend(tag, r)
	case CCNVSetBits:
		return t.cmdNVSetBits(tag, r)
	case CCNVWriteLock:
		return t.cmdNVWriteLock(tag, r)
	case CCNVReadLock:
		return t.cmdNVReadLock(tag, r)
	case CCUnseal:
		return t.cmdUnseal(tag, r)
	case CCSign:
		return t.cmdSign(tag, r)
	case CCVerifySignature:
		return t.cmdVerifySignature(r)
	case CCHash:
		return t.cmdHash(r)
	case CCQuote:
		return t.cmdQuote(tag, r)
	case CCReadClock:
		return t.cmdReadClock(r)
	default:
		return errorResponse(RCCommandCode)
	}
}

// Init models a TPM (re)initialization at the hardware level — the swtpm
// CMD_INIT a hypervisor sends when the VM powers on. It clears the started flag
// so the guest firmware must issue TPM2_Startup again; persistent PCR values are
// retained until TPM2_Startup(CLEAR) zeroes the resettable banks. deleteVolatile
// additionally discards any accumulated PCR extends, returning every bank to its
// power-on value.
func (t *TPM) Init(deleteVolatile bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.started = false
	t.failed = false
	t.h.reset()                    // regenerate the volatile null-hierarchy seed, restore enables
	t.sessions = newSessionTable() // sessions are volatile: dropped on reset
	t.objects.resetTransient()     // transient objects are volatile; persistent ones remain
	t.contextKey = randomSeed()    // invalidate any previously saved contexts
	if deleteVolatile {
		t.pcr.reset()
	}
}

// SetLocality records the locality at which subsequent commands are received.
// The swtpm transport calls this on CMD_SET_LOCALITY; PCR operations enforce the
// per-PCR locality attributes against it (TPM 2.0 Part 1, §17.4 / PC Client).
func (t *TPM) SetLocality(loc byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.locality = loc
}

// requireStarted returns an INITIALIZE error response if Startup has not run.
func (t *TPM) requireStarted() []byte {
	if !t.started {
		return errorResponse(RCInitialize)
	}
	return nil
}

// readAuthArea parses the command authorization area (present only when the
// command tag is TPM_ST_SESSIONS): authSize (UINT32) followed by one or more
// TPMS_AUTH_COMMAND sessions filling exactly authSize bytes.
func readAuthArea(r *reader) ([]session, bool) {
	authSize := int(r.u32())
	if r.err != nil || authSize < 0 || authSize > r.remaining() {
		return nil, false
	}
	end := r.off + authSize
	var sessions []session
	for r.off < end {
		s := session{
			handle: r.u32(),
			nonce:  r.bytes(int(r.u16())),
			attrs:  r.u8(),
			hmac:   r.bytes(int(r.u16())),
		}
		if r.err != nil {
			return nil, false
		}
		sessions = append(sessions, s)
	}
	if r.off != end || len(sessions) == 0 {
		return nil, false
	}
	return sessions, true
}

// putHeader writes a TPM command/response header (tag, size, code/responseCode)
// into the first headerLen bytes of buf.
func putHeader(buf []byte, tag uint16, size, code uint32) {
	binary.BigEndian.PutUint16(buf[0:], tag)
	binary.BigEndian.PutUint32(buf[2:], size)
	binary.BigEndian.PutUint32(buf[6:], code)
}

// errorResponse builds a 10-byte error response. Per the TPM 2.0 spec an error
// response always uses TPM_ST_NO_SESSIONS and carries only the header.
func errorResponse(rc uint32) []byte {
	out := make([]byte, headerLen)
	putHeader(out, TPMSTNoSessions, headerLen, rc)
	return out
}

// successResponse frames a successful response. When sessionCount > 0 the
// response is tagged TPM_ST_SESSIONS and carries a parameterSize field plus one
// empty acknowledgment session per request session (sufficient for password
// authorizations); otherwise it is tagged TPM_ST_NO_SESSIONS.
func successResponse(params []byte, sessionCount int) []byte {
	var body writer
	if sessionCount > 0 {
		body.u32(uint32(len(params)))
		body.raw(params)
		for i := 0; i < sessionCount; i++ {
			body.u16(0) // empty nonceTPM
			body.u8(0)  // sessionAttributes
			body.u16(0) // empty hmac/ack
		}
	} else {
		body.raw(params)
	}

	tag := TPMSTNoSessions
	if sessionCount > 0 {
		tag = TPMSTSessions
	}
	payload := body.bytes()
	out := make([]byte, headerLen, headerLen+len(payload))
	binary.BigEndian.PutUint16(out[0:], tag)
	binary.BigEndian.PutUint32(out[2:], uint32(headerLen+len(payload)))
	binary.BigEndian.PutUint32(out[6:], RCSuccess)
	return append(out, payload...)
}
