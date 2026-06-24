// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import "io"

// This file implements object creation and inspection (TPM 2.0 Part 3, §24/§12).
// Primary objects (the EK/SRK) are derived deterministically from a hierarchy's
// primary seed so they are stable across reboots: TPM2_CreatePrimary with the
// same template and seed always yields the same key.

// derivestorageSeed reports whether an object is a restricted decryption (storage)
// key, which carries a symmetric seed used to protect its children.
func isStorageKey(attrs uint32) bool {
	return attrs&ObjRestricted != 0 && attrs&ObjDecrypt != 0
}

// qualifiedNameOf computes an object's Qualified Name, QN = H_nameAlg(parentQN ‖
// Name) (TPM 2.0 Part 1, §26.5). For a primary the parent QN is the hierarchy
// handle (the Name of a permanent handle).
func qualifiedNameOf(nameAlg uint16, parentQN, name []byte) []byte {
	return hashSum(nameAlg, parentQN, name)
}

// derivePrimary fills the unique (public) and secret (sensitive) of an object
// derived from primarySeed for the given template. The derivation is
// deterministic in (primarySeed, template), so the object is reproducible.
func derivePrimary(primarySeed []byte, tmpl public, userAuth []byte) (*object, []byte) {
	// Instantiate a Hash_DRBG seeded with the primary seed, the template hash and a
	// use string (TPM 2.0 Part 1, §24.6.3), so different templates/hierarchies yield
	// independent keys and the same inputs always reproduce the same key.
	var tb writer
	tmpl.marshal(&tb)
	templateHash := hashSum(tmpl.NameAlg, tb.bytes())
	r := newHashDRBG(tmpl.NameAlg, primarySeed, templateHash, []byte("CreatePrimary"))

	pub := tmpl
	sens := sensitive{Type: tmpl.Type, AuthValue: append([]byte(nil), userAuth...)}
	if isStorageKey(tmpl.Attrs) {
		sens.SeedValue = make([]byte, hashSize(tmpl.NameAlg))
		_, _ = r.Read(sens.SeedValue)
	}

	switch tmpl.Type {
	case AlgRSA:
		bits := int(tmpl.KeyBits)
		n, p, err := deriveRSAKey(r, bits)
		if err != nil {
			return nil, errorResponse(RCKey)
		}
		pub.Unique, sens.Secret = n, p
	case AlgECC:
		curve := curveFor(tmpl.Curve)
		if curve == nil {
			return nil, errorResponse(withParam(RCValue, 2))
		}
		x, y, d, err := deriveECCKey(r, curve, tmpl.Curve)
		if err != nil {
			return nil, errorResponse(RCKey)
		}
		pub.UniqueX, pub.UniqueY, sens.Secret = x, y, d
	case AlgKeyedHash:
		sens.SeedValue = make([]byte, hashSize(tmpl.NameAlg))
		_, _ = r.Read(sens.SeedValue)
		sens.Secret = make([]byte, hashSize(tmpl.NameAlg))
		_, _ = r.Read(sens.Secret)
		// unique = H_nameAlg(seedValue ‖ secret), per the keyed-hash object rules.
		pub.Unique = hashSum(tmpl.NameAlg, sens.SeedValue, sens.Secret)
	default:
		return nil, errorResponse(withParam(RCType, 2))
	}

	o := &object{public: pub, sensitive: sens}
	o.name = pub.name()
	return o, nil
}

// buildCreationData assembles the TPMS_CREATION_DATA / creationHash /
// creationTicket triple a creation command returns (TPM 2.0 Part 2, §15.1).
// ticketHierarchy is the hierarchy stamped into the ticket; parentName and
// parentNameAlg describe the creating parent (a hierarchy handle with NULL alg
// for a primary, or the parent object's Name and nameAlg for a child).
func (t *TPM) buildCreationData(ticketHierarchy uint32, nameAlg uint16, name, proof, parentName, parentQN []byte, parentNameAlg uint16, pcrs []pcrSelection, outsideInfo []byte) (data, hashOut, ticket []byte) {
	var cd writer
	writePCRSelectionList(&cd, pcrs)              // pcrSelect
	cd.tpm2b(t.pcrSelectionDigest(nameAlg, pcrs)) // pcrDigest
	cd.u8(0)                                      // locality
	cd.u16(parentNameAlg)                         // parentNameAlg
	cd.tpm2b(parentName)                          // parentName
	cd.tpm2b(parentQN)                            // parentQualifiedName
	cd.tpm2b(outsideInfo)                         // outsideInfo
	inner := cd.bytes()

	creationHash := hashSum(nameAlg, inner)
	// creationTicket digest authenticates that this TPM created the object:
	// HMAC_proof(TPM_ST_CREATION ‖ name ‖ creationHash).
	tDigest := hmacSum(nameAlg, proof, be16(STCreation), name, creationHash)

	var tk writer // TPMT_TK_CREATION
	tk.u16(STCreation)
	tk.u32(ticketHierarchy)
	tk.tpm2b(tDigest)

	// TPM2B_CREATION_DATA wraps the inner data with a size prefix.
	var d2b writer
	d2b.tpm2b(inner)
	return d2b.bytes(), creationHash, tk.bytes()
}

// cmdCreatePrimary implements TPM2_CreatePrimary: derive a primary object under a
// hierarchy, load it, and return its public area, Name and creation data.
func (t *TPM) cmdCreatePrimary(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCCreatePrimary, 1, r)
	if errResp != nil {
		return errResp
	}
	t.decryptCommandParams(ac, r) // inSensitive may be encrypted by a decrypt session
	// inSensitive (TPM2B_SENSITIVE_CREATE): outer size, then userAuth + data.
	_ = r.u16()
	userAuth := r.tpm2b()
	_ = r.tpm2b() // data (only meaningful for sealed keyed-hash objects)
	tmpl := readPublic2B(r)
	outsideInfo := r.tpm2b()
	pcrs := readPCRSelectionList(r)
	if r.err != nil {
		if r.err == errBadValue {
			return errorResponse(withParam(RCValue, 4))
		}
		return errorResponse(RCInsufficient)
	}

	primaryHandle := ac.handles[0]
	hi := t.h.byHandle(primaryHandle)
	if hi == nil {
		return errorResponse(withHandle(RCValue, 1))
	}
	if _, ok := cryptoHash(tmpl.NameAlg); !ok {
		return errorResponse(withParam(RCValue, 2))
	}
	if errResp := t.authorizeHierarchy(ac, primaryHandle); errResp != nil {
		return errResp
	}

	o, derr := derivePrimary(hi.seed, tmpl, userAuth)
	if derr != nil {
		return derr
	}
	// A primary's parent is the hierarchy, whose Qualified Name is its handle.
	parentQN := permanentName(primaryHandle)
	o.qualifiedName = qualifiedNameOf(tmpl.NameAlg, parentQN, o.name)
	handle, ok := t.objects.loadTransient(o)
	if !ok {
		return errorResponse(RCObjectMemory)
	}

	creationData, creationHash, ticket := t.buildCreationData(primaryHandle, tmpl.NameAlg, o.name, t.hierarchyProof(primaryHandle), parentQN, parentQN, AlgNull, pcrs, outsideInfo)

	var w writer
	o.public.marshal2B(&w) // outPublic
	w.raw(creationData)    // creationData (TPM2B_CREATION_DATA)
	w.tpm2b(creationHash)  // creationHash
	w.raw(ticket)          // creationTicket (TPMT_TK_CREATION)
	w.tpm2b(o.name)        // name
	return t.authResponse(ac, []uint32{handle}, w.bytes())
}

// platformPersistentBase is the start of the platform persistent-handle range;
// handles below it belong to the owner (storage) hierarchy.
const platformPersistentBase = 0x81800000

// cmdEvictControl implements TPM2_EvictControl: make a transient object
// persistent, or evict a persistent one. Authorized by Owner or Platform.
func (t *TPM) cmdEvictControl(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCEvictControl, 2, r) // auth hierarchy, objectHandle
	if errResp != nil {
		return errResp
	}
	persistentHandle := r.u32()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	authHandle := ac.handles[0]
	objHandle := ac.handles[1]
	if authHandle != RHOwner && authHandle != RHPlatform {
		return errorResponse(withHandle(RCValue, 1))
	}
	if errResp := t.authorizeHierarchy(ac, authHandle); errResp != nil {
		return errResp
	}

	// Evicting an existing persistent object: objectHandle is itself persistent.
	if classifyHandle(objHandle) == htPersistent {
		if !t.objects.evict(objHandle) {
			return errorResponse(withHandle(RCHandle, 2))
		}
		return t.authResponse(ac, nil, nil)
	}

	// Otherwise persist the transient object at persistentHandle.
	o, ok := t.objects.get(objHandle)
	if !ok {
		return errorResponse(withHandle(RCHandle, 2))
	}
	if classifyHandle(persistentHandle) != htPersistent {
		return errorResponse(withParam(RCValue, 1))
	}
	// The hierarchy owns its half of the persistent range.
	ownerRange := persistentHandle < platformPersistentBase
	if (authHandle == RHOwner) != ownerRange {
		return errorResponse(withParam(RCValue, 1))
	}
	if _, exists := t.objects.get(persistentHandle); exists {
		return errorResponse(RCNVDefined) // persistent handle already in use
	}
	t.objects.persist(persistentHandle, o)
	return t.authResponse(ac, nil, nil)
}

// randBytes returns n bytes from r (the TPM entropy source).
func randBytes(r io.Reader, n int) []byte {
	b := make([]byte, n)
	_, _ = io.ReadFull(r, b)
	return b
}

// authorizeObject verifies the idx'th authorization against a loaded object. The
// object is dictionary-attack protected unless its noDA attribute is set.
func (t *TPM) authorizeObject(ac *commandAuth, idx int, o *object) []byte {
	daProtected := o.public.Attrs&ObjNoDA == 0
	return t.verifyAuth(ac, idx, o.name, o.sensitive.AuthValue, o.public.AuthPolicy, daProtected)
}

// createChild builds a child object for the given template: a key from rng, or a
// sealed data blob (keyed-hash without sensitiveDataOrigin) from data.
func createChild(tmpl public, userAuth, data []byte, rng io.Reader) (*object, []byte) {
	pub := tmpl
	sens := sensitive{Type: tmpl.Type, AuthValue: append([]byte(nil), userAuth...)}
	if isStorageKey(tmpl.Attrs) {
		sens.SeedValue = randBytes(rng, hashSize(tmpl.NameAlg))
	}

	switch tmpl.Type {
	case AlgRSA:
		n, p, err := deriveRSAKey(rng, int(tmpl.KeyBits))
		if err != nil {
			return nil, errorResponse(RCKey)
		}
		pub.Unique, sens.Secret = n, p
	case AlgECC:
		curve := curveFor(tmpl.Curve)
		if curve == nil {
			return nil, errorResponse(withParam(RCValue, 2))
		}
		x, y, d, err := deriveECCKey(rng, curve, tmpl.Curve)
		if err != nil {
			return nil, errorResponse(RCKey)
		}
		pub.UniqueX, pub.UniqueY, sens.Secret = x, y, d
	case AlgKeyedHash:
		sens.SeedValue = randBytes(rng, hashSize(tmpl.NameAlg))
		if tmpl.Attrs&ObjSensitiveDataOrigin != 0 {
			sens.Secret = randBytes(rng, hashSize(tmpl.NameAlg)) // generated HMAC key
		} else {
			if len(data) == 0 {
				return nil, errorResponse(withParam(RCValue, 1)) // sealed data required
			}
			sens.Secret = append([]byte(nil), data...) // user data to seal
		}
		pub.Unique = hashSum(tmpl.NameAlg, sens.SeedValue, sens.Secret)
	default:
		return nil, errorResponse(withParam(RCType, 2))
	}

	o := &object{public: pub, sensitive: sens}
	o.name = pub.name()
	return o, nil
}

// cmdCreate implements TPM2_Create: create a child object under a storage parent
// and return it wrapped as a TPM2B_PRIVATE plus its public area. The object is not
// loaded — TPM2_Load loads it.
func (t *TPM) cmdCreate(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCCreate, 1, r) // parentHandle
	if errResp != nil {
		return errResp
	}
	t.decryptCommandParams(ac, r) // inSensitive may be encrypted by a decrypt session
	_ = r.u16()                   // inSensitive (TPM2B_SENSITIVE_CREATE) outer size
	userAuth := r.tpm2b()
	data := r.tpm2b()
	tmpl := readPublic2B(r)
	outsideInfo := r.tpm2b()
	pcrs := readPCRSelectionList(r)
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}

	parentHandle := ac.handles[0]
	parent, ok := t.objects.get(parentHandle)
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if !isStorageKey(parent.public.Attrs) {
		return errorResponse(withHandle(RCType, 1)) // parent must be a storage key
	}
	if _, ok := cryptoHash(tmpl.NameAlg); !ok {
		return errorResponse(withParam(RCValue, 2))
	}
	if errResp := t.authorizeObject(ac, 0, parent); errResp != nil {
		return errResp
	}

	child, derr := createChild(tmpl, userAuth, data, t.rand)
	if derr != nil {
		return derr
	}
	outPrivate := wrapSensitive(parent, &child.sensitive, child.name, t.rand)
	creationData, creationHash, ticket := t.buildCreationData(RHNull, tmpl.NameAlg, child.name, proofFromSeed(parent.sensitive.SeedValue), parent.name, parent.qualifiedName, parent.public.NameAlg, pcrs, outsideInfo)

	var w writer
	w.raw(outPrivate)          // outPrivate (TPM2B_PRIVATE)
	child.public.marshal2B(&w) // outPublic
	w.raw(creationData)        // creationData
	w.tpm2b(creationHash)      // creationHash
	w.raw(ticket)              // creationTicket
	return t.authResponse(ac, nil, w.bytes())
}

// cmdLoad implements TPM2_Load: unwrap a TPM2B_PRIVATE under its parent and load
// the object, returning a transient handle and the object Name.
func (t *TPM) cmdLoad(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCLoad, 1, r) // parentHandle
	if errResp != nil {
		return errResp
	}
	inPrivate := r.tpm2b() // TPM2B_PRIVATE content
	inPublic := readPublic2B(r)
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}

	parentHandle := ac.handles[0]
	parent, ok := t.objects.get(parentHandle)
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if !isStorageKey(parent.public.Attrs) {
		return errorResponse(withHandle(RCType, 1))
	}
	if errResp := t.authorizeObject(ac, 0, parent); errResp != nil {
		return errResp
	}

	childName := inPublic.name()
	sens, ok := unwrapPrivate(parent, inPrivate, childName)
	if !ok {
		return errorResponse(RCIntegrity) // wrong parent or tampered blob
	}
	o := &object{public: inPublic, sensitive: *sens, name: childName}
	o.qualifiedName = qualifiedNameOf(inPublic.NameAlg, parent.qualifiedName, childName)
	handle, ok := t.objects.loadTransient(o)
	if !ok {
		return errorResponse(RCObjectMemory)
	}
	var w writer
	w.tpm2b(o.name) // name
	return t.authResponse(ac, []uint32{handle}, w.bytes())
}

// cmdObjectChangeAuth implements TPM2_ObjectChangeAuth: produce a new
// TPM2B_PRIVATE for a loaded object with a different authValue, re-wrapped under
// its parent. The object's public area (and therefore its Name) is unchanged.
func (t *TPM) cmdObjectChangeAuth(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCObjectChangeAuth, 2, r) // objectHandle, parentHandle
	if errResp != nil {
		return errResp
	}
	newAuth := r.tpm2b()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	obj, ok := t.objects.get(ac.handles[0])
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	parent, ok := t.objects.get(ac.handles[1])
	if !ok {
		return errorResponse(withHandle(RCHandle, 2))
	}
	if !isStorageKey(parent.public.Attrs) {
		return errorResponse(withHandle(RCType, 2))
	}
	if errResp := t.authorizeObject(ac, 0, obj); errResp != nil {
		return errResp
	}

	newSens := obj.sensitive
	newSens.AuthValue = append([]byte(nil), newAuth...)
	outPrivate := wrapSensitive(parent, &newSens, obj.name, t.rand)

	var w writer
	w.raw(outPrivate) // outPrivate (TPM2B_PRIVATE)
	return t.authResponse(ac, nil, w.bytes())
}

// cmdLoadExternal implements TPM2_LoadExternal: load a public (and optionally
// sensitive) object not derived from a TPM parent. No authorization is required.
func (t *TPM) cmdLoadExternal(r *reader) []byte {
	inPrivate := r.tpm2b() // TPM2B_SENSITIVE (may be empty for public-only)
	inPublic := readPublic2B(r)
	_ = r.u32() // hierarchy (TPMI_RH_HIERARCHY)
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	o := &object{public: inPublic, name: inPublic.name()}
	// An externally loaded object has no TPM ancestry: its Qualified Name is its
	// Name (TPM 2.0 Part 1, §26.5).
	o.qualifiedName = append([]byte(nil), o.name...)
	if len(inPrivate) > 0 {
		sr := newReader(inPrivate)
		_ = sr.u16() // TPM2B_SENSITIVE outer size
		o.sensitive.unmarshal(sr)
		if sr.err != nil {
			return errorResponse(RCInsufficient)
		}
	}
	handle, ok := t.objects.loadTransient(o)
	if !ok {
		return errorResponse(RCObjectMemory)
	}
	var w writer
	w.u32(handle)   // objectHandle (response handle area)
	w.tpm2b(o.name) // name
	return successResponse(w.bytes(), 0)
}

// cmdUnseal implements TPM2_Unseal: release the data sealed in a keyed-hash data
// object (the BitLocker VMK release). The object must be a sealed data blob, not a
// signing or decryption key.
func (t *TPM) cmdUnseal(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCUnseal, 1, r) // itemHandle
	if errResp != nil {
		return errResp
	}
	o, ok := t.objects.get(ac.handles[0])
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if o.public.Type != AlgKeyedHash || o.public.Attrs&(ObjSign|ObjDecrypt) != 0 {
		return errorResponse(withHandle(RCAttributes, 1)) // only sealed data objects unseal
	}
	if errResp := t.authorizeObject(ac, 0, o); errResp != nil {
		return errResp
	}
	var w writer
	w.tpm2b(o.sensitive.Secret) // outData (TPM2B_SENSITIVE_DATA)
	return t.authResponse(ac, nil, w.bytes())
}

// cmdReadPublic implements TPM2_ReadPublic: return an object's public area, Name
// and qualified Name. No authorization is required.
func (t *TPM) cmdReadPublic(r *reader) []byte {
	handle := r.u32()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	o, ok := t.objects.get(handle)
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	qn := o.qualifiedName
	if len(qn) == 0 {
		qn = o.name // pre-QN object (e.g. restored from an older snapshot)
	}
	var w writer
	o.public.marshal2B(&w) // outPublic
	w.tpm2b(o.name)        // name
	w.tpm2b(qn)            // qualifiedName
	return successResponse(w.bytes(), 0)
}
