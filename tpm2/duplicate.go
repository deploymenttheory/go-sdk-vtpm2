// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

// This file implements the duplication/migration commands (TPM 2.0 Part 3, §13):
// TPM2_Duplicate, TPM2_Import and TPM2_Rewrap. They move an object's sensitive
// area between parents using the outer wrapper (Part 1, §23.3) with the seed shared
// via the "DUPLICATE" Labeled KEM. The optional inner symmetric wrapper is not
// supported (symmetricAlg must be NULL and encryptionKeyIn empty).

// noInnerWrap reports whether the request asks only for the outer wrapper.
func noInnerWrap(symAlg symDef, encKey []byte) bool {
	return symAlg.Alg == AlgNull && len(encKey) == 0
}

// cmdDuplicate implements TPM2_Duplicate (Part 3, §13.1): export a duplicable
// object's sensitive area, outer-wrapped to a new asymmetric parent. Handles:
// objectHandle (authorized), newParentHandle (public).
func (t *TPM) cmdDuplicate(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCDuplicate, 2, r)
	if errResp != nil {
		return errResp
	}
	encryptionKeyIn := r.tpm2b()
	var symAlg symDef
	symAlg.unmarshal(r) // TPMT_SYM_DEF_OBJECT
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if !noInnerWrap(symAlg, encryptionKeyIn) {
		return errorResponse(withParam(RCValue, 1)) // inner wrapper unsupported
	}
	obj, ok := t.objects.get(ac.handles[0])
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if obj.public.Attrs&ObjFixedParent != 0 {
		return errorResponse(withHandle(RCAttributes, 1)) // not duplicable
	}
	if errResp := t.authorizeObject(ac, 0, obj); errResp != nil {
		return errResp
	}
	newParent, ok := t.objects.get(ac.handles[1])
	if !ok {
		return errorResponse(withHandle(RCHandle, 2))
	}
	if !isStorageKey(newParent.public.Attrs) || newParent.public.Sym.Alg == AlgNull {
		return errorResponse(withHandle(RCType, 2))
	}

	var sw writer
	obj.sensitive.marshal2B(&sw) // TPM2B_SENSITIVE
	seed, secret, ok := encryptSeed(newParent, []byte("DUPLICATE"), t.rand)
	if !ok {
		return errorResponse(RCKey)
	}
	dup := wrapDuplication(newParent.public.NameAlg, seed, sw.bytes(), obj.name, newParent.public.Sym.KeyBits)

	var w writer
	w.tpm2b(nil)    // encryptionKeyOut (no inner wrapper)
	w.tpm2b(dup)    // duplicate (TPM2B_PRIVATE)
	w.tpm2b(secret) // outSymSeed (TPM2B_ENCRYPTED_SECRET)
	return t.authResponse(ac, nil, w.bytes())
}

// cmdImport implements TPM2_Import (Part 3, §13.3): unwrap a duplicated object and
// re-wrap it as a TPM2B_PRIVATE under the new parent. Handle: parentHandle.
func (t *TPM) cmdImport(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCImport, 1, r)
	if errResp != nil {
		return errResp
	}
	encryptionKey := r.tpm2b()
	objectPublic := readPublic2B(r)
	duplicate := r.tpm2b()
	inSymSeed := r.tpm2b()
	var symAlg symDef
	symAlg.unmarshal(r)
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if !noInnerWrap(symAlg, encryptionKey) {
		return errorResponse(withParam(RCValue, 1))
	}
	parent, ok := t.objects.get(ac.handles[0])
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if !isStorageKey(parent.public.Attrs) {
		return errorResponse(withHandle(RCType, 1))
	}
	if errResp := t.authorizeObject(ac, 0, parent); errResp != nil {
		return errResp
	}
	seed, ok := decryptSeed(parent, inSymSeed, []byte("DUPLICATE"), t.rand)
	if !ok {
		return errorResponse(withParam(RCValue, 4))
	}
	objName := objectPublic.name()
	dec, ok := unwrapDuplication(parent.public.NameAlg, seed, duplicate, objName, parent.public.Sym.KeyBits)
	if !ok {
		return errorResponse(RCIntegrity)
	}
	sr := newReader(dec)
	_ = sr.u16() // TPM2B_SENSITIVE outer size
	var sens sensitive
	sens.unmarshal(sr)
	if sr.err != nil {
		return errorResponse(RCIntegrity)
	}

	var w writer
	w.raw(wrapSensitive(parent, &sens, objName, t.rand)) // outPrivate (TPM2B_PRIVATE)
	return t.authResponse(ac, nil, w.bytes())
}

// cmdRewrap implements TPM2_Rewrap (Part 3, §13.2): move a duplication blob from
// one parent to another. Handles: oldParent (authorized), newParent (public).
func (t *TPM) cmdRewrap(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCRewrap, 2, r)
	if errResp != nil {
		return errResp
	}
	inDuplicate := r.tpm2b()
	name := r.tpm2b()
	inSymSeed := r.tpm2b()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	oldParent, ok := t.objects.get(ac.handles[0])
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if errResp := t.authorizeObject(ac, 0, oldParent); errResp != nil {
		return errResp
	}
	seed, ok := decryptSeed(oldParent, inSymSeed, []byte("DUPLICATE"), t.rand)
	if !ok {
		return errorResponse(withParam(RCValue, 3))
	}
	sens2B, ok := unwrapDuplication(oldParent.public.NameAlg, seed, inDuplicate, name, oldParent.public.Sym.KeyBits)
	if !ok {
		return errorResponse(RCIntegrity)
	}
	newParent, ok := t.objects.get(ac.handles[1])
	if !ok {
		return errorResponse(withHandle(RCHandle, 2))
	}
	if !isStorageKey(newParent.public.Attrs) || newParent.public.Sym.Alg == AlgNull {
		return errorResponse(withHandle(RCType, 2))
	}
	newSeed, newSecret, ok := encryptSeed(newParent, []byte("DUPLICATE"), t.rand)
	if !ok {
		return errorResponse(RCKey)
	}
	out := wrapDuplication(newParent.public.NameAlg, newSeed, sens2B, name, newParent.public.Sym.KeyBits)

	var w writer
	w.tpm2b(out)       // outDuplicate
	w.tpm2b(newSecret) // outSymSeed
	return t.authResponse(ac, nil, w.bytes())
}
