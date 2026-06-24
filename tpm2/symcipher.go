// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"crypto/aes"
	"crypto/cipher"
)

// This file implements the symmetric-cipher commands (TPM 2.0 Part 3, §15):
// TPM2_EncryptDecrypt and TPM2_EncryptDecrypt2. Both run a loaded SYMCIPHER (AES)
// key in a selectable block-cipher mode; they differ only in parameter order so
// that EncryptDecrypt2's inData may be parameter-encrypted.

// lastBlock returns the final bs bytes of b (for IV chaining), or all of b when
// shorter than a block.
func lastBlock(b []byte, bs int) []byte {
	if len(b) < bs {
		return append([]byte(nil), b...)
	}
	return append([]byte(nil), b[len(b)-bs:]...)
}

// symCrypt runs AES in the requested TPM block-cipher mode. It returns the output,
// the chaining IV for the next call, and whether the mode/inputs were valid.
func symCrypt(mode uint16, key, iv, data []byte, decrypt bool) (out, ivOut []byte, ok bool) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, false
	}
	bs := block.BlockSize()
	switch mode {
	case AlgCFB:
		out = aesCFB(key, iv, data, !decrypt)
		ct := out
		if decrypt {
			ct = data
		}
		return out, lastBlock(ct, bs), true
	case AlgOFB:
		if len(iv) != bs {
			return nil, nil, false
		}
		out = make([]byte, len(data))
		cipher.NewOFB(block, iv).XORKeyStream(out, data)
		return out, nil, true
	case AlgCTR:
		if len(iv) != bs {
			return nil, nil, false
		}
		out = make([]byte, len(data))
		cipher.NewCTR(block, iv).XORKeyStream(out, data)
		return out, nil, true
	case AlgCBC:
		if len(iv) != bs || len(data)%bs != 0 {
			return nil, nil, false
		}
		out = make([]byte, len(data))
		if decrypt {
			cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
		} else {
			cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, data)
		}
		ct := out
		if decrypt {
			ct = data
		}
		return out, lastBlock(ct, bs), true
	case AlgECB:
		if len(data)%bs != 0 {
			return nil, nil, false
		}
		out = make([]byte, len(data))
		for i := 0; i < len(data); i += bs {
			if decrypt {
				block.Decrypt(out[i:i+bs], data[i:i+bs])
			} else {
				block.Encrypt(out[i:i+bs], data[i:i+bs])
			}
		}
		return out, nil, true
	}
	return nil, nil, false
}

// encryptDecrypt is the shared body of TPM2_EncryptDecrypt and ..._2.
func (t *TPM) encryptDecrypt(ac *commandAuth, decrypt byte, mode uint16, ivIn, inData []byte) []byte {
	key, ok := t.objects.get(ac.handles[0])
	if !ok {
		return errorResponse(withHandle(RCHandle, 1))
	}
	if key.public.Type != AlgSymCipher {
		return errorResponse(withHandle(RCKey, 1))
	}
	if errResp := t.authorizeObject(ac, 0, key); errResp != nil {
		return errResp
	}
	if mode == AlgNull {
		mode = key.public.Sym.Mode
	}
	out, ivOut, ok := symCrypt(mode, key.sensitive.Secret, ivIn, inData, decrypt != 0)
	if !ok {
		return errorResponse(withParam(RCMode, 1))
	}
	var w writer
	w.tpm2b(out)   // outData
	w.tpm2b(ivOut) // ivOut
	return t.authResponse(ac, nil, w.bytes())
}

// cmdEncryptDecrypt implements TPM2_EncryptDecrypt (Part 3, §15.2).
func (t *TPM) cmdEncryptDecrypt(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCEncryptDecrypt, 1, r) // @keyHandle
	if errResp != nil {
		return errResp
	}
	decrypt := r.u8()
	mode := r.u16()
	ivIn := r.tpm2b()
	inData := r.tpm2b()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	return t.encryptDecrypt(ac, decrypt, mode, ivIn, inData)
}

// cmdEncryptDecrypt2 implements TPM2_EncryptDecrypt2 (Part 3, §15.3): identical to
// EncryptDecrypt but with inData first, so it can be the encrypted parameter.
func (t *TPM) cmdEncryptDecrypt2(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCEncryptDecrypt2, 1, r) // @keyHandle
	if errResp != nil {
		return errResp
	}
	inData := r.tpm2b()
	decrypt := r.u8()
	mode := r.u16()
	ivIn := r.tpm2b()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	return t.encryptDecrypt(ac, decrypt, mode, ivIn, inData)
}
