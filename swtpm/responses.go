// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package swtpm

import "encoding/binary"

// tpmBufferSize is the command buffer the server advertises via
// CMD_SET_BUFFERSIZE. 4096 covers every command the processor handles.
const tpmBufferSize uint32 = 4096

// infoJSON is the static description returned by CMD_GET_INFO. swtpm returns a
// JSON document; QEMU does not parse it in the normal path, but a well-formed
// answer keeps any probing client happy.
const infoJSON = `{"TPMSpecification":{"family":"2.0","level":0,"revision":164},` +
	`"TPMAttributes":{"manufacturer":"id:44505448","model":"vtpm2","version":"id:00000001"}}`

// resResult encodes a bare ptm_res (4-byte big-endian result code).
func resResult(rc uint32) []byte {
	return binary.BigEndian.AppendUint32(nil, rc)
}

// resCapability encodes the ptm_cap_n response: tpm_result + caps mask.
func resCapability() []byte {
	b := binary.BigEndian.AppendUint32(nil, ptmSuccess)
	return binary.BigEndian.AppendUint32(b, advertisedCaps)
}

// resEstablished encodes ptm_est.u.resp: tpm_result + bit + 3 pad bytes.
func resEstablished(set bool) []byte {
	b := binary.BigEndian.AppendUint32(nil, ptmSuccess)
	bit := byte(0)
	if set {
		bit = 1
	}
	return append(b, bit, 0, 0, 0)
}

// resConfig encodes ptm_getconfig.u.resp: tpm_result + flags (no keys set).
func resConfig() []byte {
	b := binary.BigEndian.AppendUint32(nil, ptmSuccess)
	return binary.BigEndian.AppendUint32(b, 0)
}

// resBufferSize encodes ptm_setbuffersize.u.resp: result + buffersize + min + max.
func resBufferSize() []byte {
	b := binary.BigEndian.AppendUint32(nil, ptmSuccess)
	b = binary.BigEndian.AppendUint32(b, tpmBufferSize)
	b = binary.BigEndian.AppendUint32(b, tpmBufferSize) // minsize
	b = binary.BigEndian.AppendUint32(b, tpmBufferSize) // maxsize
	return b
}

// resStateBlob encodes ptm_getstate.u.resp: result + state_flags + totlength +
// length + the chunk data. The emulator returns the whole blob in one chunk.
func resStateBlob(totlength uint32, data []byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, ptmSuccess)
	b = binary.BigEndian.AppendUint32(b, 0)         // state_flags
	b = binary.BigEndian.AppendUint32(b, totlength) // totlength
	b = binary.BigEndian.AppendUint32(b, uint32(len(data)))
	return append(b, data...)
}

// resInfo encodes ptm_getinfo.u.resp: result + totlength + length + buffer. The
// whole document is returned in one chunk (offset handling is unnecessary for so
// small a payload).
func resInfo() []byte {
	body := []byte(infoJSON)
	b := binary.BigEndian.AppendUint32(nil, ptmSuccess)
	b = binary.BigEndian.AppendUint32(b, uint32(len(body))) // totlength
	b = binary.BigEndian.AppendUint32(b, uint32(len(body))) // length (this chunk)
	return append(b, body...)
}
