// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package client

import "encoding/binary"

// reader / writer are the big-endian, size-prefix marshalling primitives the TPM
// 2.0 wire format uses. They mirror the responder's own buffer helpers so the
// client and the device agree on every byte.

type writer struct{ b []byte }

func (w *writer) u8(v byte)      { w.b = append(w.b, v) }
func (w *writer) u16(v uint16)   { w.b = binary.BigEndian.AppendUint16(w.b, v) }
func (w *writer) u32(v uint32)   { w.b = binary.BigEndian.AppendUint32(w.b, v) }
func (w *writer) raw(v []byte)   { w.b = append(w.b, v...) }
func (w *writer) tpm2b(v []byte) { w.u16(uint16(len(v))); w.raw(v) }
func (w *writer) bytes() []byte  { return w.b }

type reader struct {
	b   []byte
	off int
	err bool
}

func newReader(b []byte) *reader { return &reader{b: b} }

func (r *reader) need(n int) bool {
	if r.err || r.off+n > len(r.b) {
		r.err = true
		return false
	}
	return true
}

func (r *reader) u16() uint16 {
	if !r.need(2) {
		return 0
	}
	v := binary.BigEndian.Uint16(r.b[r.off:])
	r.off += 2
	return v
}

func (r *reader) u32() uint32 {
	if !r.need(4) {
		return 0
	}
	v := binary.BigEndian.Uint32(r.b[r.off:])
	r.off += 4
	return v
}

func (r *reader) bytes(n int) []byte {
	if !r.need(n) {
		return nil
	}
	v := r.b[r.off : r.off+n]
	r.off += n
	return append([]byte(nil), v...)
}

func (r *reader) tpm2b() []byte { return r.bytes(int(r.u16())) }
