// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"encoding/binary"
	"errors"
)

// errShort is returned by reader methods when the buffer is exhausted before a
// requested field could be read. Handlers translate it into TPM_RC_INSUFFICIENT.
var errShort = errors.New("tpm2: buffer underrun")

// errBadValue latches a structural value violation (e.g. an out-of-range size
// field) that is distinct from a plain underrun. Handlers translate it into
// TPM_RC_VALUE rather than TPM_RC_INSUFFICIENT.
var errBadValue = errors.New("tpm2: value out of range")

// reader is a big-endian cursor over a TPM command parameter buffer. All TPM
// 2.0 wire integers are big-endian. Once a read fails the reader latches its
// error, so callers may read a sequence of fields and check err once.
type reader struct {
	b   []byte
	off int
	err error
}

func newReader(b []byte) *reader { return &reader{b: b} }

// remaining returns the bytes not yet consumed.
func (r *reader) remaining() int { return len(r.b) - r.off }

func (r *reader) u8() byte {
	if r.err != nil {
		return 0
	}
	if r.remaining() < 1 {
		r.err = errShort
		return 0
	}
	v := r.b[r.off]
	r.off++
	return v
}

func (r *reader) u16() uint16 {
	if r.err != nil {
		return 0
	}
	if r.remaining() < 2 {
		r.err = errShort
		return 0
	}
	v := binary.BigEndian.Uint16(r.b[r.off:])
	r.off += 2
	return v
}

func (r *reader) u32() uint32 {
	if r.err != nil {
		return 0
	}
	if r.remaining() < 4 {
		r.err = errShort
		return 0
	}
	v := binary.BigEndian.Uint32(r.b[r.off:])
	r.off += 4
	return v
}

func (r *reader) u64() uint64 {
	if r.err != nil {
		return 0
	}
	if r.remaining() < 8 {
		r.err = errShort
		return 0
	}
	v := binary.BigEndian.Uint64(r.b[r.off:])
	r.off += 8
	return v
}

// tpm2b reads a TPM2B_* field: a UINT16 size prefix followed by that many bytes.
// The returned slice is a copy (possibly empty, never sharing the input buffer).
func (r *reader) tpm2b() []byte {
	n := int(r.u16())
	return r.bytes(n)
}

// boundedListCount reads a UINT32 list/array element count and rejects one that is
// implausibly large before it is used to size an allocation. Every list element
// consumes at least one byte on the wire, so a count exceeding the bytes remaining
// is malformed; this latches errBadValue (→ TPM_RC_VALUE) rather than letting a
// hostile count drive a multi-gigabyte make(). Returns the count and whether it is
// in range.
func (r *reader) boundedListCount() (uint32, bool) {
	n := r.u32()
	if r.err != nil {
		return 0, false
	}
	if n > uint32(r.remaining()) {
		r.err = errBadValue
		return 0, false
	}
	return n, true
}

// bytes consumes exactly n bytes and returns a copy.
func (r *reader) bytes(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || r.remaining() < n {
		r.err = errShort
		return nil
	}
	out := make([]byte, n)
	copy(out, r.b[r.off:r.off+n])
	r.off += n
	return out
}

// writer accumulates a big-endian TPM response parameter buffer.
type writer struct {
	b []byte
}

func (w *writer) u8(v byte)    { w.b = append(w.b, v) }
func (w *writer) u16(v uint16) { w.b = binary.BigEndian.AppendUint16(w.b, v) }
func (w *writer) u32(v uint32) { w.b = binary.BigEndian.AppendUint32(w.b, v) }
func (w *writer) u64(v uint64) { w.b = binary.BigEndian.AppendUint64(w.b, v) }
func (w *writer) raw(p []byte) { w.b = append(w.b, p...) }

// tpm2b writes a TPM2B_* field: a UINT16 size prefix followed by p's bytes.
func (w *writer) tpm2b(p []byte) {
	w.u16(uint16(len(p)))
	w.b = append(w.b, p...)
}

// bytes returns the accumulated buffer.
func (w *writer) bytes() []byte { return w.b }
