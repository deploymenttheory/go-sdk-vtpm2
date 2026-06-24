// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package swtpm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
)

// maxTPMFrame caps a single data-channel TPM command/response, guarding against
// a bogus size field. The TPM 2.0 max command buffer is well under this.
const maxTPMFrame = 1 << 16

// Device is the TPM the server drives. *tpm2.TPM satisfies it.
type Device interface {
	// Execute processes one raw TPM 2.0 command blob and returns the response.
	Execute(cmd []byte) []byte
	// Init (re)initializes the TPM at the hardware level (swtpm CMD_INIT).
	Init(deleteVolatile bool)
}

// stateBlobDevice is an optional Device capability: export/import the full TPM
// state as an opaque blob, backing CMD_GET_STATEBLOB / CMD_SET_STATEBLOB.
// *tpm2.TPM satisfies it.
type stateBlobDevice interface {
	StateBlob() ([]byte, error)
	LoadStateBlob(blob []byte) error
}

// localityDevice is an optional Device capability: receive the command locality
// from CMD_SET_LOCALITY. *tpm2.TPM satisfies it.
type localityDevice interface {
	SetLocality(loc byte)
}

// Server hosts the swtpm control + data channels on a Unix control socket. QEMU
// connects its tpm-emulator backend to that socket and passes the data-channel
// fd over it. The zero value is unusable; build one with NewServer.
type Server struct {
	ctrlPath string
	dev      Device
	// onPersist, if set, is invoked when the guest asks the TPM to persist
	// volatile state (CMD_STORE_VOLATILE / CMD_SHUTDOWN), letting the owner
	// snapshot to disk.
	onPersist func()

	mu       sync.Mutex
	ln       *net.UnixListener
	conns    map[*net.UnixConn]struct{}
	dataConn net.Conn
	locality byte   // most recent CMD_SET_LOCALITY value
	setBuf   []byte // accumulates CMD_SET_STATEBLOB chunks until the final one
	closed   bool
}

// NewServer returns a server that will host dev on ctrlPath. onPersist may be
// nil. Call Start to begin listening.
func NewServer(ctrlPath string, dev Device, onPersist func()) *Server {
	return &Server{
		ctrlPath:  ctrlPath,
		dev:       dev,
		onPersist: onPersist,
		conns:     make(map[*net.UnixConn]struct{}),
	}
}

// Start binds the control socket and serves connections in the background. It
// returns once the socket is listening (so a caller can launch QEMU against it).
func (s *Server) Start() error {
	_ = os.Remove(s.ctrlPath) // clear a stale socket from a prior run
	addr := &net.UnixAddr{Name: s.ctrlPath, Net: "unix"}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		return fmt.Errorf("swtpm: listen %s: %w", s.ctrlPath, err)
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()

	go s.acceptLoop(ln)
	return nil
}

// Close stops listening, drops all connections, and removes the socket file.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	ln := s.ln
	dataConn := s.dataConn
	conns := make([]*net.UnixConn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}
	for _, c := range conns {
		_ = c.Close()
	}
	if dataConn != nil {
		_ = dataConn.Close()
	}
	_ = os.Remove(s.ctrlPath)
	return nil
}

func (s *Server) acceptLoop(ln *net.UnixListener) {
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			return // listener closed
		}
		s.mu.Lock()
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		go s.serveControl(conn)
	}
}

// serveControl reads one control request per message, dispatches it, and writes
// the response. The fd for CMD_SET_DATAFD arrives as SCM_RIGHTS ancillary data
// on the same message.
func (s *Server) serveControl(conn *net.UnixConn) {
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		_ = conn.Close()
	}()

	// Large enough that a single-chunk CMD_SET_STATEBLOB (the serialized TPM
	// state) arrives in one control message; bigger states would need chunking.
	buf := make([]byte, 1<<16)
	oob := make([]byte, 256)
	for {
		n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
		if err != nil {
			return
		}
		if n < 4 {
			continue
		}
		cmd := binary.BigEndian.Uint32(buf[:4])
		payload := buf[4:n]

		resp, fd := s.handleControl(cmd, payload, oob[:oobn])
		if _, err := conn.Write(resp); err != nil {
			return
		}
		if fd >= 0 {
			s.startDataChannel(fd)
		}
	}
}

// handleControl builds the response for one control command. When the command
// is CMD_SET_DATAFD it also returns the extracted data-channel fd (or -1).
func (s *Server) handleControl(cmd uint32, payload, oob []byte) (resp []byte, fd int) {
	fd = -1
	switch cmd {
	case cmdGetCapability:
		return resCapability(), fd
	case cmdInit:
		flags := uint32(0)
		if len(payload) >= 4 {
			flags = binary.BigEndian.Uint32(payload)
		}
		s.dev.Init(flags&ptmInitFlagDeleteVolatile != 0)
		return resResult(ptmSuccess), fd
	case cmdShutdown:
		s.persist()
		return resResult(ptmSuccess), fd
	case cmdStoreVolatile:
		s.persist()
		return resResult(ptmSuccess), fd
	case cmdGetTPMEstablished:
		return resEstablished(false), fd
	case cmdSetLocality:
		if len(payload) >= 1 {
			s.mu.Lock()
			s.locality = payload[0]
			s.mu.Unlock()
			if dev, ok := s.dev.(localityDevice); ok {
				dev.SetLocality(payload[0]) // enforced by PCR operations
			}
		}
		return resResult(ptmSuccess), fd
	case cmdGetStateBlob:
		return s.handleGetStateBlob(payload), fd
	case cmdSetStateBlob:
		return s.handleSetStateBlob(payload), fd
	case cmdResetTPMEstablished, cmdStop, cmdCancelTPMCmd:
		return resResult(ptmSuccess), fd
	case cmdGetConfig:
		return resConfig(), fd
	case cmdSetBufferSize:
		return resBufferSize(), fd
	case cmdGetInfo:
		return resInfo(), fd
	case cmdSetDataFD:
		if got, err := extractFD(oob); err == nil {
			fd = got
			return resResult(ptmSuccess), fd
		}
		return resResult(ptmBadInput), -1
	default:
		return resResult(ptmBadInput), fd
	}
}

// handleGetStateBlob serves CMD_GET_STATEBLOB: it returns the requested chunk of
// the TPM's permanent state blob (the whole blob fits in one chunk here).
// Request layout: state_flags(4) tpm_number(4) type(4) offset(4).
func (s *Server) handleGetStateBlob(payload []byte) []byte {
	if len(payload) < 16 {
		return resResult(ptmBadInput)
	}
	blobType := binary.BigEndian.Uint32(payload[8:12])
	offset := binary.BigEndian.Uint32(payload[12:16])

	dev, ok := s.dev.(stateBlobDevice)
	if !ok {
		return resResult(ptmBadInput)
	}
	var blob []byte
	if blobType == blobPermanent {
		b, err := dev.StateBlob()
		if err != nil {
			return resResult(ptmBadInput)
		}
		blob = b
	}
	if int(offset) >= len(blob) {
		return resStateBlob(uint32(len(blob)), nil) // past the end: no more data
	}
	end := int(offset) + maxStateChunk
	if end > len(blob) {
		end = len(blob)
	}
	return resStateBlob(uint32(len(blob)), blob[offset:end])
}

// handleSetStateBlob serves CMD_SET_STATEBLOB. It accumulates the permanent-blob
// chunks; a chunk shorter than maxStateChunk is the final one, at which point the
// reassembled blob is loaded. Request layout: state_flags(4) type(4) length(4)
// data(length).
func (s *Server) handleSetStateBlob(payload []byte) []byte {
	if len(payload) < 12 {
		return resResult(ptmBadInput)
	}
	blobType := binary.BigEndian.Uint32(payload[4:8])
	length := binary.BigEndian.Uint32(payload[8:12])
	if 12+int(length) > len(payload) {
		return resResult(ptmBadInput)
	}
	if blobType != blobPermanent {
		return resResult(ptmSuccess) // volatile/save-state are not persisted here
	}

	s.mu.Lock()
	s.setBuf = append(s.setBuf, payload[12:12+length]...)
	final := int(length) < maxStateChunk // short (or zero) chunk ends the transfer
	blob := s.setBuf
	if final {
		s.setBuf = nil
	}
	s.mu.Unlock()

	if !final || len(blob) == 0 {
		return resResult(ptmSuccess) // keep accumulating
	}
	dev, ok := s.dev.(stateBlobDevice)
	if !ok {
		return resResult(ptmBadInput)
	}
	if err := dev.LoadStateBlob(blob); err != nil {
		return resResult(ptmBadInput)
	}
	return resResult(ptmSuccess)
}

// startDataChannel adopts the fd QEMU passed and serves TPM traffic on it.
func (s *Server) startDataChannel(fd int) {
	f := os.NewFile(uintptr(fd), "vtpm2-data")
	if f == nil {
		_ = syscall.Close(fd)
		return
	}
	conn, err := net.FileConn(f) // dups the fd
	_ = f.Close()
	if err != nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = conn.Close()
		return
	}
	if s.dataConn != nil {
		_ = s.dataConn.Close() // replace any prior data channel
	}
	s.dataConn = conn
	s.mu.Unlock()

	go s.serveData(conn)
}

// serveData reads framed TPM commands off the data channel, executes them, and
// writes back the raw responses, until the channel closes.
func (s *Server) serveData(conn net.Conn) {
	defer conn.Close()
	for {
		cmd, err := readTPMCommand(conn)
		if err != nil {
			return
		}
		if _, err := conn.Write(s.dev.Execute(cmd)); err != nil {
			return
		}
	}
}

func (s *Server) persist() {
	if s.onPersist != nil {
		s.onPersist()
	}
}

// readTPMCommand reads exactly one TPM 2.0 command: the 6-byte tag+size prefix
// determines the total length, and the remainder follows.
func readTPMCommand(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 6) // tag (2) + commandSize (4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(hdr[2:6])
	if size < tpmCmdHeaderLen || size > maxTPMFrame {
		return nil, fmt.Errorf("swtpm: bad TPM command size %d", size)
	}
	cmd := make([]byte, size)
	copy(cmd, hdr)
	if _, err := io.ReadFull(r, cmd[6:]); err != nil {
		return nil, err
	}
	return cmd, nil
}

// extractFD pulls the first file descriptor out of SCM_RIGHTS ancillary data.
func extractFD(oob []byte) (int, error) {
	scms, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return -1, err
	}
	for _, scm := range scms {
		fds, err := syscall.ParseUnixRights(&scm)
		if err == nil && len(fds) > 0 {
			return fds[0], nil
		}
	}
	return -1, errors.New("swtpm: no fd in control message")
}
