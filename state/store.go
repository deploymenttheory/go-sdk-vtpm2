// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

// Package state persists a vtpm2 TPM's state across host restarts. Windows 11
// requires its vTPM (and therefore the keys sealed against it, e.g. BitLocker)
// to survive reboots, so the emulator snapshots its state to a per-VM directory.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/deploymenttheory/go-sdk-vtpm2/tpm2"
)

// stateFile is the snapshot filename within a Store's directory.
const stateFile = "tpm-state.json"

// Store reads and writes a TPM Snapshot under a directory (the per-VM TPM state
// dir). The zero value is unusable; construct one with NewStore.
type Store struct {
	dir string
}

// NewStore returns a Store rooted at dir, creating the directory if needed.
func NewStore(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("vtpm2/state: empty directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("vtpm2/state: create %s: %w", dir, err)
	}
	return &Store{dir: dir}, nil
}

// path is the absolute snapshot path.
func (s *Store) path() string { return filepath.Join(s.dir, stateFile) }

// Load reads the persisted snapshot. The bool is false (with a nil error) when
// no snapshot exists yet, so a caller can start a fresh TPM on first boot.
func (s *Store) Load() (tpm2.Snapshot, bool, error) {
	data, err := os.ReadFile(s.path())
	if errors.Is(err, fs.ErrNotExist) {
		return tpm2.Snapshot{}, false, nil
	}
	if err != nil {
		return tpm2.Snapshot{}, false, fmt.Errorf("vtpm2/state: read: %w", err)
	}
	var snap tpm2.Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return tpm2.Snapshot{}, false, fmt.Errorf("vtpm2/state: decode: %w", err)
	}
	return snap, true, nil
}

// Save writes snap atomically (temp file + rename) so a crash mid-write cannot
// corrupt the persisted state.
func (s *Store) Save(snap tpm2.Snapshot) error {
	data, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("vtpm2/state: encode: %w", err)
	}
	tmp, err := os.CreateTemp(s.dir, ".tpm-state-*.tmp")
	if err != nil {
		return fmt.Errorf("vtpm2/state: temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("vtpm2/state: write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("vtpm2/state: close: %w", err)
	}
	if err := os.Rename(tmpName, s.path()); err != nil {
		return fmt.Errorf("vtpm2/state: rename: %w", err)
	}
	return nil
}

// LoadInto restores a persisted snapshot into tpm, returning whether state was
// found. A fresh TPM (no prior snapshot) leaves tpm untouched.
func (s *Store) LoadInto(tpm *tpm2.TPM) (bool, error) {
	snap, ok, err := s.Load()
	if err != nil || !ok {
		return false, err
	}
	if err := tpm.Restore(snap); err != nil {
		return false, err
	}
	return true, nil
}
