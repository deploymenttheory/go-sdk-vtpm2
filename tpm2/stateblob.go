// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import "encoding/json"

// StateBlob and LoadStateBlob export/import the TPM's full persistent state as an
// opaque, self-describing blob. They back the swtpm CMD_GET_STATEBLOB /
// CMD_SET_STATEBLOB control commands that QEMU uses to save, restore and migrate
// a vTPM. The format is the JSON-serialized Snapshot, so it carries its own
// version and migrates forward through Restore.

// StateBlob returns the serialized persistent state.
func (t *TPM) StateBlob() ([]byte, error) {
	return json.Marshal(t.Snapshot())
}

// LoadStateBlob restores persistent state previously produced by StateBlob.
func (t *TPM) LoadStateBlob(blob []byte) error {
	var s Snapshot
	if err := json.Unmarshal(blob, &s); err != nil {
		return err
	}
	return t.Restore(s)
}
