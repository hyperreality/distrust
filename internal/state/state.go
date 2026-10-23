// Package state records what each backend actually changed, so that changes
// can be reverted exactly (restore prior trust flags, put files back) even
// after the policy entry is gone.
package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"

	"distrust/internal/policy"
)

// State is persisted as state.json in the state directory.
type State struct {
	Version int `json:"version"`
	// Entries keeps a copy of every entry that has records, so an entry
	// removed from the policy can still be unblocked.
	Entries map[string]policy.Entry `json:"entries"`
	// Records[backend][entryID] is backend-specific undo data.
	Records map[string]map[string]json.RawMessage `json:"records"`

	dir string
}

// DefaultDir is where state lives.
func DefaultDir(systemScope bool) string {
	if systemScope {
		if p := os.Getenv("ProgramData"); p != "" {
			return filepath.Join(p, "distrust", "state")
		}
		return "/var/lib/distrust"
	}
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "distrust")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state", "distrust")
}

// Load reads state from dir (missing file = empty state).
func Load(dir string) (*State, error) {
	s := &State{Version: 1, dir: dir}
	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		if err := json.Unmarshal(data, s); err != nil {
			return nil, err
		}
	}
	s.dir = dir
	if s.Entries == nil {
		s.Entries = map[string]policy.Entry{}
	}
	if s.Records == nil {
		s.Records = map[string]map[string]json.RawMessage{}
	}
	return s, nil
}

// Dir returns the state directory (also used for quarantine/backups).
func (s *State) Dir() string { return s.dir }

// Save writes state atomically, dropping entries that no longer have records.
func (s *State) Save() error {
	used := map[string]bool{}
	for _, m := range s.Records {
		for id := range m {
			used[id] = true
		}
	}
	for id := range s.Entries {
		if !used[id] {
			delete(s.Entries, id)
		}
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return policy.WriteFileAtomic(filepath.Join(s.dir, "state.json"), append(data, '\n'), 0o600)
}

// Get decodes the record for backend/id into v; false if none.
func (s *State) Get(backend, id string, v any) bool {
	raw, ok := s.Records[backend][id]
	if !ok {
		return false
	}
	return json.Unmarshal(raw, v) == nil
}

// Put stores (or, if v is nil, deletes) the record for backend/id.
func (s *State) Put(backend string, e *policy.Entry, v any) error {
	if v == nil {
		s.Delete(backend, e.ID)
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if s.Records[backend] == nil {
		s.Records[backend] = map[string]json.RawMessage{}
	}
	s.Records[backend][e.ID] = raw
	cp := *e
	s.Entries[e.ID] = cp
	return nil
}

// Delete drops the record for backend/id.
func (s *State) Delete(backend, id string) {
	delete(s.Records[backend], id)
	if len(s.Records[backend]) == 0 {
		delete(s.Records, backend)
	}
}

// IDs lists entry IDs with records for backend.
func (s *State) IDs(backend string) []string {
	var ids []string
	for id := range s.Records[backend] {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Has reports whether backend has a record for id.
func (s *State) Has(backend, id string) bool {
	_, ok := s.Records[backend][id]
	return ok
}
