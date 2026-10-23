// Package policy defines the desired state: which CA certificates must be
// distrusted, on which backends, plus extra locations to manage.
package policy

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"distrust/internal/certs"
)

// Match modes for an entry.
const (
	MatchCert = "cert" // only the exact certificate (sha256 of DER)
	MatchSPKI = "spki" // any cert with the same subject + public key (re-issues, cross-signs)
)

// Entry is one distrusted CA.
type Entry struct {
	ID         string    `json:"id"`
	SHA256     string    `json:"sha256"`
	SPKISHA256 string    `json:"spki_sha256"`
	Subject    string    `json:"subject"`
	NotAfter   time.Time `json:"not_after"`
	Match      string    `json:"match"`
	// Backends restricts enforcement; empty means every available backend.
	Backends []string `json:"backends,omitempty"`
	// Certs holds PEM for the primary cert followed by any variants that
	// share its subject and key. Backends that must insert a certificate in
	// order to distrust it (NSS, Keychain, Windows) need these bytes.
	Certs   []string  `json:"certs"`
	Source  string    `json:"source,omitempty"`
	Comment string    `json:"comment,omitempty"`
	Added   time.Time `json:"added"`

	parsed []*certs.Cert
}

// Policy is the full desired state.
type Policy struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
	// Bundles are standalone PEM files (certifi, app bundles) to manage.
	Bundles []string `json:"bundles,omitempty"`
	// Keystores are extra Java keystores beyond the auto-detected cacerts.
	Keystores []string `json:"keystores,omitempty"`
	// NSSDBs are extra NSS database directories beyond auto-detected ones.
	NSSDBs []string `json:"nss_dbs,omitempty"`

	path string
}

// NewEntry builds an entry for primary plus same-key variants.
func NewEntry(primary *certs.Cert, variants []*certs.Cert, match string, backends []string, source string) Entry {
	e := Entry{
		ID:         primary.SHA256[:12],
		SHA256:     primary.SHA256,
		SPKISHA256: primary.SPKI,
		Subject:    primary.X.Subject.String(),
		NotAfter:   primary.X.NotAfter,
		Match:      match,
		Backends:   backends,
		Certs:      []string{primary.PEM()},
		Source:     source,
		Added:      time.Now().UTC().Truncate(time.Second),
	}
	for _, v := range variants {
		if v.SHA256 != primary.SHA256 && !e.has(v.SHA256) {
			e.Certs = append(e.Certs, v.PEM())
			e.parsed = nil
		}
	}
	return e
}

func (e *Entry) has(sha string) bool {
	for _, c := range e.Parsed() {
		if c.SHA256 == sha {
			return true
		}
	}
	return false
}

// Parsed returns the entry's certificates, parsed once.
func (e *Entry) Parsed() []*certs.Cert {
	if e.parsed == nil {
		for _, p := range e.Certs {
			e.parsed = append(e.parsed, certs.Parse([]byte(p))...)
		}
	}
	return e.parsed
}

// Primary returns the main certificate, or nil if the entry has no PEM.
func (e *Entry) Primary() *certs.Cert {
	if p := e.Parsed(); len(p) > 0 {
		return p[0]
	}
	return nil
}

// Name is a short display name.
func (e *Entry) Name() string {
	if p := e.Primary(); p != nil {
		return p.Name()
	}
	return e.Subject
}

// Matches reports whether c is covered by this entry.
func (e *Entry) Matches(c *certs.Cert) bool {
	if c.SHA256 == e.SHA256 {
		return true
	}
	if e.Match == MatchSPKI && c.SPKI == e.SPKISHA256 {
		p := e.Primary()
		return p == nil || bytes.Equal(p.X.RawSubject, c.X.RawSubject)
	}
	return e.has(c.SHA256)
}

// MatchesX509 is Matches for a bare x509 certificate.
func (e *Entry) MatchesX509(c *x509.Certificate) bool { return e.Matches(certs.New(c)) }

// Targets reports whether backend should enforce this entry.
func (e *Entry) Targets(backend string) bool {
	if len(e.Backends) == 0 {
		return true
	}
	for _, b := range e.Backends {
		if b == backend {
			return true
		}
	}
	return false
}

// DefaultPath is where the system policy lives.
func DefaultPath(systemScope bool) string {
	if systemScope {
		if p := os.Getenv("ProgramData"); p != "" { // windows
			return filepath.Join(p, "distrust", "policy.json")
		}
		return "/etc/distrust/policy.json"
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	return filepath.Join(dir, "distrust", "policy.json")
}

// Load reads a policy file; a missing file yields an empty policy.
func Load(path string) (*Policy, error) {
	p := &Policy{Version: 1, path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	p.path = path
	for i := range p.Entries {
		e := &p.Entries[i]
		if e.Match == "" {
			e.Match = MatchSPKI
		}
		if e.ID == "" && len(e.SHA256) >= 12 {
			e.ID = e.SHA256[:12]
		}
		if e.Primary() == nil {
			return nil, fmt.Errorf("%s: entry %s has no parsable certificate PEM", path, e.ID)
		}
	}
	return p, nil
}

// Path is the file the policy was loaded from.
func (p *Policy) Path() string { return p.path }

// Save writes the policy atomically.
func (p *Policy) Save() error {
	sort.SliceStable(p.Entries, func(i, j int) bool { return p.Entries[i].Added.Before(p.Entries[j].Added) })
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(p.path, append(data, '\n'), 0o644)
}

// Find resolves an id, id prefix, or full fingerprint to an entry.
func (p *Policy) Find(id string) (*Entry, error) {
	return FindIn(p.Entries, id)
}

// FindIn resolves id against a slice of entries.
func FindIn(entries []Entry, id string) (*Entry, error) {
	id = strings.ToLower(strings.ReplaceAll(id, ":", ""))
	var hits []*Entry
	for i := range entries {
		e := &entries[i]
		if e.ID == id || e.SHA256 == id {
			return e, nil
		}
		if id != "" && (strings.HasPrefix(e.ID, id) || strings.HasPrefix(e.SHA256, id)) {
			hits = append(hits, e)
		}
	}
	switch len(hits) {
	case 0:
		return nil, fmt.Errorf("no policy entry matches %q", id)
	case 1:
		return hits[0], nil
	default:
		return nil, fmt.Errorf("%q is ambiguous (%d entries)", id, len(hits))
	}
}

// Upsert inserts e or merges it into an existing entry with the same ID.
func (p *Policy) Upsert(e Entry) *Entry {
	for i := range p.Entries {
		if p.Entries[i].ID == e.ID {
			old := &p.Entries[i]
			old.Backends = e.Backends
			old.Match = e.Match
			for _, c := range e.Parsed() {
				if !old.has(c.SHA256) {
					old.Certs = append(old.Certs, c.PEM())
					old.parsed = nil
				}
			}
			return old
		}
	}
	p.Entries = append(p.Entries, e)
	return &p.Entries[len(p.Entries)-1]
}

// Remove deletes the entry with the given ID.
func (p *Policy) Remove(id string) {
	out := p.Entries[:0]
	for _, e := range p.Entries {
		if e.ID != id {
			out = append(out, e)
		}
	}
	p.Entries = out
}

// AddPath appends path to list if not already present.
func AddPath(list *[]string, path string) bool {
	for _, x := range *list {
		if x == path {
			return false
		}
	}
	*list = append(*list, path)
	return true
}

// WriteFileAtomic writes via a temp file + rename, keeping the mode and
// ownership of an existing file.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return err
	}
	copyOwner(path, tmp.Name())
	return os.Rename(tmp.Name(), path)
}
