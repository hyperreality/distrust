// Package backend defines the interface every trust store implementation
// satisfies, plus the registry used by the CLI and the engine.
//
// A backend is one *kind* of trust store (NSS databases, the OS store, Java
// keystores, loose PEM bundles). It may manage many locations on a host (one
// NSS DB per Firefox profile, several JDKs...). Backends must be idempotent:
// Block on an already-blocked entry is a no-op, and they record exactly what
// they changed in the state so Unblock can restore the prior situation.
package backend

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"distrust/internal/certs"
	"distrust/internal/policy"
	"distrust/internal/state"
)

// Trust is the observed state of a CA in one location.
type Trust string

const (
	Trusted     Trust = "trusted"
	Distrusted  Trust = "distrusted"
	Absent      Trust = "absent"      // not present, and so not trusted
	Unsupported Trust = "unsupported" // this store cannot express distrust for this cert
	Unknown     Trust = "unknown"
	Error       Trust = "error"
)

// Location is one concrete store managed by a backend.
type Location struct {
	Path string `json:"path"`
	Kind string `json:"kind"`
	Note string `json:"note,omitempty"`
}

// Detection describes what a backend found on this host.
type Detection struct {
	Available bool       `json:"available"`
	Writable  bool       `json:"writable"`
	Reason    string     `json:"reason,omitempty"`
	Tools     []string   `json:"tools,omitempty"`
	Locations []Location `json:"locations"`
	Notes     []string   `json:"notes,omitempty"`
}

// LocState is the trust state for one location.
type LocState struct {
	Location string `json:"location"`
	Trust    Trust  `json:"trust"`
	Detail   string `json:"detail,omitempty"`
	Method   string `json:"method,omitempty"` // for verify: how it was checked
}

// Env is passed to every backend call.
type Env struct {
	Policy *policy.Policy
	State  *state.State
	DryRun bool
	Log    io.Writer
	// Probe is an optional host[:port] whose live chain verify replays to
	// real clients (browsers) to observe their actual verdict.
	Probe string
}

// Logf prints an action line, prefixed with "would" in dry-run mode.
func (e *Env) Logf(backend, format string, args ...any) {
	if e.Log == nil {
		return
	}
	prefix := ""
	if e.DryRun {
		prefix = "(dry-run) would "
	}
	fmt.Fprintf(e.Log, "[%s] %s%s\n", backend, prefix, fmt.Sprintf(format, args...))
}

// Backend is a trust store implementation.
type Backend interface {
	Name() string
	Description() string
	Detect(env *Env) Detection
	// Status reports per-location state from cheap inspection.
	Status(env *Env, e *policy.Entry) []LocState
	// Block makes e distrusted in every location; idempotent.
	Block(env *Env, e *policy.Entry) error
	// Unblock reverts what Block recorded for e; idempotent.
	Unblock(env *Env, e *policy.Entry) error
	// Verify performs a real chain validation against each store, the way
	// consuming programs would.
	Verify(env *Env, e *policy.Entry) []LocState
}

var registry = map[string]Backend{}

// Register adds a backend; called from init() in platform-specific files.
func Register(b Backend) { registry[b.Name()] = b }

// All returns registered backends sorted by name.
func All() []Backend {
	var out []Backend
	for _, b := range registry {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// Get returns a backend by name.
func Get(name string) (Backend, bool) {
	b, ok := registry[name]
	return b, ok
}

// Names lists registered backend names.
func Names() []string {
	var n []string
	for _, b := range All() {
		n = append(n, b.Name())
	}
	return n
}

// ParseList validates a comma separated backend list.
func ParseList(s string) ([]string, error) {
	if s == "" || s == "all" {
		return nil, nil
	}
	var out []string
	for _, n := range strings.Split(s, ",") {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if _, ok := registry[n]; !ok {
			return nil, fmt.Errorf("unknown backend %q (have: %s)", n, strings.Join(Names(), ", "))
		}
		out = append(out, n)
	}
	return out, nil
}

// Summarize collapses per-location states into one cell for a matrix.
func Summarize(ls []LocState) Trust {
	if len(ls) == 0 {
		return Absent
	}
	count := map[Trust]int{}
	for _, l := range ls {
		count[l.Trust]++
	}
	// Any location still trusting the cert is the headline.
	for _, t := range []Trust{Trusted, Error, Unknown} {
		if count[t] > 0 {
			return t
		}
	}
	if count[Distrusted] > 0 {
		return Distrusted
	}
	if count[Unsupported] > 0 {
		return Unsupported
	}
	return Absent
}

// Count formats "n/m distrusted" style detail for a summary cell.
func Count(ls []LocState, t Trust) int {
	n := 0
	for _, l := range ls {
		if l.Trust == t {
			n++
		}
	}
	return n
}

// CertLister is implemented by backends that can enumerate the CA
// certificates they hold; used to resolve --sha256 and to find variants.
type CertLister interface {
	Certs(env *Env) []*certs.Cert
}
