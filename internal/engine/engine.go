// Package engine reconciles the policy with the backends: it decides which
// backends an entry applies to, blocks what is missing, and unblocks state
// records whose entry left the policy (or no longer targets that backend).
package engine

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"distrust/internal/backend"
	"distrust/internal/certs"
	"distrust/internal/policy"
	"distrust/internal/state"
)

// Engine binds a policy, state and the registered backends.
type Engine struct {
	Policy *policy.Policy
	State  *state.State
	DryRun bool
	Log    io.Writer
	// Only restricts operations to these backends (nil = all).
	Only []string
	// Probe is passed to backends' Verify (see backend.Env.Probe).
	Probe string
	// Checkpoint, when set, persists the state after each entry so that undo
	// records survive an interrupted run.
	Checkpoint func() error
	// Stopped, when set, is polled between entries; true ends Apply early.
	Stopped func() bool

	detect map[string]backend.Detection
}

// Env returns the environment passed to backends.
func (en *Engine) Env() *backend.Env {
	return &backend.Env{Policy: en.Policy, State: en.State, DryRun: en.DryRun, Log: en.Log, Probe: en.Probe}
}

// Detect runs (and caches) detection for every backend.
func (en *Engine) Detect() map[string]backend.Detection {
	if en.detect == nil {
		en.detect = map[string]backend.Detection{}
		for _, b := range backend.All() {
			en.detect[b.Name()] = b.Detect(en.Env())
		}
	}
	return en.detect
}

func (en *Engine) selected(b backend.Backend) bool {
	if len(en.Only) == 0 {
		return true
	}
	for _, n := range en.Only {
		if n == b.Name() {
			return true
		}
	}
	return false
}

// AdminBackends lists the selected, available backends that need admin
// rights to change and that uses reports as involved in an operation.
func (en *Engine) AdminBackends(uses func(backend string) bool) []string {
	var out []string
	det := en.Detect()
	for _, b := range backend.All() {
		if d := det[b.Name()]; en.selected(b) && d.Available && d.NeedsAdmin && uses(b.Name()) {
			out = append(out, b.Name())
		}
	}
	return out
}

// Result collects per-backend outcomes of an operation.
type Result struct {
	Errors  map[string]error
	Skipped map[string]string
}

func newResult() *Result {
	return &Result{Errors: map[string]error{}, Skipped: map[string]string{}}
}

// Err folds the per-backend errors into one.
func (r *Result) Err() error {
	if len(r.Errors) == 0 {
		return nil
	}
	var names []string
	for n := range r.Errors {
		names = append(names, n)
	}
	sort.Strings(names)
	var parts []string
	for _, n := range names {
		parts = append(parts, fmt.Sprintf("%s: %v", n, r.Errors[n]))
	}
	return fmt.Errorf("%s", strings.Join(parts, "\n"))
}

func (r *Result) merge(o *Result) {
	for k, v := range o.Errors {
		r.Errors[k] = errors.Join(r.Errors[k], v) // keep every entry's failure
	}
	for k, v := range o.Skipped {
		r.Skipped[k] = v
	}
}

// ApplyEntry enforces one entry: Block on every targeted, usable backend and
// Unblock on backends it no longer targets.
func (en *Engine) ApplyEntry(e *policy.Entry) *Result {
	res := newResult()
	det := en.Detect()
	env := en.Env()
	for _, b := range backend.All() {
		if !en.selected(b) {
			continue
		}
		name := b.Name()
		d := det[name]
		if !e.Targets(name) {
			if en.State.Has(name, e.ID) {
				if err := b.Unblock(env, e); err != nil {
					res.Errors[name] = err
				}
			}
			continue
		}
		explicit := len(e.Backends) > 0
		switch {
		case !d.Available:
			if explicit {
				res.Errors[name] = fmt.Errorf("not available: %s", d.Reason)
			} else {
				res.Skipped[name] = d.Reason
			}
			continue
		case !d.Writable && !en.DryRun:
			msg := d.Reason
			if msg == "" {
				msg = "not writable with current privileges"
			}
			if explicit {
				res.Errors[name] = fmt.Errorf("%s", msg)
			} else {
				res.Skipped[name] = msg
			}
			continue
		}
		if err := b.Block(env, e); err != nil {
			res.Errors[name] = err
		}
	}
	return res
}

// ErrInterrupted is reported when Stopped ends Apply early.
var ErrInterrupted = errors.New("interrupted; the rest of the policy was not applied")

// step checkpoints after one unit of work and reports whether to go on.
func (en *Engine) step(res *Result) bool {
	if en.Checkpoint != nil && !en.DryRun {
		if err := en.Checkpoint(); err != nil {
			res.Errors["state"] = err
			return false
		}
	}
	if en.Stopped != nil && en.Stopped() {
		res.Errors["apply"] = ErrInterrupted
		return false
	}
	return true
}

// Apply converges the whole policy, including unblocking orphaned records.
func (en *Engine) Apply() *Result {
	res := newResult()
	env := en.Env()
	for _, b := range backend.All() {
		if bt, ok := b.(backend.Batcher); ok && en.selected(b) {
			bt.Begin(env)
			defer func(name string) {
				if err := bt.End(env); err != nil {
					res.Errors[name] = errors.Join(res.Errors[name], err)
				}
			}(b.Name())
		}
	}
	inPolicy := map[string]bool{}
	for i := range en.Policy.Entries {
		inPolicy[en.Policy.Entries[i].ID] = true
	}
	for i := range en.Policy.Entries {
		res.merge(en.ApplyEntry(&en.Policy.Entries[i]))
		if !en.step(res) {
			return res
		}
	}
	for _, b := range backend.All() {
		if !en.selected(b) {
			continue
		}
		for _, id := range en.State.IDs(b.Name()) {
			if inPolicy[id] {
				continue
			}
			e, ok := en.State.Entries[id]
			if !ok {
				continue
			}
			if en.Log != nil {
				fmt.Fprintf(en.Log, "[%s] %s is no longer in the policy: unblocking\n", b.Name(), id)
			}
			if err := b.Unblock(env, &e); err != nil {
				res.Errors[b.Name()] = err
			}
			if !en.step(res) {
				return res
			}
		}
	}
	return res
}

// Unblock reverts e on every backend with a record.
func (en *Engine) Unblock(e *policy.Entry) *Result {
	res := newResult()
	env := en.Env()
	for _, b := range backend.All() {
		if !en.selected(b) || !en.State.Has(b.Name(), e.ID) {
			continue
		}
		if err := b.Unblock(env, e); err != nil {
			res.Errors[b.Name()] = err
		}
	}
	return res
}

// KnownCerts gathers CA certificates from every store that can list them,
// plus those already in the policy/state.
func (en *Engine) KnownCerts() []*certs.Cert {
	var out []*certs.Cert
	env := en.Env()
	for _, b := range backend.All() {
		if l, ok := b.(backend.CertLister); ok {
			out = append(out, l.Certs(env)...)
		}
	}
	for i := range en.Policy.Entries {
		out = append(out, en.Policy.Entries[i].Parsed()...)
	}
	for _, e := range en.State.Entries {
		out = append(out, e.Parsed()...)
	}
	return dedupe(out)
}

func dedupe(cs []*certs.Cert) []*certs.Cert {
	seen := map[string]bool{}
	var out []*certs.Cert
	for _, c := range cs {
		if !seen[c.SHA256] {
			seen[c.SHA256] = true
			out = append(out, c)
		}
	}
	return out
}

// FindBySHA256 looks a fingerprint up as either a cert or SPKI hash.
func (en *Engine) FindBySHA256(h string) []*certs.Cert {
	var out []*certs.Cert
	for _, c := range en.KnownCerts() {
		if c.SHA256 == h || c.SPKI == h {
			out = append(out, c)
		}
	}
	return out
}

// Variants returns known certs with the same subject and key as c.
func (en *Engine) Variants(c *certs.Cert) []*certs.Cert {
	var out []*certs.Cert
	for _, k := range en.KnownCerts() {
		if k.SHA256 != c.SHA256 && k.SPKI == c.SPKI && bytes.Equal(k.X.RawSubject, c.X.RawSubject) {
			out = append(out, k)
		}
	}
	return out
}

// Row is the per-backend status of one entry.
type Row struct {
	Backend   string             `json:"backend"`
	Targeted  bool               `json:"targeted"`
	Available bool               `json:"available"`
	Summary   backend.Trust      `json:"summary"`
	Locations []backend.LocState `json:"locations"`
}

// Status computes the backend matrix for e (verify=true runs real checks).
func (en *Engine) Status(e *policy.Entry, verify bool) []Row {
	det := en.Detect()
	env := en.Env()
	var rows []Row
	for _, b := range backend.All() {
		if !en.selected(b) {
			continue
		}
		d := det[b.Name()]
		r := Row{Backend: b.Name(), Targeted: e.Targets(b.Name()), Available: d.Available}
		if d.Available {
			if verify {
				r.Locations = b.Verify(env, e)
			} else {
				r.Locations = b.Status(env, e)
			}
			r.Summary = backend.Summarize(r.Locations)
		} else {
			r.Summary = "n/a"
		}
		rows = append(rows, r)
	}
	return rows
}
