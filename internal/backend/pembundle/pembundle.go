// Package pembundle manages standalone PEM CA bundles that programs ship or
// point at directly (Python certifi, conda's ssl/cacert.pem, botocore,
// application-specific bundles). These bypass the system store, so they must
// be edited individually. Bundles are listed in the policy, typically added
// with `distrust scan --adopt`. Matching blocks (with their "# comment"
// headers) are cut out byte-exactly and kept in state for unblock.
package pembundle

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"distrust/internal/backend"
	"distrust/internal/certs"
	"distrust/internal/policy"
)

func init() { backend.Register(&Bundle{}) }

// Bundle is the backend.
type Bundle struct{}

type record struct {
	Files map[string][]string `json:"files"` // path -> removed text blocks
}

func (b *Bundle) Name() string { return "bundle" }
func (b *Bundle) Description() string {
	return "standalone PEM bundles listed in the policy (certifi, conda, app bundles)"
}

func (b *Bundle) files(env *backend.Env) []string {
	if env == nil || env.Policy == nil {
		return nil
	}
	return env.Policy.Bundles
}

func (b *Bundle) Detect(env *backend.Env) backend.Detection {
	d := backend.Detection{}
	for _, f := range b.files(env) {
		loc := backend.Location{Path: f, Kind: "pem bundle"}
		if data, err := os.ReadFile(f); err != nil {
			loc.Note = err.Error()
		} else {
			loc.Note = fmt.Sprintf("%d certs", len(certs.Blocks(data)))
		}
		d.Locations = append(d.Locations, loc)
	}
	if len(d.Locations) == 0 {
		d.Reason = "no bundles configured (find them with `distrust scan`, add with `distrust scan --adopt`)"
		return d
	}
	d.Available, d.Writable = true, true
	return d
}

func (b *Bundle) Certs(env *backend.Env) []*certs.Cert {
	var out []*certs.Cert
	for _, f := range b.files(env) {
		data, _ := os.ReadFile(f)
		for _, bl := range certs.Blocks(data) {
			out = append(out, bl.Cert)
		}
	}
	return out
}

func (b *Bundle) Block(env *backend.Env, e *policy.Entry) error {
	var rec record
	env.State.Get(b.Name(), e.ID, &rec)
	if rec.Files == nil {
		rec.Files = map[string][]string{}
	}
	var errs []string
	for _, f := range b.files(env) {
		data, err := os.ReadFile(f)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		blocks := certs.Blocks(data)
		var cut []certs.Block
		for _, bl := range blocks {
			if e.Matches(bl.Cert) {
				cut = append(cut, bl)
			}
		}
		if len(cut) == 0 {
			continue
		}
		env.Logf(b.Name(), "remove %d cert(s) from %s", len(cut), f)
		if env.DryRun {
			continue
		}
		out := make([]byte, 0, len(data))
		pos := 0
		for _, bl := range cut {
			out = append(out, data[pos:bl.Start]...)
			end := bl.End
			if end < len(data) && data[end] == '\n' { // swallow the separating blank line
				end++
			}
			rec.Files[f] = append(rec.Files[f], string(data[bl.Start:bl.End]))
			pos = end
		}
		out = append(out, data[pos:]...)
		if err := policy.WriteFileAtomic(f, out, 0o644); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if !env.DryRun && len(rec.Files) > 0 {
		if err := env.State.Put(b.Name(), e, rec); err != nil {
			return err
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (b *Bundle) Unblock(env *backend.Env, e *policy.Entry) error {
	var rec record
	if !env.State.Get(b.Name(), e.ID, &rec) {
		return nil
	}
	var errs []string
	for f, texts := range rec.Files {
		data, err := os.ReadFile(f)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		have := map[string]bool{}
		for _, bl := range certs.Blocks(data) {
			have[bl.Cert.SHA256] = true
		}
		out := data
		added := 0
		for _, t := range texts {
			cs := certs.Parse([]byte(t))
			if len(cs) == 0 || have[cs[0].SHA256] {
				continue
			}
			// Separate with exactly one blank line (Block leaves the one
			// that preceded a cert at the end of the file).
			if len(out) > 0 && out[len(out)-1] != '\n' {
				out = append(out, '\n')
			}
			if len(out) > 0 && !bytes.HasSuffix(out, []byte("\n\n")) {
				out = append(out, '\n')
			}
			out = append(out, t...)
			added++
		}
		if added == 0 {
			continue
		}
		env.Logf(b.Name(), "restore %d cert(s) to %s", added, f)
		if !env.DryRun {
			if err := policy.WriteFileAtomic(f, out, 0o644); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	if !env.DryRun {
		env.State.Delete(b.Name(), e.ID)
	}
	return nil
}

func (b *Bundle) inspect(env *backend.Env, e *policy.Entry, verify bool) []backend.LocState {
	var rec record
	env.State.Get(b.Name(), e.ID, &rec)
	var out []backend.LocState
	for _, f := range b.files(env) {
		ls := backend.LocState{Location: f}
		if verify {
			ls.Method = "go crypto/x509 against bundle"
		}
		data, err := os.ReadFile(f)
		if err != nil {
			ls.Trust, ls.Detail = backend.Error, err.Error()
			out = append(out, ls)
			continue
		}
		var cs []*certs.Cert
		for _, bl := range certs.Blocks(data) {
			cs = append(cs, bl.Cert)
		}
		ls.Trust = backend.Absent
		if len(rec.Files[f]) > 0 {
			ls.Trust, ls.Detail = backend.Distrusted, "removed by distrust"
		}
		for _, c := range e.Parsed() {
			present := false
			for _, x := range cs {
				if e.Matches(x) {
					present = true
				}
			}
			if present || (verify && certs.VerifyAgainst(c.X, certs.Pool(cs)) == nil) {
				ls.Trust, ls.Detail = backend.Trusted, "present"
				break
			}
		}
		out = append(out, ls)
	}
	return out
}

func (b *Bundle) Status(env *backend.Env, e *policy.Entry) []backend.LocState {
	return b.inspect(env, e, false)
}

func (b *Bundle) Verify(env *backend.Env, e *policy.Entry) []backend.LocState {
	return b.inspect(env, e, true)
}
