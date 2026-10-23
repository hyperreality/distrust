// Package chromium enforces distrust in Chromium-based browsers (Chrome,
// Chromium, Edge, Brave, Vivaldi, Opera) through the CADistrustedCertificates
// enterprise policy (Chromium 132+).
//
// Why policy rather than (only) NSS: Chromium on Linux verifies against the
// Chrome Root Store and consults ~/.pki/nssdb only for exact-certificate trust
// records. An NSS "p,p,p" record is bypassed as soon as the path builder finds
// another certificate with the same key (a cross-sign or re-issue, which the
// browser often has). CADistrustedCertificates matches by SPKI, overrides the
// Chrome Root Store, CACertificates and NSS trust, applies to every profile and
// user, and is picked up by running browsers within seconds.
//
// Chromium reads every file in <policy dir>/managed in lexicographic order and
// the last file setting a key wins (no list merging). This backend owns
// zz-distrust.json, rewrites it from the whole policy on every change, and
// carries over values another file sets for the same key so an admin's own
// distrust list is not silently dropped.
package chromium

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"distrust/internal/backend"
	"distrust/internal/certs"
	"distrust/internal/policy"
	"distrust/internal/sysx"
)

// PolicyKey is the enterprise policy this backend manages.
const PolicyKey = "CADistrustedCertificates"

// MinVersion is the first Chromium major supporting PolicyKey.
const MinVersion = 132

func init() { backend.Register(&Chromium{}) }

// Browser describes one Chromium-based product.
type Browser struct {
	Name string
	// Bins are globs for the main executable.
	Bins []string
	// PolicyDir is the base directory holding managed/ (Linux).
	PolicyDir string
	// RegKey is the policy key under HKLM (Windows).
	RegKey string
	// VersionIsChromium is set when "--version" prints the Chromium major
	// first (Chrome, Chromium, Edge, Brave), so support can be checked.
	VersionIsChromium bool
}

// Chromium is the backend.
type Chromium struct {
	mu      sync.Mutex
	version map[string]int
	probes  map[string]*probeResult
}

// location is one policy store, possibly shared by several browsers
// (e.g. Chrome stable/beta/dev all read /etc/opt/chrome/policies).
type location struct {
	store    store
	browsers []*Browser
	bins     []string // one executable per browser found, parallel to browsers
}

type record struct {
	Stores []string `json:"stores"`
}

func (c *Chromium) Name() string { return "chromium" }
func (c *Chromium) Description() string {
	return "Chromium-based browsers via the " + PolicyKey + " enterprise policy (Chrome, Chromium, Edge, Brave, Vivaldi, Opera)"
}

// binOverrides parses DISTRUST_BROWSERS="name=/path/to/bin,..." for
// browsers installed outside their standard location.
func binOverrides() map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(os.Getenv("DISTRUST_BROWSERS"), ",") {
		if name, path, ok := strings.Cut(strings.TrimSpace(kv), "="); ok {
			out[name] = path
		}
	}
	return out
}

func (c *Chromium) locations() []*location {
	var out []*location
	byID := map[string]*location{}
	over := binOverrides()
	for i := range browsers {
		b := &browsers[i]
		bin := ""
		if p, ok := over[b.Name]; ok && sysx.Exists(p) {
			bin = p
		} else if m := sysx.Globs(b.Bins...); len(m) > 0 {
			bin = m[0]
		}
		st := newStore(b)
		if st == nil || (bin == "" && !st.Exists()) {
			continue
		}
		loc, ok := byID[st.ID()]
		if !ok {
			loc = &location{store: st}
			byID[st.ID()] = loc
			out = append(out, loc)
		}
		loc.browsers = append(loc.browsers, b)
		loc.bins = append(loc.bins, bin)
	}
	return out
}

func (l *location) names() string {
	var n []string
	for _, b := range l.browsers {
		n = append(n, b.Name)
	}
	return strings.Join(n, ", ")
}

func (c *Chromium) Detect(env *backend.Env) backend.Detection {
	d := backend.Detection{}
	if len(browsers) == 0 {
		d.Reason = unsupportedReason
		return d
	}
	for _, l := range c.locations() {
		var notes []string
		for i, b := range l.browsers {
			if l.bins[i] == "" {
				notes = append(notes, b.Name+": policy dir only")
				continue
			}
			v := c.versionOf(b, l.bins[i])
			switch {
			case v == 0:
				notes = append(notes, b.Name+" (version unknown)")
			case v < MinVersion:
				notes = append(notes, fmt.Sprintf("%s %d: too old for %s (needs %d+)", b.Name, v, PolicyKey, MinVersion))
			default:
				notes = append(notes, fmt.Sprintf("%s %d", b.Name, v))
			}
			d.Tools = append(d.Tools, l.bins[i])
		}
		eff, err := l.store.Read()
		if err != nil {
			notes = append(notes, "unreadable: "+err.Error())
		} else if eff.OverriddenBy != "" {
			notes = append(notes, "WARNING: "+eff.OverriddenBy+" sorts after ours and overrides "+PolicyKey)
		}
		d.Locations = append(d.Locations, backend.Location{Path: l.store.Path(), Kind: l.names(), Note: strings.Join(notes, "; ")})
	}
	if len(d.Locations) == 0 {
		d.Reason = "no Chromium-based browser found"
		return d
	}
	d.Available, d.NeedsAdmin = true, true
	d.Writable = sysx.IsAdmin()
	if !d.Writable {
		d.Reason = "policy directories are machine-wide: run as root"
	}
	d.Notes = append(d.Notes,
		"policy distrust is by SPKI and overrides the Chrome Root Store; running browsers reload it within ~15s",
		"a CA is only blocked if its key is on the path the browser builds: verify with `distrust verify <id> --probe host:443`")
	return d
}

// versionOf returns the Chromium major version of a browser binary (0 if unknown).
func (c *Chromium) versionOf(b *Browser, bin string) int {
	if !b.VersionIsChromium {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.version == nil {
		c.version = map[string]int{}
	}
	if v, ok := c.version[bin]; ok {
		return v
	}
	v := 0
	if out, err := exec.Command(bin, "--version").Output(); err == nil {
		if m := regexp.MustCompile(`\b(\d{2,3})\.\d+`).FindStringSubmatch(string(out)); m != nil {
			v, _ = strconv.Atoi(m[1])
		}
	}
	c.version[bin] = v
	return v
}

// spkiValues returns one base64 DER certificate per distinct key in e. The
// policy matches by SPKI, so one certificate per key covers all variants.
func spkiValues(e *policy.Entry) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range e.Parsed() {
		if seen[c.SPKI] {
			continue
		}
		seen[c.SPKI] = true
		out = append(out, base64.StdEncoding.EncodeToString(c.X.Raw))
	}
	return out
}

// desired lists our values: every policy entry targeting this backend, plus
// include, minus exclude.
func (c *Chromium) desired(env *backend.Env, include *policy.Entry, exclude string) []string {
	var entries []*policy.Entry
	if env.Policy != nil {
		for i := range env.Policy.Entries {
			e := &env.Policy.Entries[i]
			if e.ID != exclude && e.Targets(c.Name()) && (include == nil || e.ID != include.ID) {
				entries = append(entries, e)
			}
		}
	}
	if include != nil {
		entries = append(entries, include)
	}
	var out []string
	for _, e := range entries {
		out = append(out, spkiValues(e)...)
	}
	return uniqueBySPKI(out)
}

// uniqueBySPKI drops values whose certificate key was already listed (and
// unparsable duplicates), keeping order.
func uniqueBySPKI(vals []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range vals {
		k := spkiKey(v)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, v)
	}
	return out
}

// spkiKey identifies a policy value by its key (falling back to the raw value).
func spkiKey(v string) string {
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v))
	if err == nil {
		if cs := certs.Parse(der); len(cs) == 1 {
			return cs[0].SPKI
		}
	}
	h := sha256.Sum256([]byte(v))
	return "raw:" + fmt.Sprintf("%x", h)
}

// sync rewrites every store so it holds exactly the desired values plus any
// values carried over from other policy sources.
func (c *Chromium) sync(env *backend.Env, include *policy.Entry, exclude string) ([]string, error) {
	ours := c.desired(env, include, exclude)
	var touched []string
	var errs []string
	for _, l := range c.locations() {
		eff, err := l.store.Read()
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if len(ours) == 0 {
			if eff.OursExists {
				env.Logf(c.Name(), "remove %s (%s)", l.store.Path(), l.names())
				if !env.DryRun {
					if err := l.store.Remove(); err != nil {
						errs = append(errs, err.Error())
					}
				}
			}
			continue
		}
		want := uniqueBySPKI(append(append([]string{}, ours...), eff.Foreign...))
		touched = append(touched, l.store.ID())
		if sameSet(want, eff.Ours) {
			continue
		}
		carried := ""
		if len(eff.Foreign) > 0 {
			carried = fmt.Sprintf(" (+%d carried over from %s)", len(eff.Foreign), eff.ForeignSource)
		}
		env.Logf(c.Name(), "write %d distrusted key(s)%s to %s (%s)", len(want), carried, l.store.Path(), l.names())
		if eff.OverriddenBy != "" {
			env.Logf(c.Name(), "WARNING: %s sorts after %s and overrides %s", eff.OverriddenBy, l.store.Path(), PolicyKey)
		}
		if !env.DryRun {
			if err := l.store.Write(want, ours); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	if len(errs) > 0 {
		return touched, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return touched, nil
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string{}, a...)
	y := append([]string{}, b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func (c *Chromium) Block(env *backend.Env, e *policy.Entry) error {
	touched, err := c.sync(env, e, "")
	if env.DryRun {
		return err
	}
	if len(touched) > 0 {
		if perr := env.State.Put(c.Name(), e, record{Stores: touched}); perr != nil {
			return perr
		}
	}
	return err
}

func (c *Chromium) Unblock(env *backend.Env, e *policy.Entry) error {
	if !env.State.Has(c.Name(), e.ID) {
		return nil
	}
	_, err := c.sync(env, nil, e.ID)
	if err == nil && !env.DryRun {
		env.State.Delete(c.Name(), e.ID)
	}
	return err
}

func (c *Chromium) Status(env *backend.Env, e *policy.Entry) []backend.LocState {
	var out []backend.LocState
	want := spkiValues(e)
	for _, l := range c.locations() {
		ls := backend.LocState{Location: l.store.Path()}
		eff, err := l.store.Read()
		if err != nil {
			ls.Trust, ls.Detail = backend.Error, err.Error()
			out = append(out, ls)
			continue
		}
		effective := map[string]bool{}
		for _, v := range eff.Effective {
			effective[spkiKey(v)] = true
		}
		covered := 0
		for _, v := range want {
			if effective[spkiKey(v)] {
				covered++
			}
		}
		switch {
		case covered == len(want):
			ls.Trust, ls.Detail = backend.Distrusted, "in effective "+PolicyKey+" ("+l.names()+")"
		case eff.OverriddenBy != "":
			ls.Trust, ls.Detail = backend.Trusted, "overridden by "+eff.OverriddenBy+" (last file wins)"
		default:
			ls.Trust, ls.Detail = backend.Trusted, "not in "+PolicyKey+" (trusted if in the Chrome Root Store or chaining to it)"
		}
		if old := c.tooOld(l); old != "" && ls.Trust == backend.Distrusted {
			ls.Trust, ls.Detail = backend.Unsupported, old
		}
		out = append(out, ls)
	}
	return out
}

// tooOld reports browsers at this location that ignore the policy.
func (c *Chromium) tooOld(l *location) string {
	var old []string
	for i, b := range l.browsers {
		if l.bins[i] == "" {
			continue
		}
		if v := c.versionOf(b, l.bins[i]); v > 0 && v < MinVersion {
			old = append(old, fmt.Sprintf("%s %d", b.Name, v))
		}
	}
	if len(old) == 0 {
		return ""
	}
	return strings.Join(old, ", ") + fmt.Sprintf(" ignore %s (needs %d+)", PolicyKey, MinVersion)
}

// effective is what a store currently yields.
type effective struct {
	Effective     []string // the value the browser will use
	Ours          []string // our file's value
	OursExists    bool
	Foreign       []string // value from the highest-priority other source
	ForeignSource string
	OverriddenBy  string // a source that beats ours, if any
}

// lenientJSON parses Chromium's relaxed JSON (comments, trailing commas).
func lenientJSON(data []byte, v any) error {
	if err := json.Unmarshal(data, v); err == nil {
		return nil
	}
	return json.Unmarshal(stripJSONExtensions(data), v)
}

// stripJSONExtensions removes // and /* */ comments and trailing commas
// outside of string literals.
func stripJSONExtensions(in []byte) []byte {
	var out []byte
	inStr, esc := false, false
	for i := 0; i < len(in); i++ {
		ch := in[i]
		if inStr {
			out = append(out, ch)
			switch {
			case esc:
				esc = false
			case ch == '\\':
				esc = true
			case ch == '"':
				inStr = false
			}
			continue
		}
		switch {
		case ch == '"':
			inStr = true
			out = append(out, ch)
		case ch == '/' && i+1 < len(in) && in[i+1] == '/':
			for i < len(in) && in[i] != '\n' {
				i++
			}
			out = append(out, '\n')
		case ch == '/' && i+1 < len(in) && in[i+1] == '*':
			i += 2
			for i+1 < len(in) && !(in[i] == '*' && in[i+1] == '/') {
				i++
			}
			i++
		case ch == ']' || ch == '}':
			// drop a trailing comma before the closer
			j := len(out) - 1
			for j >= 0 && (out[j] == ' ' || out[j] == '\n' || out[j] == '\t' || out[j] == '\r') {
				j--
			}
			if j >= 0 && out[j] == ',' {
				out = append(out[:j], out[j+1:]...)
			}
			out = append(out, ch)
		default:
			out = append(out, ch)
		}
	}
	return out
}

func readFileIfExists(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	return data, err == nil, err
}
