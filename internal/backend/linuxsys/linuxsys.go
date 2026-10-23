//go:build linux

// Package linuxsys manages the distribution trust store that OpenSSL, GnuTLS,
// p11-kit, curl, wget, Go, Python's ssl module etc. read on Linux.
//
// Two families are supported:
//
//   - debian: ca-certificates (Debian, Ubuntu, Alpine). Certificates shipped
//     under /usr/share/ca-certificates are deselected with a "!" line in
//     /etc/ca-certificates.conf; locally added ones are moved to quarantine.
//     update-ca-certificates then regenerates the bundle and hash links (and
//     runs hooks such as ca-certificates-java).
//   - p11kit: ca-certificates with p11-kit trust policy (Fedora, RHEL, Arch,
//     openSUSE). The certificate is dropped into the blocklist directory and
//     the extracted bundles are regenerated.
//
// The flat bundle format has no way to express distrust, so a CA that is not
// itself a trust anchor here (an intermediate) cannot be blocked by this
// backend; status reports that as "unsupported".
package linuxsys

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"distrust/internal/backend"
	"distrust/internal/certs"
	"distrust/internal/policy"
	"distrust/internal/sysx"
)

func init() { backend.Register(&System{}) }

// System is the backend.
type System struct {
	once sync.Once
	fl   *flavor

	mu    sync.Mutex
	cache map[string][]*certs.Cert
}

type flavor struct {
	Name      string
	Update    []string // regeneration command
	Bundles   []string // generated PEM bundles consumers read
	HashDir   string   // OpenSSL CApath, if any
	Conf      string   // debian: ca-certificates.conf
	ShareDir  string   // debian: packaged certs
	LocalDirs []string // admin-added certs
	Blocklist string   // p11kit: blocklist directory
}

type record struct {
	Deselected  []deselect   `json:"deselected,omitempty"`
	Quarantined []quarantine `json:"quarantined,omitempty"`
	Blocklisted string       `json:"blocklisted,omitempty"`
}

type deselect struct {
	Rel     string `json:"rel"`
	HadLine bool   `json:"had_line"` // the cert was listed (selected) before
}

type quarantine struct {
	From string `json:"from"`
	To   string `json:"to"`
}

func (s *System) Name() string { return "system" }
func (s *System) Description() string {
	return "distribution CA store (ca-certificates / p11-kit): OpenSSL, GnuTLS, curl, wget, Go, Python ssl"
}

func (s *System) flavor() *flavor {
	s.once.Do(func() { s.fl = detectFlavor() })
	return s.fl
}

func detectFlavor() *flavor {
	if sysx.Exists("/etc/ca-certificates.conf") && sysx.LookPath("update-ca-certificates", "/usr/sbin", "/sbin") != "" {
		return &flavor{
			Name:      "debian",
			Update:    []string{sysx.LookPath("update-ca-certificates", "/usr/sbin", "/sbin")},
			Bundles:   []string{"/etc/ssl/certs/ca-certificates.crt"},
			HashDir:   "/etc/ssl/certs",
			Conf:      "/etc/ca-certificates.conf",
			ShareDir:  "/usr/share/ca-certificates",
			LocalDirs: []string{"/usr/local/share/ca-certificates"},
		}
	}
	type cand struct {
		blocklists []string
		tool       string
		args       []string
		bundles    []string
		hashDir    string
	}
	for _, c := range []cand{
		{ // Fedora / RHEL / CentOS
			[]string{"/etc/pki/ca-trust/source/blocklist", "/etc/pki/ca-trust/source/blacklist"},
			"update-ca-trust", []string{"extract"},
			[]string{"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/etc/pki/tls/certs/ca-bundle.crt"},
			"/etc/pki/tls/certs",
		},
		{ // Arch
			[]string{"/etc/ca-certificates/trust-source/blocklist", "/etc/ca-certificates/trust-source/blacklist"},
			"update-ca-trust", nil,
			[]string{"/etc/ssl/certs/ca-certificates.crt"},
			"/etc/ssl/certs",
		},
		{ // openSUSE
			[]string{"/etc/pki/trust/blocklist", "/etc/pki/trust/blacklist"},
			"update-ca-certificates", nil,
			[]string{"/var/lib/ca-certificates/ca-bundle.pem", "/etc/ssl/ca-bundle.pem"},
			"/etc/ssl/certs",
		},
	} {
		tool := sysx.LookPath(c.tool, "/usr/sbin", "/sbin", "/usr/bin")
		if tool == "" {
			continue
		}
		for _, bl := range c.blocklists {
			if !sysx.Exists(bl) {
				continue
			}
			var bundles []string
			for _, b := range c.bundles {
				if sysx.Exists(b) {
					bundles = append(bundles, b)
				}
			}
			return &flavor{Name: "p11kit", Update: append([]string{tool}, c.args...), Bundles: bundles, HashDir: c.hashDir, Blocklist: bl}
		}
	}
	return nil
}

func (s *System) Detect(env *backend.Env) backend.Detection {
	f := s.flavor()
	if f == nil {
		return backend.Detection{Reason: "no supported ca-certificates / p11-kit setup found"}
	}
	d := backend.Detection{Available: true, Writable: sysx.IsAdmin(), Tools: []string{strings.Join(f.Update, " ")}}
	for _, b := range f.Bundles {
		d.Locations = append(d.Locations, backend.Location{Path: b, Kind: f.Name + " bundle"})
	}
	if f.HashDir != "" && f.Name == "debian" {
		d.Locations = append(d.Locations, backend.Location{Path: f.HashDir, Kind: "openssl CApath"})
	}
	for _, dir := range append([]string{f.ShareDir}, f.LocalDirs...) {
		if dir != "" {
			d.Locations = append(d.Locations, backend.Location{Path: dir, Kind: "source certificates"})
		}
	}
	if f.Blocklist != "" {
		d.Locations = append(d.Locations, backend.Location{Path: filepath.Dir(f.Blocklist), Kind: "p11-kit trust source"})
	}
	if f.Conf != "" {
		d.Notes = append(d.Notes, "selection file: "+f.Conf)
	}
	if !d.Writable {
		d.Notes = append(d.Notes, "read-only: run as root to change the system store")
	}
	return d
}

// load parses a bundle or cert file, cached for this run.
func (s *System) load(path string) []*certs.Cert {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache == nil {
		s.cache = map[string][]*certs.Cert{}
	}
	if c, ok := s.cache[path]; ok {
		return c
	}
	data, err := os.ReadFile(path)
	var cs []*certs.Cert
	if err == nil {
		cs = certs.Parse(data)
	}
	s.cache[path] = cs
	return cs
}

func (s *System) flush() {
	s.mu.Lock()
	s.cache = nil
	s.mu.Unlock()
}

// hashDirCerts parses the OpenSSL hash links (<hash>.<n>) in dir.
func (s *System) hashDirCerts(dir string) []*certs.Cert {
	var out []*certs.Cert
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		name := e.Name()
		dot := strings.LastIndexByte(name, '.')
		if dot != 8 {
			continue
		}
		if _, err := strconv.Atoi(name[dot+1:]); err != nil {
			continue
		}
		out = append(out, s.load(filepath.Join(dir, name))...)
	}
	return out
}

func anyMatch(e *policy.Entry, cs []*certs.Cert) *certs.Cert {
	for _, c := range cs {
		if e.Matches(c) {
			return c
		}
	}
	return nil
}

// sourceFiles lists *.crt certificate files under dir.
func sourceFiles(dir string) []string {
	var out []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && (strings.HasSuffix(p, ".crt") || strings.HasSuffix(p, ".pem")) {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// Certs lists the anchors currently in the bundle plus every shipped source
// certificate (including deselected ones), for fingerprint lookups.
func (s *System) Certs(env *backend.Env) []*certs.Cert {
	f := s.flavor()
	if f == nil {
		return nil
	}
	var out []*certs.Cert
	for _, b := range f.Bundles {
		out = append(out, s.load(b)...)
	}
	dirs := append([]string{f.ShareDir}, f.LocalDirs...)
	if f.Name == "p11kit" {
		dirs = append(dirs, "/usr/share/pki/ca-trust-source", "/usr/share/ca-certificates/trust-source")
	}
	for _, d := range dirs {
		if d == "" {
			continue
		}
		for _, p := range sourceFiles(d) {
			out = append(out, s.load(p)...)
		}
	}
	return out
}

func (s *System) Block(env *backend.Env, e *policy.Entry) error {
	f := s.flavor()
	if f == nil {
		return errors.New("no supported system store")
	}
	var rec record
	env.State.Get(s.Name(), e.ID, &rec)
	changed := false
	var err error
	switch f.Name {
	case "debian":
		changed, err = s.blockDebian(env, f, e, &rec)
	case "p11kit":
		changed, err = s.blockP11(env, f, e, &rec)
	}
	if err != nil {
		return err
	}
	// Regenerate if we changed something, or the bundle still has the cert
	// (e.g. a previous run was interrupted before regenerating).
	if changed || s.bundleHas(f, e) != "" {
		if err := s.regenerate(env, f); err != nil {
			return err
		}
	}
	if env.DryRun {
		return nil
	}
	if left := s.bundleHas(f, e); left != "" && len(rec.Deselected)+len(rec.Quarantined) == 0 && rec.Blocklisted == "" {
		return fmt.Errorf("%s still contains %s but no source file was found to remove", left, e.Name())
	}
	if len(rec.Deselected)+len(rec.Quarantined) == 0 && rec.Blocklisted == "" {
		env.State.Delete(s.Name(), e.ID)
		return nil
	}
	return env.State.Put(s.Name(), e, rec)
}

func (s *System) needRoot(env *backend.Env) error {
	if !sysx.IsAdmin() && !env.DryRun {
		return errors.New("modifying the system store requires root")
	}
	return nil
}

func (s *System) blockDebian(env *backend.Env, f *flavor, e *policy.Entry, rec *record) (bool, error) {
	var toDeselect []string
	for _, p := range sourceFiles(f.ShareDir) {
		if anyMatch(e, s.load(p)) != nil {
			rel, _ := filepath.Rel(f.ShareDir, p)
			toDeselect = append(toDeselect, rel)
		}
	}
	var move []string
	for _, d := range f.LocalDirs {
		for _, p := range sourceFiles(d) {
			if anyMatch(e, s.load(p)) != nil {
				move = append(move, p)
			}
		}
	}
	// Loose PEM files dropped straight into /etc/ssl/certs get hashed too.
	if ents, err := os.ReadDir(f.HashDir); err == nil {
		for _, de := range ents {
			p := filepath.Join(f.HashDir, de.Name())
			if de.Type()&fs.ModeSymlink != 0 || de.IsDir() || containsStr(f.Bundles, p) {
				continue
			}
			if anyMatch(e, s.load(p)) != nil {
				move = append(move, p)
			}
		}
	}
	changed := false
	if len(toDeselect) > 0 {
		lines, err := readLines(f.Conf)
		if err != nil {
			return false, err
		}
		edited := false
		for _, rel := range toDeselect {
			idx, neg := indexOf(lines, rel), indexOf(lines, "!"+rel)
			switch {
			case neg >= 0:
				continue
			case idx >= 0:
				lines[idx] = "!" + rel
			default:
				lines = append(lines, "!"+rel)
			}
			env.Logf(s.Name(), "deselect %s in %s", rel, f.Conf)
			rec.Deselected = append(rec.Deselected, deselect{Rel: rel, HadLine: idx >= 0})
			edited = true
		}
		if edited {
			if err := s.needRoot(env); err != nil {
				return false, err
			}
			if !env.DryRun {
				if err := policy.WriteFileAtomic(f.Conf, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
					return false, err
				}
			}
			changed = true
		}
	}
	for _, p := range move {
		if err := s.needRoot(env); err != nil {
			return false, err
		}
		dst := filepath.Join(env.State.Dir(), "quarantine", e.ID, strings.ReplaceAll(strings.TrimPrefix(p, "/"), "/", "_"))
		env.Logf(s.Name(), "quarantine %s -> %s", p, dst)
		if !env.DryRun {
			if err := moveFile(p, dst); err != nil {
				return false, err
			}
		}
		rec.Quarantined = append(rec.Quarantined, quarantine{From: p, To: dst})
		changed = true
	}
	return changed, nil
}

func (s *System) blockP11(env *backend.Env, f *flavor, e *policy.Entry, rec *record) (bool, error) {
	dst := filepath.Join(f.Blocklist, "distrust-"+e.ID+".pem")
	var pem strings.Builder
	fmt.Fprintf(&pem, "# distrust %s: %s\n", e.ID, e.Subject)
	for _, c := range e.Parsed() {
		pem.WriteString(c.PEM())
	}
	if cur, err := os.ReadFile(dst); err == nil && string(cur) == pem.String() {
		rec.Blocklisted = dst
		return false, nil
	}
	if err := s.needRoot(env); err != nil {
		return false, err
	}
	env.Logf(s.Name(), "write blocklist %s", dst)
	if !env.DryRun {
		if err := policy.WriteFileAtomic(dst, []byte(pem.String()), 0o644); err != nil {
			return false, err
		}
	}
	rec.Blocklisted = dst
	return true, nil
}

func (s *System) Unblock(env *backend.Env, e *policy.Entry) error {
	f := s.flavor()
	var rec record
	if f == nil || !env.State.Get(s.Name(), e.ID, &rec) {
		return nil
	}
	if err := s.needRoot(env); err != nil {
		return err
	}
	if len(rec.Deselected) > 0 {
		lines, err := readLines(f.Conf)
		if err != nil {
			return err
		}
		for _, d := range rec.Deselected {
			i := indexOf(lines, "!"+d.Rel)
			if i < 0 {
				continue
			}
			env.Logf(s.Name(), "reselect %s in %s", d.Rel, f.Conf)
			if d.HadLine {
				lines[i] = d.Rel
			} else {
				lines = append(lines[:i], lines[i+1:]...)
			}
		}
		if !env.DryRun {
			if err := policy.WriteFileAtomic(f.Conf, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
				return err
			}
		}
	}
	for _, q := range rec.Quarantined {
		env.Logf(s.Name(), "restore %s", q.From)
		if env.DryRun {
			continue
		}
		if sysx.Exists(q.From) {
			continue // something put it back already
		}
		if err := moveFile(q.To, q.From); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if rec.Blocklisted != "" {
		env.Logf(s.Name(), "remove %s", rec.Blocklisted)
		if !env.DryRun {
			if err := os.Remove(rec.Blocklisted); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	if err := s.regenerate(env, f); err != nil {
		return err
	}
	if !env.DryRun {
		os.Remove(filepath.Join(env.State.Dir(), "quarantine", e.ID))
		env.State.Delete(s.Name(), e.ID)
	}
	return nil
}

func (s *System) regenerate(env *backend.Env, f *flavor) error {
	env.Logf(s.Name(), "run %s", strings.Join(f.Update, " "))
	if env.DryRun {
		return nil
	}
	if err := s.needRoot(env); err != nil {
		return err
	}
	_, err := sysx.Run(sysx.Cmd{Name: f.Update[0], Args: f.Update[1:]})
	s.flush()
	return err
}

// bundleHas returns the first bundle still containing a matching cert.
func (s *System) bundleHas(f *flavor, e *policy.Entry) string {
	for _, b := range f.Bundles {
		if anyMatch(e, s.load(b)) != nil {
			return b
		}
	}
	return ""
}

func (s *System) Status(env *backend.Env, e *policy.Entry) []backend.LocState {
	f := s.flavor()
	if f == nil {
		return nil
	}
	recorded := env.State.Has(s.Name(), e.ID)
	judge := func(loc string, cs []*certs.Cert) backend.LocState {
		ls := backend.LocState{Location: loc}
		if c := anyMatch(e, cs); c != nil {
			ls.Trust, ls.Detail = backend.Trusted, "present ("+c.SHA256[:12]+")"
			return ls
		}
		if recorded {
			ls.Trust, ls.Detail = backend.Distrusted, "removed by distrust"
			return ls
		}
		if p := e.Primary(); p != nil && !certs.SelfSigned(p.X) {
			if certs.VerifyAgainst(p.X, certs.Pool(cs)) == nil {
				ls.Trust, ls.Detail = backend.Unsupported, "intermediate chaining to a trusted root; flat bundles cannot distrust intermediates (block the root, or rely on NSS)"
				return ls
			}
		}
		ls.Trust = backend.Absent
		return ls
	}
	var out []backend.LocState
	for _, b := range f.Bundles {
		out = append(out, judge(b, s.load(b)))
	}
	if f.Name == "debian" && f.HashDir != "" {
		out = append(out, judge(f.HashDir, s.hashDirCerts(f.HashDir)))
	}
	return out
}

func (s *System) Verify(env *backend.Env, e *policy.Entry) []backend.LocState {
	f := s.flavor()
	if f == nil {
		return nil
	}
	recorded := env.State.Has(s.Name(), e.ID)
	negative := func() backend.Trust {
		if recorded {
			return backend.Distrusted
		}
		return backend.Absent
	}
	var out []backend.LocState
	ossl := sysx.LookPath("openssl", "/usr/bin")
	if p := "/usr/bin/openssl"; sysx.Exists(p) {
		ossl = p // the distribution's, not one from a conda/venv on PATH
	}
	for _, c := range e.Parsed() {
		tmp, err := sysx.TempFile("distrust-*.pem", []byte(c.PEM()))
		if err != nil {
			continue
		}
		defer os.Remove(tmp)
		label := ""
		if len(e.Parsed()) > 1 {
			label = " [" + c.SHA256[:12] + "]"
		}
		var attime []string
		if now := time.Now(); now.After(c.X.NotAfter) || now.Before(c.X.NotBefore) {
			mid := c.X.NotBefore.Add(c.X.NotAfter.Sub(c.X.NotBefore) / 2)
			attime = []string{"-attime", strconv.FormatInt(mid.Unix(), 10)}
		}
		for _, b := range f.Bundles {
			ls := backend.LocState{Location: b + label, Method: "go crypto/x509"}
			if err := certs.VerifyAgainst(c.X, certs.Pool(s.load(b))); err == nil {
				ls.Trust, ls.Detail = backend.Trusted, "chain verifies"
			} else {
				ls.Trust, ls.Detail = negative(), shortErr(err)
			}
			out = append(out, ls)
			if ossl != "" {
				args := append([]string{"verify", "-no-CApath", "-CAfile", b}, attime...)
				out = append(out, opensslCheck(ossl, append(args, tmp), b+label, "openssl verify -CAfile", negative))
			}
		}
		if ossl != "" && f.HashDir != "" {
			args := append([]string{"verify", "-no-CAfile", "-CApath", f.HashDir}, attime...)
			out = append(out, opensslCheck(ossl, append(args, tmp), f.HashDir+label, "openssl verify -CApath", negative))
		}
	}
	return out
}

func opensslCheck(bin string, args []string, loc, method string, negative func() backend.Trust) backend.LocState {
	ls := backend.LocState{Location: loc, Method: method}
	r, err := sysx.Run(sysx.Cmd{Name: bin, Args: args})
	out := r.Combined()
	if err == nil && strings.HasSuffix(strings.TrimSpace(r.Stdout), ": OK") {
		ls.Trust, ls.Detail = backend.Trusted, "OK"
		return ls
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "error ") {
			ls.Detail = strings.TrimSpace(l[strings.Index(l, "error "):])
			break
		}
	}
	ls.Trust = negative()
	if ls.Detail == "" {
		ls.Trust, ls.Detail = backend.Error, firstLine(out)
	}
	return ls
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.Index(s, "("); i > 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s
}

func firstLine(s string) string { return strings.TrimSpace(strings.SplitN(s, "\n", 2)[0]) }

func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n"), nil
}

func indexOf(lines []string, s string) int {
	for i, l := range lines {
		if strings.TrimSpace(l) == s {
			return i
		}
	}
	return -1
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func moveFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return err
	}
	return os.Remove(src)
}
