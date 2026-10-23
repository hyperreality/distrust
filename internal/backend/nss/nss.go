// Package nss manages Mozilla NSS certificate databases (Firefox, Thunderbird,
// Chromium's ~/.pki/nssdb, /etc/pki/nssdb).
//
// NSS can express explicit distrust: a trust object with "p,p,p" in the soft
// token overrides the built-in root list (libnssckbi), so blocking means
// importing the CA into each DB with that trust. If the cert already exists in
// a DB, its trust flags are changed instead and the previous flags recorded.
// All modifications go through certutil, never by editing SQLite directly.
package nss

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"distrust/internal/backend"
	"distrust/internal/certs"
	"distrust/internal/policy"
	"distrust/internal/sysx"
)

const distrustFlags = "p,p,p"

func init() { backend.Register(&NSS{}) }

// NSS is the backend.
type NSS struct {
	mu        sync.Mutex
	soft      map[string][]softCert // per DB, cached for one run
	builtin   map[string]backend.Trust
	ckbi      string
	ckbiFound bool
}

type softCert struct {
	Nick, Trust string
	Cert        *certs.Cert
}

// record is the undo data per entry.
type record struct {
	DBs map[string][]item `json:"dbs"`
}

type item struct {
	SHA256    string `json:"sha256"`
	Nick      string `json:"nick"`
	Added     bool   `json:"added"`                // we imported it: unblock deletes it
	PrevTrust string `json:"prev_trust,omitempty"` // otherwise restore these flags
}

func (n *NSS) Name() string { return "nss" }
func (n *NSS) Description() string {
	return "Mozilla NSS databases (Firefox, Thunderbird, Chromium ~/.pki/nssdb, /etc/pki/nssdb)"
}

func certutil() string { return sysx.LookPath("certutil", toolDirs...) }
func vfychain() string { return sysx.LookPath("vfychain", toolDirs...) }
func modutil() string  { return sysx.LookPath("modutil", toolDirs...) }

func (n *NSS) Detect(env *backend.Env) backend.Detection {
	d := backend.Detection{}
	for _, db := range n.dbs(env) {
		loc := backend.Location{Path: db, Kind: kindOf(db)}
		if inUse(db) {
			loc.Note = "in use (restart the application after changes)"
		}
		d.Locations = append(d.Locations, loc)
	}
	for _, p := range legacyDBs() {
		d.Notes = append(d.Notes, "legacy cert8.db (dbm) not managed: "+p)
	}
	cu := certutil()
	if cu == "" {
		d.Reason = "certutil not found (install libnss3-tools / nss-tools / brew nss)"
		return d
	}
	d.Tools = append(d.Tools, cu)
	if v := vfychain(); v != "" {
		d.Tools = append(d.Tools, v)
	} else {
		d.Notes = append(d.Notes, "vfychain not found: verify unavailable")
	}
	if lib := n.builtinsLib(); lib != "" {
		d.Tools = append(d.Tools, lib)
	} else {
		d.Notes = append(d.Notes, "libnssckbi not found: built-in roots cannot be inspected (blocking still works)")
	}
	for _, l := range d.Locations {
		if strings.HasSuffix(l.Path, ".pki/nssdb") {
			d.Notes = append(d.Notes, "Chromium-based browsers honour ~/.pki/nssdb distrust only for the exact certificate; same-key cross-signs bypass it, so also use the chromium backend")
			break
		}
	}
	if len(d.Locations) == 0 {
		d.Reason = "no NSS databases found"
		d.Notes = append(d.Notes, "new profiles are picked up by the next `distrust apply`")
		return d
	}
	d.Available, d.Writable = true, true
	return d
}

func (n *NSS) dbs(env *backend.Env) []string {
	var cands []string
	cands = append(cands, sysx.GlobHomes(profileGlobs...)...)
	cands = append(cands, sysx.Globs(systemDBs...)...)
	if env != nil && env.Policy != nil {
		cands = append(cands, env.Policy.NSSDBs...)
	}
	var out []string
	for _, c := range sysx.Dedupe(cands) {
		if sysx.Exists(filepath.Join(c, "cert9.db")) {
			out = append(out, c)
		}
	}
	return out
}

func legacyDBs() []string {
	var out []string
	for _, c := range sysx.GlobHomes(profileGlobs...) {
		if sysx.Exists(filepath.Join(c, "cert8.db")) && !sysx.Exists(filepath.Join(c, "cert9.db")) {
			out = append(out, c)
		}
	}
	return out
}

func kindOf(db string) string {
	switch {
	case strings.Contains(db, "firefox") || strings.Contains(db, "Firefox"):
		return "firefox"
	case strings.Contains(strings.ToLower(db), "thunderbird"):
		return "thunderbird"
	case strings.Contains(db, "librewolf"):
		return "librewolf"
	case strings.HasSuffix(db, ".pki/nssdb"):
		return "user-nssdb (chromium)"
	case strings.HasPrefix(db, "/etc/"):
		return "system-nssdb"
	}
	return "nssdb"
}

// inUse detects a running Firefox/Thunderbird via the profile lock symlink.
func inUse(db string) bool {
	if runtime.GOOS != "linux" {
		return false
	}
	_, err := os.Lstat(filepath.Join(db, "lock"))
	return err == nil
}

var lineRE = regexp.MustCompile(`^(.*\S)\s+([a-zA-Z]*,[a-zA-Z]*,[a-zA-Z]*)\s*$`)

// softCerts lists certificates stored in the DB's soft token.
func (n *NSS) softCerts(db string) ([]softCert, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.soft == nil {
		n.soft = map[string][]softCert{}
	}
	if s, ok := n.soft[db]; ok {
		return s, nil
	}
	cu := certutil()
	if cu == "" {
		return nil, fmt.Errorf("certutil not found")
	}
	r, err := sysx.Run(sysx.Cmd{Name: cu, Args: []string{"-L", "-d", "sql:" + db}, As: db})
	if err != nil {
		return nil, err
	}
	var out []softCert
	seen := map[string]bool{}
	for _, line := range strings.Split(r.Stdout, "\n") {
		m := lineRE.FindStringSubmatch(line)
		if m == nil || strings.HasPrefix(m[1], "Certificate Nickname") {
			continue
		}
		nick, trust := m[1], m[2]
		if seen[nick] {
			continue
		}
		seen[nick] = true
		pr, err := sysx.Run(sysx.Cmd{Name: cu, Args: []string{"-L", "-d", "sql:" + db, "-n", nick, "-a"}, As: db})
		if err != nil {
			continue
		}
		for _, c := range certs.Parse([]byte(pr.Stdout)) {
			out = append(out, softCert{Nick: nick, Trust: trust, Cert: c})
		}
	}
	n.soft[db] = out
	return out, nil
}

// remember updates the cached soft-token listing of db after a change made
// through certutil, sparing a full re-listing (one certutil call per
// certificate) for every entry. trust == "" means the cert was deleted.
func (n *NSS) remember(db string, sc softCert) {
	n.mu.Lock()
	defer n.mu.Unlock()
	soft, ok := n.soft[db]
	if !ok {
		return
	}
	out := soft[:0:0]
	for _, s := range soft {
		if s.Cert.SHA256 != sc.Cert.SHA256 {
			out = append(out, s)
		}
	}
	if sc.Trust != "" {
		out = append(out, sc)
	}
	n.soft[db] = out
}

func find(soft []softCert, sha string) *softCert {
	for i := range soft {
		if soft[i].Cert.SHA256 == sha {
			return &soft[i]
		}
	}
	return nil
}

func nickFor(e *policy.Entry, i int) string {
	if i == 0 {
		return "distrust-" + e.ID
	}
	return fmt.Sprintf("distrust-%s-%d", e.ID, i)
}

func (n *NSS) Block(env *backend.Env, e *policy.Entry) error {
	cu := certutil()
	if cu == "" {
		return fmt.Errorf("certutil not found")
	}
	var rec record
	env.State.Get(n.Name(), e.ID, &rec)
	if rec.DBs == nil {
		rec.DBs = map[string][]item{}
	}
	var errs []string
	for _, db := range n.dbs(env) {
		if !sysx.Writable(filepath.Join(db, "cert9.db")) {
			env.Logf(n.Name(), "skip %s: not writable (run as root)", db)
			continue
		}
		soft, err := n.softCerts(db)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		for i, c := range e.Parsed() {
			if err := n.blockOne(env, &rec, db, soft, e, i, c); err != nil {
				errs = append(errs, err.Error())
			}
		}
		if inUse(db) && !env.DryRun {
			env.Logf(n.Name(), "note: %s is in use; restart the application to pick up the change", db)
		}
	}
	if !env.DryRun {
		if len(rec.DBs) == 0 {
			env.State.Delete(n.Name(), e.ID)
		} else if err := env.State.Put(n.Name(), e, rec); err != nil {
			return err
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func (n *NSS) blockOne(env *backend.Env, rec *record, db string, soft []softCert, e *policy.Entry, i int, c *certs.Cert) error {
	cu := certutil()
	var prev *item
	for k := range rec.DBs[db] {
		if rec.DBs[db][k].SHA256 == c.SHA256 {
			prev = &rec.DBs[db][k]
		}
	}
	if sc := find(soft, c.SHA256); sc != nil {
		if sc.Trust == distrustFlags {
			// Already distrusted. Adopt our own nickname if state was lost so
			// that unblock can still clean it up.
			if prev == nil && strings.HasPrefix(sc.Nick, "distrust-") && !env.DryRun {
				rec.DBs[db] = append(rec.DBs[db], item{SHA256: c.SHA256, Nick: sc.Nick, Added: true})
			}
			return nil
		}
		env.Logf(n.Name(), "set trust %s on %q (was %s) in %s", distrustFlags, sc.Nick, sc.Trust, db)
		if env.DryRun {
			return nil
		}
		if _, err := sysx.Run(sysx.Cmd{Name: cu, Args: []string{"-M", "-d", "sql:" + db, "-n", sc.Nick, "-t", distrustFlags}, As: db}); err != nil {
			return err
		}
		n.remember(db, softCert{Nick: sc.Nick, Trust: distrustFlags, Cert: c})
		if prev == nil { // keep the original flags if we touched this before
			rec.DBs[db] = append(rec.DBs[db], item{SHA256: c.SHA256, Nick: sc.Nick, PrevTrust: sc.Trust})
		}
		return nil
	}
	nick := nickFor(e, i)
	env.Logf(n.Name(), "import %q with trust %s into %s", nick, distrustFlags, db)
	if env.DryRun {
		return nil
	}
	tmp, err := sysx.TempFile("distrust-*.pem", []byte(c.PEM()))
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if _, err := sysx.Run(sysx.Cmd{Name: cu, Args: []string{"-A", "-d", "sql:" + db, "-n", nick, "-t", distrustFlags, "-a", "-i", tmp}, As: db}); err != nil {
		return err
	}
	n.remember(db, softCert{Nick: nick, Trust: distrustFlags, Cert: c})
	if prev == nil {
		rec.DBs[db] = append(rec.DBs[db], item{SHA256: c.SHA256, Nick: nick, Added: true})
	}
	return nil
}

func (n *NSS) Unblock(env *backend.Env, e *policy.Entry) error {
	var rec record
	if !env.State.Get(n.Name(), e.ID, &rec) {
		return nil
	}
	cu := certutil()
	if cu == "" {
		return fmt.Errorf("certutil not found")
	}
	var errs []string
	for db, items := range rec.DBs {
		if !sysx.Exists(filepath.Join(db, "cert9.db")) {
			env.Logf(n.Name(), "forget %s (database no longer exists)", db)
			delete(rec.DBs, db)
			continue
		}
		soft, err := n.softCerts(db)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		var keep []item
		for _, it := range items {
			sc := find(soft, it.SHA256)
			var args []string
			var after softCert
			switch {
			case sc == nil:
				env.Logf(n.Name(), "skip %q in %s (already gone)", it.Nick, db)
				continue
			case it.Added:
				env.Logf(n.Name(), "delete %q from %s", sc.Nick, db)
				args = []string{"-D", "-d", "sql:" + db, "-n", sc.Nick}
				after = softCert{Cert: sc.Cert}
			default:
				prev := it.PrevTrust
				if prev == "" {
					prev = ",,"
				}
				env.Logf(n.Name(), "restore trust %s on %q in %s", prev, sc.Nick, db)
				args = []string{"-M", "-d", "sql:" + db, "-n", sc.Nick, "-t", prev}
				after = softCert{Nick: sc.Nick, Trust: prev, Cert: sc.Cert}
			}
			if env.DryRun {
				continue
			}
			if _, err := sysx.Run(sysx.Cmd{Name: cu, Args: args, As: db}); err != nil {
				errs = append(errs, err.Error())
				keep = append(keep, it)
				continue
			}
			n.remember(db, after)
		}
		if len(keep) == 0 {
			delete(rec.DBs, db)
		} else {
			rec.DBs[db] = keep
		}
	}
	if !env.DryRun {
		if len(rec.DBs) == 0 {
			env.State.Delete(n.Name(), e.ID)
		} else if err := env.State.Put(n.Name(), e, rec); err != nil {
			return err
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func (n *NSS) Status(env *backend.Env, e *policy.Entry) []backend.LocState {
	var out []backend.LocState
	for _, db := range n.dbs(env) {
		ls := backend.LocState{Location: db}
		soft, err := n.softCerts(db)
		if err != nil {
			ls.Trust, ls.Detail = backend.Error, err.Error()
			out = append(out, ls)
			continue
		}
		var states []backend.LocState
		for _, c := range e.Parsed() {
			s := backend.LocState{}
			if sc := find(soft, c.SHA256); sc != nil && sslField(sc.Trust) != "" {
				s.Detail = fmt.Sprintf("%q %s", sc.Nick, sc.Trust)
				if strings.Contains(sslField(sc.Trust), "p") {
					s.Trust = backend.Distrusted
				} else if strings.ContainsAny(sslField(sc.Trust), "CT") {
					s.Trust = backend.Trusted
				} else {
					s.Trust = n.builtinTrust(c) // no SSL trust set locally: built-ins decide
				}
			} else if !certs.SelfSigned(c.X) {
				// An intermediate is trusted if it chains to any anchor in this DB.
				s.Trust, s.Detail = backend.Unknown, "chain check failed"
				if tmp, err := n.copyWithBuiltins(db); err == nil {
					s.Trust, s.Detail = n.vfy(tmp, c)
					os.RemoveAll(tmp)
				}
			} else {
				s.Trust = n.builtinTrust(c)
				if s.Trust == backend.Trusted {
					s.Detail = "built-in root"
				}
			}
			states = append(states, s)
		}
		ls.Trust = backend.Summarize(states)
		for _, s := range states {
			if s.Trust == ls.Trust && s.Detail != "" {
				ls.Detail = s.Detail
				break
			}
		}
		if inUse(db) && ls.Trust == backend.Distrusted {
			ls.Detail += " (app running: effective after restart)"
		}
		out = append(out, ls)
	}
	return out
}

func sslField(trust string) string { return strings.SplitN(trust, ",", 2)[0] }

func (n *NSS) Verify(env *backend.Env, e *policy.Entry) []backend.LocState {
	var out []backend.LocState
	if vfychain() == "" {
		return []backend.LocState{{Location: "-", Trust: backend.Unknown, Detail: "vfychain not installed"}}
	}
	for _, db := range n.dbs(env) {
		ls := backend.LocState{Location: db, Method: "vfychain -u 3 on a copy of the DB + built-in roots"}
		tmp, err := n.copyWithBuiltins(db)
		if err != nil {
			ls.Trust, ls.Detail = backend.Error, err.Error()
			out = append(out, ls)
			continue
		}
		var states []backend.LocState
		for _, c := range e.Parsed() {
			t, detail := n.vfy(tmp, c)
			states = append(states, backend.LocState{Trust: t, Detail: detail})
		}
		os.RemoveAll(tmp)
		ls.Trust = backend.Summarize(states)
		for _, s := range states {
			if s.Trust == ls.Trust {
				ls.Detail = s.Detail
				break
			}
		}
		out = append(out, ls)
	}
	return out
}

// Certs lists every certificate held in the soft tokens.
func (n *NSS) Certs(env *backend.Env) []*certs.Cert {
	var out []*certs.Cert
	for _, db := range n.dbs(env) {
		soft, _ := n.softCerts(db)
		for _, s := range soft {
			out = append(out, s.Cert)
		}
	}
	return out
}

// builtinsLib locates libnssckbi (the built-in root module).
func (n *NSS) builtinsLib() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.ckbiFound {
		n.ckbiFound = true
		for _, p := range sysx.Globs(ckbiGlobs...) {
			n.ckbi = p
			break
		}
	}
	return n.ckbi
}

// newTempDB creates an NSS DB in a temp dir, optionally seeded from src, with
// the built-in roots module loaded.
func (n *NSS) newTempDB(src string) (string, error) {
	dir, err := os.MkdirTemp("", "distrust-nss-*")
	if err != nil {
		return "", err
	}
	if src != "" {
		for _, f := range []string{"cert9.db", "key4.db"} {
			data, err := os.ReadFile(filepath.Join(src, f))
			if err != nil {
				os.RemoveAll(dir)
				return "", err
			}
			if err := os.WriteFile(filepath.Join(dir, f), data, 0o600); err != nil {
				os.RemoveAll(dir)
				return "", err
			}
		}
	} else if _, err := sysx.Run(sysx.Cmd{Name: certutil(), Args: []string{"-N", "-d", "sql:" + dir, "--empty-password"}}); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	if lib := n.builtinsLib(); lib != "" && modutil() != "" {
		_, _ = sysx.Run(sysx.Cmd{Name: modutil(), Args: []string{"-dbdir", "sql:" + dir, "-add", "Builtin Roots", "-libfile", lib, "-force"}})
	}
	return dir, nil
}

func (n *NSS) copyWithBuiltins(db string) (string, error) { return n.newTempDB(db) }

// builtinTrust checks whether c is trusted by the built-in root list alone.
func (n *NSS) builtinTrust(c *certs.Cert) backend.Trust {
	n.mu.Lock()
	if t, ok := n.builtin[c.SHA256]; ok {
		n.mu.Unlock()
		return t
	}
	n.mu.Unlock()
	t := backend.Unknown
	if n.builtinsLib() != "" && vfychain() != "" {
		if dir, err := n.newTempDB(""); err == nil {
			t, _ = n.vfy(dir, c)
			os.RemoveAll(dir)
		}
	}
	n.mu.Lock()
	if n.builtin == nil {
		n.builtin = map[string]backend.Trust{}
	}
	n.builtin[c.SHA256] = t
	n.mu.Unlock()
	return t
}

// vfy runs vfychain for c as an SSL CA against db.
func (n *NSS) vfy(db string, c *certs.Cert) (backend.Trust, string) {
	tmp, err := sysx.TempFile("distrust-*.pem", []byte(c.PEM()))
	if err != nil {
		return backend.Error, err.Error()
	}
	defer os.Remove(tmp)
	args := []string{"-d", "sql:" + db, "-u", "3"}
	if now := time.Now(); now.After(c.X.NotAfter) || now.Before(c.X.NotBefore) {
		mid := c.X.NotBefore.Add(c.X.NotAfter.Sub(c.X.NotBefore) / 2).UTC()
		args = append(args, "-b", mid.Format("0601021504Z"))
	}
	args = append(args, "-a", tmp)
	r, err := sysx.Run(sysx.Cmd{Name: vfychain(), Args: args})
	out := r.Combined()
	switch {
	case err == nil && strings.Contains(out, "Chain is good"):
		return backend.Trusted, "chain is good"
	case strings.Contains(out, "-8171"):
		return backend.Distrusted, "SEC_ERROR_UNTRUSTED_CERT (explicitly distrusted)"
	case strings.Contains(out, "-8172") && certs.SelfSigned(c.X):
		return backend.Absent, "SEC_ERROR_UNTRUSTED_ISSUER (not a trust anchor)"
	case strings.Contains(out, "-8172"):
		return backend.Distrusted, "SEC_ERROR_UNTRUSTED_ISSUER (issuer distrusted)"
	case strings.Contains(out, "-8179"):
		return backend.Absent, "SEC_ERROR_UNKNOWN_ISSUER"
	}
	return backend.Error, firstLine(out)
}

func firstLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, "ERROR") {
			return strings.TrimSpace(l)
		}
	}
	return strings.TrimSpace(strings.SplitN(s, "\n", 2)[0])
}

// ListDB returns the certificates in an NSS database's soft token, except
// those explicitly distrusted.
func ListDB(dir string) ([]*certs.Cert, error) {
	soft, err := (&NSS{}).softCerts(dir)
	var out []*certs.Cert
	for _, s := range soft {
		if !strings.Contains(sslField(s.Trust), "p") {
			out = append(out, s.Cert)
		}
	}
	return out, err
}
