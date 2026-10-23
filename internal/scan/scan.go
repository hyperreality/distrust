// Package scan walks the filesystem looking for trust stores of any kind:
// PEM bundles, single CA files, Java keystores and NSS databases, and reports
// which policy entries each one contains and whether a backend manages it.
package scan

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"distrust/internal/certs"
	"distrust/internal/policy"
)

// Kinds of findings.
const (
	KindBundle   = "pem-bundle"
	KindCert     = "ca-file"
	KindKeystore = "java-keystore"
	KindNSS      = "nss-db"
	KindNSSOld   = "nss-db (legacy dbm)"
)

// Finding is one trust store found on disk.
type Finding struct {
	Path    string   `json:"path"`
	Kind    string   `json:"kind"`
	Certs   int      `json:"certs"`
	Matches []string `json:"matches,omitempty"` // policy entry IDs present
	Managed string   `json:"managed,omitempty"` // backend that covers it
	Error   string   `json:"error,omitempty"`
}

// Options control a scan.
type Options struct {
	Paths   []string
	Skip    []string // directories to leave out (e.g. our own state dir)
	Entries []policy.Entry
	// Managed names the backend covering a (symlink-resolved) path, or "".
	Managed func(real string) string
	// ListKeystore and ListNSS read stores via the backend packages.
	ListKeystore func(path string) ([]*certs.Cert, error)
	ListNSS      func(dir string) ([]*certs.Cert, error)
}

// DefaultPaths is what to scan when no --paths are given.
func DefaultPaths() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{"/etc", "/usr/local", "/opt", "/Applications", "/Library", "/Users"}
	case "windows":
		return []string{`C:\ProgramData`, `C:\Program Files`, `C:\Program Files (x86)`, `C:\Users`}
	}
	return []string{"/etc", "/usr", "/opt", "/home", "/root", "/var/lib", "/srv", "/snap"}
}

var skipDirs = map[string]bool{
	"/proc": true, "/sys": true, "/dev": true, "/run": true, "/tmp": true,
	".git": true, "node_modules": true, "__pycache__": true, ".cache": true,
}

const maxSize = 8 << 20

var pemExts = map[string]bool{".pem": true, ".crt": true, ".cer": true, ".der": true, ".ca-bundle": true, ".ca": true}
var ksExts = map[string]bool{".jks": true, ".keystore": true, ".truststore": true, ".ts": false}

// Run performs the scan.
func Run(o Options) []Finding {
	var out []Finding
	seen := map[string]bool{}
	for _, root := range o.Paths {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				if p != root && (skipDirs[p] || skipDirs[d.Name()] || contains(o.Skip, p)) {
					return fs.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			real, err := filepath.EvalSymlinks(p)
			if err != nil || seen[real] {
				return nil
			}
			if f, ok := classify(o, p, d); ok {
				seen[real] = true
				if o.Managed != nil {
					f.Managed = o.Managed(real)
				}
				out = append(out, f)
			}
			return nil
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func classify(o Options, p string, d fs.DirEntry) (Finding, bool) {
	name := d.Name()
	lower := strings.ToLower(name)
	ext := strings.ToLower(filepath.Ext(name))
	switch {
	case name == "cert9.db":
		f := Finding{Path: filepath.Dir(p), Kind: KindNSS}
		if o.ListNSS != nil {
			cs, err := o.ListNSS(f.Path)
			f.fill(o, cs, err)
		}
		return f, true
	case name == "cert8.db":
		return Finding{Path: filepath.Dir(p), Kind: KindNSSOld}, true
	case name == "cacerts" || ksExts[ext] || ((ext == ".p12" || ext == ".pfx") && strings.Contains(lower, "trust")):
		if !keystoreMagic(p) {
			return Finding{}, false // e.g. /etc/default/cacerts is a config file
		}
		f := Finding{Path: p, Kind: KindKeystore}
		if o.ListKeystore != nil {
			cs, err := o.ListKeystore(p)
			if err != nil && name != "cacerts" && !ksExts[ext] {
				return f, false
			}
			f.fill(o, cs, err)
		}
		return f, true
	case pemExts[ext] || strings.Contains(lower, "ca-bundle") || strings.Contains(lower, "cacert"):
		info, err := d.Info()
		if err != nil || info.Size() > maxSize || info.Size() == 0 {
			return Finding{}, false
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return Finding{}, false
		}
		cs := certs.Parse(data)
		var cas []*certs.Cert
		for _, c := range cs {
			if c.X.IsCA {
				cas = append(cas, c)
			}
		}
		if len(cas) == 0 {
			return Finding{}, false
		}
		f := Finding{Path: p, Kind: KindCert}
		if len(cs) > 1 {
			f.Kind = KindBundle
		}
		f.fill(o, cas, nil)
		return f, true
	}
	return Finding{}, false
}

func (f *Finding) fill(o Options, cs []*certs.Cert, err error) {
	if err != nil {
		f.Error = err.Error()
		return
	}
	f.Certs = len(cs)
	for i := range o.Entries {
		e := &o.Entries[i]
		for _, c := range cs {
			if e.Matches(c) {
				f.Matches = append(f.Matches, e.ID)
				break
			}
		}
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// keystoreMagic accepts JKS/JCEKS magic or a DER SEQUENCE (PKCS#12).
func keystoreMagic(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	b := make([]byte, 4)
	if _, err := f.Read(b); err != nil {
		return false
	}
	return string(b) == "\xfe\xed\xfe\xed" || string(b) == "\xce\xce\xce\xce" || b[0] == 0x30
}
