// Package java manages Java trust stores (cacerts and configured keystores).
//
// Java keystores have no notion of distrust, so blocking deletes the matching
// trustedCertEntry aliases (keeping a copy in state for unblock). On Debian the
// shared /etc/ssl/certs/java/cacerts is also regenerated from the system
// store by ca-certificates-java, which stays consistent with the system backend.
package java

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"crypto/x509"

	"distrust/internal/backend"
	"distrust/internal/certs"
	"distrust/internal/policy"
	"distrust/internal/sysx"
)

func init() { backend.Register(&Java{}) }

// Java is the backend.
type Java struct {
	mu    sync.Mutex
	cache map[string][]entry
}

type entry struct {
	Alias string
	Cert  *certs.Cert
}

type record struct {
	Removed []removed `json:"removed"`
}

type removed struct {
	Keystore string `json:"keystore"`
	Alias    string `json:"alias"`
	PEM      string `json:"pem"`
}

func (j *Java) Name() string        { return "java" }
func (j *Java) Description() string { return "Java keystores (JDK/JRE cacerts, configured keystores)" }

func storepass() string {
	if p := os.Getenv("DISTRUST_JAVA_STOREPASS"); p != "" {
		return p
	}
	return "changeit"
}

func keytool() string {
	extra := append([]string{}, jdkBinGlobs...)
	if jh := os.Getenv("JAVA_HOME"); jh != "" {
		extra = append([]string{jh + "/bin"}, extra...)
	}
	return sysx.LookPath("keytool", extra...)
}

func (j *Java) keystores(env *backend.Env) []string {
	pats := append([]string{}, cacertsGlobs...)
	if jh := os.Getenv("JAVA_HOME"); jh != "" {
		pats = append(pats, jh+"/lib/security/cacerts", jh+"/jre/lib/security/cacerts")
	}
	out := sysx.Globs(pats...)
	if env != nil && env.Policy != nil {
		out = sysx.Dedupe(append(out, env.Policy.Keystores...))
	}
	var keep []string
	for _, p := range out {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			keep = append(keep, p)
		}
	}
	return keep
}

func (j *Java) Detect(env *backend.Env) backend.Detection {
	d := backend.Detection{}
	anyWritable := false
	for _, k := range j.keystores(env) {
		loc := backend.Location{Path: k, Kind: "keystore"}
		if _, err := j.list(k); err != nil {
			loc.Note = "unreadable: " + err.Error()
		}
		if sysx.Writable(k) {
			anyWritable = true
		} else {
			loc.Note = strings.TrimSpace(loc.Note + " read-only")
		}
		d.Locations = append(d.Locations, loc)
	}
	kt := keytool()
	if kt != "" {
		d.Tools = append(d.Tools, kt)
	}
	switch {
	case len(d.Locations) == 0:
		d.Reason = "no Java keystores found"
	case kt == "":
		d.Available = true
		d.Reason = "keytool not found: read-only"
	case !anyWritable:
		d.Available = true
		d.Reason = "no writable keystore (run as root)"
	default:
		d.Available, d.Writable = true, true
	}
	return d
}

// list returns the trusted cert entries in a keystore (native JKS parser,
// falling back to keytool for PKCS#12 and anything else).
func (j *Java) list(path string) ([]entry, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.cache == nil {
		j.cache = map[string][]entry{}
	}
	if es, ok := j.cache[path]; ok {
		return es, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	es, err := parseJKS(data)
	if errors.Is(err, errNotJKS) {
		es, err = keytoolList(path)
	}
	if err != nil {
		return nil, err
	}
	j.cache[path] = es
	return es, nil
}

func (j *Java) invalidate(path string) {
	j.mu.Lock()
	delete(j.cache, path)
	j.mu.Unlock()
}

func keytoolList(path string) ([]entry, error) {
	kt := keytool()
	if kt == "" {
		return nil, errors.New("not JKS and keytool not available")
	}
	r, err := sysx.Run(sysx.Cmd{Name: kt, Args: []string{"-list", "-rfc", "-keystore", path, "-storepass", storepass()}})
	if err != nil {
		return nil, err
	}
	var out []entry
	for _, chunk := range strings.Split(r.Stdout, "Alias name: ")[1:] {
		alias := strings.TrimSpace(strings.SplitN(chunk, "\n", 2)[0])
		if !strings.Contains(chunk, "trustedCertEntry") {
			continue
		}
		for _, c := range certs.Parse([]byte(chunk)) {
			out = append(out, entry{Alias: alias, Cert: c})
		}
	}
	return out, nil
}

var errNotJKS = errors.New("not a JKS keystore")

// parseJKS reads trusted certificate entries from a JKS/JCEKS file. The
// integrity hash is not checked: this is only used for reading.
func parseJKS(data []byte) ([]entry, error) {
	r := bytes.NewReader(data)
	var magic, version, count uint32
	if binary.Read(r, binary.BigEndian, &magic) != nil || (magic != 0xFEEDFEED && magic != 0xCECECECE) {
		return nil, errNotJKS
	}
	if err := binary.Read(r, binary.BigEndian, &version); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.BigEndian, &count); err != nil {
		return nil, err
	}
	readUTF := func() (string, error) {
		var n uint16
		if err := binary.Read(r, binary.BigEndian, &n); err != nil {
			return "", err
		}
		b := make([]byte, n)
		_, err := io.ReadFull(r, b)
		return string(b), err
	}
	readBlob := func() ([]byte, error) {
		var n uint32
		if err := binary.Read(r, binary.BigEndian, &n); err != nil {
			return nil, err
		}
		if int(n) > r.Len() {
			return nil, errors.New("truncated keystore")
		}
		b := make([]byte, n)
		_, err := io.ReadFull(r, b)
		return b, err
	}
	readCert := func() ([]byte, error) {
		if version == 2 {
			if _, err := readUTF(); err != nil { // cert type, "X.509"
				return nil, err
			}
		}
		return readBlob()
	}
	var out []entry
	for i := uint32(0); i < count; i++ {
		var tag uint32
		if err := binary.Read(r, binary.BigEndian, &tag); err != nil {
			return nil, err
		}
		alias, err := readUTF()
		if err != nil {
			return nil, err
		}
		var ts int64
		if err := binary.Read(r, binary.BigEndian, &ts); err != nil {
			return nil, err
		}
		switch tag {
		case 1: // private key + chain: skip
			if _, err := readBlob(); err != nil {
				return nil, err
			}
			var n uint32
			if err := binary.Read(r, binary.BigEndian, &n); err != nil {
				return nil, err
			}
			for k := uint32(0); k < n; k++ {
				if _, err := readCert(); err != nil {
					return nil, err
				}
			}
		case 2:
			der, err := readCert()
			if err != nil {
				return nil, err
			}
			if c, err := x509.ParseCertificate(der); err == nil {
				out = append(out, entry{Alias: alias, Cert: certs.New(c)})
			}
		default: // JCEKS secret keys are serialized Java objects
			return nil, errNotJKS
		}
	}
	return out, nil
}

func (j *Java) Certs(env *backend.Env) []*certs.Cert {
	var out []*certs.Cert
	for _, k := range j.keystores(env) {
		es, _ := j.list(k)
		for _, e := range es {
			out = append(out, e.Cert)
		}
	}
	return out
}

func (j *Java) Block(env *backend.Env, e *policy.Entry) error {
	var rec record
	env.State.Get(j.Name(), e.ID, &rec)
	kt := keytool()
	var errs []string
	for _, ks := range j.keystores(env) {
		es, err := j.list(ks)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", ks, err))
			continue
		}
		writable := sysx.Writable(ks)
		for _, en := range es {
			if !e.Matches(en.Cert) {
				continue
			}
			if !writable {
				env.Logf(j.Name(), "skip %s: not writable (run as root)", ks)
				if sysx.IsAdmin() {
					errs = append(errs, ks+": not writable")
				}
				break
			}
			env.Logf(j.Name(), "delete alias %q from %s", en.Alias, ks)
			if env.DryRun {
				continue
			}
			if kt == "" {
				errs = append(errs, "keytool not found")
				break
			}
			if _, err := sysx.Run(sysx.Cmd{Name: kt, Args: []string{"-delete", "-alias", en.Alias, "-keystore", ks, "-storepass", storepass()}}); err != nil {
				errs = append(errs, err.Error())
				continue
			}
			rec.Removed = append(rec.Removed, removed{Keystore: ks, Alias: en.Alias, PEM: en.Cert.PEM()})
		}
		j.invalidate(ks)
	}
	if !env.DryRun && len(rec.Removed) > 0 {
		if err := env.State.Put(j.Name(), e, rec); err != nil {
			return err
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (j *Java) Unblock(env *backend.Env, e *policy.Entry) error {
	var rec record
	if !env.State.Get(j.Name(), e.ID, &rec) {
		return nil
	}
	kt := keytool()
	if kt == "" && !env.DryRun {
		return errors.New("keytool not found")
	}
	var keep []removed
	var errs []string
	for _, rm := range rec.Removed {
		if !sysx.Exists(rm.Keystore) {
			continue
		}
		es, err := j.list(rm.Keystore)
		if err != nil {
			errs = append(errs, err.Error())
			keep = append(keep, rm)
			continue
		}
		c := certs.Parse([]byte(rm.PEM))
		present, aliasTaken := false, false
		for _, en := range es {
			if len(c) > 0 && en.Cert.SHA256 == c[0].SHA256 {
				present = true
			}
			if strings.EqualFold(en.Alias, rm.Alias) {
				aliasTaken = true
			}
		}
		if present {
			continue // e.g. regenerated by ca-certificates-java after the system unblock
		}
		alias := rm.Alias
		if aliasTaken {
			alias += "-restored"
		}
		env.Logf(j.Name(), "re-import alias %q into %s", alias, rm.Keystore)
		if env.DryRun {
			continue
		}
		tmp, err := sysx.TempFile("distrust-*.pem", []byte(rm.PEM))
		if err != nil {
			return err
		}
		_, err = sysx.Run(sysx.Cmd{Name: kt, Args: []string{"-importcert", "-noprompt", "-trustcacerts", "-alias", alias, "-file", tmp, "-keystore", rm.Keystore, "-storepass", storepass()}})
		os.Remove(tmp)
		j.invalidate(rm.Keystore)
		if err != nil {
			errs = append(errs, err.Error())
			keep = append(keep, rm)
		}
	}
	if !env.DryRun {
		if len(keep) == 0 {
			env.State.Delete(j.Name(), e.ID)
		} else {
			rec.Removed = keep
			if err := env.State.Put(j.Name(), e, rec); err != nil {
				return err
			}
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (j *Java) Status(env *backend.Env, e *policy.Entry) []backend.LocState {
	var rec record
	env.State.Get(j.Name(), e.ID, &rec)
	var out []backend.LocState
	for _, ks := range j.keystores(env) {
		ls := backend.LocState{Location: ks}
		es, err := j.list(ks)
		if err != nil {
			ls.Trust, ls.Detail = backend.Error, err.Error()
			out = append(out, ls)
			continue
		}
		ls.Trust = backend.Absent
		for _, en := range es {
			if e.Matches(en.Cert) {
				ls.Trust, ls.Detail = backend.Trusted, "alias "+en.Alias
				break
			}
		}
		if ls.Trust == backend.Absent {
			for _, rm := range rec.Removed {
				if rm.Keystore == ks {
					ls.Trust, ls.Detail = backend.Distrusted, "alias "+rm.Alias+" removed"
				}
			}
		}
		out = append(out, ls)
	}
	return out
}

func (j *Java) Verify(env *backend.Env, e *policy.Entry) []backend.LocState {
	var out []backend.LocState
	recorded := env.State.Has(j.Name(), e.ID)
	for _, ks := range j.keystores(env) {
		ls := backend.LocState{Location: ks, Method: "go crypto/x509 against keystore anchors (as Java PKIX)"}
		es, err := j.list(ks)
		if err != nil {
			ls.Trust, ls.Detail = backend.Error, err.Error()
			out = append(out, ls)
			continue
		}
		var anchors []*certs.Cert
		for _, en := range es {
			anchors = append(anchors, en.Cert)
		}
		pool := certs.Pool(anchors)
		ls.Trust = backend.Absent
		if recorded {
			ls.Trust = backend.Distrusted
		}
		ls.Detail = "does not chain to any anchor"
		for _, c := range e.Parsed() {
			if certs.VerifyAgainst(c.X, pool) == nil {
				ls.Trust, ls.Detail = backend.Trusted, "chain verifies ("+c.SHA256[:12]+")"
				break
			}
		}
		out = append(out, ls)
	}
	return out
}

// ListKeystore returns the trusted certificates in a keystore file.
func ListKeystore(path string) ([]*certs.Cert, error) {
	es, err := (&Java{}).list(path)
	var out []*certs.Cert
	for _, e := range es {
		out = append(out, e.Cert)
	}
	return out, err
}
