//go:build darwin

// Package keychain is the macOS "system" backend: an admin trust setting of
// "deny" (security add-trusted-cert -d -r deny) overrides the system roots
// for every Security.framework client (Safari, Chrome, curl, Go, ...).
package keychain

import (
	"crypto/x509"
	"errors"
	"os"
	"strings"

	"distrust/internal/backend"
	"distrust/internal/certs"
	"distrust/internal/policy"
	"distrust/internal/sysx"
)

const systemKeychain = "/Library/Keychains/System.keychain"

func init() { backend.Register(&Keychain{}) }

// Keychain is the backend.
type Keychain struct{}

type record struct {
	Certs []string `json:"certs"` // sha256 of certs given a deny setting
}

func (k *Keychain) Name() string        { return "system" }
func (k *Keychain) Description() string { return "macOS admin trust settings (System keychain)" }

func (k *Keychain) Detect(env *backend.Env) backend.Detection {
	sec := sysx.LookPath("security", "/usr/bin")
	if sec == "" {
		return backend.Detection{Reason: "security(1) not found"}
	}
	return backend.Detection{
		Available: true, Writable: sysx.IsAdmin(), Tools: []string{sec},
		Locations: []backend.Location{{Path: systemKeychain, Kind: "admin trust settings"}},
	}
}

func (k *Keychain) run(args ...string) (sysx.Result, error) {
	return sysx.Run(sysx.Cmd{Name: "/usr/bin/security", Args: args})
}

func (k *Keychain) Block(env *backend.Env, e *policy.Entry) error {
	if !sysx.IsAdmin() && !env.DryRun {
		return errors.New("requires root (sudo)")
	}
	var rec record
	env.State.Get(k.Name(), e.ID, &rec)
	for _, c := range e.Parsed() {
		if k.denied(c) {
			continue
		}
		env.Logf(k.Name(), "add deny trust setting for %s", c.Name())
		if env.DryRun {
			continue
		}
		tmp, err := sysx.TempFile("distrust-*.pem", []byte(c.PEM()))
		if err != nil {
			return err
		}
		_, err = k.run("add-trusted-cert", "-d", "-r", "deny", "-k", systemKeychain, tmp)
		os.Remove(tmp)
		if err != nil {
			return err
		}
		rec.Certs = append(rec.Certs, c.SHA256)
	}
	if env.DryRun || len(rec.Certs) == 0 {
		return nil
	}
	return env.State.Put(k.Name(), e, rec)
}

func (k *Keychain) Unblock(env *backend.Env, e *policy.Entry) error {
	var rec record
	if !env.State.Get(k.Name(), e.ID, &rec) {
		return nil
	}
	for _, c := range e.Parsed() {
		env.Logf(k.Name(), "remove trust setting for %s", c.Name())
		if env.DryRun {
			continue
		}
		tmp, err := sysx.TempFile("distrust-*.pem", []byte(c.PEM()))
		if err != nil {
			return err
		}
		_, _ = k.run("remove-trusted-cert", "-d", tmp)
		os.Remove(tmp)
	}
	if !env.DryRun {
		env.State.Delete(k.Name(), e.ID)
	}
	return nil
}

// denied checks the admin trust settings export for the cert.
func (k *Keychain) denied(c *certs.Cert) bool {
	r, err := k.run("dump-trust-settings", "-d")
	if err != nil {
		return false
	}
	return strings.Contains(r.Stdout, c.Name()) && strings.Contains(r.Stdout, "kSecTrustSettingsResultDeny")
}

func (k *Keychain) Status(env *backend.Env, e *policy.Entry) []backend.LocState {
	return k.Verify(env, e)
}

// Verify uses Go's verifier, which on macOS delegates to Security.framework
// and thus honours admin trust settings.
func (k *Keychain) Verify(env *backend.Env, e *policy.Entry) []backend.LocState {
	ls := backend.LocState{Location: systemKeychain, Method: "Security.framework via go crypto/x509"}
	ls.Trust = backend.Absent
	if env.State.Has(k.Name(), e.ID) {
		ls.Trust = backend.Distrusted
	}
	for _, c := range e.Parsed() {
		if _, err := c.X.Verify(x509.VerifyOptions{KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err == nil {
			ls.Trust, ls.Detail = backend.Trusted, "chain verifies"
			break
		} else {
			ls.Detail = err.Error()
		}
	}
	return []backend.LocState{ls}
}
