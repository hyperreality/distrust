//go:build windows

// Package winstore is the Windows "system" backend: certificates placed in
// the LocalMachine "Disallowed" store are rejected by CryptoAPI/CNG for every
// client (Edge, Chrome, curl with schannel, .NET, Go), and Windows' automatic
// root update cannot re-trust them.
package winstore

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"os"
	"strings"

	"distrust/internal/backend"
	"distrust/internal/certs"
	"distrust/internal/policy"
	"distrust/internal/sysx"
)

func init() { backend.Register(&Store{}) }

// Store is the backend.
type Store struct{}

type record struct {
	Thumbprints []string `json:"thumbprints"`
}

func (s *Store) Name() string        { return "system" }
func (s *Store) Description() string { return "Windows LocalMachine Disallowed certificate store" }

func certutilExe() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return root + `\System32\certutil.exe`
}

func thumb(c *certs.Cert) string {
	h := sha1.Sum(c.X.Raw)
	return hex.EncodeToString(h[:])
}

func (s *Store) Detect(env *backend.Env) backend.Detection {
	if !sysx.Exists(certutilExe()) {
		return backend.Detection{Reason: "certutil.exe not found"}
	}
	return backend.Detection{
		Available: true, Writable: sysx.IsAdmin(), NeedsAdmin: true, Tools: []string{certutilExe()},
		Locations: []backend.Location{
			{Path: `Cert:\LocalMachine\Disallowed`, Kind: "disallowed store"},
			{Path: `Cert:\LocalMachine\Root`, Kind: "root store"},
		},
	}
}

func (s *Store) inStore(store string, c *certs.Cert) bool {
	_, err := sysx.Run(sysx.Cmd{Name: certutilExe(), Args: []string{"-store", store, thumb(c)}})
	return err == nil
}

func (s *Store) Block(env *backend.Env, e *policy.Entry) error {
	if !sysx.IsAdmin() && !env.DryRun {
		return errors.New("requires an elevated (Administrator) prompt")
	}
	var rec record
	env.State.Get(s.Name(), e.ID, &rec)
	for _, c := range e.Parsed() {
		if s.inStore("Disallowed", c) {
			continue
		}
		env.Logf(s.Name(), "add %s to Disallowed", c.Name())
		if env.DryRun {
			continue
		}
		tmp, err := sysx.TempFile("distrust-*.cer", c.X.Raw)
		if err != nil {
			return err
		}
		_, err = sysx.Run(sysx.Cmd{Name: certutilExe(), Args: []string{"-addstore", "-f", "Disallowed", tmp}})
		os.Remove(tmp)
		if err != nil {
			return err
		}
		rec.Thumbprints = append(rec.Thumbprints, thumb(c))
	}
	if env.DryRun || len(rec.Thumbprints) == 0 {
		return nil
	}
	return env.State.Put(s.Name(), e, rec)
}

func (s *Store) Unblock(env *backend.Env, e *policy.Entry) error {
	var rec record
	if !env.State.Get(s.Name(), e.ID, &rec) {
		return nil
	}
	for _, t := range rec.Thumbprints {
		env.Logf(s.Name(), "remove %s from Disallowed", t)
		if env.DryRun {
			continue
		}
		if _, err := sysx.Run(sysx.Cmd{Name: certutilExe(), Args: []string{"-delstore", "Disallowed", t}}); err != nil && !strings.Contains(err.Error(), "not found") {
			return err
		}
	}
	if !env.DryRun {
		env.State.Delete(s.Name(), e.ID)
	}
	return nil
}

func (s *Store) Status(env *backend.Env, e *policy.Entry) []backend.LocState {
	dis := backend.LocState{Location: `Cert:\LocalMachine\Disallowed`, Trust: backend.Absent}
	root := backend.LocState{Location: `Cert:\LocalMachine\Root`, Trust: backend.Absent}
	for _, c := range e.Parsed() {
		if s.inStore("Disallowed", c) {
			dis.Trust, dis.Detail = backend.Distrusted, thumb(c)
		}
		if s.inStore("Root", c) {
			root.Trust, root.Detail = backend.Trusted, thumb(c)
		}
	}
	// Disallowed wins over Root in CryptoAPI chain building.
	if dis.Trust == backend.Distrusted && root.Trust == backend.Trusted {
		root.Trust, root.Detail = backend.Distrusted, "present in Root but overridden by Disallowed"
	}
	return []backend.LocState{dis, root}
}

// Verify uses Go's verifier, which on Windows calls CertGetCertificateChain
// and so applies the Disallowed store and automatic root update.
func (s *Store) Verify(env *backend.Env, e *policy.Entry) []backend.LocState {
	ls := backend.LocState{Location: "CryptoAPI", Method: "CertGetCertificateChain via go crypto/x509", Trust: backend.Absent}
	for _, c := range e.Parsed() {
		if _, err := c.X.Verify(x509.VerifyOptions{KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err == nil {
			ls.Trust, ls.Detail = backend.Trusted, "chain verifies"
			break
		} else if strings.Contains(err.Error(), "explicitly distrusted") || s.inStore("Disallowed", c) {
			ls.Trust, ls.Detail = backend.Distrusted, err.Error()
		} else {
			ls.Detail = err.Error()
		}
	}
	return []backend.LocState{ls}
}
