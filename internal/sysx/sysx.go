// Package sysx wraps the OS-specific bits: running helper tools (optionally as
// another user), enumerating user homes, privilege checks and locking.
package sysx

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Cmd describes a helper invocation.
type Cmd struct {
	Name  string
	Args  []string
	Stdin []byte
	// As runs the command as the owner of this path when we are root, so
	// files in user-owned NSS databases keep their ownership.
	As string
	// Env entries appended to the environment.
	Env []string
}

// Result of a helper invocation.
type Result struct {
	Stdout, Stderr string
	Code           int
}

// Combined returns trimmed stdout+stderr.
func (r Result) Combined() string {
	return strings.TrimSpace(r.Stdout + "\n" + r.Stderr)
}

// Run executes c with a timeout. A non-zero exit is reported in Result.Code
// and as an error.
func Run(c Cmd) (Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Name, c.Args...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	if c.Stdin != nil {
		cmd.Stdin = bytes.NewReader(c.Stdin)
	}
	cmd.Env = append(os.Environ(), c.Env...)
	if c.As != "" {
		setCredential(cmd, c.As)
	}
	err := cmd.Run()
	r := Result{Stdout: so.String(), Stderr: se.String()}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			r.Code = ee.ExitCode()
		} else {
			r.Code = -1
		}
		msg := strings.TrimSpace(r.Stderr)
		if msg == "" {
			msg = strings.TrimSpace(r.Stdout)
		}
		return r, fmt.Errorf("%s %s: %v: %s", c.Name, strings.Join(c.Args, " "), err, firstLines(msg, 3))
	}
	return r, nil
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, " | ")
}

// LookPath finds a binary on PATH or in any of the extra directories/globs.
func LookPath(name string, extra ...string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, pat := range extra {
		matches, _ := filepath.Glob(filepath.Join(pat, name+exeSuffix))
		for _, m := range matches {
			if fi, err := os.Stat(m); err == nil && !fi.IsDir() {
				return m
			}
		}
	}
	return ""
}

// Exists reports whether path exists.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Homes returns home directories to scan: every real user's home when
// running with admin rights, otherwise just the caller's.
//
// DISTRUST_HOMES (a list separated by the OS path-list separator) overrides
// the set, e.g. to limit a run to one user or to test against a sandbox.
func Homes() []string {
	if v := os.Getenv("DISTRUST_HOMES"); v != "" {
		return filepath.SplitList(v)
	}
	if IsAdmin() {
		if hs := allHomes(); len(hs) > 0 {
			return hs
		}
	}
	if h, err := os.UserHomeDir(); err == nil {
		return []string{h}
	}
	return nil
}

// Glob expands patterns relative to each home, de-duplicating by real path.
func GlobHomes(patterns ...string) []string {
	var out []string
	for _, h := range Homes() {
		for _, p := range patterns {
			out = append(out, Globs(filepath.Join(h, p))...)
		}
	}
	return Dedupe(out)
}

// Globs expands patterns, de-duplicating by real path.
func Globs(patterns ...string) []string {
	var out []string
	for _, p := range patterns {
		m, _ := filepath.Glob(p)
		out = append(out, m...)
	}
	return Dedupe(out)
}

// Dedupe removes paths that resolve to the same file, keeping the first.
func Dedupe(paths []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		r, err := filepath.EvalSymlinks(p)
		if err != nil {
			r = p
		}
		if !seen[r] {
			seen[r] = true
			out = append(out, p)
		}
	}
	return out
}

// TempFile writes data to a new temp file and returns its path.
func TempFile(pattern string, data []byte) (string, error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	// Helpers may run as another user (see Cmd.As); the content is a public cert.
	_ = f.Chmod(0o644)
	return f.Name(), nil
}

// Writable reports whether the current process can write path (a file, or a
// directory's files).
func Writable(path string) bool {
	if fi, err := os.Stat(path); err == nil && fi.IsDir() {
		f, err := os.CreateTemp(path, ".distrust-probe-*")
		if err != nil {
			return false
		}
		f.Close()
		os.Remove(f.Name())
		return true
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// Start launches c in the background (same credential rules as Run).
func Start(c Cmd) (*exec.Cmd, error) {
	cmd := exec.Command(c.Name, c.Args...)
	cmd.Env = append(os.Environ(), c.Env...)
	if c.As != "" {
		setCredential(cmd, c.As)
	}
	return cmd, cmd.Start()
}
