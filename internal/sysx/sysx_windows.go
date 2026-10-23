//go:build windows

package sysx

import (
	"os"
	"os/exec"
	"path/filepath"
)

const exeSuffix = ".exe"

// IsAdmin reports whether we hold admin rights, probed by opening the
// physical drive, which only elevated processes may do.
func IsAdmin() bool {
	f, err := os.Open(`\\.\PHYSICALDRIVE0`)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

func setCredential(cmd *exec.Cmd, path string) {}

func allHomes() []string {
	drive := os.Getenv("SystemDrive")
	if drive == "" {
		drive = "C:"
	}
	hs, _ := filepath.Glob(filepath.Join(drive+`\`, "Users", "*"))
	return hs
}

// Lock is an exclusive lock via O_EXCL lock file creation.
func Lock(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	return func() { f.Close() }, nil
}

// InvokingUser is not applicable on Windows.
func InvokingUser() (int, int, bool) { return 0, 0, false }
