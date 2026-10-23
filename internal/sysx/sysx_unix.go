//go:build unix

package sysx

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

const exeSuffix = ""

// IsAdmin reports whether we run as root.
func IsAdmin() bool { return os.Geteuid() == 0 }

func setCredential(cmd *exec.Cmd, path string) {
	if !IsAdmin() {
		return
	}
	uid, gid, ok := Owner(path)
	if !ok || uid == 0 {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid}}
}

// Owner returns the uid/gid owning path.
func Owner(path string) (uint32, uint32, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return st.Uid, st.Gid, true
}

func allHomes() []string {
	if runtime.GOOS == "darwin" {
		hs, _ := filepath.Glob("/Users/*")
		return append(hs, "/var/root")
	}
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(parts[2])
		home := parts[5]
		shell := parts[6]
		// root plus regular users; skip system accounts and nologin shells.
		if uid != 0 && (uid < 1000 || uid == 65534) {
			continue
		}
		if strings.HasSuffix(shell, "nologin") || strings.HasSuffix(shell, "false") {
			continue
		}
		if home == "" || seen[home] || !Exists(home) {
			continue
		}
		seen[home] = true
		out = append(out, home)
	}
	return out
}

// Lock takes an exclusive advisory lock on path, returning an unlock func.
func Lock(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

// InvokingUser returns the uid/gid of the user behind sudo, if any.
func InvokingUser() (int, int, bool) {
	u, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	g, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if !IsAdmin() || err1 != nil || err2 != nil || u == 0 {
		return 0, 0, false
	}
	return u, g, true
}
