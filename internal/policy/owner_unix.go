//go:build unix

package policy

import (
	"os"
	"syscall"
)

func copyOwner(from, to string) {
	fi, err := os.Stat(from)
	if err != nil {
		return
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		_ = os.Lchown(to, int(st.Uid), int(st.Gid))
	}
}
