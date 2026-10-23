//go:build windows

package chromium

import (
	"os"
	"strconv"
	"strings"

	"distrust/internal/sysx"
)

// store is a browser policy source we can read and write.
type store interface {
	ID() string
	Path() string
	Exists() bool
	Read() (effective, error)
	Write(values, ours []string) error
	Remove() error
}

// markerKey remembers which values in each policy key are ours, since a
// registry list policy has no per-source split. Group Policy refreshes may
// rewrite the policy key if a GPO also sets this policy.
const markerKey = `HKLM\SOFTWARE\distrust\chromium`

// regStore is HKLM\<RegKey>\CADistrustedCertificates (values "1".."n").
type regStore struct{ key string }

func newStore(b *Browser) store {
	if b.RegKey == "" {
		return nil
	}
	return &regStore{key: `HKLM\` + b.RegKey}
}

func regExe() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return root + `\System32\reg.exe`
}

func reg(args ...string) (string, error) {
	r, err := sysx.Run(sysx.Cmd{Name: regExe(), Args: append(args, "/reg:64")})
	return r.Stdout, err
}

func (r *regStore) listKey() string { return r.key + `\` + PolicyKey }
func (r *regStore) ID() string      { return strings.ToLower(r.key) }
func (r *regStore) Path() string    { return r.listKey() }

func (r *regStore) Exists() bool {
	_, err := reg("query", r.key)
	return err == nil
}

func (r *regStore) markerName() string { return strings.ReplaceAll(r.key, `\`, "_") }

// queryValues parses "reg query" output lines: "    <name>    REG_xx    <data>".
func queryValues(out string) map[string]string {
	vals := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && strings.HasPrefix(f[1], "REG_") {
			vals[f[0]] = strings.Join(f[2:], " ")
		}
	}
	return vals
}

func (r *regStore) Read() (effective, error) {
	var eff effective
	out, err := reg("query", r.listKey())
	if err != nil {
		return eff, nil // key absent
	}
	raw := queryValues(out)
	for i := 1; ; i++ {
		v, ok := raw[strconv.Itoa(i)]
		if !ok {
			break
		}
		eff.Effective = append(eff.Effective, v)
	}
	mine := map[string]bool{}
	if mout, err := reg("query", markerKey, "/v", r.markerName()); err == nil {
		for _, v := range strings.Split(queryValues(mout)[r.markerName()], `\0`) {
			mine[v] = true
		}
	}
	for _, v := range eff.Effective {
		if mine[v] {
			eff.Ours = append(eff.Ours, v)
			eff.OursExists = true
		} else {
			eff.Foreign = append(eff.Foreign, v)
			eff.ForeignSource = r.listKey()
		}
	}
	return eff, nil
}

func (r *regStore) Write(values, ours []string) error {
	_, _ = reg("delete", r.listKey(), "/f")
	for i, v := range values {
		if _, err := reg("add", r.listKey(), "/v", strconv.Itoa(i+1), "/t", "REG_SZ", "/d", v, "/f"); err != nil {
			return err
		}
	}
	_, err := reg("add", markerKey, "/v", r.markerName(), "/t", "REG_MULTI_SZ", "/d", strings.Join(ours, `\0`), "/f")
	return err
}

// Remove deletes our values, leaving any foreign ones in place.
func (r *regStore) Remove() error {
	eff, _ := r.Read()
	_, _ = reg("delete", markerKey, "/v", r.markerName(), "/f")
	if len(eff.Foreign) == 0 {
		_, _ = reg("delete", r.listKey(), "/f")
		return nil
	}
	return r.Write(eff.Foreign, nil)
}
