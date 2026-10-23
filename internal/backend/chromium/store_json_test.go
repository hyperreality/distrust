//go:build !windows

package chromium

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"distrust/internal/testutil"
)

func TestJSONDirLastFileWins(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "managed")
	os.MkdirAll(dir, 0o755)
	a, _ := testutil.CA(t, "A", nil)
	b, _ := testutil.CA(t, "B", nil)
	write := func(name string, vals ...string) {
		data, _ := json.Marshal(map[string]any{PolicyKey: vals, "Other": 1})
		os.WriteFile(filepath.Join(dir, name), data, 0o644)
	}
	write("10-admin.json", b64(a))
	os.WriteFile(filepath.Join(dir, "20-broken.json"), []byte("{nope"), 0o644)
	st := &jsonDir{dir: dir}

	eff, err := st.Read()
	if err != nil || eff.ForeignSource != "10-admin.json" || len(eff.Foreign) != 1 || eff.OursExists {
		t.Fatalf("before write: %+v %v", eff, err)
	}
	if err := st.Write([]string{b64(b), b64(a)}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(base, "."+OwnFile+".tmp")); err == nil {
		t.Fatal("temp file left behind")
	}
	eff, _ = st.Read()
	if !eff.OursExists || len(eff.Effective) != 2 || eff.OverriddenBy != "" {
		t.Fatalf("after write: %+v", eff)
	}
	write("zzz-late.json")
	eff, _ = st.Read()
	if eff.OverriddenBy != "zzz-late.json" || len(eff.Effective) != 0 {
		t.Fatalf("late file should override: %+v", eff)
	}
	os.Remove(filepath.Join(dir, "zzz-late.json"))
	if err := st.Remove(nil); err != nil {
		t.Fatal(err)
	}
	eff, _ = st.Read()
	if eff.OursExists || len(eff.Effective) != 1 {
		t.Fatalf("after remove the admin value should be effective again: %+v", eff)
	}
}
