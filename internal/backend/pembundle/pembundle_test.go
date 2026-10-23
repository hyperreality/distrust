package pembundle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"distrust/internal/backend"
	"distrust/internal/certs"
	"distrust/internal/policy"
	"distrust/internal/state"
	"distrust/internal/testutil"
)

func TestBlockUnblockRoundTrip(t *testing.T) {
	dir := t.TempDir()
	a, _ := testutil.CA(t, "Keep A", nil)
	bad, _ := testutil.CA(t, "Bad", nil)
	c, _ := testutil.CA(t, "Keep C", nil)

	for name, layout := range map[string]string{
		"middle": "# A\n" + a.PEM() + "\n# Bad\n" + bad.PEM() + "\n# C\n" + c.PEM(),
		"end":    "# A\n" + a.PEM() + "\n# C\n" + c.PEM() + "\n# Bad\n" + bad.PEM(),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".pem")
			if err := os.WriteFile(path, []byte(layout), 0o644); err != nil {
				t.Fatal(err)
			}
			st, _ := state.Load(filepath.Join(dir, name+"-state"))
			pol := &policy.Policy{Bundles: []string{path}}
			env := &backend.Env{Policy: pol, State: st}
			e := policy.NewEntry(bad, nil, policy.MatchSPKI, nil, "")
			b := &Bundle{}

			if err := b.Block(env, &e); err != nil {
				t.Fatal(err)
			}
			data, _ := os.ReadFile(path)
			if strings.Contains(string(data), "# Bad") || len(certs.Parse(data)) != 2 {
				t.Fatalf("bad cert not cut cleanly:\n%s", data)
			}
			if got := backend.Summarize(b.Status(env, &e)); got != backend.Distrusted {
				t.Fatalf("status after block = %s", got)
			}
			// Idempotent.
			if err := b.Block(env, &e); err != nil {
				t.Fatal(err)
			}
			if err := b.Unblock(env, &e); err != nil {
				t.Fatal(err)
			}
			data, _ = os.ReadFile(path)
			if len(certs.Parse(data)) != 3 {
				t.Fatalf("unblock did not restore the cert")
			}
			if name == "end" && string(data) != layout {
				t.Fatalf("unblock not byte-identical:\n%q\nvs\n%q", data, layout)
			}
			if st.Has("bundle", e.ID) {
				t.Fatal("state record left behind")
			}
		})
	}
}
