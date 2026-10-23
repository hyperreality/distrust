package chromium

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"distrust/internal/backend"
	"distrust/internal/certs"
	"distrust/internal/policy"
	"distrust/internal/testutil"
)

func b64(c *certs.Cert) string { return base64.StdEncoding.EncodeToString(c.X.Raw) }

func TestStripJSONExtensions(t *testing.T) {
	in := `// header
{
  "a": "keep // this /* and this */", /* block */
  "b": [1, 2,],
}`
	var v map[string]any
	if err := lenientJSON([]byte(in), &v); err != nil {
		t.Fatalf("lenientJSON: %v\n%s", err, stripJSONExtensions([]byte(in)))
	}
	if v["a"] != "keep // this /* and this */" || len(v["b"].([]any)) != 2 {
		t.Fatalf("got %v", v)
	}
}

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
	if err := st.Remove(); err != nil {
		t.Fatal(err)
	}
	eff, _ = st.Read()
	if eff.OursExists || len(eff.Effective) != 1 {
		t.Fatalf("after remove the admin value should be effective again: %+v", eff)
	}
}

func TestSpkiValuesOnePerKey(t *testing.T) {
	a, key := testutil.CA(t, "Root", nil)
	reissue, _ := testutil.CA(t, "Root", key)
	e := policy.NewEntry(a, []*certs.Cert{reissue}, policy.MatchSPKI, nil, "")
	if got := spkiValues(&e); len(got) != 1 {
		t.Fatalf("same-key variants should collapse to one policy value, got %d", len(got))
	}
	if got := uniqueBySPKI([]string{b64(a), b64(reissue), "not-base64!"}); len(got) != 2 {
		t.Fatalf("uniqueBySPKI = %d values", len(got))
	}
}

func TestDesiredHonoursTargetsAndExclude(t *testing.T) {
	a, _ := testutil.CA(t, "A", nil)
	b, _ := testutil.CA(t, "B", nil)
	c, _ := testutil.CA(t, "C", nil)
	pol := &policy.Policy{Entries: []policy.Entry{
		policy.NewEntry(a, nil, policy.MatchSPKI, nil, ""),
		policy.NewEntry(b, nil, policy.MatchSPKI, []string{"nss"}, ""), // not targeted
		policy.NewEntry(c, nil, policy.MatchSPKI, []string{"chromium"}, ""),
	}}
	ch := &Chromium{}
	env := envFor(pol)
	if got := ch.desired(env, nil, ""); len(got) != 2 {
		t.Fatalf("desired = %d, want 2", len(got))
	}
	if got := ch.desired(env, nil, pol.Entries[2].ID); len(got) != 1 || got[0] != b64(a) {
		t.Fatalf("exclude failed: %v", got)
	}
}

func TestParseNetLog(t *testing.T) {
	ca, _ := testutil.CA(t, "Evil Root", nil)
	spki := base64.StdEncoding.EncodeToString(ca.X.RawSubjectPublicKeyInfo)
	pem := strings.ReplaceAll(ca.PEM(), "\n", `\n`)
	log := strings.Join([]string{
		`{"constants":{"logEventTypes":{"CERT_VERIFY_PROC":1,"CERT_VERIFY_PROC_ADDITIONAL_CERT":2,"CERT_VERIFY_PROC_PATH_BUILT":3}},`,
		`"events": [`,
		`{"params":{"spki":"` + spki + `","trust":"DISTRUSTED"},"phase":0,"source":{"id":5},"time":"1","type":2},`,
		`{"params":{"host":"example.test","verify_flags":0},"phase":1,"source":{"id":9},"time":"2","type":1},`,
		`{"params":{"certificates":["` + pem + `"],"errors":"----- Certificate i=1 (CN=Evil Root) -----\nERROR: Distrusted by trust store\n","is_valid":false},"phase":2,"source":{"id":9},"time":"3","type":3},`,
		`{"params":{"cert_status":4},"phase":2,"source":{"id":9},"time":"4","type":1},`,
		`{"params":{"truncated`, // killed mid-write
	}, "\n")
	path := filepath.Join(t.TempDir(), "netlog.json")
	os.WriteFile(path, []byte(log), 0o644)
	r := &probeResult{loaded: map[string]bool{}}
	parseNetLog(path, "example.test", r)
	if !r.loaded[spki] || !r.verified || r.accepted {
		t.Fatalf("parse: %+v", r)
	}
	if r.rejectWhy != "Distrusted by trust store at CN=Evil Root" {
		t.Fatalf("rejectWhy = %q", r.rejectWhy)
	}
	e := policy.NewEntry(ca, nil, policy.MatchSPKI, nil, "")
	if trust, _ := judge(&e, r, "example.test"); trust != "distrusted" {
		t.Fatalf("judge = %s", trust)
	}
}

func envFor(p *policy.Policy) *backend.Env { return &backend.Env{Policy: p} }
