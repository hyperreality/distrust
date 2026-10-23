package chromium

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"distrust/internal/backend"
	"distrust/internal/certs"
	"distrust/internal/policy"
	"distrust/internal/state"
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

// memList behaves like the registry store: one list shared with other
// administrators, plus our ownership marker.
type memList struct {
	values, marker []string
	haveMarker     bool
	writes         int
}

func (m *memList) ID() string   { return "mem" }
func (m *memList) Path() string { return "mem" }
func (m *memList) Exists() bool { return true }
func (m *memList) Read() (effective, error) {
	return splitOwned(m.values, m.marker, m.haveMarker, "mem"), nil
}
func (m *memList) Write(values, ours []string) error {
	m.values, m.marker, m.haveMarker = values, ownedKeys(ours), true
	m.writes++
	return nil
}
func (m *memList) Remove(keep []string) error {
	m.values, m.marker, m.haveMarker = keep, nil, false
	m.writes++
	return nil
}

func sharedListSetup(t *testing.T, n int) (*Chromium, *memList, *backend.Env, string) {
	admin, _ := testutil.CA(t, "Admin listed", nil)
	pol := &policy.Policy{}
	for i := 0; i < n; i++ {
		ca, _ := testutil.CA(t, "CA "+strconv.Itoa(i), nil)
		pol.Upsert(policy.NewEntry(ca, nil, policy.MatchSPKI, nil, ""))
	}
	st, _ := state.Load(t.TempDir())
	m := &memList{values: []string{b64(admin)}}
	return &Chromium{locs: []*location{{store: m}}}, m, &backend.Env{Policy: pol, State: st}, b64(admin)
}

func TestSharedListWritesOnceAndKeepsForeign(t *testing.T) {
	ch, m, env, admin := sharedListSetup(t, 5)
	for i := range env.Policy.Entries {
		if err := ch.Block(env, &env.Policy.Entries[i]); err != nil {
			t.Fatal(err)
		}
	}
	if m.writes != 1 || len(m.values) != 6 || len(m.marker) != 5 {
		t.Fatalf("writes=%d values=%d marker=%d, want 1/6/5", m.writes, len(m.values), len(m.marker))
	}
	entries := env.Policy.Entries
	env.Policy.Entries = nil
	for i := range entries {
		if err := ch.Unblock(env, &entries[i]); err != nil {
			t.Fatal(err)
		}
	}
	if len(m.values) != 1 || m.values[0] != admin || m.haveMarker {
		t.Fatalf("after unblock: values=%d marker=%v", len(m.values), m.haveMarker)
	}
}

// A lost marker (the old reg.exe write failed on long lists) must not turn
// our own values into "foreign" ones that are carried over forever.
func TestSharedListReclaimsWithoutMarker(t *testing.T) {
	ch, m, env, admin := sharedListSetup(t, 3)
	for i := range env.Policy.Entries {
		ch.Block(env, &env.Policy.Entries[i])
	}
	m.marker, m.haveMarker = nil, false // simulate the failed marker write

	ch.Block(env, &env.Policy.Entries[0])
	if len(m.values) != 4 || len(m.marker) != 3 {
		t.Fatalf("re-block: values=%d marker=%d, want 4/3", len(m.values), len(m.marker))
	}
	m.marker, m.haveMarker = nil, false
	entries := env.Policy.Entries
	env.Policy.Entries = nil
	for i := range entries {
		ch.Unblock(env, &entries[i])
	}
	if len(m.values) != 1 || m.values[0] != admin {
		t.Fatalf("after unblock without marker: %d values left", len(m.values))
	}
}
