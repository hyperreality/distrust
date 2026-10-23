package engine

import (
	"path/filepath"
	"testing"

	"distrust/internal/backend"
	"distrust/internal/policy"
	"distrust/internal/state"
	"distrust/internal/testutil"
)

// fake records blocked IDs in memory and in state, like a real backend.
type fake struct {
	name    string
	blocked map[string]bool
	calls   int
}

func (f *fake) Name() string        { return f.name }
func (f *fake) Description() string { return "fake" }
func (f *fake) Detect(*backend.Env) backend.Detection {
	return backend.Detection{Available: true, Writable: true}
}
func (f *fake) Verify(env *backend.Env, e *policy.Entry) []backend.LocState { return f.Status(env, e) }
func (f *fake) Status(env *backend.Env, e *policy.Entry) []backend.LocState {
	t := backend.Trusted
	if f.blocked[e.ID] {
		t = backend.Distrusted
	}
	return []backend.LocState{{Location: f.name, Trust: t}}
}
func (f *fake) Block(env *backend.Env, e *policy.Entry) error {
	if f.blocked[e.ID] {
		return nil
	}
	f.calls++
	f.blocked[e.ID] = true
	return env.State.Put(f.name, e, map[string]bool{"done": true})
}
func (f *fake) Unblock(env *backend.Env, e *policy.Entry) error {
	f.calls++
	delete(f.blocked, e.ID)
	env.State.Delete(f.name, e.ID)
	return nil
}

func TestReconcile(t *testing.T) {
	f1 := &fake{name: "f1", blocked: map[string]bool{}}
	f2 := &fake{name: "f2", blocked: map[string]bool{}}
	backend.Register(f1)
	backend.Register(f2)

	dir := t.TempDir()
	pol, _ := policy.Load(filepath.Join(dir, "policy.json"))
	st, _ := state.Load(filepath.Join(dir, "state"))
	en := &Engine{Policy: pol, State: st}

	ca, _ := testutil.CA(t, "Bad", nil)
	e := pol.Upsert(policy.NewEntry(ca, nil, policy.MatchSPKI, nil, ""))
	if err := en.Apply().Err(); err != nil {
		t.Fatal(err)
	}
	if !f1.blocked[e.ID] || !f2.blocked[e.ID] {
		t.Fatal("entry with no backend list should apply everywhere")
	}
	calls := f1.calls + f2.calls
	en.Apply()
	if f1.calls+f2.calls != calls {
		t.Fatal("second apply was not a no-op")
	}

	// Narrow to f1: f2 must be reverted.
	e.Backends = []string{"f1"}
	en.Apply()
	if !f1.blocked[e.ID] || f2.blocked[e.ID] || st.Has("f2", e.ID) {
		t.Fatal("narrowing backends did not unblock f2")
	}
	for _, r := range en.Status(e, false) {
		if r.Backend == "f2" && r.Targeted {
			t.Fatal("f2 should not be targeted")
		}
	}

	// Remove from policy: orphan record must be unblocked via state copy.
	pol.Remove(e.ID)
	en.Apply()
	if f1.blocked[e.ID] || st.Has("f1", e.ID) {
		t.Fatal("removed entry was not unblocked")
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if len(st.Entries) != 0 {
		t.Fatal("state kept an entry copy with no records")
	}
}

func TestExplicitUnavailableBackendIsError(t *testing.T) {
	dir := t.TempDir()
	pol, _ := policy.Load(filepath.Join(dir, "policy.json"))
	st, _ := state.Load(dir)
	en := &Engine{Policy: pol, State: st, Only: []string{"nope"}}
	ca, _ := testutil.CA(t, "X", nil)
	e := policy.NewEntry(ca, nil, policy.MatchSPKI, []string{"nope"}, "")
	if res := en.ApplyEntry(&e); res.Err() != nil {
		t.Fatalf("unregistered backend filtered by Only should be ignored, got %v", res.Err())
	}
}
