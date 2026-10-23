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
	admin   bool
}

func (f *fake) Name() string        { return f.name }
func (f *fake) Description() string { return "fake" }
func (f *fake) Detect(*backend.Env) backend.Detection {
	return backend.Detection{Available: true, Writable: true, NeedsAdmin: f.admin}
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

// An interrupted apply must leave undo records on disk for every entry it
// already enforced, so a later apply can revert them.
func TestApplyCheckpointsAndStops(t *testing.T) {
	f := &fake{name: "f3", blocked: map[string]bool{}}
	backend.Register(f)
	dir := t.TempDir()
	pol, _ := policy.Load(filepath.Join(dir, "policy.json"))
	st, _ := state.Load(filepath.Join(dir, "state"))
	for _, n := range []string{"A", "B", "C"} {
		ca, _ := testutil.CA(t, n, nil)
		pol.Upsert(policy.NewEntry(ca, nil, policy.MatchSPKI, nil, ""))
	}
	en := &Engine{Policy: pol, State: st, Only: []string{"f3"}, Checkpoint: st.Save}
	en.Stopped = func() bool { return f.calls == 2 }

	if err := en.Apply().Err(); err == nil {
		t.Fatal("stopped apply should report an error")
	}
	if f.calls != 2 {
		t.Fatalf("apply went on after the stop request: %d entries blocked", f.calls)
	}
	onDisk, _ := state.Load(filepath.Join(dir, "state"))
	if got := len(onDisk.IDs("f3")); got != 2 {
		t.Fatalf("state on disk has %d records, want 2", got)
	}

	// Emptying the policy reverts what the interrupted run did.
	pol.Entries = nil
	en = &Engine{Policy: pol, State: onDisk, Only: []string{"f3"}, Checkpoint: onDisk.Save}
	if err := en.Apply().Err(); err != nil {
		t.Fatal(err)
	}
	if len(f.blocked) != 0 || len(onDisk.IDs("f3")) != 0 {
		t.Fatalf("left blocked: %v", f.blocked)
	}
}

func TestAdminBackends(t *testing.T) {
	backend.Register(&fake{name: "fa", blocked: map[string]bool{}, admin: true})
	backend.Register(&fake{name: "fu", blocked: map[string]bool{}})
	en := &Engine{Policy: &policy.Policy{}, State: &state.State{}, Only: []string{"fa", "fu"}}
	if got := en.AdminBackends(func(string) bool { return true }); len(got) != 1 || got[0] != "fa" {
		t.Fatalf("AdminBackends = %v, want [fa]", got)
	}
	if got := en.AdminBackends(func(b string) bool { return b == "fu" }); len(got) != 0 {
		t.Fatalf("uninvolved admin backend reported: %v", got)
	}
}

// batcher counts finishing steps around an Apply.
type batcher struct {
	fake
	begun, ended int
}

func (b *batcher) Begin(*backend.Env)     { b.begun++ }
func (b *batcher) End(*backend.Env) error { b.ended++; return nil }

func TestApplyBatchesFinishingStep(t *testing.T) {
	b := &batcher{fake: fake{name: "fb", blocked: map[string]bool{}}}
	backend.Register(b)
	dir := t.TempDir()
	pol, _ := policy.Load(filepath.Join(dir, "policy.json"))
	st, _ := state.Load(filepath.Join(dir, "state"))
	for _, n := range []string{"A", "B", "C"} {
		ca, _ := testutil.CA(t, n, nil)
		pol.Upsert(policy.NewEntry(ca, nil, policy.MatchSPKI, nil, ""))
	}
	en := &Engine{Policy: pol, State: st, Only: []string{"fb"}}
	en.Apply()
	if b.calls != 3 || b.begun != 1 || b.ended != 1 {
		t.Fatalf("calls=%d begun=%d ended=%d, want 3/1/1", b.calls, b.begun, b.ended)
	}
	// End must also run when the apply is stopped early.
	pol.Entries = nil
	en.Stopped = func() bool { return true }
	en.Apply()
	if b.ended != 2 {
		t.Fatalf("End not run after a stopped apply (ended=%d)", b.ended)
	}
}
