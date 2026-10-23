package policy_test

import (
	"path/filepath"
	"testing"

	"distrust/internal/certs"
	"distrust/internal/policy"
	"distrust/internal/testutil"
)

func TestMatchModes(t *testing.T) {
	a, key := testutil.CA(t, "Root", nil)
	reissued, _ := testutil.CA(t, "Root", key) // same subject + key, new serial
	otherName, _ := testutil.CA(t, "Other", key)

	spki := policy.NewEntry(a, nil, policy.MatchSPKI, nil, "")
	if !spki.Matches(a) || !spki.Matches(reissued) {
		t.Error("spki entry should match the cert and its re-issue")
	}
	if spki.Matches(otherName) {
		t.Error("spki entry must not match a different subject with the same key")
	}
	exact := policy.NewEntry(a, nil, policy.MatchCert, nil, "")
	if exact.Matches(reissued) {
		t.Error("cert entry must only match the exact certificate")
	}
	withVariant := policy.NewEntry(a, []*certs.Cert{reissued}, policy.MatchCert, nil, "")
	if !withVariant.Matches(reissued) {
		t.Error("explicit variants are always matched")
	}
}

func TestSaveLoadFind(t *testing.T) {
	a, _ := testutil.CA(t, "A", nil)
	b, _ := testutil.CA(t, "B", nil)
	path := filepath.Join(t.TempDir(), "sub", "policy.json")
	p, err := policy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	p.Upsert(policy.NewEntry(a, nil, policy.MatchSPKI, []string{"nss"}, "test"))
	p.Upsert(policy.NewEntry(b, nil, policy.MatchSPKI, nil, "test"))
	if err := p.Save(); err != nil {
		t.Fatal(err)
	}
	q, err := policy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	e, err := q.Find(a.SHA256[:6])
	if err != nil || e.SHA256 != a.SHA256 || !e.Targets("nss") || e.Targets("system") {
		t.Fatalf("Find: %v %+v", err, e)
	}
	if e.Primary() == nil || e.Primary().SHA256 != a.SHA256 {
		t.Fatal("PEM did not round-trip")
	}
	if _, err := q.Find(""); err == nil {
		t.Fatal("empty id should not match")
	}
	q.Remove(e.ID)
	if len(q.Entries) != 1 {
		t.Fatalf("Remove left %d entries", len(q.Entries))
	}
}
