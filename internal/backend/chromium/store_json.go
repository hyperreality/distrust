//go:build !windows

package chromium

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"

	"distrust/internal/policy"
)

// OwnFile is the file this backend owns in each managed/ directory. It sorts
// after conventional names so our value wins over earlier files.
const OwnFile = "zz-distrust.json"

// jsonDir is Linux's /etc/.../policies/managed directory.
type jsonDir struct{ dir string }

func newStore(b *Browser) store {
	if b.PolicyDir == "" {
		return nil
	}
	return &jsonDir{dir: filepath.Join(b.PolicyDir, "managed")}
}

func (j *jsonDir) ID() string {
	if r, err := filepath.EvalSymlinks(j.dir); err == nil {
		return r
	}
	// Not created yet: resolve the base so /etc/chromium-browser -> /etc/chromium dedupes.
	if r, err := filepath.EvalSymlinks(filepath.Dir(filepath.Dir(j.dir))); err == nil {
		return filepath.Join(r, filepath.Base(filepath.Dir(j.dir)), "managed")
	}
	return j.dir
}

func (j *jsonDir) Path() string { return filepath.Join(j.dir, OwnFile) }

// Exists reports whether the browser's policy base directory exists.
func (j *jsonDir) Exists() bool {
	_, err := os.Stat(filepath.Dir(j.dir))
	return err == nil
}

// Read replays Chromium's ConfigDirPolicyLoader: every regular file in
// managed/, lexicographic order, last file setting the key wins.
func (j *jsonDir) Read() (effective, error) {
	var eff effective
	ents, err := os.ReadDir(j.dir)
	if errors.Is(err, os.ErrNotExist) {
		return eff, nil
	}
	if err != nil {
		return eff, err
	}
	var names []string
	for _, e := range ents {
		if e.Type().IsRegular() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, n := range names {
		data, err := os.ReadFile(filepath.Join(j.dir, n))
		if err != nil {
			continue
		}
		var doc map[string]json.RawMessage
		if lenientJSON(data, &doc) != nil {
			continue // Chromium skips unparsable files too
		}
		raw, ok := doc[PolicyKey]
		if n == OwnFile {
			eff.OursExists = true
		}
		if !ok {
			continue
		}
		var vals []string
		if json.Unmarshal(raw, &vals) != nil {
			continue
		}
		eff.Effective = vals
		switch {
		case n == OwnFile:
			eff.Ours = vals
		case n > OwnFile:
			eff.OverriddenBy = n
		default:
			eff.Foreign, eff.ForeignSource = vals, n
		}
	}
	return eff, nil
}

func (j *jsonDir) Write(values, _ []string) error {
	if err := os.MkdirAll(j.dir, 0o755); err != nil {
		return err
	}
	doc := map[string]any{PolicyKey: values}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	// Chromium reads every file in managed/, including temp files, so stage
	// the write in the parent directory and rename it into place.
	tmp := filepath.Join(filepath.Dir(j.dir), "."+OwnFile+".tmp")
	if err := policy.WriteFileAtomic(tmp, append(data, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, j.Path())
}

// Remove deletes our file; foreign values live in other files, so keep is unused.
func (j *jsonDir) Remove(keep []string) error {
	err := os.Remove(j.Path())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
