package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"distrust/internal/backend/java"
	"distrust/internal/backend/nss"
	"distrust/internal/policy"
	"distrust/internal/scan"
)

func cmdScan(g *globals, args []string) int {
	fs := newFlags(g, "scan", "[--paths /opt,/usr] [--id ID] [--all] [--adopt | --adopt-all]")
	paths := fs.String("paths", "", "comma separated roots to scan (default: "+strings.Join(scan.DefaultPaths(), ",")+")")
	id := fs.String("id", "", "only report stores containing this entry")
	all := fs.Bool("all", false, "also list stores that contain no blocked CA")
	adopt := fs.Bool("adopt", false, "add unmanaged stores that contain a blocked CA to the policy")
	adoptAll := fs.Bool("adopt-all", false, "add every unmanaged store found to the policy")
	if _, err := parse(fs, args); err != nil {
		return exitUsage
	}
	s, err := open(g, *adopt || *adoptAll)
	if err != nil {
		return fail(err)
	}
	defer s.unlock()
	roots := scan.DefaultPaths()
	if *paths != "" {
		roots = strings.Split(*paths, ",")
	}
	entries := s.pol.Entries
	if *id != "" {
		e, err := s.pol.Find(*id)
		if err != nil {
			return fail(err)
		}
		entries = []policy.Entry{*e}
	}

	// Map every location a backend manages to that backend.
	type cover struct{ path, backend string }
	var covers []cover
	for name, d := range s.en.Detect() {
		for _, l := range d.Locations {
			p := l.Path
			if r, err := filepath.EvalSymlinks(p); err == nil {
				p = r
			}
			covers = append(covers, cover{p, name})
		}
	}
	managed := func(real string) string { // most specific location wins
		best, bestLen := "", -1
		for _, c := range covers {
			if (real == c.path || strings.HasPrefix(real, c.path+string(filepath.Separator))) && len(c.path) > bestLen {
				best, bestLen = c.backend, len(c.path)
			}
		}
		return best
	}

	fmt.Fprintf(os.Stderr, "Scanning %s ...\n", strings.Join(roots, ", "))
	found := scan.Run(scan.Options{
		Paths: roots, Skip: []string{g.stateDir}, Entries: entries, Managed: managed,
		ListKeystore: java.ListKeystore, ListNSS: nss.ListDB,
	})
	var shown []scan.Finding
	for _, f := range found {
		if *all || len(f.Matches) > 0 {
			shown = append(shown, f)
		}
	}
	if g.json {
		return printJSON(shown)
	}
	t := newTable("KIND", "CERTS", "CONTAINS", "MANAGED BY", "PATH")
	unmanagedHits := 0
	for _, f := range shown {
		m := f.Managed
		if m == "" {
			m = "-"
			if len(f.Matches) > 0 {
				m = colorTrust("UNMANAGED")
				unmanagedHits++
			}
		}
		n := strconv.Itoa(f.Certs)
		if f.Error != "" {
			n = "err"
		}
		t.add(f.Kind, n, strings.Join(f.Matches, ","), m, f.Path)
	}
	t.print(os.Stdout)
	fmt.Printf("\n%d trust stores found, %d shown", len(found), len(shown))
	if !*all {
		fmt.Print(" (containing blocked CAs; --all for every store)")
	}
	fmt.Println()

	if !*adopt && !*adoptAll {
		if unmanagedHits > 0 {
			fmt.Println("Unmanaged stores still contain blocked CAs: run `distrust scan --adopt` then `distrust apply`.")
		}
		return exitOK
	}
	added := 0
	for _, f := range found {
		if f.Managed != "" || (!*adoptAll && len(f.Matches) == 0) {
			continue
		}
		var ok bool
		switch f.Kind {
		case scan.KindBundle:
			ok = policy.AddPath(&s.pol.Bundles, f.Path)
		case scan.KindCert:
			// A lone CA file is usually passed explicitly (--cacert); emptying
			// it would break that consumer silently, so leave it to the admin.
			fmt.Printf("not adopting single CA file %s (remove it by hand if unwanted)\n", f.Path)
		case scan.KindKeystore:
			ok = f.Error == "" && policy.AddPath(&s.pol.Keystores, f.Path)
		case scan.KindNSS:
			ok = policy.AddPath(&s.pol.NSSDBs, f.Path)
		}
		if ok {
			fmt.Printf("adopted %s (%s)\n", f.Path, f.Kind)
			added++
		}
	}
	if added == 0 {
		fmt.Println("Nothing to adopt.")
		return exitOK
	}
	if err := s.pol.Save(); err != nil {
		return fail(err)
	}
	fmt.Printf("Added %d location(s) to %s; run `distrust apply` to enforce.\n", added, s.pol.Path())
	return exitOK
}
