// Command distrust blocklists CA certificates across every trust store on a
// host: NSS (Firefox/Thunderbird/Chromium), the OS store (OpenSSL, GnuTLS,
// curl...), Java keystores and standalone PEM bundles.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"

	"distrust/internal/backend"
	_ "distrust/internal/backend/all"
	"distrust/internal/engine"
	"distrust/internal/policy"
	"distrust/internal/state"
	"distrust/internal/sysx"
)

const usage = `distrust - block CA certificates in every trust store on this host

Usage:
  distrust block <cert.pem | --sha256 X | --from-url host:443> [--backends nss,system] [--dry-run]
  distrust unblock <id> [--dry-run]
  distrust list                      policy entries + per-backend state
  distrust status <id|cert.pem>      matrix: backend x trusted/distrusted/absent
  distrust apply [--policy file]     converge to policy (used by timer)
  distrust scan [--paths /opt,/usr]  find PEM bundles / cacerts / NSS DBs containing the cert
  distrust backends                  what was detected on this host
  distrust verify [id|cert.pem]      x509 chain check per store to confirm

Global flags (any position):
  --policy FILE     policy file (default /etc/distrust/policy.json as root,
                    ~/.config/distrust/policy.json otherwise)
  --state-dir DIR   state directory (default /var/lib/distrust as root)
  --json            machine readable output
  -v                verbose (per-location detail)

Run "distrust <command> -h" for command flags.
`

// exit codes
const (
	exitOK       = 0
	exitErr      = 1
	exitUsage    = 2
	exitNotClean = 3 // verify/status: something still trusts a blocked CA
)

type globals struct {
	policyPath string
	stateDir   string
	json       bool
	verbose    bool
	out        io.Writer
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(exitUsage)
	}
	cmd, args := splitCommand(os.Args[1:])
	cmds := map[string]func(*globals, []string) int{
		"block":    cmdBlock,
		"unblock":  cmdUnblock,
		"list":     cmdList,
		"status":   cmdStatus,
		"apply":    cmdApply,
		"scan":     cmdScan,
		"backends": cmdBackends,
		"verify":   cmdVerify,
	}
	switch cmd {
	case "-h", "--help", "help":
		fmt.Print(usage)
		os.Exit(exitOK)
	}
	f, ok := cmds[cmd]
	if !ok {
		fmt.Fprintf(os.Stderr, "distrust: unknown command %q\n\n%s", cmd, usage)
		os.Exit(exitUsage)
	}
	os.Exit(f(&globals{out: os.Stdout}, args))
}

// splitCommand finds the subcommand, letting global flags precede it
// ("distrust --policy x.json apply" == "distrust apply --policy x.json").
func splitCommand(args []string) (string, []string) {
	var pre []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") || a == "-h" || a == "--help" {
			rest := append(append([]string{}, args[i+1:]...), pre...)
			return a, rest
		}
		pre = append(pre, a)
		switch strings.TrimLeft(a, "-") {
		case "policy", "state-dir":
			if i+1 < len(args) {
				pre = append(pre, args[i+1])
				i++
			}
		}
	}
	return "help", nil
}

// newFlags builds a flag set with the global flags attached.
func newFlags(g *globals, name, synopsis string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	sys := sysx.IsAdmin()
	fs.StringVar(&g.policyPath, "policy", policy.DefaultPath(sys), "policy file")
	fs.StringVar(&g.stateDir, "state-dir", state.DefaultDir(sys), "state directory")
	fs.BoolVar(&g.json, "json", false, "JSON output")
	fs.BoolVar(&g.verbose, "v", false, "verbose")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: distrust %s %s\n\nFlags:\n", name, synopsis)
		fs.PrintDefaults()
	}
	return fs
}

// parse allows flags and positional arguments in any order.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		if args[0] == "--" {
			return append(pos, args[1:]...), nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "distrust:", err)
	return exitErr
}

// session loads policy + state, optionally under the state lock.
type session struct {
	g      *globals
	pol    *policy.Policy
	st     *state.State
	en     *engine.Engine
	unlock func()
}

func open(g *globals, lock bool) (*session, error) {
	s := &session{g: g, unlock: func() {}}
	if lock {
		u, err := sysx.Lock(filepath.Join(g.stateDir, "lock"))
		if err != nil {
			return nil, fmt.Errorf("lock state dir (need root?): %w", err)
		}
		s.unlock = u
	}
	var err error
	if s.pol, err = policy.Load(g.policyPath); err != nil {
		s.unlock()
		return nil, err
	}
	if s.st, err = state.Load(g.stateDir); err != nil {
		s.unlock()
		return nil, err
	}
	s.en = &engine.Engine{Policy: s.pol, State: s.st, Log: os.Stdout}
	return s, nil
}

func (s *session) save(policyToo bool) error {
	if policyToo {
		if err := s.pol.Save(); err != nil {
			return err
		}
	}
	return s.st.Save()
}

// findEntry resolves id in the policy, then among state entries pending unblock.
func (s *session) findEntry(id string) (*policy.Entry, bool, error) {
	if e, err := s.pol.Find(id); err == nil {
		return e, true, nil
	} else if !strings.HasPrefix(err.Error(), "no policy entry") {
		return nil, false, err
	}
	var orphans []policy.Entry
	for _, e := range s.st.Entries {
		orphans = append(orphans, e)
	}
	e, err := policy.FindIn(orphans, id)
	return e, false, err
}

func reportResult(r *engine.Result, verbose bool) int {
	for name, why := range r.Skipped {
		if verbose {
			fmt.Printf("[%s] skipped: %s\n", name, why)
		}
	}
	if err := r.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "distrust: errors:")
		for _, l := range strings.Split(err.Error(), "\n") {
			fmt.Fprintln(os.Stderr, "  "+l)
		}
		return exitErr
	}
	return exitOK
}

func cmdUnblock(g *globals, args []string) int {
	fs := newFlags(g, "unblock", "<id> [--dry-run]")
	dry := fs.Bool("dry-run", false, "show what would change")
	pos, err := parse(fs, args)
	if err != nil {
		return exitUsage
	}
	if len(pos) != 1 {
		fs.Usage()
		return exitUsage
	}
	s, err := open(g, !*dry)
	if err != nil {
		return fail(err)
	}
	defer s.unlock()
	e, _, err := s.findEntry(pos[0])
	if err != nil {
		return fail(err)
	}
	ecopy := *e
	s.en.DryRun = *dry
	fmt.Printf("Unblocking %s  %s\n", ecopy.ID, ecopy.Name())
	code := reportResult(s.en.Unblock(&ecopy), g.verbose)
	if *dry {
		return code
	}
	if code == exitOK {
		s.pol.Remove(ecopy.ID)
	} else {
		fmt.Fprintln(os.Stderr, "distrust: entry kept in policy; fix the errors and re-run unblock")
	}
	if err := s.save(true); err != nil {
		return fail(err)
	}
	return code
}

func cmdApply(g *globals, args []string) int {
	fs := newFlags(g, "apply", "[--policy file] [--dry-run] [--backends list]")
	dry := fs.Bool("dry-run", false, "show what would change")
	bl := fs.String("backends", "", "only these backends")
	quiet := fs.Bool("q", false, "only print changes and errors")
	if _, err := parse(fs, args); err != nil {
		return exitUsage
	}
	only, err := backend.ParseList(*bl)
	if err != nil {
		return fail(err)
	}
	s, err := open(g, !*dry)
	if err != nil {
		return fail(err)
	}
	defer s.unlock()
	s.en.DryRun, s.en.Only = *dry, only
	s.en.Checkpoint = s.st.Save
	s.en.Stopped = stopOnSignal()
	if !*quiet {
		fmt.Printf("Applying %s (%d entries)\n", s.pol.Path(), len(s.pol.Entries))
	}
	code := reportResult(s.en.Apply(), g.verbose)
	if !*dry {
		if err := s.st.Save(); err != nil {
			return fail(err)
		}
	}
	if code == exitOK && !*quiet {
		fmt.Println("Converged.")
	}
	return code
}

// stopOnSignal makes the first SIGINT/SIGTERM a request to stop after the
// current entry (whose undo records are then saved); a second one exits.
func stopOnSignal() func() bool {
	var stop atomic.Bool
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		stop.Store(true)
		fmt.Fprintln(os.Stderr, "\ndistrust: stopping after the current entry (interrupt again to abort now)")
		<-ch
		fmt.Fprintln(os.Stderr, "distrust: aborted; changes to the current entry may be missing from the state")
		os.Exit(130)
	}()
	return stop.Load
}

func cmdList(g *globals, args []string) int {
	fs := newFlags(g, "list", "")
	if _, err := parse(fs, args); err != nil {
		return exitUsage
	}
	s, err := open(g, false)
	if err != nil {
		return fail(err)
	}
	type item struct {
		policy.Entry
		Pending bool                     `json:"pending_unblock,omitempty"`
		State   map[string]backend.Trust `json:"state"`
	}
	var items []item
	var names []string
	for _, b := range backend.All() {
		if s.en.Detect()[b.Name()].Available {
			names = append(names, b.Name())
		}
	}
	add := func(e policy.Entry, pending bool) {
		it := item{Entry: e, Pending: pending, State: map[string]backend.Trust{}}
		for _, r := range s.en.Status(&e, false) {
			if r.Available {
				it.State[r.Backend] = r.Summary
			}
		}
		items = append(items, it)
	}
	for _, e := range s.pol.Entries {
		add(e, false)
	}
	for id, e := range s.st.Entries {
		if _, err := s.pol.Find(id); err != nil {
			add(e, true)
		}
	}
	if g.json {
		return printJSON(items)
	}
	if len(items) == 0 {
		fmt.Printf("No entries in %s\n", s.pol.Path())
		return exitOK
	}
	t := newTable("ID", "CA", "EXPIRES", "TARGET")
	for _, n := range names {
		t.cols = append(t.cols, strings.ToUpper(n))
	}
	for _, it := range items {
		target := "all"
		if len(it.Backends) > 0 {
			target = strings.Join(it.Backends, ",")
		}
		if it.Pending {
			target = "(pending unblock)"
		}
		row := []string{it.ID, truncate(it.Name(), 36), it.NotAfter.Format("2006-01-02"), target}
		for _, n := range names {
			cell := string(it.State[n])
			if !it.Targets(n) {
				cell = "-" + cell
			}
			row = append(row, colorTrust(cell))
		}
		t.add(row...)
	}
	t.print(os.Stdout)
	return exitOK
}

func cmdStatus(g *globals, args []string) int {
	return statusLike(g, args, false)
}

func cmdVerify(g *globals, args []string) int {
	return statusLike(g, args, true)
}

func statusLike(g *globals, args []string, verify bool) int {
	name, syn := "status", "<id | cert.pem> [--backends list]"
	if verify {
		name, syn = "verify", "[id | cert.pem] [--backends list] [--probe host:443]"
	}
	fs := newFlags(g, name, syn)
	bl := fs.String("backends", "", "only these backends")
	var probe *string
	if verify {
		probe = fs.String("probe", "", "host[:port] whose live chain is replayed to real clients (browsers) to observe their verdict")
	}
	pos, err := parse(fs, args)
	if err != nil {
		return exitUsage
	}
	if len(pos) > 1 || (!verify && len(pos) != 1) {
		fs.Usage()
		return exitUsage
	}
	only, err := backend.ParseList(*bl)
	if err != nil {
		return fail(err)
	}
	s, err := open(g, false)
	if err != nil {
		return fail(err)
	}
	s.en.Only = only
	if probe != nil {
		s.en.Probe = *probe
	}
	var entries []*policy.Entry
	adhoc := false
	if len(pos) == 1 {
		e, _, err := s.findEntry(pos[0])
		if err != nil {
			// Not an entry: allow inspecting a certificate file before blocking it.
			c, ferr := fromFile(pos[0], 0)
			if ferr != nil {
				return fail(err)
			}
			tmp := policy.NewEntry(c, s.en.Variants(c), policy.MatchSPKI, nil, "file:"+pos[0])
			e, adhoc = &tmp, true
		}
		entries = append(entries, e)
	} else {
		for i := range s.pol.Entries {
			entries = append(entries, &s.pol.Entries[i])
		}
		if len(entries) == 0 {
			fmt.Println("No entries in policy.")
			return exitOK
		}
	}
	type out struct {
		ID   string       `json:"id"`
		Name string       `json:"name"`
		Rows []engine.Row `json:"backends"`
	}
	var all []out
	code := exitOK
	for _, e := range entries {
		rows := s.en.Status(e, verify)
		for _, r := range rows {
			if r.Targeted && r.Summary == backend.Trusted && !adhoc {
				code = exitNotClean
			}
		}
		all = append(all, out{ID: e.ID, Name: e.Name(), Rows: rows})
	}
	if g.json {
		printJSON(all)
		return code
	}
	for i, o := range all {
		if i > 0 {
			fmt.Println()
		}
		printMatrix(entries[i], o.Rows, verify, g.verbose || verify)
	}
	if code == exitNotClean {
		fmt.Println("\nWARNING: at least one targeted store still trusts this CA (run `distrust apply`, then restart affected apps).")
	}
	return code
}

func printMatrix(e *policy.Entry, rows []engine.Row, verify, detail bool) {
	fmt.Printf("%s  %s\n", e.ID, e.Subject)
	fmt.Printf("  sha256 %s\n", e.SHA256)
	if n := len(e.Parsed()); n > 1 {
		fmt.Printf("  + %d same-key variant(s)\n", n-1)
	}
	fmt.Println()
	t := newTable("BACKEND", "STATE", "TRUSTED", "DISTRUSTED", "ABSENT", "OTHER", "")
	for _, r := range rows {
		if !r.Available {
			t.add(r.Backend, "n/a", "", "", "", "", "")
			continue
		}
		tr := backend.Count(r.Locations, backend.Trusted)
		di := backend.Count(r.Locations, backend.Distrusted)
		ab := backend.Count(r.Locations, backend.Absent)
		note := ""
		if !r.Targeted {
			note = "(not targeted)"
		}
		t.add(r.Backend, colorTrust(string(r.Summary)), strconv.Itoa(tr), strconv.Itoa(di), strconv.Itoa(ab),
			strconv.Itoa(len(r.Locations)-tr-di-ab), note)
	}
	t.print(os.Stdout)
	if !detail {
		return
	}
	fmt.Println()
	for _, r := range rows {
		for _, l := range r.Locations {
			line := fmt.Sprintf("  %-8s %-11s %s", r.Backend, colorTrust(string(l.Trust)), l.Location)
			if l.Detail != "" {
				line += "  — " + l.Detail
			}
			if verify && l.Method != "" {
				line += "  [" + l.Method + "]"
			}
			fmt.Println(line)
		}
	}
}

func cmdBackends(g *globals, args []string) int {
	fs := newFlags(g, "backends", "")
	if _, err := parse(fs, args); err != nil {
		return exitUsage
	}
	s, err := open(g, false)
	if err != nil {
		return fail(err)
	}
	det := s.en.Detect()
	if g.json {
		type item struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			backend.Detection
		}
		var items []item
		for _, b := range backend.All() {
			items = append(items, item{b.Name(), b.Description(), det[b.Name()]})
		}
		return printJSON(items)
	}
	scope := "user"
	if sysx.IsAdmin() {
		scope = "system (all users)"
	}
	fmt.Printf("Scope: %s   policy: %s   state: %s\n\n", scope, g.policyPath, g.stateDir)
	for _, b := range backend.All() {
		d := det[b.Name()]
		status := colorTrust("available")
		switch {
		case !d.Available:
			status = "unavailable"
		case !d.Writable:
			status = "read-only"
		}
		fmt.Printf("%-8s %-12s %s\n", b.Name(), status, b.Description())
		if d.Reason != "" {
			fmt.Printf("         reason: %s\n", d.Reason)
		}
		for _, t := range d.Tools {
			fmt.Printf("         tool:   %s\n", t)
		}
		for _, l := range d.Locations {
			line := fmt.Sprintf("         - %s  (%s)", l.Path, l.Kind)
			if l.Note != "" {
				line += "  " + l.Note
			}
			fmt.Println(line)
		}
		for _, n := range d.Notes {
			fmt.Printf("         note:   %s\n", n)
		}
		fmt.Println()
	}
	fmt.Println("Not manageable from here: programs with compiled-in roots (Node.js default store, some")
	fmt.Println("Electron/Rust apps). Use `distrust scan` to find standalone bundles they ship.")
	return exitOK
}

func truncate(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}
