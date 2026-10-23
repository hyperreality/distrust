package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"distrust/internal/backend"
	"distrust/internal/certs"
	"distrust/internal/policy"
)

func cmdBlock(g *globals, args []string) int {
	fs := newFlags(g, "block", "<cert.pem | --sha256 X | --from-url host:443> [--backends nss,system] [--dry-run]")
	sha := fs.String("sha256", "", "fingerprint (cert or SPKI sha256) of a CA already present in a local store")
	url := fs.String("from-url", "", "fetch the chain from host[:port] and block its root")
	pick := fs.String("pick", "root", "with --from-url: \"root\", or the chain index to block")
	index := fs.Int("index", -1, "with a multi-cert file: which certificate to block")
	bl := fs.String("backends", "", "comma separated backends (default: all available)")
	match := fs.String("match", policy.MatchSPKI, "\"spki\" also blocks re-issued/cross-signed certs with the same subject+key; \"cert\" blocks only this exact cert")
	dry := fs.Bool("dry-run", false, "show what would change without changing anything")
	comment := fs.String("comment", "", "note stored with the entry")
	force := fs.Bool("force", false, "allow blocking a certificate that is not a CA")
	pos, err := parse(fs, args)
	if err != nil {
		return exitUsage
	}
	sources := 0
	for _, set := range []bool{len(pos) > 0, *sha != "", *url != ""} {
		if set {
			sources++
		}
	}
	if sources != 1 || len(pos) > 1 {
		fs.Usage()
		return exitUsage
	}
	if *match != policy.MatchSPKI && *match != policy.MatchCert {
		return fail(fmt.Errorf("--match must be spki or cert"))
	}
	backends, err := backend.ParseList(*bl)
	if err != nil {
		return fail(err)
	}
	s, err := open(g, !*dry)
	if err != nil {
		return fail(err)
	}
	defer s.unlock()

	var primary *certs.Cert
	var source string
	switch {
	case len(pos) == 1:
		primary, err = fromFile(pos[0], *index)
		source = "file:" + pos[0]
	case *sha != "":
		primary, err = s.fromSHA(*sha)
		source = "sha256:" + *sha
	default:
		primary, err = s.fromURL(*url, *pick)
		source = "url:" + *url
	}
	if err != nil {
		return fail(err)
	}
	if !primary.X.IsCA && !*force {
		return fail(fmt.Errorf("%q is not a CA certificate (basicConstraints CA:FALSE); use --force to block it anyway", primary.Name()))
	}
	var variants []*certs.Cert
	if *match == policy.MatchSPKI {
		variants = s.en.Variants(primary)
	}
	e := policy.NewEntry(primary, variants, *match, backends, source)
	e.Comment = *comment

	fmt.Printf("Blocking %s\n", e.ID)
	fmt.Printf("  subject  %s\n", primary.X.Subject)
	fmt.Printf("  issuer   %s\n", primary.X.Issuer)
	fmt.Printf("  valid    %s .. %s\n", primary.X.NotBefore.Format("2006-01-02"), primary.X.NotAfter.Format("2006-01-02"))
	fmt.Printf("  sha256   %s\n", certs.Colon(primary.SHA256))
	fmt.Printf("  spki     %s\n", primary.SPKI)
	if !certs.SelfSigned(primary.X) {
		fmt.Println("  note     not a self-signed root: flat-bundle stores (system/java/bundle) can only drop roots")
	}
	for _, v := range variants {
		fmt.Printf("  variant  %s (same subject+key, %s..%s)\n", v.SHA256[:12], v.X.NotBefore.Format("2006"), v.X.NotAfter.Format("2006"))
	}
	if len(backends) > 0 {
		fmt.Printf("  backends %v\n", backends)
	}
	fmt.Println()

	s.en.DryRun = *dry
	stored := &e
	if !*dry {
		stored = s.pol.Upsert(e)
		if err := s.pol.Save(); err != nil {
			return fail(err)
		}
	}
	code := reportResult(s.en.ApplyEntry(stored), true)
	if *dry {
		return code
	}
	if err := s.st.Save(); err != nil {
		return fail(err)
	}
	fmt.Println()
	printMatrix(stored, s.en.Status(stored, false), false, g.verbose)
	fmt.Printf("\nRecorded in %s. Restart running browsers; check with `distrust verify %s`.\n", s.pol.Path(), stored.ID)
	if *url != "" && stored.Targets("chromium") {
		fmt.Printf("Browsers may anchor below the root (e.g. at an intermediate in their root store); confirm with\n  distrust verify %s --probe %s\n", stored.ID, *url)
	}
	return code
}

func fromFile(path string, index int) (*certs.Cert, error) {
	cs, err := certs.ParseFile(path)
	if err != nil {
		return nil, err
	}
	if len(cs) == 1 {
		return cs[0], nil
	}
	if index >= 0 && index < len(cs) {
		return cs[index], nil
	}
	msg := fmt.Sprintf("%s contains %d certificates; choose one with --index:\n", path, len(cs))
	for i, c := range cs {
		msg += fmt.Sprintf("  %d  %s  %s\n", i, c.SHA256[:12], c.X.Subject)
	}
	return nil, errors.New(msg)
}

func (s *session) fromSHA(h string) (*certs.Cert, error) {
	h, err := certs.NormalizeHex(h)
	if err != nil {
		return nil, err
	}
	hits := s.en.FindBySHA256(h)
	if len(hits) == 0 {
		return nil, fmt.Errorf("no certificate with sha256 %s found in any local store; pass the PEM file or use --from-url", h[:16]+"…")
	}
	for _, c := range hits { // prefer the exact cert over SPKI matches
		if c.SHA256 == h {
			return c, nil
		}
	}
	return hits[0], nil
}

func (s *session) fromURL(target, pick string) (*certs.Cert, error) {
	chain, err := certs.FetchChain(target, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", target, err)
	}
	fmt.Printf("Chain presented by %s:\n", target)
	for i, c := range chain {
		fmt.Printf("  [%d] %s\n", i, c.Subject)
	}
	if pick != "root" {
		i, err := strconv.Atoi(pick)
		if err != nil || i < 0 || i >= len(chain) {
			return nil, fmt.Errorf("--pick must be \"root\" or an index 0..%d", len(chain)-1)
		}
		return certs.New(chain[i]), nil
	}
	top := chain[len(chain)-1]
	if certs.SelfSigned(top) {
		fmt.Printf("  -> root is [%d] (sent by server)\n\n", len(chain)-1)
		return certs.New(top), nil
	}
	// Servers normally omit the root; find it among local stores.
	known := s.en.KnownCerts()
	var root *x509.Certificate
	for cur, hops := top, 0; hops < 5; hops++ {
		iss := certs.FindIssuer(cur, known)
		if iss == nil {
			break
		}
		root = iss.X
		if certs.SelfSigned(iss.X) {
			break
		}
		cur = iss.X
	}
	if root == nil {
		fmt.Fprintf(os.Stderr, "  warning: issuer of [%d] not found locally; blocking [%d] instead\n\n", len(chain)-1, len(chain)-1)
		return certs.New(top), nil
	}
	fmt.Printf("  -> root (from local store): %s\n\n", root.Subject)
	return certs.New(root), nil
}
