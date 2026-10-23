package chromium

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"distrust/internal/backend"
	"distrust/internal/certs"
	"distrust/internal/policy"
	"distrust/internal/sysx"
)

// The verifier reads what the browser itself did, from its net-log:
//
//   - CERT_VERIFY_PROC_ADDITIONAL_CERT events list the SPKIs loaded from
//     CADistrustedCertificates into the certificate verifier, which proves the
//     policy reached the verifier (not just chrome://policy).
//   - With --probe, the server's real chain is replayed from a local TLS
//     server holding a random key of the leaf's type. Chromium (BoringSSL)
//     verifies the chain before it checks CertificateVerify, so its verdict
//     and the path it built (including the anchor) are logged even though the
//     handshake then fails. The browser is pointed at the replay server with
//     --host-resolver-rules, so no real traffic reaches the host.

const probeHost = "distrust-probe.invalid"

type probeResult struct {
	err       string
	verified  bool                // the browser verified a cert for the target host
	loaded    map[string]bool     // SPKI (base64 DER) loaded as distrusted
	accepted  bool                // target chain accepted
	anchor    string              // anchor subject of the accepted path
	pathSPKIs []map[string]string // per valid path: SPKI hash -> subject
	rejectWhy string
	mode      string
}

func (c *Chromium) Verify(env *backend.Env, e *policy.Entry) []backend.LocState {
	var out []backend.LocState
	var chain [][]byte
	host := ""
	if env.Probe != "" {
		var err error
		host, chain, err = fetchChain(env.Probe)
		if err != nil {
			return []backend.LocState{{Location: env.Probe, Trust: backend.Error, Detail: "probe: " + err.Error()}}
		}
	}
	for _, l := range c.locations() {
		for i, b := range l.browsers {
			bin := l.bins[i]
			if bin == "" {
				continue
			}
			ls := backend.LocState{Location: fmt.Sprintf("%s [%s]", l.store.Path(), b.Name)}
			r := c.runProbe(bin, host, chain)
			ls.Method = "net-log of " + filepath.Base(bin) + " (" + r.mode + ")"
			ls.Trust, ls.Detail = judge(e, r, host)
			out = append(out, ls)
		}
	}
	if len(out) == 0 {
		out = append(out, backend.LocState{Location: "-", Trust: backend.Unknown, Detail: "no browser executable to run"})
	}
	return out
}

// judge turns a probe result into a trust verdict for e.
func judge(e *policy.Entry, r *probeResult, host string) (backend.Trust, string) {
	if r.err != "" {
		return backend.Unknown, r.err
	}
	if !r.verified {
		return backend.Unknown, "browser performed no certificate verification (did not start or navigate)"
	}
	want := entrySPKIs(e)
	missing := 0
	for _, k := range want {
		if !r.loaded[k] {
			missing++
		}
	}
	loadMsg := "distrusted key loaded into the certificate verifier"
	if missing > 0 {
		loadMsg = fmt.Sprintf("%d of %d key(s) NOT loaded into the certificate verifier", missing, len(want))
	}
	if host == "" {
		if missing > 0 {
			return backend.Trusted, loadMsg
		}
		return backend.Distrusted, loadMsg
	}
	if !r.accepted {
		return backend.Distrusted, fmt.Sprintf("%s: chain from %s rejected (%s)", loadMsg, host, r.rejectWhy)
	}
	onPath := false
	for _, p := range r.pathSPKIs {
		for _, c := range e.Parsed() {
			if _, ok := p[c.SPKI]; ok {
				onPath = true
			}
		}
	}
	msg := fmt.Sprintf("%s, but chain from %s ACCEPTED via anchor %q", loadMsg, host, r.anchor)
	if !onPath {
		msg += "; this CA's key is not on that path: block the anchor/intermediate the browser used"
	}
	return backend.Trusted, msg
}

func entrySPKIs(e *policy.Entry) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range e.Parsed() {
		k := base64.StdEncoding.EncodeToString(c.X.RawSubjectPublicKeyInfo)
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}

func fetchChain(target string) (string, [][]byte, error) {
	chain, err := certs.FetchChain(target, 10*time.Second)
	if err != nil {
		return "", nil, err
	}
	host := strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	host = strings.SplitN(host, "/", 2)[0]
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	var ders [][]byte
	for _, c := range chain {
		ders = append(ders, c.Raw)
	}
	return host, ders, nil
}

// runProbe starts a replay server, runs the browser against it and parses
// the net-log. With no chain, a throwaway self-signed cert is served: any
// verification creates the verifier and logs the loaded policy SPKIs.
func (c *Chromium) runProbe(bin, host string, chain [][]byte) *probeResult {
	r := &probeResult{loaded: map[string]bool{}}
	if host == "" {
		host = probeHost
		chain = [][]byte{selfSigned(host)}
	}
	ln, err := replayServer(chain)
	if err != nil {
		r.err = err.Error()
		return r
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	dir, err := os.MkdirTemp("", "distrust-chromium-*")
	if err != nil {
		r.err = err.Error()
		return r
	}
	defer os.RemoveAll(dir)
	uid, gid, asUser := sysx.InvokingUser()
	if asUser {
		_ = os.Chown(dir, uid, gid)
	}
	netlog := filepath.Join(dir, "netlog.json")
	debugPort := freePort()
	args := []string{
		"--no-first-run", "--no-default-browser-check", "--password-store=basic", "--use-mock-keychain",
		"--disable-sync", "--disable-extensions", "--disable-component-update", "--disable-background-networking",
		"--user-data-dir=" + filepath.Join(dir, "profile"),
		"--log-net-log=" + netlog,
		fmt.Sprintf("--remote-debugging-port=%d", debugPort),
		fmt.Sprintf("--host-resolver-rules=MAP %s 127.0.0.1:%d", host, port),
	}
	if sysx.IsAdmin() && !asUser {
		args = append(args, "--no-sandbox") // Chromium refuses to run as root otherwise
	}
	env := []string{"HOME=" + dir}
	stopX := func() {}
	r.mode = "headless"
	if d, stop := startXvfb(dir); d != "" {
		env = append(env, "DISPLAY="+d)
		stopX, r.mode = stop, "xvfb"
	} else {
		args = append(args, "--headless=new")
	}
	defer stopX()
	cmd, err := sysx.Start(sysx.Cmd{Name: bin, Args: append(args, "about:blank"), Env: env, As: asDir(dir, asUser)})
	if err != nil {
		r.err = err.Error()
		return r
	}
	defer func() {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			<-done
		}
		parseNetLog(netlog, host, r)
	}()
	base := fmt.Sprintf("http://127.0.0.1:%d", debugPort)
	if !waitHTTP(base+"/json/version", 20*time.Second) {
		r.err = "browser did not expose DevTools (failed to start?)"
		return r
	}
	req, _ := http.NewRequest(http.MethodPut, base+"/json/new?"+url.QueryEscape("https://"+host+"/"), nil)
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
	}
	// Wait for the verification to show up in the log, then a little more
	// so the result event is flushed.
	deadline := time.Now().Add(15 * time.Second)
	needle := []byte(`"host":"` + host + `"`)
	for time.Now().Before(deadline) {
		if data, _ := os.ReadFile(netlog); bytes.Contains(data, needle) && bytes.Contains(data, []byte(`"cert_status"`)) {
			time.Sleep(2 * time.Second)
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	return r
}

func asDir(dir string, asUser bool) string {
	if asUser {
		return dir
	}
	return ""
}

func waitHTTP(u string, d time.Duration) bool {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if resp, err := http.Get(u); err == nil {
			resp.Body.Close()
			return true
		}
		time.Sleep(300 * time.Millisecond)
	}
	return false
}

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 9339
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// startXvfb runs a private X server when available (some vendors, e.g.
// Vivaldi and Brave, do not navigate in headless mode).
func startXvfb(dir string) (string, func()) {
	if runtime.GOOS != "linux" {
		return "", nil
	}
	xvfb := sysx.LookPath("Xvfb", "/usr/bin")
	if xvfb == "" {
		return "", nil
	}
	for n := 140; n < 200; n++ {
		if sysx.Exists(fmt.Sprintf("/tmp/.X11-unix/X%d", n)) || sysx.Exists(fmt.Sprintf("/tmp/.X%d-lock", n)) {
			continue
		}
		uid, _, asUser := sysx.InvokingUser()
		_ = uid
		cmd, err := sysx.Start(sysx.Cmd{Name: xvfb, Args: []string{fmt.Sprintf(":%d", n), "-nolisten", "tcp", "-screen", "0", "1280x800x24"}, As: asDir(dir, asUser)})
		if err != nil {
			return "", nil
		}
		for i := 0; i < 20 && !sysx.Exists(fmt.Sprintf("/tmp/.X11-unix/X%d", n)); i++ {
			time.Sleep(100 * time.Millisecond)
		}
		return fmt.Sprintf(":%d", n), func() { cmd.Process.Kill(); cmd.Wait() }
	}
	return "", nil
}

// replayServer serves chain with a random key of the leaf's key type.
func replayServer(chain [][]byte) (net.Listener, error) {
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, err
	}
	var key crypto.Signer
	switch pk := leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		key, err = ecdsa.GenerateKey(pk.Curve, rand.Reader)
	case *rsa.PublicKey:
		key, err = rsa.GenerateKey(rand.Reader, pk.N.BitLen())
	default:
		return nil, fmt.Errorf("unsupported leaf key type %T", pk)
	}
	if err != nil {
		return nil, err
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: key}},
		MinVersion:   tls.VersionTLS13, // verification precedes CertificateVerify
	})
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				_ = conn.(*tls.Conn).Handshake()
				conn.Close()
			}()
		}
	}()
	return ln, nil
}

func selfSigned(host string) []byte {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	return der
}

var typeRE = regexp.MustCompile(`"type":(\d+)\},?$`)

// parseNetLog reads a (possibly truncated) net-log: constants on the first
// line, then one event per line.
func parseNetLog(path, host string, r *probeResult) {
	f, err := os.Open(path)
	if err != nil {
		if r.err == "" {
			r.err = "no net-log written"
		}
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	types := map[int]string{}
	type ev struct {
		Params json.RawMessage `json:"params"`
		Phase  int             `json:"phase"`
		Source struct {
			ID int `json:"id"`
		} `json:"source"`
		Type int `json:"type"`
	}
	sources := map[int]bool{}
	var pending []ev
	first := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if first {
			first = false
			var hdr struct {
				Constants struct {
					LogEventTypes map[string]int `json:"logEventTypes"`
				} `json:"constants"`
			}
			if json.Unmarshal([]byte(strings.TrimSuffix(line, ",")+"}"), &hdr) == nil || json.Unmarshal([]byte(line), &hdr) == nil {
				for k, v := range hdr.Constants.LogEventTypes {
					types[v] = k
				}
			}
			continue
		}
		line = strings.TrimPrefix(line, `"events": [`)
		line = strings.TrimSuffix(strings.TrimSuffix(line, "]}"), ",")
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var e ev
		if json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		switch types[e.Type] {
		case "CERT_VERIFY_PROC_ADDITIONAL_CERT":
			var p struct{ SPKI, Trust string }
			if json.Unmarshal(e.Params, &p) == nil && p.Trust == "DISTRUSTED" && p.SPKI != "" {
				r.loaded[p.SPKI] = true
			}
		case "CERT_VERIFY_PROC":
			var p struct {
				Host       string `json:"host"`
				CertStatus *int   `json:"cert_status"`
			}
			_ = json.Unmarshal(e.Params, &p)
			if e.Phase == 1 && p.Host == host {
				sources[e.Source.ID] = true
			}
			if e.Phase == 2 && sources[e.Source.ID] && p.CertStatus != nil {
				r.verified = true
				r.accepted = *p.CertStatus&(4|128) == 0 // AUTHORITY_INVALID | INVALID
			}
		case "CERT_VERIFY_PROC_PATH_BUILT":
			if e.Phase == 2 {
				pending = append(pending, e)
			}
		}
	}
	for _, e := range pending {
		if !sources[e.Source.ID] {
			continue
		}
		var p struct {
			Certificates []string `json:"certificates"`
			IsValid      bool     `json:"is_valid"`
			Errors       string   `json:"errors"`
		}
		if json.Unmarshal(e.Params, &p) != nil {
			continue
		}
		if p.IsValid {
			m := map[string]string{}
			for _, pemText := range p.Certificates {
				for _, c := range certs.Parse([]byte(pemText)) {
					m[c.SPKI] = c.X.Subject.String()
					r.anchor = c.X.Subject.String()
				}
			}
			r.pathSPKIs = append(r.pathSPKIs, m)
		} else if r.rejectWhy == "" && p.Errors != "" {
			r.rejectWhy = summarizeErrors(p.Errors)
		}
	}
	if r.rejectWhy == "" {
		r.rejectWhy = "no valid path"
	}
}

// summarizeErrors condenses a path builder error dump to "ERROR at subject".
func summarizeErrors(s string) string {
	subj, msg := "", ""
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "----- Certificate") {
			if i := strings.Index(l, "("); i > 0 {
				subj = strings.TrimSuffix(strings.TrimSuffix(l[i+1:], " -----"), ")")
			}
		}
		if strings.HasPrefix(l, "ERROR: ") && msg == "" {
			msg = strings.TrimPrefix(l, "ERROR: ")
			break
		}
	}
	if subj != "" {
		return msg + " at " + subj
	}
	return msg
}
