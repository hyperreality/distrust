// Package certs holds certificate parsing, fingerprinting and fetching helpers
// shared by every backend.
package certs

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// Cert is a parsed certificate together with its identifying hashes.
type Cert struct {
	X      *x509.Certificate
	SHA256 string // hex sha256 of the DER encoding
	SPKI   string // hex sha256 of the SubjectPublicKeyInfo
}

// New wraps a parsed certificate.
func New(c *x509.Certificate) *Cert {
	d := sha256.Sum256(c.Raw)
	s := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return &Cert{X: c, SHA256: hex.EncodeToString(d[:]), SPKI: hex.EncodeToString(s[:])}
}

// PEM returns the PEM encoding of the certificate.
func (c *Cert) PEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.X.Raw}))
}

// Name is a short human readable name (CN, falling back to the full subject).
func (c *Cert) Name() string { return Name(c.X) }

// Name returns the CN of a certificate or its full subject when there is none.
func Name(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	if len(c.Subject.OrganizationalUnit) > 0 {
		return c.Subject.OrganizationalUnit[0]
	}
	return c.Subject.String()
}

// SelfSigned reports whether the certificate is a self-issued root.
func SelfSigned(c *x509.Certificate) bool {
	if !bytes.Equal(c.RawSubject, c.RawIssuer) {
		return false
	}
	return c.CheckSignatureFrom(c) == nil
}

// Parse decodes every certificate in data, which may be PEM (one or many
// blocks, including OpenSSL "TRUSTED CERTIFICATE" blocks) or a single DER cert.
// Certificates that fail to parse are skipped.
func Parse(data []byte) []*Cert {
	var out []*Cert
	if !bytes.Contains(data, []byte("-----BEGIN")) {
		if c, err := x509.ParseCertificate(data); err == nil {
			return []*Cert{New(c)}
		}
		return nil
	}
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		switch b.Type {
		case "CERTIFICATE", "X509 CERTIFICATE":
		case "TRUSTED CERTIFICATE":
			// DER cert followed by OpenSSL aux trust data; ParseCertificate
			// rejects trailing data so cut it at the cert's own length.
			b.Bytes = firstDER(b.Bytes)
		default:
			continue
		}
		if c, err := x509.ParseCertificate(b.Bytes); err == nil {
			out = append(out, New(c))
		}
	}
	return out
}

// firstDER returns the first complete ASN.1 element in b.
func firstDER(b []byte) []byte {
	if len(b) < 2 || b[0] != 0x30 {
		return b
	}
	l := int(b[1])
	hdr := 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 || len(b) < 2+n {
			return b
		}
		l = 0
		for _, x := range b[2 : 2+n] {
			l = l<<8 | int(x)
		}
		hdr += n
	}
	if hdr+l > len(b) {
		return b
	}
	return b[:hdr+l]
}

// ParseFile reads and parses a certificate file.
func ParseFile(path string) ([]*Cert, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cs := Parse(data)
	if len(cs) == 0 {
		return nil, fmt.Errorf("%s: no certificates found", path)
	}
	return cs, nil
}

// NormalizeHex lower-cases a fingerprint and strips separators.
func NormalizeHex(s string) (string, error) {
	r := strings.NewReplacer(":", "", " ", "", "-", "")
	s = strings.ToLower(r.Replace(strings.TrimSpace(s)))
	s = strings.TrimPrefix(s, "sha256/")
	if _, err := hex.DecodeString(s); err != nil || len(s) != 64 {
		return "", fmt.Errorf("%q is not a sha256 fingerprint (64 hex chars)", s)
	}
	return s, nil
}

// Colon formats a hex fingerprint as AA:BB:CC...
func Colon(h string) string {
	h = strings.ToUpper(h)
	var b strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i:min(i+2, len(h))])
	}
	return b.String()
}

// FetchChain connects to host:port and returns the certificate chain the
// server presents, without validating it.
func FetchChain(target string, timeout time.Duration) ([]*x509.Certificate, error) {
	target = strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	target = strings.SplitN(target, "/", 2)[0]
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host, port = target, "443"
	}
	d := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(host, port), &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // we want whatever is presented, trusted or not
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	chain := conn.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return nil, errors.New("server presented no certificates")
	}
	return chain, nil
}

// FindIssuer returns the first candidate that signed c.
func FindIssuer(c *x509.Certificate, candidates []*Cert) *Cert {
	for _, k := range candidates {
		if !bytes.Equal(k.X.RawSubject, c.RawIssuer) {
			continue
		}
		if len(c.AuthorityKeyId) > 0 && len(k.X.SubjectKeyId) > 0 && !bytes.Equal(c.AuthorityKeyId, k.X.SubjectKeyId) {
			continue
		}
		if c.CheckSignatureFrom(k.X) == nil {
			return k
		}
	}
	return nil
}

// Pool builds an x509.CertPool from certs.
func Pool(cs []*Cert) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range cs {
		p.AddCert(c.X)
	}
	return p
}

// VerifyAgainst checks whether c chains to (or is) a trust anchor in roots,
// the way a TLS client trusting exactly that root set would.
func VerifyAgainst(c *x509.Certificate, roots *x509.CertPool) error {
	_, err := c.Verify(x509.VerifyOptions{
		Roots:       roots,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime: verifyTime(c),
	})
	return err
}

// verifyTime picks a moment inside the validity window so that an expired CA
// still reports trust state rather than an expiry error.
func verifyTime(c *x509.Certificate) time.Time {
	now := time.Now()
	if now.After(c.NotAfter) || now.Before(c.NotBefore) {
		return c.NotBefore.Add(c.NotAfter.Sub(c.NotBefore) / 2)
	}
	return now
}
