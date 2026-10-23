package certs

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
)

// Block is one PEM certificate inside a bundle file, with the byte range it
// occupies (including directly preceding "#" comment lines, as used by certifi
// and the ca-certificates bundle) so it can be cut out without touching the
// rest of the file.
type Block struct {
	Cert       *Cert
	Start, End int
}

// Blocks locates every certificate PEM block in data.
func Blocks(data []byte) []Block {
	var out []Block
	begin := []byte("-----BEGIN ")
	off := 0
	for {
		i := bytes.Index(data[off:], begin)
		if i < 0 {
			return out
		}
		start := off + i
		b, rest := pem.Decode(data[start:])
		if b == nil {
			off = start + len(begin)
			continue
		}
		end := len(data) - len(rest)
		off = end
		if b.Type != "CERTIFICATE" && b.Type != "TRUSTED CERTIFICATE" {
			continue
		}
		der := b.Bytes
		if b.Type == "TRUSTED CERTIFICATE" {
			der = firstDER(der)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		out = append(out, Block{Cert: New(c), Start: commentStart(data, start), End: end})
	}
}

// commentStart walks back over "#" comment lines immediately above pos.
func commentStart(data []byte, pos int) int {
	for pos > 0 {
		lineEnd := pos - 1 // the '\n' ending the previous line
		if data[lineEnd] != '\n' {
			return pos
		}
		lineStart := bytes.LastIndexByte(data[:lineEnd], '\n') + 1
		line := bytes.TrimSpace(data[lineStart:lineEnd])
		if len(line) == 0 || line[0] != '#' {
			return pos
		}
		pos = lineStart
	}
	return pos
}
