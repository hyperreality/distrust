package java

import (
	"bytes"
	"encoding/binary"
	"testing"

	"distrust/internal/testutil"
)

// writeJKS builds a minimal JKS v2 keystore of trusted cert entries.
func writeJKS(certs map[string][]byte) []byte {
	var b bytes.Buffer
	w := func(v any) { _ = binary.Write(&b, binary.BigEndian, v) }
	utf := func(s string) { w(uint16(len(s))); b.WriteString(s) }
	w(uint32(0xFEEDFEED))
	w(uint32(2))
	w(uint32(len(certs)))
	for alias, der := range certs {
		w(uint32(2))
		utf(alias)
		w(int64(0))
		utf("X.509")
		w(uint32(len(der)))
		b.Write(der)
	}
	b.Write(make([]byte, 20)) // SHA-1 integrity digest, not checked
	return b.Bytes()
}

func TestParseJKS(t *testing.T) {
	a, _ := testutil.CA(t, "A", nil)
	b, _ := testutil.CA(t, "B", nil)
	es, err := parseJKS(writeJKS(map[string][]byte{"a": a.X.Raw, "b": b.X.Raw}))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range es {
		got[e.Alias] = e.Cert.SHA256
	}
	if got["a"] != a.SHA256 || got["b"] != b.SHA256 {
		t.Fatalf("parsed %v", got)
	}
	if _, err := parseJKS([]byte("PK\x03\x04 not a keystore")); err != errNotJKS {
		t.Fatalf("want errNotJKS, got %v", err)
	}
}
