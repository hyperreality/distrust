package certs_test

import (
	"encoding/pem"
	"strings"
	"testing"

	"distrust/internal/certs"
	"distrust/internal/testutil"
)

func TestParseFormats(t *testing.T) {
	a, _ := testutil.CA(t, "A", nil)
	b, _ := testutil.CA(t, "B", nil)

	if got := certs.Parse(a.X.Raw); len(got) != 1 || got[0].SHA256 != a.SHA256 {
		t.Fatalf("DER: got %d certs", len(got))
	}
	bundle := "junk\n" + a.PEM() + "\n# comment\n" + b.PEM()
	if got := certs.Parse([]byte(bundle)); len(got) != 2 {
		t.Fatalf("bundle: got %d certs, want 2", len(got))
	}
	// OpenSSL TRUSTED CERTIFICATE = DER cert followed by aux trust data.
	aux := append(append([]byte{}, a.X.Raw...), 0x30, 0x03, 0x02, 0x01, 0x00)
	trusted := pem.EncodeToMemory(&pem.Block{Type: "TRUSTED CERTIFICATE", Bytes: aux})
	if got := certs.Parse(trusted); len(got) != 1 || got[0].SHA256 != a.SHA256 {
		t.Fatalf("TRUSTED CERTIFICATE: got %v", got)
	}
}

func TestBlocksIncludeCommentHeader(t *testing.T) {
	a, _ := testutil.CA(t, "A", nil)
	b, _ := testutil.CA(t, "B", nil)
	data := "# Issuer: A\n# Label: \"A\"\n" + a.PEM() + "\n# Issuer: B\n" + b.PEM()
	blocks := certs.Blocks([]byte(data))
	if len(blocks) != 2 {
		t.Fatalf("got %d blocks", len(blocks))
	}
	second := data[blocks[1].Start:blocks[1].End]
	if !strings.HasPrefix(second, "# Issuer: B\n-----BEGIN") || blocks[1].Cert.SHA256 != b.SHA256 {
		t.Fatalf("second block = %q", second[:30])
	}
	if blocks[0].Start != 0 {
		t.Fatalf("first block should start at its comment, got %d", blocks[0].Start)
	}
}

func TestNormalizeHex(t *testing.T) {
	h := strings.Repeat("AB", 32)
	for _, in := range []string{h, certs.Colon(h), "sha256/" + strings.ToLower(h), " " + h + " "} {
		got, err := certs.NormalizeHex(in)
		if err != nil || got != strings.ToLower(h) {
			t.Errorf("NormalizeHex(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := certs.NormalizeHex("abcd"); err == nil {
		t.Error("short fingerprint accepted")
	}
}

func TestSelfSignedAndVerify(t *testing.T) {
	a, _ := testutil.CA(t, "A", nil)
	b, _ := testutil.CA(t, "B", nil)
	if !certs.SelfSigned(a.X) {
		t.Fatal("root not detected as self-signed")
	}
	if err := certs.VerifyAgainst(a.X, certs.Pool([]*certs.Cert{a})); err != nil {
		t.Fatalf("root should verify against itself: %v", err)
	}
	if err := certs.VerifyAgainst(a.X, certs.Pool([]*certs.Cert{b})); err == nil {
		t.Fatal("root verified against unrelated pool")
	}
}
