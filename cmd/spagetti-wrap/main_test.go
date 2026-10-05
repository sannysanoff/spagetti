package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sannysanoff/spagetti/conf"
)

func TestGatewayEndpoint(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr string
	}{
		{in: defaultEndpoint, want: "wss://mux.san.systems/ws"},
		{in: "https://example.test/ws", want: "wss://example.test/ws"},
		{in: "http://127.0.0.1:18080/ws", want: "ws://127.0.0.1:18080/ws"},
		{in: "ws://127.0.0.1:18080/ws", want: "ws://127.0.0.1:18080/ws"},
		{in: "wss://example.test/ws", want: "wss://example.test/ws"},
		{in: "ftp://example.test/ws", wantErr: "is not one of http, https, ws, wss"},
		{in: "example.test/ws", wantErr: "is not one of http, https, ws, wss"},
		{in: "https:///ws", wantErr: "no host"},
	}
	for _, tc := range cases {
		got, err := gatewayEndpoint(tc.in)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("gatewayEndpoint(%q) err = %v, want %q", tc.in, err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("gatewayEndpoint(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("gatewayEndpoint(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseEnvFile(t *testing.T) {
	body := strings.Join([]string{
		"# a comment",
		"",
		"  spagetty_target = http://127.0.0.1:9000  ",
		"SPAGETTY_NAME=web1 # trailing comment",
		`SPAGETTY_TOKEN="tok with spaces" # and a comment`,
		"export SPAGETTY_PASSWORD='quoted'",
		"SPAGETTY_KEYS = /tmp/keys",
	}, "\n")
	vals, err := parseEnvFile(strings.NewReader(body), "test.env")
	if err != nil {
		t.Fatalf("parseEnvFile: %v", err)
	}
	want := map[string]string{
		"SPAGETTY_TARGET":   "http://127.0.0.1:9000",
		"SPAGETTY_NAME":     "web1",
		"SPAGETTY_TOKEN":    "tok with spaces",
		"SPAGETTY_PASSWORD": "quoted",
		"SPAGETTY_KEYS":     "/tmp/keys",
	}
	for k, v := range want {
		if got := vals[k].value; got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if vals["SPAGETTY_TARGET"].line != 3 {
		t.Errorf("line = %d, want 3", vals["SPAGETTY_TARGET"].line)
	}

	for _, bad := range []struct{ body, want string }{
		{"not a setting\n", "expected KEY=VALUE"},
		{`SPAGETTY_TOKEN="unterminated` + "\n", "unterminated"},
		{"=value\n", "empty key"},
	} {
		if _, err := parseEnvFile(strings.NewReader(bad.body), "test.env"); err == nil || !strings.Contains(err.Error(), bad.want) {
			t.Errorf("parseEnvFile(%q) err = %v, want %q", bad.body, err, bad.want)
		}
	}
}

func TestDecodePassword(t *testing.T) {
	pw := bytes.Repeat([]byte{7}, conf.PasswordLen)
	good := base64.RawURLEncoding.EncodeToString(pw)
	got, err := decodePassword(good)
	if err != nil || !bytes.Equal(got, pw) {
		t.Fatalf("decodePassword(%q) = %v, %v", good, got, err)
	}
	if _, err := decodePassword("c2hvcnQ"); err == nil || !strings.Contains(err.Error(), "want 32") {
		t.Errorf("a short password was accepted: %v", err)
	}
	if _, err := decodePassword("not base64!!"); err == nil {
		t.Error("a non-base64 password was accepted")
	}
}

func TestCheckName(t *testing.T) {
	for _, ok := range []string{"web1", "my.server-1", "A_b.c"} {
		if err := checkName(ok); err != nil {
			t.Errorf("checkName(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{"web 1", "web/1", "web\n", strings.Repeat("a", 129)} {
		if err := checkName(bad); err == nil {
			t.Errorf("checkName(%q) accepted a bad name", bad)
		}
	}
}

func TestLoadOrCreateIdentity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "keys")

	id, minted, err := loadOrCreateIdentity(path)
	if err != nil {
		t.Fatalf("minting: %v", err)
	}
	if !minted {
		t.Error("a missing cache file was not reported as minted")
	}
	if len(id.Priv) != conf.KeySize {
		t.Errorf("private key is %d bytes, want %d", len(id.Priv), conf.KeySize)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("cache file mode = %v (%v), want 0600", fi.Mode().Perm(), err)
	}

	again, minted, err := loadOrCreateIdentity(path)
	if err != nil {
		t.Fatalf("reloading: %v", err)
	}
	if minted {
		t.Error("an existing cache file was reported as minted")
	}
	if !bytes.Equal(id.Pub, again.Pub) {
		t.Error("the cached keypair did not come back")
	}

	// a public key file that disagrees must refuse rather than announce another
	// identity
	other, err := conf.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := conf.WritePub(path+pubSuffix, other.Pub); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadOrCreateIdentity(path); err == nil || !strings.Contains(err.Error(), "public key mismatch") {
		t.Errorf("a mismatched public key file was accepted: %v", err)
	}

	// a mangled cache file must refuse too
	if err := os.WriteFile(path, []byte("not hex\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadOrCreateIdentity(path); err == nil {
		t.Error("a mangled cache file was accepted")
	}
}

func TestUsageDocumentsEveryKey(t *testing.T) {
	for _, k := range knownKeys {
		if !strings.Contains(usage, k) {
			t.Errorf("-h does not document %s", k)
		}
	}
	if !strings.Contains(usage, defaultEndpoint) {
		t.Errorf("-h does not state the default endpoint %s", defaultEndpoint)
	}
}
