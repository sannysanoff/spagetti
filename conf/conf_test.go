package conf

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/flynn/noise"
)

func TestDirHonoursEnv(t *testing.T) {
	t.Setenv("SPAGETTI_CONF_DIR", "/tmp/spagetti-test-dir")
	if got := Dir(); got != "/tmp/spagetti-test-dir" {
		t.Fatalf("Dir() = %q", got)
	}
}

func TestIdentityMatchesNoiseKeypair(t *testing.T) {
	// The identity layer and the Noise layer must agree on what a keypair is.
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
	kp, err := cs.GenerateKeypair(nil)
	if err != nil {
		t.Fatal(err)
	}
	id, err := IdentityFromPrivate(kp.Private)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(id.Pub, kp.Public) {
		t.Fatal("public key derived from the private key does not match noise's")
	}
	if len(id.Priv) != KeySize || len(id.Pub) != KeySize {
		t.Fatalf("unexpected key sizes: %d %d", len(id.Priv), len(id.Pub))
	}
	if _, err := IdentityFromPrivate([]byte("short")); err == nil {
		t.Fatal("a short private key was accepted")
	}
}

func TestFingerprintIsStableAndKeyed(t *testing.T) {
	a, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if a.Fingerprint() != a.ID() || !strings.HasPrefix(a.Fingerprint(), "spg1:") {
		t.Fatalf("unexpected fingerprint %q", a.Fingerprint())
	}
	if a.Fingerprint() == b.Fingerprint() {
		t.Fatal("two keypairs share a fingerprint")
	}
}

func TestServerDirCannotEscapeBase(t *testing.T) {
	base := "/base"
	got := ServerDir(base, "../../etc")
	if !strings.HasPrefix(got, base+string(filepath.Separator)) {
		t.Fatalf("ServerDir escaped its base: %q", got)
	}
	if got := ServerDir(base, ""); !strings.HasPrefix(got, base+string(filepath.Separator)) {
		t.Fatalf("empty id produced %q", got)
	}
}

func TestServerFirstRunGeneratesAndPersists(t *testing.T) {
	dir := t.TempDir()
	files, err := EnsureServer(dir, "web1")
	if err != nil {
		t.Fatal(err)
	}
	if !files.Created {
		t.Fatal("first run did not report generation")
	}
	if len(files.Password) != PasswordLen {
		t.Fatalf("password is %d bytes", len(files.Password))
	}
	for path, want := range map[string]os.FileMode{
		files.KeyFile:      0o600,
		files.PasswordFile: 0o600,
		files.PubFile:      0o644,
	} {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if st.Mode().Perm() != want {
			t.Fatalf("%s has mode %v, want %v", path, st.Mode().Perm(), want)
		}
	}
	// The generated files must be loadable back, and a second run must not
	// regenerate anything.
	again, err := EnsureServer(dir, "web1")
	if err != nil {
		t.Fatal(err)
	}
	if again.Created {
		t.Fatal("second run regenerated the identity")
	}
	if !bytes.Equal(again.Identity.Priv, files.Identity.Priv) || !bytes.Equal(again.Password, files.Password) {
		t.Fatal("second run produced different material")
	}
}

func TestServerPartialStateIsRefused(t *testing.T) {
	dir := t.TempDir()
	files, err := EnsureServer(dir, "web1")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(files.PubFile); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureServer(dir, "web1"); err == nil {
		t.Fatal("a partial enrolment was silently repaired")
	} else if !strings.Contains(err.Error(), "partial state") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

func TestTamperedPublicKeyIsDetected(t *testing.T) {
	dir := t.TempDir()
	files, err := EnsureServer(dir, "web1")
	if err != nil {
		t.Fatal(err)
	}
	other, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := WritePub(files.PubFile, other.Pub); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentity(files.Dir); err == nil {
		t.Fatal("a public key that does not match the private key was accepted")
	}
}

func TestPasswordFileValidation(t *testing.T) {
	dir := t.TempDir()
	pw, err := GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, PasswordFile)
	if err := WritePassword(path, pw); err != nil {
		t.Fatal(err)
	}
	got, err := LoadPassword(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pw) {
		t.Fatal("password round trip changed the value")
	}
	// Comments and blank lines are tolerated; a wrong length is not.
	if err := os.WriteFile(path, []byte("# header\n\n"+base64Of(pw[:16])+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPassword(path); err == nil {
		t.Fatal("a short password was accepted")
	}
	if err := os.WriteFile(path, []byte("# only a comment\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPassword(path); err == nil {
		t.Fatal("a password file with no value was accepted")
	}
}

func TestPeerRoundTrip(t *testing.T) {
	base := t.TempDir()
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pw, err := GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := SavePeer(base, "web1", id.Pub, pw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(peer.PubKey, id.Pub) || !bytes.Equal(peer.Password, pw) {
		t.Fatal("pinned material changed")
	}
	back, err := LoadPeer(base, "web1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back.PubKey, id.Pub) || !bytes.Equal(back.Password, pw) {
		t.Fatal("loaded pin differs from the saved one")
	}
	if _, err := LoadPeer(base, "absent"); err == nil {
		t.Fatal("a missing pin was not reported")
	} else if !strings.Contains(err.Error(), "identity.pub") && !strings.Contains(err.Error(), "access.password") {
		t.Fatalf("unhelpful pin error: %v", err)
	}
}

func TestLoadPubToleratesComments(t *testing.T) {
	dir := t.TempDir()
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, PubFile)
	if err := WritePub(path, id.Pub); err != nil {
		t.Fatal(err)
	}
	pub, err := LoadPub(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, id.Pub) {
		t.Fatal("public key changed through the file format")
	}
}

func base64Of(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var out strings.Builder
	for i := 0; i < len(b); i += 3 {
		var chunk [3]byte
		n := copy(chunk[:], b[i:])
		out.WriteByte(alphabet[chunk[0]>>2])
		out.WriteByte(alphabet[(chunk[0]&0x03)<<4|chunk[1]>>4])
		if n > 1 {
			out.WriteByte(alphabet[(chunk[1]&0x0f)<<2|chunk[2]>>6])
		}
		if n > 2 {
			out.WriteByte(alphabet[chunk[2]&0x3f])
		}
	}
	return out.String()
}
