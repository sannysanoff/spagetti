// Package conf manages the on-disk identity and secret files in the spagetti
// configuration directory.
//
// Layout:
//
//	$SPAGETTI_CONF_DIR (default ~/.spagetti)
//	├── servers/<server-id>/identity.key     X25519 private key, mode 0600
//	│                       identity.pub     public key, mode 0644 (copy to clients)
//	│                       access.password  access password, mode 0600 (copy to clients)
//	├── clients/<client-id>/identity.key     client device key, mode 0600
//	│                       identity.pub
//	└── peers/<server-id>/identity.pub       pinned server key (copied by a human)
//	                       access.password    access password (copied by a human)
//
// The first run of a spagetti server generates its keypair and password and
// prints the exact copy commands for a human to move the two files to a client.
// Nothing here ever logs a secret value.
package conf

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"crypto/ecdh"
)

// File names inside a server, client or peer directory.
const (
	KeyFile      = "identity.key"
	PubFile      = "identity.pub"
	PasswordFile = "access.password"
)

// PasswordLen is the access password length in bytes (256 bits of entropy, used
// directly as the Noise pre-shared key).
const PasswordLen = 32

// Identity is a static X25519 keypair.
type Identity struct {
	Priv []byte
	Pub  []byte
}

// Fingerprint is the human-comparable server identity, derived from the public
// key only: "spg1:" plus the first 8 bytes of SHA-256, in hex.
func Fingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	return "spg1:" + hex.EncodeToString(sum[:8])
}

// Fingerprint reports this identity's fingerprint.
func (i Identity) Fingerprint() string { return Fingerprint(i.Pub) }

// Dir returns the spagetti configuration directory.
func Dir() string {
	if d := os.Getenv("SPAGETTI_CONF_DIR"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".spagetti"
	}
	return filepath.Join(home, ".spagetti")
}

// ServerDir returns the directory holding a server's own files.
func ServerDir(base, serverID string) string { return join(base, "servers", serverID) }

// ClientDir returns the directory holding a client's own files.
func ClientDir(base, clientID string) string { return join(base, "clients", clientID) }

// PeerDir returns the directory holding a pinned server's files.
func PeerDir(base, serverID string) string { return join(base, "peers", serverID) }

func join(base, kind, id string) string {
	if base == "" {
		base = Dir()
	}
	return filepath.Join(base, kind, sanitize(id))
}

func sanitize(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "_"
	}
	return b.String()
}

// KeySize is the X25519 key size in bytes.
const KeySize = 32

// GenerateIdentity mints a fresh X25519 keypair.
func GenerateIdentity() (Identity, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, fmt.Errorf("spagetti: generating keypair: %w", err)
	}
	return Identity{Priv: k.Bytes(), Pub: k.PublicKey().Bytes()}, nil
}

// IdentityFromPrivate rebuilds an identity from its private key.
func IdentityFromPrivate(priv []byte) (Identity, error) {
	if len(priv) != KeySize {
		return Identity{}, fmt.Errorf("spagetti: private key must be %d bytes, got %d", KeySize, len(priv))
	}
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return Identity{}, fmt.Errorf("spagetti: deriving public key: %w", err)
	}
	return Identity{Priv: append([]byte(nil), priv...), Pub: k.PublicKey().Bytes()}, nil
}

// ID is the identity's stable label: its key fingerprint.
func (i Identity) ID() string { return Fingerprint(i.Pub) }

// GeneratePassword mints a 256-bit access password.
func GeneratePassword() ([]byte, error) {
	pw := make([]byte, PasswordLen)
	if _, err := rand.Read(pw); err != nil {
		return nil, fmt.Errorf("spagetti: generating password: %w", err)
	}
	return pw, nil
}

// LoadOrCreateIdentity loads the keypair in dir, generating and writing it on a
// first run. It refuses to guess when the directory is in a partial state.
func LoadOrCreateIdentity(dir string) (Identity, bool, error) {
	keyPath := filepath.Join(dir, KeyFile)
	pubPath := filepath.Join(dir, PubFile)
	keyExists := exists(keyPath)
	pubExists := exists(pubPath)
	switch {
	case keyExists && pubExists:
		id, err := LoadIdentity(dir)
		return id, false, err
	case keyExists != pubExists:
		return Identity{}, false, fmt.Errorf(
			"spagetti: %s is in a partial state (%s exists: %v, %s exists: %v); refusing to overwrite, remove the directory to re-enroll",
			dir, KeyFile, keyExists, PubFile, pubExists)
	}
	id, err := GenerateIdentity()
	if err != nil {
		return Identity{}, false, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Identity{}, false, fmt.Errorf("spagetti: creating %s: %w", dir, err)
	}
	body := "# spagetti public key — copy this file to a client's peers/<server-id>/identity.pub\n" +
		"# fingerprint: " + id.Fingerprint() + "\n" +
		hex.EncodeToString(id.Pub) + "\n"
	if err := os.WriteFile(pubPath, []byte(body), 0o644); err != nil {
		return Identity{}, false, fmt.Errorf("spagetti: writing %s: %w", pubPath, err)
	}
	priv := "# spagetti private key — never copy this file anywhere\n" + hex.EncodeToString(id.Priv) + "\n"
	if err := os.WriteFile(keyPath, []byte(priv), 0o600); err != nil {
		return Identity{}, false, fmt.Errorf("spagetti: writing %s: %w", keyPath, err)
	}
	return id, true, nil
}

// LoadIdentity reads an existing keypair, verifying that the private key
// actually yields the stored public key.
func LoadIdentity(dir string) (Identity, error) {
	priv, err := readHex(filepath.Join(dir, KeyFile))
	if err != nil {
		return Identity{}, err
	}
	id, err := IdentityFromPrivate(priv)
	if err != nil {
		return Identity{}, err
	}
	want, err := LoadPub(filepath.Join(dir, PubFile))
	if err != nil {
		return Identity{}, err
	}
	if len(want) != 0 && !equal(want, id.Pub) {
		return Identity{}, fmt.Errorf("spagetti: %s does not match %s (public key mismatch)",
			filepath.Join(dir, PubFile), filepath.Join(dir, KeyFile))
	}
	return id, nil
}

// LoadOrCreatePassword loads the access password in dir, generating and writing
// it on a first run.
func LoadOrCreatePassword(dir string) ([]byte, bool, error) {
	path := filepath.Join(dir, PasswordFile)
	if exists(path) {
		pw, err := LoadPassword(path)
		return pw, false, err
	}
	pw, err := GeneratePassword()
	if err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, false, fmt.Errorf("spagetti: creating %s: %w", dir, err)
	}
	if err := WritePassword(path, pw); err != nil {
		return nil, false, err
	}
	return pw, true, nil
}

// WritePassword writes a password file, mode 0600.
func WritePassword(path string, pw []byte) error {
	body := "# spagetti access password — copy this file to a client's peers/<server-id>/access.password\n" +
		base64.RawURLEncoding.EncodeToString(pw) + "\n"
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("spagetti: creating %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return fmt.Errorf("spagetti: writing %s: %w", path, err)
	}
	return nil
}

// LoadPassword reads a password file.
func LoadPassword(path string) ([]byte, error) {
	raw, err := strip(read(path))
	if err != nil {
		return nil, err
	}
	pw, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("spagetti: %s is not a valid access password: %w", path, err)
	}
	if len(pw) != PasswordLen {
		return nil, fmt.Errorf("spagetti: %s holds %d password bytes, want %d", path, len(pw), PasswordLen)
	}
	return pw, nil
}

// LoadPub reads a public key file (comment lines and blanks are ignored).
func LoadPub(path string) ([]byte, error) {
	return readHex(path)
}

// WritePub writes a public key file in the documented format.
func WritePub(path string, pub []byte) error {
	body := "# spagetti public key — copied from a server's identity.pub\n" +
		"# fingerprint: " + Fingerprint(pub) + "\n" +
		hex.EncodeToString(pub) + "\n"
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("spagetti: creating %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return fmt.Errorf("spagetti: writing %s: %w", path, err)
	}
	return nil
}

// ServerFiles describes a server's enrolment on disk.
type ServerFiles struct {
	Dir          string
	KeyFile      string
	PubFile      string
	PasswordFile string
	Identity     Identity
	Password     []byte
	Created      bool // true when this run generated them
}

// EnsureServer loads or creates a server's identity and password.
func EnsureServer(base, serverID string) (ServerFiles, error) {
	dir := ServerDir(base, serverID)
	id, created, err := LoadOrCreateIdentity(dir)
	if err != nil {
		return ServerFiles{}, err
	}
	pw, pwCreated, err := LoadOrCreatePassword(dir)
	if err != nil {
		return ServerFiles{}, err
	}
	return ServerFiles{
		Dir:          dir,
		KeyFile:      filepath.Join(dir, KeyFile),
		PubFile:      filepath.Join(dir, PubFile),
		PasswordFile: filepath.Join(dir, PasswordFile),
		Identity:     id,
		Password:     pw,
		Created:      created || pwCreated,
	}, nil
}

// Peer is a pinned server as seen from a client.
type Peer struct {
	ServerID     string
	PubFile      string
	PasswordFile string
	PubKey       []byte
	Password     []byte
}

// LoadPeer reads a pinned server's public key and access password.
func LoadPeer(base, serverID string) (Peer, error) {
	dir := PeerDir(base, serverID)
	pubPath := filepath.Join(dir, PubFile)
	pwPath := filepath.Join(dir, PasswordFile)
	pub, err := LoadPub(pubPath)
	if err != nil {
		return Peer{}, fmt.Errorf("%w (pin the server key by copying its identity.pub to %s)", err, pubPath)
	}
	pw, err := LoadPassword(pwPath)
	if err != nil {
		return Peer{}, fmt.Errorf("%w (copy the server's access.password to %s)", err, pwPath)
	}
	return Peer{ServerID: serverID, PubFile: pubPath, PasswordFile: pwPath, PubKey: pub, Password: pw}, nil
}

// SavePeer pins a server's public key and password for a client, as a human
// would by copying the two files.
func SavePeer(base, serverID string, pub, password []byte) (Peer, error) {
	dir := PeerDir(base, serverID)
	if err := WritePub(filepath.Join(dir, PubFile), pub); err != nil {
		return Peer{}, err
	}
	if err := WritePassword(filepath.Join(dir, PasswordFile), password); err != nil {
		return Peer{}, err
	}
	return LoadPeer(base, serverID)
}

func read(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("spagetti: reading %s: %w", path, err)
	}
	return b, nil
}

// strip removes comment lines, blank lines and surrounding whitespace so the
// documented file format stays both human readable and machine parseable.
func strip(b []byte, err error) (string, error) {
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return line, nil
	}
	return "", errors.New("spagetti: file holds no value")
}

func readHex(path string) ([]byte, error) {
	raw, err := strip(read(path))
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("spagetti: %s is not valid hex: %w", path, err)
	}
	return b, nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
