// Command spagetti-wrap publishes an existing HTTP server through a spagetti
// gateway.
//
// It reverse-proxies a local target — a webserver that knows nothing about
// spagetti — through the tunnel, so an ordinary service becomes reachable by
// authenticated clients of the gateway without a line of change in its own code.
// Requests keep their method, path, body, streaming and websocket upgrades; the
// caller's identity is available to the target in the X-Spagetti-Peer header.
//
// Configuration lives in an env file and/or the process environment. The command
// line carries nothing but the env file, which defaults to .env:
//
//	spagetti-wrap                     # reads .env
//	spagetti-wrap -env prod.env       # reads prod.env, then .env for what is missing
//
// Keys, all prefixed SPAGETTY_:
//
//	SPAGETTY_TARGET    required   the webserver to expose, e.g. http://127.0.0.1:9000
//	SPAGETTY_TOKEN     required   bearer token that authorises announcing this server
//	SPAGETTY_NAME      required   the name clients ask the gateway for
//	SPAGETTY_PASSWORD  required   challenge password: base64url of exactly 32 bytes
//	SPAGETTY_ENDPOINT  optional   gateway endpoint (default https://mux.san.systems/ws)
//	SPAGETTY_KEYS      optional   keypair cache file (default .spagetti-keys)
//
// Values are resolved from the process environment first, then from the file
// named with -env, then from .env. Every one of those files is read whenever it
// exists and each source only fills in what is still missing, so an exported
// variable overrides a file without editing it. A required key that no source
// supplies is a refusal, not a guess.
//
// The keypair is cached in SPAGETTY_KEYS (mode 0600) and minted on the first run;
// its public half and the password are written next to it as <cache>.pub and
// <cache>.password so they can be copied to a client.
//
// The wrapper logs the connection to the gateway and one line per request it
// forwards — timestamp, verb, path — at request time. Responses are not logged.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/sannysanoff/spagetti/conf"
	"github.com/sannysanoff/spagetti/server"
)

const (
	keyTarget   = "SPAGETTY_TARGET"
	keyToken    = "SPAGETTY_TOKEN"
	keyName     = "SPAGETTY_NAME"
	keyPassword = "SPAGETTY_PASSWORD"
	keyEndpoint = "SPAGETTY_ENDPOINT"
	keyKeys     = "SPAGETTY_KEYS"

	defaultEnvFile  = ".env"
	defaultEndpoint = "https://mux.san.systems/ws"
	defaultKeysFile = ".spagetti-keys"

	pubSuffix      = ".pub"
	passwordSuffix = ".password"
)

var (
	knownKeys    = []string{keyTarget, keyToken, keyName, keyPassword, keyEndpoint, keyKeys}
	requiredKeys = []string{keyTarget, keyToken, keyName, keyPassword}
	secretKeys   = map[string]bool{keyToken: true, keyPassword: true}
)

const usage = `spagetti-wrap publishes an existing HTTP server through a spagetti gateway.

usage: spagetti-wrap [-env FILE]

  -env FILE   env file holding the configuration (default ".env")

The command line takes nothing else: the target and every credential come from
the env file and/or the process environment. Keys (all prefixed SPAGETTY_):

  SPAGETTY_TARGET    required   the webserver to expose, e.g. http://127.0.0.1:9000
  SPAGETTY_TOKEN     required   bearer token that authorises announcing this server
  SPAGETTY_NAME      required   the name clients ask the gateway for
  SPAGETTY_PASSWORD  required   challenge password: base64url of exactly 32 bytes
  SPAGETTY_ENDPOINT  optional   gateway endpoint (default https://mux.san.systems/ws)
  SPAGETTY_KEYS      optional   keypair cache file (default .spagetti-keys)

Resolution order, each source filling only what is still missing: the process
environment, then the file named with -env, then .env. Files are read whenever
they exist. A required key no source supplies refuses to start.

An env file looks like this:

  # the webserver to publish, and how clients will ask for it
  SPAGETTY_TARGET=http://127.0.0.1:9000
  SPAGETTY_NAME=web1

  # the gateway and the bearer token it accepts from this server
  SPAGETTY_ENDPOINT=wss://mux.san.systems/ws
  SPAGETTY_TOKEN=<the server token from the gateway's config>

  # base64url of 32 bytes; mint one with
  #   openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
  SPAGETTY_PASSWORD=<43 characters>
`

func main() {
	// the timestamped flags give every request line a timestamp
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if err := run(os.Args[1:]); err != nil {
		log.Printf("spagetti-wrap: %v", err)
		os.Exit(1)
	}
}

func run(argv []string) error {
	fs := flag.NewFlagSet("spagetti-wrap", flag.ExitOnError)
	envPath := fs.String("env", defaultEnvFile, "env file holding the configuration")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	_ = fs.Parse(argv)

	if fs.NArg() > 1 {
		return fmt.Errorf("expected at most one argument (the env file), got %q", fs.Args())
	}
	if fs.NArg() == 1 {
		if wasSet(fs, "env") {
			return fmt.Errorf("-env %s and the argument %s both name an env file", *envPath, fs.Arg(0))
		}
		*envPath = fs.Arg(0)
	}

	cfg, err := loadConfig(*envPath)
	if err != nil {
		return err
	}
	for _, line := range cfg.describe() {
		log.Printf("spagetti-wrap: %s", line)
	}
	for _, w := range cfg.warnings {
		log.Printf("spagetti-wrap: warning: %s", w)
	}

	endpoint, err := gatewayEndpoint(cfg.get(keyEndpoint))
	if err != nil {
		return err
	}
	target, err := targetURL(cfg.get(keyTarget))
	if err != nil {
		return err
	}
	name := cfg.get(keyName)
	if err := checkName(name); err != nil {
		return err
	}
	password, err := decodePassword(cfg.get(keyPassword))
	if err != nil {
		return err
	}

	keysPath := cfg.get(keyKeys)
	identity, minted, err := loadOrCreateIdentity(keysPath)
	if err != nil {
		return err
	}
	pubPath := keysPath + pubSuffix
	if err := conf.WritePub(pubPath, identity.Pub); err != nil {
		return err
	}
	passwordPath := keysPath + passwordSuffix
	if err := conf.WritePassword(passwordPath, password); err != nil {
		return err
	}

	log.Printf("spagetti-wrap: server %q fingerprint %s", name, identity.Fingerprint())
	if minted {
		log.Printf("spagetti-wrap: first run: minted the keypair into %s (mode 0600)", keysPath)
	}
	log.Printf("spagetti-wrap: public key %s and password %s (mode 0600) are what a client pins", pubPath, passwordPath)
	log.Printf("spagetti-wrap: exposing %s through %s", target, endpoint)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("spagetti-wrap: connecting to the gateway %s", endpoint)
	err = server.Serve(ctx, server.Options{
		ServerID:   name,
		GatewayURL: endpoint,
		Token:      cfg.get(keyToken),
		Identity:   identity,
		Password:   password,
		Handler:    forwardTo(target),
		Logf:       log.Printf,
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	log.Printf("spagetti-wrap: stopped")
	return nil
}

// forwardTo reverse-proxies every tunneled request to the target and logs it at
// request time: the logger adds the timestamp, then verb and path. Responses are
// not logged. Upgrades are proxied too, so a target that speaks websockets keeps
// speaking them through the tunnel.
func forwardTo(target *url.URL) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(target)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.RequestURI())
		if peer, ok := server.PeerFromContext(r.Context()); ok {
			// the target learns who called without trusting a client header
			r.Header.Set("X-Spagetti-Peer", peer.Fingerprint)
		}
		proxy.ServeHTTP(w, r)
	})
}

// config is the resolved configuration plus where each value came from.
type config struct {
	spec     string
	values   map[string]string
	origin   map[string]string
	files    []attempt
	warnings []string
}

// attempt records a candidate env file and what happened to it.
type attempt struct {
	path    string
	missing bool
	keys    int
}

// envValue is a value read from a file, with the line it came from.
type envValue struct {
	value string
	line  int
}

func (c *config) get(key string) string { return c.values[key] }

// loadConfig merges the process environment, the env file named on the command
// line and .env, then applies the defaults and refuses if a required key is
// still unknown.
func loadConfig(spec string) (*config, error) {
	c := &config{spec: spec, values: map[string]string{}, origin: map[string]string{}}

	// The environment wins over the files, so an operator can override one value
	// without editing a file.
	for _, k := range knownKeys {
		if v, ok := os.LookupEnv(k); ok && strings.TrimSpace(v) != "" {
			c.values[k] = strings.TrimSpace(v)
			c.origin[k] = "the environment"
		}
	}

	// Every candidate that exists is read, each only filling the gaps left by
	// what came before it.
	candidates := []string{spec}
	if spec != defaultEnvFile {
		candidates = append(candidates, defaultEnvFile)
	}
	for _, path := range candidates {
		if path == "" {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				c.files = append(c.files, attempt{path: path, missing: true})
				continue
			}
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		vals, err := parseEnvFile(f, path)
		f.Close()
		if err != nil {
			return nil, err
		}
		c.files = append(c.files, attempt{path: path, keys: len(vals)})
		if secrets := fileHasSecrets(vals); secrets != "" {
			if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
				c.warnings = append(c.warnings, fmt.Sprintf(
					"%s holds %s and is readable by group or others (mode %04o); chmod 600 it",
					path, secrets, fi.Mode().Perm()))
			}
		}
		for k, v := range vals {
			if !isKnownKey(k) {
				c.warnings = append(c.warnings, fmt.Sprintf(
					"%s line %d: %s is not a spagetti-wrap key, ignored", path, v.line, k))
				continue
			}
			if _, have := c.values[k]; have {
				continue
			}
			c.values[k] = v.value
			c.origin[k] = fmt.Sprintf("%s line %d", path, v.line)
		}
	}

	if _, ok := c.values[keyEndpoint]; !ok {
		c.values[keyEndpoint] = defaultEndpoint
		c.origin[keyEndpoint] = "the default"
	}
	if _, ok := c.values[keyKeys]; !ok {
		c.values[keyKeys] = defaultKeysFile
		c.origin[keyKeys] = "the default"
	}

	// Refusing here is the point: a wrapper that starts with a guessed target or
	// an empty token looks like a network fault later on.
	var missing []string
	for _, k := range requiredKeys {
		if c.values[k] == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return nil, c.missingError(missing)
	}
	return c, nil
}

// missingError says exactly what is missing and what was consulted, so the
// operator can see whether the file was unreadable, incomplete or absent.
func (c *config) missingError(missing []string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "missing required %s", strings.Join(missing, ", "))
	b.WriteString("; refused to start. Sources: the process environment")
	for _, a := range c.files {
		if a.missing {
			fmt.Fprintf(&b, ", %s (not found)", a.path)
		} else {
			fmt.Fprintf(&b, ", %s (%d keys)", a.path, a.keys)
		}
	}
	if len(c.files) == 0 {
		b.WriteString(", no env file named")
	}
	b.WriteString(". Accepted keys: " + strings.Join(knownKeys, ", ") + " (see -h)")
	return errors.New(b.String())
}

// describe reports the effective values and where each came from. The token and
// the password are reported by length only: they are never logged.
func (c *config) describe() []string {
	out := []string{"configuration sources: the environment" + c.sources()}
	for _, k := range knownKeys {
		v := c.values[k]
		from := c.origin[k]
		if secretKeys[k] {
			out = append(out, fmt.Sprintf("  %s: %d characters (%s)", k, len(v), from))
			continue
		}
		out = append(out, fmt.Sprintf("  %s: %s (%s)", k, v, from))
	}
	return out
}

func (c *config) sources() string {
	var b strings.Builder
	for _, a := range c.files {
		if a.missing {
			fmt.Fprintf(&b, ", %s (not found)", a.path)
			continue
		}
		fmt.Fprintf(&b, ", %s", a.path)
	}
	return b.String()
}

// parseEnvFile reads KEY=VALUE lines, ignoring blanks and # comments. Keys are
// matched case-insensitively; a line that is not KEY=VALUE, or a value with an
// unterminated quote, is a misconfiguration and refuses to start.
func parseEnvFile(r io.Reader, path string) (map[string]envValue, error) {
	out := map[string]envValue{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		key, raw, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s line %d: expected KEY=VALUE, got %q", path, n, sc.Text())
		}
		key = strings.ToUpper(strings.TrimSpace(key))
		if key == "" {
			return nil, fmt.Errorf("%s line %d: empty key", path, n)
		}
		value, err := envValueOf(raw)
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, n, err)
		}
		out[key] = envValue{value: value, line: n}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return out, nil
}

// envValueOf trims a value: a quoted value is taken verbatim up to its closing
// quote, an unquoted one loses a trailing " #" comment.
func envValueOf(raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", nil
	}
	if q := v[0]; q == '"' || q == '\'' {
		end := strings.IndexByte(v[1:], q)
		if end < 0 {
			return "", fmt.Errorf("unterminated %c quote", q)
		}
		return v[1 : 1+end], nil
	}
	for _, marker := range []string{" #", "\t#"} {
		if i := strings.Index(v, marker); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
	}
	return v, nil
}

// fileHasSecrets names the secret keys in a file, for the permission warning.
func fileHasSecrets(vals map[string]envValue) string {
	var names []string
	for _, k := range []string{keyPassword, keyToken} {
		if v, ok := vals[k]; ok && v.value != "" {
			names = append(names, k)
		}
	}
	return strings.Join(names, " and ")
}

func isKnownKey(k string) bool {
	for _, known := range knownKeys {
		if k == known {
			return true
		}
	}
	return false
}

// gatewayEndpoint turns the configured endpoint into the websocket URL the tunnel
// dials. http and https are accepted because operators write the gateway's public
// URL; they map onto ws and wss.
func gatewayEndpoint(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("%s %q: %w", keyEndpoint, raw, err)
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	case "ws", "wss":
	default:
		return "", fmt.Errorf("%s %q: scheme %q is not one of http, https, ws, wss", keyEndpoint, raw, u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("%s %q: no host", keyEndpoint, raw)
	}
	return u.String(), nil
}

// targetURL parses the webserver to expose. It is reached over plain TCP from
// this host, so only http and https make sense.
func targetURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("%s %q: %w", keyTarget, raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%s %q: scheme must be http or https", keyTarget, raw)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%s %q: no host", keyTarget, raw)
	}
	return u, nil
}

// checkName keeps the server name to what the gateway and a config directory can
// carry without surprises.
func checkName(name string) error {
	if len(name) > 128 {
		return fmt.Errorf("%s %q: longer than 128 characters", keyName, name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return fmt.Errorf("%s %q: %q is not allowed; use letters, digits, dot, dash or underscore", keyName, name, r)
		}
	}
	return nil
}

// decodePassword reads the challenge password, which is used as the Noise
// pre-shared key, so it must be exactly the 32 bytes an access.password file
// holds — base64url without padding.
func decodePassword(raw string) ([]byte, error) {
	pw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("%s is not base64url: %w", keyPassword, err)
	}
	if len(pw) != conf.PasswordLen {
		return nil, fmt.Errorf("%s holds %d bytes, want %d (base64url of 32 bytes; mint one with openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')",
			keyPassword, len(pw), conf.PasswordLen)
	}
	return pw, nil
}

// loadOrCreateIdentity reads the cached keypair, minting it when the cache file
// is absent. The file holds the private key in the same format as a server's
// identity.key; <cache>.pub is checked against it when present, so a mixed-up
// cache refuses instead of silently announcing a different identity.
func loadOrCreateIdentity(path string) (conf.Identity, bool, error) {
	if !fileExists(path) {
		id, err := conf.GenerateIdentity()
		if err != nil {
			return conf.Identity{}, false, err
		}
		if dir := filepath.Dir(path); dir != "" {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return conf.Identity{}, false, fmt.Errorf("creating %s: %w", dir, err)
			}
		}
		body := "# spagetti private key — never copy this file anywhere\n" +
			hex.EncodeToString(id.Priv) + "\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			return conf.Identity{}, false, fmt.Errorf("writing %s: %w", path, err)
		}
		return id, true, nil
	}

	// the same hex-with-comments reader the library uses for identity.key
	priv, err := conf.LoadPub(path)
	if err != nil {
		return conf.Identity{}, false, fmt.Errorf("%s: %w", path, err)
	}
	id, err := conf.IdentityFromPrivate(priv)
	if err != nil {
		return conf.Identity{}, false, fmt.Errorf("%s: %w", path, err)
	}
	pubPath := path + pubSuffix
	if fileExists(pubPath) {
		want, err := conf.LoadPub(pubPath)
		if err != nil {
			return conf.Identity{}, false, fmt.Errorf("%s: %w", pubPath, err)
		}
		if len(want) != 0 && !bytes.Equal(want, id.Pub) {
			return conf.Identity{}, false, fmt.Errorf("%s does not match %s (public key mismatch)", pubPath, path)
		}
	}
	return id, false, nil
}

func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

func wasSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}
