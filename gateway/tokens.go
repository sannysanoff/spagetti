package gateway

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/sannysanoff/spagetti/wire"
)

// Token is one admitted bearer token: the gateway's admission layer. It says
// nothing about content — a token holder can ask the gateway to route, not to
// read.
type Token struct {
	// Name is a label for logs.
	Name string `json:"name"`
	// Kind is "server" or "client"; a connection must present a token of the
	// role it claims in its hello frame.
	Kind string `json:"kind"`
	// Secret is given inline, or by file, or by environment variable. Exactly
	// one source must be set.
	Token     string `json:"token,omitempty"`
	TokenFile string `json:"token_file,omitempty"`
	TokenEnv  string `json:"token_env,omitempty"`
	// Allow lists the server ids this token may touch: for a server token, the
	// ids it may register; for a client token, the ids it may open channels to.
	// "*" allows any. This must be stated explicitly.
	Allow []string `json:"allow"`
}

type resolvedToken struct {
	name   string
	kind   wire.Kind
	secret string
	allow  []string
}

func (t Token) resolve() (resolvedToken, error) {
	rt := resolvedToken{name: t.Name, allow: append([]string(nil), t.Allow...)}
	switch strings.ToLower(strings.TrimSpace(t.Kind)) {
	case "server":
		rt.kind = wire.KindServer
	case "client":
		rt.kind = wire.KindClient
	default:
		return rt, fmt.Errorf("spagetti: token %q: kind must be \"server\" or \"client\"", t.Name)
	}
	if len(rt.allow) == 0 {
		return rt, fmt.Errorf("spagetti: token %q: allow must list server ids (use [\"*\"] to allow any)", t.Name)
	}
	switch {
	case t.Token != "":
		rt.secret = t.Token
	case t.TokenFile != "":
		b, err := os.ReadFile(t.TokenFile)
		if err != nil {
			return rt, fmt.Errorf("spagetti: token %q: %w", t.Name, err)
		}
		rt.secret = firstValue(string(b))
	case t.TokenEnv != "":
		rt.secret = strings.TrimSpace(os.Getenv(t.TokenEnv))
		if rt.secret == "" {
			return rt, fmt.Errorf("spagetti: token %q: environment variable %s is empty", t.Name, t.TokenEnv)
		}
	default:
		return rt, fmt.Errorf("spagetti: token %q: set one of token, token_file, token_env", t.Name)
	}
	if len(rt.secret) < 16 {
		return rt, fmt.Errorf("spagetti: token %q: secret must be at least 16 characters", t.Name)
	}
	return rt, nil
}

func (t resolvedToken) allows(serverID string) bool {
	for _, a := range t.allow {
		if a == "*" || a == serverID {
			return true
		}
	}
	return false
}

// firstValue returns the first non-comment, non-blank line of a token file.
func firstValue(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return line
	}
	return ""
}

type tokenStore struct {
	entries []resolvedToken
}

func newTokenStore(tokens []Token) (*tokenStore, error) {
	if len(tokens) == 0 {
		return nil, fmt.Errorf("spagetti: the gateway needs at least one token")
	}
	st := &tokenStore{}
	for _, t := range tokens {
		rt, err := t.resolve()
		if err != nil {
			return nil, err
		}
		for _, other := range st.entries {
			if other.name == rt.name {
				return nil, fmt.Errorf("spagetti: duplicate token name %q", rt.name)
			}
		}
		st.entries = append(st.entries, rt)
	}
	return st, nil
}

// find returns the token entry matching a presented secret, comparing in
// constant time against every entry.
func (s *tokenStore) find(secret string) (resolvedToken, bool) {
	if secret == "" {
		return resolvedToken{}, false
	}
	match := -1
	for i, e := range s.entries {
		if subtle.ConstantTimeCompare([]byte(e.secret), []byte(secret)) == 1 {
			match = i
		}
	}
	if match < 0 {
		return resolvedToken{}, false
	}
	return s.entries[match], true
}

// fileConfig is the on-disk gateway configuration.
type fileConfig struct {
	Tokens               []Token `json:"tokens"`
	MaxChannelsPerClient int     `json:"max_channels_per_client,omitempty"`
	MaxFrame             int     `json:"max_frame,omitempty"`
	PingIntervalSec      int     `json:"ping_interval_sec,omitempty"`
	IdleTimeoutSec       int     `json:"idle_timeout_sec,omitempty"`
	MaxOutBufferBytes    int64   `json:"max_out_buffer_bytes,omitempty"`
	OpenTimeoutSec       int     `json:"open_timeout_sec,omitempty"`
	OpenRatePerSec       float64 `json:"open_rate_per_sec,omitempty"`
	OpenBurst            int     `json:"open_burst,omitempty"`
}

// LoadConfigFile reads a gateway configuration file.
func LoadConfigFile(path string) (Config, error) {
	var fc fileConfig
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("spagetti: reading %s: %w", path, err)
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&fc); err != nil {
		return Config{}, fmt.Errorf("spagetti: parsing %s: %w", path, err)
	}
	return fc.config()
}

func (fc fileConfig) config() (Config, error) {
	cfg := Config{
		Tokens:               fc.Tokens,
		MaxChannelsPerClient: fc.MaxChannelsPerClient,
		MaxFrame:             fc.MaxFrame,
		MaxOutBuffer:         fc.MaxOutBufferBytes,
		OpenRatePerSec:       fc.OpenRatePerSec,
		OpenBurst:            fc.OpenBurst,
	}
	cfg.PingInterval = seconds(fc.PingIntervalSec)
	cfg.IdleTimeout = seconds(fc.IdleTimeoutSec)
	cfg.OpenTimeout = seconds(fc.OpenTimeoutSec)
	return cfg, nil
}
