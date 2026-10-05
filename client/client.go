// Package client connects to the spagetti gateway and talks to registered
// servers through end-to-end encrypted channels.
//
// A channel is an authenticated net.Conn, so the natural way to use a server is
// ordinary net/http:
//
//	c, _ := client.New(client.Options{GatewayURL: "wss://gw/ws", Token: "...", ConfDir: conf.Dir()})
//	hc := c.HTTPClient("web1")
//	resp, _ := hc.Get("http://web1/v1/status")   // the host is the server id
//
// The URL host is only a label: the transport dials a fresh spagetti channel to
// that server and speaks HTTP inside it. WebSocket clients work the same way
// through DialWS.
package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/sannysanoff/spagetti/conf"
	"github.com/sannysanoff/spagetti/e2e"
	"github.com/sannysanoff/spagetti/tunnel"
	"github.com/sannysanoff/spagetti/wire"
)

// Options configures a client.
type Options struct {
	GatewayURL string
	// Token authenticates the client to the gateway. Give it inline, or via
	// file ("file:/path" or a path), or via environment variable.
	Token     string
	TokenFile string
	TokenEnv  string
	// TLSClientConfig is used for wss:// to the gateway.
	TLSClientConfig *tls.Config

	// ConfDir is the spagetti configuration directory; defaults to conf.Dir().
	ConfDir string
	// ClientID defaults to the client key fingerprint.
	ClientID string
	// Identity is normally loaded (or created on first use) from ConfDir.
	Identity conf.Identity

	// Pins overrides the pinned key/password files under
	// <ConfDir>/peers/<server-id>/ for the named servers.
	Pins map[string]Pin

	// EpochLifetime bounds how long a channel may exist before it must be
	// re-handshaked: a revoked password stops working within one epoch. It must
	// match the server's setting.
	EpochLifetime time.Duration
	// MaxChannelLifetime retires established channels (idle or busy) so that
	// long-lived streams are re-authenticated too.
	MaxChannelLifetime time.Duration
	HandshakeTimeout   time.Duration

	Logf   func(format string, args ...any)
	Dialer *websocket.Dialer
}

// Pin is a server's pinned public key and access password.
type Pin struct {
	PublicKey []byte
	Password  []byte
}

// DefaultEpochLifetime is the re-authentication period shared with servers.
const DefaultEpochLifetime = e2e.DefaultEpochLifetime

// Client is a gateway client. It is safe for concurrent use.
type Client struct {
	o        Options
	identity conf.Identity

	mu   sync.Mutex
	conn *tunnel.Conn
}

// New prepares a client, loading or creating its device key.
func New(o Options) (*Client, error) {
	if o.GatewayURL == "" {
		return nil, fmt.Errorf("spagetti: gateway url is required")
	}
	if o.ConfDir == "" {
		o.ConfDir = conf.Dir()
	}
	if o.EpochLifetime <= 0 {
		o.EpochLifetime = DefaultEpochLifetime
	}
	if o.HandshakeTimeout <= 0 {
		o.HandshakeTimeout = e2e.DefaultHandshakeTimeout
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	c := &Client{o: o, identity: o.Identity}
	if len(c.identity.Priv) == 0 {
		dir := conf.ClientDir(o.ConfDir, o.ClientID)
		id, created, err := conf.LoadOrCreateIdentity(dir)
		if err != nil {
			return nil, err
		}
		if created {
			o.Logf("spagetti: created client device key %s (%s)", id.Fingerprint(), dir)
		}
		c.identity = id
	}
	if o.ClientID == "" {
		o.ClientID = c.identity.Fingerprint()
	}
	c.o = o
	return c, nil
}

// ID reports the client label used on the wire.
func (c *Client) ID() string { return c.o.ClientID }

// Identity reports this client's device key.
func (c *Client) Identity() conf.Identity { return c.identity }

// Token resolves the bearer token for the gateway.
func (c *Client) Token() (string, error) {
	switch {
	case c.o.Token != "":
		return c.o.Token, nil
	case c.o.TokenFile != "":
		b, err := os.ReadFile(strings.TrimPrefix(c.o.TokenFile, "file:"))
		if err != nil {
			return "", fmt.Errorf("spagetti: reading token file: %w", err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				return line, nil
			}
		}
		return "", fmt.Errorf("spagetti: token file %s is empty", c.o.TokenFile)
	case c.o.TokenEnv != "":
		t := strings.TrimSpace(os.Getenv(c.o.TokenEnv))
		if t == "" {
			return "", fmt.Errorf("spagetti: environment variable %s is empty", c.o.TokenEnv)
		}
		return t, nil
	}
	return "", fmt.Errorf("spagetti: gateway bearer token is required (Token, TokenFile or TokenEnv)")
}

// Pin returns the pinned key and password for a server.
func (c *Client) Pin(serverID string) (Pin, error) {
	if p, ok := c.o.Pins[serverID]; ok {
		if len(p.PublicKey) == 0 || len(p.Password) == 0 {
			return Pin{}, fmt.Errorf("spagetti: pin for %q needs both a public key and a password", serverID)
		}
		return p, nil
	}
	peer, err := conf.LoadPeer(c.o.ConfDir, serverID)
	if err != nil {
		return Pin{}, err
	}
	return Pin{PublicKey: peer.PubKey, Password: peer.Password}, nil
}

// Epoch reports the current re-authentication epoch.
func (c *Client) Epoch() int64 {
	return time.Now().UnixNano() / int64(c.o.EpochLifetime)
}

// ListServers returns the gateway directory. Discovery is not authentication:
// use it to find servers, then verify the pinned key on connect.
func (c *Client) ListServers(ctx context.Context) ([]wire.ServerEntry, error) {
	for attempt := 0; ; attempt++ {
		tc, err := c.gateway(ctx)
		if err != nil {
			return nil, err
		}
		entries, err := tc.List(ctx)
		if err == nil {
			return entries, nil
		}
		if attempt == 0 && retryable(err) {
			c.dropConn(tc)
			continue
		}
		return nil, err
	}
}

// Dial opens an end-to-end encrypted channel to a server and returns it as a
// net.Conn: HTTP, SSE and WebSocket all work over it unchanged.
func (c *Client) Dial(ctx context.Context, serverID string) (*e2e.Conn, error) {
	if serverID == "" {
		return nil, fmt.Errorf("spagetti: server id is required")
	}
	pin, err := c.Pin(serverID)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		tc, err := c.gateway(ctx)
		if err != nil {
			return nil, err
		}
		ch, err := tc.Open(ctx, serverID, c.Epoch())
		if err != nil {
			lastErr = err
			if retryable(err) {
				c.dropConn(tc)
				continue
			}
			return nil, err
		}
		conn, err := e2e.Connect(ctx, ch, e2e.ClientConfig{
			Identity:  c.identity,
			ClientID:  c.o.ClientID,
			ServerID:  serverID,
			ServerPub: pin.PublicKey,
			Password:  pin.Password,
			Channel:   ch.ID(),
			Epoch:     c.Epoch(),
			Timeout:   c.o.HandshakeTimeout,
		})
		if err != nil {
			ch.Close(wire.CodeAuthFailed, err.Error())
			return nil, err
		}
		c.armLifetime(conn)
		return conn, nil
	}
	return nil, lastErr
}

// armLifetime retires a channel after MaxChannelLifetime so that even a busy
// stream is re-authenticated inside the epoch contract.
func (c *Client) armLifetime(conn *e2e.Conn) {
	if c.o.MaxChannelLifetime <= 0 {
		return
	}
	time.AfterFunc(c.o.MaxChannelLifetime, func() { conn.Close() })
}

// HTTPClient returns an *http.Client whose requests to "http://<serverID>/..."
// travel through fresh spagetti channels. Connection pooling, keep-alive and
// streaming are handled by net/http as usual.
func (c *Client) HTTPClient(serverID string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return c.Dial(ctx, serverID)
			},
			MaxIdleConns:        32,
			MaxIdleConnsPerHost: 16,
			IdleConnTimeout:     2 * time.Minute,
			DisableCompression:  true, // the tunnel is opaque; compression buys nothing
			ForceAttemptHTTP2:   false,
		},
	}
}

// DialWS opens a websocket connection that runs inside an end-to-end channel.
// The URL host is ignored; the path and headers are passed through.
func (c *Client) DialWS(ctx context.Context, serverID, urlStr string, header http.Header) (*websocket.Conn, error) {
	conn, err := c.Dial(ctx, serverID)
	if err != nil {
		return nil, err
	}
	d := &websocket.Dialer{
		HandshakeTimeout: c.o.HandshakeTimeout,
		NetDialContext: func(context.Context, string, string) (net.Conn, error) {
			return conn, nil
		},
	}
	ws, resp, err := d.DialContext(ctx, urlStr, header)
	if err != nil {
		conn.Close()
		if resp != nil {
			resp.Body.Close()
		}
		return nil, fmt.Errorf("spagetti: websocket through channel: %w", err)
	}
	return ws, nil
}

// Close tears down the gateway connection.
func (c *Client) Close() error {
	c.mu.Lock()
	tc := c.conn
	c.conn = nil
	c.mu.Unlock()
	if tc != nil {
		tc.Close()
	}
	return nil
}

func (c *Client) gateway(ctx context.Context) (*tunnel.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		select {
		case <-c.conn.Done():
			c.conn = nil
		default:
			return c.conn, nil
		}
	}
	token, err := c.Token()
	if err != nil {
		return nil, err
	}
	d := c.o.Dialer
	if d == nil {
		d = &websocket.Dialer{
			HandshakeTimeout: 15 * time.Second,
			TLSClientConfig:  c.o.TLSClientConfig,
			Proxy:            http.ProxyFromEnvironment,
		}
	}
	tc, err := tunnel.Dial(ctx, tunnel.Options{
		URL:         c.o.GatewayURL,
		Token:       token,
		Kind:        wire.KindClient,
		ID:          c.o.ClientID,
		PubKey:      c.identity.Pub,
		Fingerprint: c.identity.Fingerprint(),
		Logf:        c.o.Logf,
		Dialer:      d,
	})
	if err != nil {
		return nil, err
	}
	c.conn = tc
	return tc, nil
}

func (c *Client) dropConn(tc *tunnel.Conn) {
	c.mu.Lock()
	if c.conn == tc {
		c.conn = nil
	}
	c.mu.Unlock()
	tc.Close()
}

// retryable reports whether an error means "the relay path died, not the
// request": those are worth one reconnect attempt.
func retryable(err error) bool {
	code, ok := wire.CodeOf(err)
	if !ok {
		return false
	}
	switch code {
	case wire.CodeServerOffline, wire.CodePeerGone, wire.CodeTimeout, wire.CodeOverload:
		return true
	}
	return false
}
