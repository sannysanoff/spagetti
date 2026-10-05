// Package server wraps an ordinary http.Handler so it becomes a spagetti server:
// it dials out to the gateway, registers itself, and serves every channel that
// the gateway splices to it as end-to-end encrypted HTTP.
//
// The wrapped handler is unchanged code. It sees normal requests, can hijack,
// can stream, can upgrade to websockets; the only difference is that the caller
// was authenticated by a spagetti challenge and its identity is available from
// the request context:
//
//	http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		peer, _ := server.PeerFromContext(r.Context())
//		fmt.Fprintf(w, "hello %s (%s)\n", peer.ID, peer.Fingerprint)
//	})
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/sannysanoff/spagetti/conf"
	"github.com/sannysanoff/spagetti/e2e"
	"github.com/sannysanoff/spagetti/tunnel"
	"github.com/sannysanoff/spagetti/wire"
)

// Defaults for Options fields left zero.
const (
	DefaultMaxChannels        = 64
	DefaultReconnectMin       = 1 * time.Second
	DefaultReconnectMax       = 30 * time.Second
	DefaultMaxChannelLifetime = 24 * time.Hour
	DefaultReadHeaderTimeout  = 30 * time.Second
)

// Peer identifies an authenticated caller. It is an alias of e2e.Peer so there
// is exactly one type in play.
type Peer = e2e.Peer

// PeerFromContext returns the authenticated caller of a tunneled request.
func PeerFromContext(ctx context.Context) (Peer, bool) { return e2e.PeerFromContext(ctx) }

// FirstRun describes what was generated the first time a server started, so the
// operator can hand the public key and the password to a client.
type FirstRun struct {
	ServerID     string
	Dir          string
	PubFile      string
	PasswordFile string
	Fingerprint  string
	// CopyCommands are ready-to-paste commands that pin this server on a client
	// host. They copy files; they never print the password.
	CopyCommands string
}

// Options configures a wrapped server.
type Options struct {
	GatewayURL      string
	Token           string
	TokenFile       string
	TokenEnv        string
	TLSClientConfig *tls.Config

	// ServerID is the name clients ask for. Name and Tags are directory
	// metadata only.
	ServerID string
	Name     string
	Tags     []string

	ConfDir string
	// Identity and Password are normally loaded, or generated on the first run,
	// from ConfDir.
	Identity conf.Identity
	Password []byte

	// Handler receives the tunneled HTTP requests.
	Handler http.Handler

	MaxChannels        int
	EpochLifetime      time.Duration
	MaxChannelLifetime time.Duration
	ReplayWindow       time.Duration
	HandshakeTimeout   time.Duration

	// AllowClient optionally authorizes a caller once the end-to-end handshake
	// has proved who it is. A refusal is reported to the caller as a channel
	// verdict, so its Dial fails with a reason instead of an empty channel.
	AllowClient func(Peer) bool

	ReconnectMin time.Duration
	ReconnectMax time.Duration

	// TunnelOptions, when set, may adjust the gateway connection's tuning
	// (handshake and idle timeouts, queue sizes) before it is dialled.
	TunnelOptions func(*tunnel.Options)

	Logf   func(format string, args ...any)
	Dialer *websocket.Dialer
	// OnFirstRun is called once, at most, when this run generated the server's
	// keypair or password.
	OnFirstRun func(FirstRun)
}

func (o *Options) setDefaults() error {
	if o.GatewayURL == "" {
		return fmt.Errorf("spagetti: gateway url is required")
	}
	if o.ServerID == "" {
		return fmt.Errorf("spagetti: server id is required")
	}
	if o.Handler == nil {
		return fmt.Errorf("spagetti: handler is required")
	}
	if o.ConfDir == "" {
		o.ConfDir = conf.Dir()
	}
	if o.MaxChannels <= 0 {
		o.MaxChannels = DefaultMaxChannels
	}
	if o.EpochLifetime <= 0 {
		o.EpochLifetime = e2e.DefaultEpochLifetime
	}
	if o.MaxChannelLifetime <= 0 {
		o.MaxChannelLifetime = DefaultMaxChannelLifetime
	}
	if o.ReplayWindow <= 0 {
		o.ReplayWindow = e2e.DefaultReplayWindow
	}
	if o.HandshakeTimeout <= 0 {
		o.HandshakeTimeout = e2e.DefaultHandshakeTimeout
	}
	if o.ReconnectMin <= 0 {
		o.ReconnectMin = DefaultReconnectMin
	}
	if o.ReconnectMax <= 0 {
		o.ReconnectMax = DefaultReconnectMax
	}
	if o.Logf == nil {
		o.Logf = func(format string, args ...any) { log.Printf(format, args...) }
	}
	if o.Name == "" {
		o.Name = o.ServerID
	}
	return nil
}

// Serve runs the wrapped server until ctx is cancelled. It reconnects to the
// gateway on its own; the returned error reports only what made Serve stop.
func Serve(ctx context.Context, o Options) error {
	if err := o.setDefaults(); err != nil {
		return err
	}
	// An embedder that supplies both the identity and the password has nothing to
	// load or generate, and must not have a second, unused keypair written into
	// ConfDir — or be told about files it does not use.
	if len(o.Identity.Priv) == 0 || len(o.Password) == 0 {
		files, err := conf.EnsureServer(o.ConfDir, o.ServerID)
		if err != nil {
			return err
		}
		if len(o.Identity.Priv) == 0 {
			o.Identity = files.Identity
		}
		if len(o.Password) == 0 {
			o.Password = files.Password
		}
		if files.Created {
			first := FirstRun{
				ServerID:     o.ServerID,
				Dir:          files.Dir,
				PubFile:      files.PubFile,
				PasswordFile: files.PasswordFile,
				Fingerprint:  files.Identity.Fingerprint(),
			}
			peerDir := conf.PeerDir(o.ConfDir, o.ServerID)
			first.CopyCommands = fmt.Sprintf(
				"mkdir -p %s && cp %s %s/identity.pub && cp %s %s/access.password",
				peerDir, files.PubFile, peerDir, files.PasswordFile, peerDir)
			o.announceFirstRun(first)
			if o.OnFirstRun != nil {
				o.OnFirstRun(first)
			}
		}
	}
	token, err := o.resolveToken()
	if err != nil {
		return err
	}
	s := &instance{
		o: o, token: token,
		nonces:  e2e.NewNonceCache(o.ReplayWindow),
		serving: map[wire.Channel]struct{}{},
	}
	// the identity in use, which is the one the gateway registers and a client
	// pins; files.Identity can be a different, unused keypair
	o.Logf("spagetti: server %q ready (fingerprint %s, epoch %s, channel lifetime %s)",
		o.ServerID, o.Identity.Fingerprint(), o.EpochLifetime, o.MaxChannelLifetime)
	return s.run(ctx)
}

func (o Options) announceFirstRun(f FirstRun) {
	o.Logf("spagetti: first run: generated the keypair and access password for server %q in %s", o.ServerID, f.Dir)
	o.Logf("spagetti:   public key    %s   (%s)", f.Fingerprint, f.PubFile)
	o.Logf("spagetti:   password file %s   (mode 0600; the value is never logged)", f.PasswordFile)
	o.Logf("spagetti:   to authorise a client, copy both files on the client host:")
	o.Logf("spagetti:     %s", f.CopyCommands)
}

func (o Options) resolveToken() (string, error) {
	switch {
	case o.Token != "":
		return o.Token, nil
	case o.TokenFile != "":
		b, err := os.ReadFile(strings.TrimPrefix(o.TokenFile, "file:"))
		if err != nil {
			return "", fmt.Errorf("spagetti: reading token file: %w", err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				return line, nil
			}
		}
		return "", fmt.Errorf("spagetti: token file %s is empty", o.TokenFile)
	case o.TokenEnv != "":
		t := strings.TrimSpace(os.Getenv(o.TokenEnv))
		if t == "" {
			return "", fmt.Errorf("spagetti: environment variable %s is empty", o.TokenEnv)
		}
		return t, nil
	}
	return "", fmt.Errorf("spagetti: gateway bearer token is required (Token, TokenFile or TokenEnv)")
}

type instance struct {
	o      Options
	token  string
	nonces *e2e.NonceCache

	live    atomic.Int64
	handled atomic.Int64
	refused atomic.Int64
	mu      sync.Mutex
	conn    *tunnel.Conn
	wg      sync.WaitGroup
	// serving guards against a relay that opens the same channel label twice.
	serving map[wire.Channel]struct{}
}

func (s *instance) run(ctx context.Context) error {
	backoff := s.o.ReconnectMin
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		tc, err := s.dial(ctx)
		if err != nil {
			s.o.Logf("spagetti: gateway connect failed: %v (retrying in %s)", err, backoff)
			if !sleepCtx(ctx, backoff) {
				return nil
			}
			backoff = nextBackoff(backoff, s.o.ReconnectMax)
			continue
		}
		s.mu.Lock()
		s.conn = tc
		s.mu.Unlock()
		s.o.Logf("spagetti: registered %q with the gateway", s.o.ServerID)
		backoff = s.o.ReconnectMin
		select {
		case <-ctx.Done():
			tc.Close()
			s.wg.Wait()
			return nil
		case <-tc.Done():
			s.o.Logf("spagetti: gateway connection lost: %v (reconnecting)", tc.Err())
			s.mu.Lock()
			if s.conn == tc {
				s.conn = nil
			}
			s.mu.Unlock()
		}
	}
}

func (s *instance) dial(ctx context.Context) (*tunnel.Conn, error) {
	d := s.o.Dialer
	if d == nil {
		d = &websocket.Dialer{
			HandshakeTimeout: 15 * time.Second,
			TLSClientConfig:  s.o.TLSClientConfig,
			Proxy:            http.ProxyFromEnvironment,
		}
	}
	to := tunnel.Options{
		URL:         s.o.GatewayURL,
		Token:       s.token,
		Kind:        wire.KindServer,
		ID:          s.o.ServerID,
		PubKey:      s.o.Identity.Pub,
		Fingerprint: s.o.Identity.Fingerprint(),
		Name:        s.o.Name,
		Tags:        s.o.Tags,
		Logf:        s.o.Logf,
		Dialer:      d,
		OnOpen:      func(op tunnel.Open) { s.wg.Add(1); go func() { defer s.wg.Done(); s.handleChannel(ctx, op) }() },
	}
	if s.o.TunnelOptions != nil {
		s.o.TunnelOptions(&to)
	}
	return tunnel.Dial(ctx, to)
}

func (s *instance) epoch() int64 { return time.Now().UnixNano() / int64(s.o.EpochLifetime) }

func (s *instance) handleChannel(ctx context.Context, op tunnel.Open) {
	s.mu.Lock()
	tc := s.conn
	s.mu.Unlock()
	if tc == nil {
		return
	}
	ch := tc.Channel(op.Channel)
	if op.ServerID != s.o.ServerID {
		tc.RefuseOpen(op.Channel, wire.CodeProtocolError, "channel addressed to another server")
		return
	}
	s.mu.Lock()
	if _, dup := s.serving[op.Channel]; dup {
		s.mu.Unlock()
		tc.RefuseOpen(op.Channel, wire.CodeDuplicateChannel, "channel label already being served")
		return
	}
	s.serving[op.Channel] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.serving, op.Channel)
		s.mu.Unlock()
	}()
	if e := op.Epoch - s.epoch(); e < -1 || e > 1 {
		s.refused.Add(1)
		tc.RefuseOpen(op.Channel, wire.CodeTimeout, "stale channel epoch: reconnect to re-authenticate")
		return
	}
	if live := s.live.Load(); live >= int64(s.o.MaxChannels) {
		s.refused.Add(1)
		s.o.Logf("spagetti: channel %s refused: at capacity (%d/%d live)", op.Channel, live, s.o.MaxChannels)
		tc.RefuseOpen(op.Channel, wire.CodeTooManyChannels, "server is at capacity")
		return
	}
	s.live.Add(1)
	defer s.live.Add(-1)

	// Accept routing first: the caller's identity is only known once the
	// end-to-end handshake has run.
	if err := tc.AcceptOpen(op.Channel); err != nil {
		return
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, s.o.HandshakeTimeout)
	defer cancel()
	conn, peer, err := e2e.Accept(handshakeCtx, ch, e2e.ServerConfig{
		Identity:  s.o.Identity,
		ServerID:  s.o.ServerID,
		Password:  s.o.Password,
		Channel:   op.Channel,
		Epoch:     op.Epoch,
		Timeout:   s.o.HandshakeTimeout,
		Nonces:    s.nonces,
		Authorize: s.authorize,
	})
	if err != nil {
		code := wire.CodeAuthFailed
		if c, ok := wire.CodeOf(err); ok {
			code = c
		}
		s.refused.Add(1)
		ch.Close(code, err.Error())
		s.o.Logf("spagetti: channel %s refused: %v", op.Channel, err)
		return
	}
	s.handled.Add(1)
	s.o.Logf("spagetti: channel %s serving caller %s (%s)", op.Channel, peer.ID, peer.Fingerprint)
	if s.o.MaxChannelLifetime > 0 {
		timer := time.AfterFunc(s.o.MaxChannelLifetime, func() {
			ch.Close(wire.CodeTimeout, "channel lifetime expired: re-authenticate")
		})
		defer timer.Stop()
	}
	s.serveChannel(conn, peer)
}

// authorize adapts the caller's policy hook to the handshake layer.
func (s *instance) authorize(peer Peer) error {
	if s.o.AllowClient == nil {
		return nil
	}
	if !s.o.AllowClient(peer) {
		s.refused.Add(1)
		s.o.Logf("spagetti: caller %s (%s) refused by policy", peer.ID, peer.Fingerprint)
		return &wire.Error{Code: wire.CodeNotAllowed, Msg: "caller not allowed"}
	}
	return nil
}

func (s *instance) serveChannel(conn *e2e.Conn, peer Peer) {
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.o.Handler.ServeHTTP(w, r.WithContext(e2e.WithPeer(r.Context(), peer)))
		}),
		ReadHeaderTimeout: DefaultReadHeaderTimeout,
		ErrorLog:          log.New(&logBridge{s.o.Logf}, "", 0),
	}
	// One listener per channel: the wrapped handler sees a normal HTTP server.
	// The channel's death is the authoritative end-of-life signal — it covers
	// idle keep-alive connections and hijacked websockets alike.
	l := newOneShotListener(conn)
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(l) }()
	select {
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			s.o.Logf("spagetti: channel %s ended: %v", conn.Channel().ID(), err)
		}
	case <-conn.Channel().Done():
		l.Close()
		srv.Close()
		<-errc
	}
	conn.Close()
}

type logBridge struct{ logf func(string, ...any) }

func (l *logBridge) Write(p []byte) (int, error) {
	l.logf("spagetti: http: %s", strings.TrimSpace(string(p)))
	return len(p), nil
}

type oneShotListener struct {
	conn     net.Conn
	accepted atomic.Bool
	done     chan struct{}
	once     sync.Once
}

func newOneShotListener(conn net.Conn) *oneShotListener {
	return &oneShotListener{conn: conn, done: make(chan struct{})}
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if l.accepted.CompareAndSwap(false, true) {
		return l.conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneShotListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *oneShotListener) Addr() net.Addr { return l.conn.LocalAddr() }

var _ io.Closer = (*oneShotListener)(nil)

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func nextBackoff(cur, max time.Duration) time.Duration {
	next := cur * 2
	if next > max {
		next = max
	}
	return next
}
