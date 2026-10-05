// Package gateway is the relay: a public rendezvous that servers dial out to and
// clients connect to. It routes opaque frames between the two by routing label,
// enforces bearer admission and per-token scope, and never holds a key or a
// plaintext byte.
//
// What the gateway knows: which server ids are online, which client opened which
// channel to which server, when, and how many bytes moved. What it cannot do:
// read, modify or forge anything inside a channel — that is end-to-end
// authenticated (see package e2e), and the trust-boundary test asserts that this
// package's dependency graph contains no crypto code.
package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/sannysanoff/spagetti/wire"
)

// Defaults for Config fields left zero.
const (
	DefaultMaxChannelsPerClient = 64
	DefaultPingInterval         = 25 * time.Second
	DefaultIdleTimeout          = 90 * time.Second
	DefaultMaxOutBuffer         = int64(4 << 20)
	DefaultOpenTimeout          = 15 * time.Second
	DefaultOpenRatePerSec       = 50
	DefaultOpenBurst            = 100
	DefaultWriteTimeout         = 30 * time.Second
)

// Config configures a gateway.
type Config struct {
	Tokens []Token

	// Logf receives one line per routing event. It is never given payloads.
	Logf func(format string, args ...any)

	MaxChannelsPerClient int
	MaxFrame             int
	PingInterval         time.Duration
	IdleTimeout          time.Duration
	MaxOutBuffer         int64
	OpenTimeout          time.Duration
	OpenRatePerSec       float64
	OpenBurst            int
}

func (c *Config) setDefaults() {
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
	if c.MaxChannelsPerClient <= 0 {
		c.MaxChannelsPerClient = DefaultMaxChannelsPerClient
	}
	if c.MaxFrame <= 0 {
		c.MaxFrame = wire.MaxFrame
	}
	if c.PingInterval <= 0 {
		c.PingInterval = DefaultPingInterval
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = DefaultIdleTimeout
	}
	if c.MaxOutBuffer <= 0 {
		c.MaxOutBuffer = DefaultMaxOutBuffer
	}
	if c.OpenTimeout <= 0 {
		c.OpenTimeout = DefaultOpenTimeout
	}
	if c.OpenRatePerSec <= 0 {
		c.OpenRatePerSec = DefaultOpenRatePerSec
	}
	if c.OpenBurst <= 0 {
		c.OpenBurst = DefaultOpenBurst
	}
}

func seconds(n int) time.Duration {
	if n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}

// Gateway is a running relay.
type Gateway struct {
	cfg Config

	mu      sync.Mutex
	tokens  *tokenStore
	servers map[string]*session
	routes  map[wire.Channel]*route
	all     map[*session]struct{}

	upgrader websocket.Upgrader

	opened   atomic.Int64
	refused  atomic.Int64
	served   atomic.Int64
	sessions atomic.Int64
}

type route struct {
	ch       wire.Channel
	serverID string
	client   *session
	server   *session
	opened   time.Time
	acked    bool
	timer    *time.Timer
}

// New builds a gateway from a configuration.
func New(cfg Config) (*Gateway, error) {
	cfg.setDefaults()
	st, err := newTokenStore(cfg.Tokens)
	if err != nil {
		return nil, err
	}
	return &Gateway{
		cfg:     cfg,
		tokens:  st,
		servers: map[string]*session{},
		routes:  map[wire.Channel]*route{},
		all:     map[*session]struct{}{},
		upgrader: websocket.Upgrader{
			HandshakeTimeout:  10 * time.Second,
			ReadBufferSize:    32 << 10,
			WriteBufferSize:   32 << 10,
			EnableCompression: false, // compression on ciphertext leaks size, and buys nothing
			CheckOrigin:       func(*http.Request) bool { return true },
		},
	}, nil
}

// Handler returns the gateway's HTTP surface: /ws for peers, /servers for a
// bearer-authenticated directory listing, /healthz for liveness.
func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", g.handleWS)
	mux.HandleFunc("/servers", g.handleServers)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "ok")
	})
	return mux
}

// Run serves the gateway on addr until ctx is cancelled.
func (g *Gateway) Run(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return g.ServeListener(ctx, ln)
}

// ServeListener serves the gateway on an already-bound listener. The actual
// address is logged, so addr may use port 0.
func (g *Gateway) ServeListener(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           g.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()
	g.cfg.Logf("gateway: listening on %s", ln.Addr())
	// Whatever ends Serve — a cancelled context or the listener being closed
	// under us — the peers must be disconnected, or they sit on a relay that is
	// already gone and never reconnect.
	defer g.Close()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

// Close disconnects every peer session and unblocks their channels.
func (g *Gateway) Close() {
	g.mu.Lock()
	sessions := make([]*session, 0, len(g.all))
	for s := range g.all {
		sessions = append(sessions, s)
	}
	g.mu.Unlock()
	for _, s := range sessions {
		s.shutdown(&wire.Error{Code: wire.CodePeerGone, Msg: "gateway is shutting down"})
	}
}

func (g *Gateway) track(s *session, add bool) {
	g.mu.Lock()
	if add {
		g.all[s] = struct{}{}
	} else {
		delete(g.all, s)
	}
	g.mu.Unlock()
}

// ServerList reports the current directory.
func (g *Gateway) ServerList() []wire.ServerEntry {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.listLocked()
}

func (g *Gateway) listLocked() []wire.ServerEntry {
	out := make([]wire.ServerEntry, 0, len(g.servers))
	for id, s := range g.servers {
		out = append(out, wire.ServerEntry{
			ServerID:    id,
			Name:        s.name,
			Tags:        append([]string(nil), s.tags...),
			PubKey:      append([]byte(nil), s.pub...),
			Fingerprint: s.fingerprint,
			Online:      true,
			ConnectedAt: s.connectedAt,
			Channels:    len(s.channels),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ServerID < out[j].ServerID })
	return out
}

func (g *Gateway) handleServers(w http.ResponseWriter, r *http.Request) {
	if _, ok := g.tokens.find(bearer(r)); !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	type entry struct {
		ID          string    `json:"id"`
		Name        string    `json:"name"`
		Tags        []string  `json:"tags,omitempty"`
		Fingerprint string    `json:"fingerprint,omitempty"`
		PublicKey   string    `json:"public_key,omitempty"`
		Online      bool      `json:"online"`
		ConnectedAt time.Time `json:"connected_at,omitempty"`
		Channels    int       `json:"channels"`
	}
	g.mu.Lock()
	entries := g.listLocked()
	g.mu.Unlock()
	out := make([]entry, 0, len(entries))
	for _, e := range entries {
		out = append(out, entry{
			ID: e.ServerID, Name: e.Name, Tags: e.Tags, Fingerprint: e.Fingerprint,
			PublicKey: fmt.Sprintf("%x", e.PubKey), Online: e.Online,
			ConnectedAt: e.ConnectedAt, Channels: e.Channels,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"servers": out})
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) > len(prefix) && h[:len(prefix)] == prefix {
		return h[len(prefix):]
	}
	return ""
}

func (g *Gateway) handleWS(w http.ResponseWriter, r *http.Request) {
	tok, ok := g.tokens.find(bearer(r))
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ws, err := g.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return // Upgrade already answered
	}
	ws.SetReadLimit(int64(g.cfg.MaxFrame))
	s := newSession(g, ws, tok)
	g.sessions.Add(1)
	g.served.Add(1)
	g.track(s, true)
	go s.writeLoop()
	go s.watchdog()
	s.readLoop()
}

// ---------------------------------------------------------------------------
// sessions

type session struct {
	g    *Gateway
	ws   *websocket.Conn
	tok  resolvedToken
	kind wire.Kind
	id   string

	name        string
	tags        []string
	pub         []byte
	fingerprint string
	connectedAt time.Time

	out      chan []byte
	outBytes atomic.Int64

	mu       sync.Mutex
	channels map[wire.Channel]struct{}
	helloT   bool
	reged    bool
	dead     bool
	err      error

	lastSeen atomic.Int64
	done     chan struct{}
	once     sync.Once
	opens    *rateLimiter
}

func newSession(g *Gateway, ws *websocket.Conn, tok resolvedToken) *session {
	return &session{
		g:        g,
		ws:       ws,
		tok:      tok,
		kind:     tok.kind,
		channels: map[wire.Channel]struct{}{},
		out:      make(chan []byte, 256),
		done:     make(chan struct{}),
		opens:    newRateLimiter(g.cfg.OpenRatePerSec, float64(g.cfg.OpenBurst)),
	}
}

func (s *session) enqueue(b []byte) error {
	if s.outBytes.Load() > s.g.cfg.MaxOutBuffer {
		err := &wire.Error{Code: wire.CodeOverload, Msg: "relay buffer full"}
		s.shutdown(err)
		return err
	}
	select {
	case s.out <- b:
		s.outBytes.Add(int64(len(b)))
		return nil
	case <-s.done:
		return s.Err()
	}
}

func (s *session) send(f wire.Frame) error {
	b, err := f.Encode()
	if err != nil {
		return err
	}
	return s.enqueue(b)
}

func (s *session) writeLoop() {
	for {
		select {
		case b := <-s.out:
			if err := s.flush(b); err != nil {
				s.ws.Close()
				s.shutdown(err)
				return
			}
		case <-s.done:
			// Flush what is already queued (a refusal must reach the peer before
			// the socket goes away), then close.
			for {
				select {
				case b := <-s.out:
					if err := s.flush(b); err != nil {
						s.ws.Close()
						return
					}
				default:
					s.ws.Close()
					return
				}
			}
		}
	}
}

func (s *session) flush(b []byte) error {
	s.outBytes.Add(-int64(len(b)))
	s.ws.SetWriteDeadline(time.Now().Add(DefaultWriteTimeout))
	if err := s.ws.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return fmt.Errorf("spagetti: write to %s %q: %w", s.kind, s.id, err)
	}
	return nil
}

func (s *session) watchdog() {
	t := time.NewTicker(s.g.cfg.PingInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if time.Since(time.Unix(0, s.lastSeen.Load())) > s.g.cfg.IdleTimeout {
				s.shutdown(&wire.Error{Code: wire.CodeTimeout, Msg: "idle"})
				return
			}
			if err := s.send(wire.Frame{Type: wire.TPing, Nonce: uint64(time.Now().UnixNano())}); err != nil {
				return
			}
		case <-s.done:
			return
		}
	}
}

func (s *session) readLoop() {
	deadline := s.g.cfg.IdleTimeout
	for {
		s.ws.SetReadDeadline(time.Now().Add(deadline))
		_, b, err := s.ws.ReadMessage()
		if err != nil {
			s.shutdown(fmt.Errorf("spagetti: read from %s %q: %w", s.kind, s.id, err))
			return
		}
		s.lastSeen.Store(time.Now().UnixNano())
		if len(b) > s.g.cfg.MaxFrame {
			s.shutdown(&wire.Error{Code: wire.CodeMalformed, Msg: "frame too large"})
			return
		}
		f, err := wire.Parse(b)
		if err != nil {
			s.shutdown(fmt.Errorf("spagetti: %s %q sent an unparseable frame: %w", s.kind, s.id, err))
			return
		}
		if err := s.handle(f, b); err != nil {
			s.g.cfg.Logf("gateway: %s %q: %v", s.kind, s.id, err)
		}
	}
}

func (s *session) handle(f wire.Frame, raw []byte) error {
	switch f.Type {
	case wire.THello:
		if s.helloT {
			return errors.New("duplicate hello")
		}
		if f.Hello.Kind != s.tok.kind {
			s.send(wire.Frame{Type: wire.THelloAck, Refuse: wire.Refuse{
				Code: wire.CodeNotAllowed, Message: "token is not issued for this role",
			}})
			s.shutdown(&wire.Error{Code: wire.CodeNotAllowed, Msg: "role mismatch"})
			return nil
		}
		if f.Hello.ID == "" {
			s.send(wire.Frame{Type: wire.THelloAck, Refuse: wire.Refuse{
				Code: wire.CodeNotAllowed, Message: "identity required",
			}})
			s.shutdown(&wire.Error{Code: wire.CodeNotAllowed, Msg: "identity required"})
			return nil
		}
		if s.tok.kind == wire.KindServer && !s.tok.allows(f.Hello.ID) {
			s.send(wire.Frame{Type: wire.THelloAck, Refuse: wire.Refuse{
				Code: wire.CodeNotAllowed, Message: "token does not allow this server id",
			}})
			s.shutdown(&wire.Error{Code: wire.CodeNotAllowed, Msg: "server id not allowed by token"})
			return nil
		}
		s.helloT = true
		s.id = f.Hello.ID
		s.pub = append([]byte(nil), f.Hello.PubKey...)
		return s.send(wire.Frame{Type: wire.THelloAck})
	case wire.TRegister:
		if !s.helloT || s.kind != wire.KindServer {
			return errors.New("register from an unregistered role")
		}
		if f.Register.ServerID != s.id || !s.tok.allows(f.Register.ServerID) {
			s.send(wire.Frame{Type: wire.TRegisterAck, Refuse: wire.Refuse{
				Code: wire.CodeNotAllowed, Message: "server id not allowed",
			}})
			s.shutdown(&wire.Error{Code: wire.CodeNotAllowed, Msg: "register id not allowed"})
			return nil
		}
		s.name = f.Register.Name
		s.tags = f.Register.Tags
		s.pub = append([]byte(nil), f.Register.PubKey...)
		s.fingerprint = f.Register.Fingerprint
		s.connectedAt = time.Now()
		s.reged = true
		s.g.registerServer(s)
		if err := s.send(wire.Frame{Type: wire.TRegisterAck}); err != nil {
			return err
		}
		s.g.cfg.Logf("gateway: server online id=%s name=%q tags=%v", s.id, s.name, s.tags)
		return nil
	case wire.TListReq:
		if !s.helloT {
			return errors.New("list before hello")
		}
		s.g.mu.Lock()
		entries := s.g.listLocked()
		s.g.mu.Unlock()
		return s.send(wire.Frame{Type: wire.TListResp, Entries: entries})
	case wire.TOpen:
		if !s.helloT || s.tok.kind != wire.KindClient {
			return errors.New("open from a non-client connection")
		}
		s.g.handleOpen(s, f, raw)
		return nil
	case wire.TOpenOK, wire.TOpenRefused:
		if !s.reged {
			return errors.New("channel answer from a connection that is not a registered server")
		}
		s.g.handleChannelAnswer(s, f, raw)
		return nil
	case wire.TData, wire.TClose:
		if !s.helloT {
			return errors.New("channel traffic before hello")
		}
		s.g.handleChannelTraffic(s, f, raw)
		return nil
	case wire.TPing:
		return s.send(wire.Frame{Type: wire.TPong, Nonce: f.Nonce})
	case wire.TPong:
		return nil
	case wire.THelloAck, wire.TRegisterAck, wire.TListResp:
		return fmt.Errorf("unexpected %s from a peer", f.Type)
	}
	return nil
}

func (g *Gateway) registerServer(s *session) {
	g.mu.Lock()
	old := g.servers[s.id]
	g.servers[s.id] = s
	g.mu.Unlock()
	if old != nil && old != s {
		g.cfg.Logf("gateway: replacing stale session for server id=%s", s.id)
		old.shutdown(&wire.Error{Code: wire.CodePeerGone, Msg: "replaced by a newer registration"})
	}
}

func (g *Gateway) handleOpen(s *session, f wire.Frame, raw []byte) {
	ch := f.Open.Channel
	refuse := func(code wire.Code, msg string) {
		g.refused.Add(1)
		s.send(wire.Frame{Type: wire.TOpenRefused, Refuse: wire.Refuse{Channel: ch, Code: code, Message: msg}})
		g.cfg.Logf("gateway: refused open client=%s server=%s ch=%s code=%s", s.id, f.Open.ServerID, ch, code)
	}
	if !s.tok.allows(f.Open.ServerID) {
		refuse(wire.CodeNotAllowed, "token does not allow this server id")
		return
	}
	if !s.opens.allow() {
		refuse(wire.CodeOverload, "channel open rate exceeded")
		return
	}
	g.mu.Lock()
	srv := g.servers[f.Open.ServerID]
	switch {
	case srv == nil:
		g.mu.Unlock()
		refuse(wire.CodeServerOffline, "server is not connected")
		return
	}
	if _, dup := g.routes[ch]; dup {
		g.mu.Unlock()
		refuse(wire.CodeDuplicateChannel, "channel label already in use")
		return
	}
	if len(s.channels) >= g.cfg.MaxChannelsPerClient {
		g.mu.Unlock()
		refuse(wire.CodeTooManyChannels, "too many channels for this client")
		return
	}
	r := &route{ch: ch, serverID: f.Open.ServerID, client: s, server: srv, opened: time.Now()}
	g.routes[ch] = r
	s.channels[ch] = struct{}{}
	srv.channels[ch] = struct{}{}
	// The expiry timer is created under the lock: removeRoute reads r.timer
	// under the same lock, so the route must not become visible before the
	// timer field is set.
	r.timer = time.AfterFunc(g.cfg.OpenTimeout, func() {
		g.removeRoute(ch, true, wire.CodeTimeout, "server did not answer the open request")
	})
	g.mu.Unlock()

	if err := srv.enqueue(raw); err != nil {
		g.removeRoute(ch, true, wire.CodeServerOffline, "server connection lost")
		return
	}
	g.opened.Add(1)
	g.cfg.Logf("gateway: channel open client=%s server=%s ch=%s", s.id, f.Open.ServerID, ch)
}

func (g *Gateway) handleChannelAnswer(s *session, f wire.Frame, raw []byte) {
	ch := f.Refuse.Channel
	g.mu.Lock()
	r := g.routes[ch]
	if r == nil || r.server != s {
		g.mu.Unlock()
		return
	}
	if r.timer != nil {
		r.timer.Stop()
	}
	r.acked = true
	client := r.client
	g.mu.Unlock()
	client.enqueue(raw)
	if f.Type == wire.TOpenRefused {
		g.removeRoute(ch, false, f.Refuse.Code, f.Refuse.Message)
		g.cfg.Logf("gateway: server %s refused ch=%s code=%s", s.id, ch, f.Refuse.Code)
	}
}

func (g *Gateway) handleChannelTraffic(s *session, f wire.Frame, raw []byte) {
	var ch wire.Channel
	switch f.Type {
	case wire.TData:
		ch = f.Data.Channel
	case wire.TClose:
		ch = f.Close.Channel
	}
	g.mu.Lock()
	r := g.routes[ch]
	if r == nil || (r.client != s && r.server != s) {
		g.mu.Unlock()
		s.send(wire.Frame{Type: wire.TClose, Close: wire.Close{
			Channel: ch, Code: wire.CodeProtocolError, Message: "no such channel on this connection",
		}})
		return
	}
	peer := r.server
	if peer == s {
		peer = r.client
	}
	g.mu.Unlock()
	peer.enqueue(raw)
	if f.Type == wire.TClose {
		code := f.Close.Code
		g.removeRoute(ch, false, code, f.Close.Message)
		g.cfg.Logf("gateway: channel closed ch=%s by=%s code=%s", ch, s.id, code)
	}
}

// removeRoute drops a route. When notify is set, the surviving participant is
// told the channel is gone with a transport-level close: the gateway reports its
// own routing failures, never a server's verdict.
func (g *Gateway) removeRoute(ch wire.Channel, notify bool, code wire.Code, msg string) {
	g.mu.Lock()
	r := g.routes[ch]
	if r == nil {
		g.mu.Unlock()
		return
	}
	delete(g.routes, ch)
	delete(r.client.channels, ch)
	delete(r.server.channels, ch)
	if r.timer != nil {
		r.timer.Stop()
	}
	g.mu.Unlock()
	if !notify {
		return
	}
	frame := wire.Frame{Type: wire.TClose, Close: wire.Close{Channel: ch, Code: code, Message: msg}}
	for _, s := range []*session{r.client, r.server} {
		select {
		case <-s.done:
		default:
			s.send(frame)
		}
	}
}

func (s *session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err == nil {
		return &wire.Error{Code: wire.CodePeerGone, Msg: "connection closed"}
	}
	return s.err
}

func (s *session) shutdown(err error) {
	s.once.Do(func() {
		s.mu.Lock()
		s.dead = true
		s.err = err
		s.mu.Unlock()
		close(s.done)
		s.g.sessions.Add(-1)
		s.g.track(s, false)
		if s.helloT {
			s.g.cfg.Logf("gateway: %s %q session ended: %v", s.kind, s.id, err)
		}
		s.g.dropSession(s)
	})
}

func (g *Gateway) dropSession(s *session) {
	type notify struct {
		s    *session
		ch   wire.Channel
		code wire.Code
	}
	var notes []notify
	g.mu.Lock()
	if g.servers[s.id] == s {
		delete(g.servers, s.id)
		g.cfg.Logf("gateway: server offline id=%s", s.id)
	}
	for ch, r := range g.routes {
		if r.client != s && r.server != s {
			continue
		}
		peer := r.server
		if r.server == s {
			peer = r.client
		}
		delete(g.routes, ch)
		delete(r.client.channels, ch)
		delete(r.server.channels, ch)
		if r.timer != nil {
			r.timer.Stop()
		}
		notes = append(notes, notify{s: peer, ch: ch, code: wire.CodePeerGone})
	}
	g.mu.Unlock()
	for _, n := range notes {
		n.s.send(wire.Frame{Type: wire.TClose, Close: wire.Close{
			Channel: n.ch, Code: n.code, Message: "channel peer disconnected",
		}})
	}
}

// Stats reports gateway counters, for tests and operators.
func (g *Gateway) Stats() (sessions, servers, routes, opened, refused int64) {
	g.mu.Lock()
	r := int64(len(g.routes))
	srv := int64(len(g.servers))
	g.mu.Unlock()
	return g.sessions.Load(), srv, r, g.opened.Load(), g.refused.Load()
}

type rateLimiter struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newRateLimiter(rate, burst float64) *rateLimiter {
	return &rateLimiter{rate: rate, burst: burst, tokens: burst, last: time.Now()}
}

func (l *rateLimiter) allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.tokens += now.Sub(l.last).Seconds() * l.rate
	l.last = now
	if l.tokens > l.burst {
		l.tokens = l.burst
	}
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}
