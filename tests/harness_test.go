package tests

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sannysanoff/spagetti/client"
	"github.com/sannysanoff/spagetti/conf"
	"github.com/sannysanoff/spagetti/e2e"
	"github.com/sannysanoff/spagetti/gateway"
	"github.com/sannysanoff/spagetti/server"
)

// harn is a live gateway + wrapped server, with the pin/password handed to the
// client through the real files, exactly as a human would copy them.
type harn struct {
	t         *testing.T
	confDir   string
	serverID  string
	gw        *gateway.Gateway
	gwWS      string
	gwHTTP    string
	serverTok string
	clientTok string
	pub       []byte
	password  []byte

	hits    *atomic.Int64
	peers   *peerLog
	cancel  context.CancelFunc
	srvErr  chan error
	srvOpts func(*server.Options)
	started time.Time
	stopped bool
}

type peerLog struct {
	mu    sync.Mutex
	peers []e2e.Peer
}

func (p *peerLog) add(peer e2e.Peer) {
	p.mu.Lock()
	p.peers = append(p.peers, peer)
	p.mu.Unlock()
}

func (p *peerLog) last() (e2e.Peer, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.peers) == 0 {
		return e2e.Peer{}, false
	}
	return p.peers[len(p.peers)-1], true
}

func randToken(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

type harnOpt func(*harn, *gateway.Config)

// withGatewayConfig tunes the gateway before it starts.
func withGatewayConfig(f func(*gateway.Config)) harnOpt {
	return func(_ *harn, c *gateway.Config) { f(c) }
}

// withClientScope narrows which server ids the client token may reach.
func withClientScope(ids ...string) harnOpt {
	return func(_ *harn, c *gateway.Config) {
		for i := range c.Tokens {
			if c.Tokens[i].Kind == "client" {
				c.Tokens[i].Allow = ids
			}
		}
	}
}

// withServerAllow widens which server ids the server token may register.
func withServerAllow(ids ...string) harnOpt {
	return func(_ *harn, c *gateway.Config) {
		for i := range c.Tokens {
			if c.Tokens[i].Kind == "server" {
				c.Tokens[i].Allow = ids
			}
		}
	}
}

// withServerOptions tunes the wrapped server.
func withServerOptions(f func(*server.Options)) harnOpt {
	return func(h *harn, _ *gateway.Config) { h.srvOpts = f }
}

func startHarn(t *testing.T, handler http.Handler, opts ...harnOpt) *harn {
	t.Helper()
	h := &harn{
		t:         t,
		confDir:   t.TempDir(),
		serverID:  "web1",
		serverTok: randToken(t),
		clientTok: randToken(t),
		hits:      &atomic.Int64{},
		peers:     &peerLog{},
		srvErr:    make(chan error, 1),
		started:   time.Now(),
	}
	if handler == nil {
		handler = h.defaultHandler()
	}
	cfg := gateway.Config{
		Tokens: []gateway.Token{
			{Name: "srv", Kind: "server", Token: h.serverTok, Allow: []string{h.serverID}},
			{Name: "cli", Kind: "client", Token: h.clientTok, Allow: []string{"*"}},
		},
		Logf: func(format string, args ...any) { t.Logf("gw: "+format, args...) },
	}
	for _, o := range opts {
		if o != nil {
			o(h, &cfg)
		}
	}
	gw, err := gateway.New(cfg)
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	h.gw = gw
	ts := httptest.NewServer(gw.Handler())
	t.Cleanup(ts.Close)
	h.gwWS = "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	h.gwHTTP = ts.URL

	// Count every request that reaches application code, whatever the handler is.
	counted := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.hits.Add(1)
		handler.ServeHTTP(w, r)
	})
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	srvOpts := server.Options{
		GatewayURL:         h.gwWS,
		Token:              h.serverTok,
		ServerID:           h.serverID,
		Name:               "web1",
		Tags:               []string{"test"},
		ConfDir:            h.confDir,
		Handler:            counted,
		EpochLifetime:      15 * time.Minute,
		MaxChannelLifetime: time.Hour,
		Logf:               func(format string, args ...any) { t.Logf("srv: "+format, args...) },
	}
	if h.srvOpts != nil {
		h.srvOpts(&srvOpts)
	}
	go func() { h.srvErr <- server.Serve(ctx, srvOpts) }()

	h.loadPin()
	h.waitOnline(10 * time.Second)
	t.Cleanup(func() { h.stop() })
	return h
}

// loadPin reads the files the server generated and pins them for the client, as
// the operator does by copying identity.pub and access.password across.
func (h *harn) loadPin() {
	h.t.Helper()
	dir := conf.ServerDir(h.confDir, h.serverID)
	// The server writes its enrolment on first run; wait for it to land.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(dir, conf.PasswordFile)); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	var err error
	h.pub, err = conf.LoadPub(filepath.Join(dir, conf.PubFile))
	if err != nil {
		h.t.Fatalf("load server pub: %v", err)
	}
	h.password, err = conf.LoadPassword(filepath.Join(dir, conf.PasswordFile))
	if err != nil {
		h.t.Fatalf("load server password: %v", err)
	}
	if _, err := conf.SavePeer(h.confDir, h.serverID, h.pub, h.password); err != nil {
		h.t.Fatalf("pin server: %v", err)
	}
}

func (h *harn) waitOnline(d time.Duration) {
	h.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		for _, e := range h.gw.ServerList() {
			if e.ServerID == h.serverID && e.Online {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatalf("server %q never came online at the gateway", h.serverID)
}

func (h *harn) waitOffline(d time.Duration) {
	h.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		online := false
		for _, e := range h.gw.ServerList() {
			if e.ServerID == h.serverID && e.Online {
				online = true
			}
		}
		if !online {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatalf("server %q never went offline", h.serverID)
}

func (h *harn) client(o ...func(*client.Options)) *client.Client {
	h.t.Helper()
	opts := client.Options{
		GatewayURL: h.gwWS,
		Token:      h.clientTok,
		ConfDir:    h.confDir,
		ClientID:   "caller",
		Logf:       func(format string, args ...any) { h.t.Logf("cli: "+format, args...) },
	}
	for _, f := range o {
		if f != nil {
			f(&opts)
		}
	}
	c, err := client.New(opts)
	if err != nil {
		h.t.Fatalf("client: %v", err)
	}
	h.t.Cleanup(func() { c.Close() })
	return c
}

func (h *harn) stop() {
	if h.stopped {
		return
	}
	h.stopped = true
	if h.cancel != nil {
		h.cancel()
	}
	select {
	case err := <-h.srvErr:
		if err != nil {
			h.t.Errorf("server.Serve returned %v", err)
		}
	case <-time.After(5 * time.Second):
		buf := make([]byte, 1<<16)
		n := runtime.Stack(buf, true)
		h.t.Errorf("server.Serve did not stop; goroutines:\n%s", buf[:n])
	}
}

func (h *harn) defaultHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if p, ok := server.PeerFromContext(r.Context()); ok {
			h.peers.add(p)
		}
		fmt.Fprintf(w, "handler reached: %s %s\n", r.Method, r.URL.Path)
	})
	return mux
}

func (h *harn) url(path string) string { return "http://" + h.serverID + path }

// epoch computes the current re-authentication epoch with the harness's server
// settings, so raw-protocol tests agree with the wrapped server.
func (h *harn) epoch() int64 { return time.Now().UnixNano() / int64(e2e.DefaultEpochLifetime) }
