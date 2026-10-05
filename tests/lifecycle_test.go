package tests

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/sannysanoff/spagetti/client"
	"github.com/sannysanoff/spagetti/conf"
	"github.com/sannysanoff/spagetti/gateway"
	"github.com/sannysanoff/spagetti/server"
	"github.com/sannysanoff/spagetti/tunnel"
)

// TestGatewayConnectionSurvivesIdlePeriod guards a bug where the handshake read
// deadline was left on the gateway connection: a long-lived server died once the
// handshake timeout expired, taking every live channel with it.
func TestGatewayConnectionSurvivesIdlePeriod(t *testing.T) {
	h := startHarn(t, echoHandler(),
		withGatewayConfig(func(c *gateway.Config) { c.PingInterval = 100 * time.Millisecond }),
		withServerOptions(func(o *server.Options) {
			o.TunnelOptions = func(to *tunnel.Options) {
				to.HelloTimeout = 300 * time.Millisecond
				to.IdleTimeout = 2 * time.Second
			}
		}))
	// Sit idle for longer than the handshake timeout would have allowed.
	time.Sleep(1500 * time.Millisecond)
	h.waitOnline(2 * time.Second)
	c := h.client()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", h.url("/"), nil)
	resp, err := c.HTTPClient(h.serverID).Do(req)
	if err != nil {
		t.Fatalf("call after an idle period: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || len(body) == 0 {
		t.Fatalf("unexpected response %d %q", resp.StatusCode, body)
	}
}

// TestServerReconnectsAfterGatewayRestart walks the whole lifecycle: a server
// registers, the gateway disappears, the server notices and re-registers on its
// own once a gateway is back on the same address.
func TestServerReconnectsAfterGatewayRestart(t *testing.T) {
	confDir := t.TempDir()
	serverToken, clientToken := randToken(t), randToken(t)
	const serverID = "web1"

	mkGateway := func(t *testing.T, ln net.Listener) (*gateway.Gateway, context.CancelFunc) {
		t.Helper()
		gw, err := gateway.New(gateway.Config{
			Tokens: []gateway.Token{
				{Name: "srv", Kind: "server", Token: serverToken, Allow: []string{"*"}},
				{Name: "cli", Kind: "client", Token: clientToken, Allow: []string{"*"}},
			},
			Logf: func(format string, args ...any) { t.Logf("gw: "+format, args...) },
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() { gw.ServeListener(ctx, ln) }()
		return gw, cancel
	}

	// First gateway.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	wsURL := "ws://" + addr + "/ws"
	gw1, stop1 := mkGateway(t, ln)
	t.Cleanup(stop1)

	srvCtx, stopServer := context.WithCancel(context.Background())
	srvErr := make(chan error, 1)
	go func() {
		srvErr <- server.Serve(srvCtx, server.Options{
			GatewayURL:   wsURL,
			Token:        serverToken,
			ServerID:     serverID,
			ConfDir:      confDir,
			Handler:      http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") }),
			ReconnectMin: 50 * time.Millisecond,
			ReconnectMax: 200 * time.Millisecond,
			Logf:         func(format string, args ...any) { t.Logf("srv: "+format, args...) },
		})
	}()
	t.Cleanup(func() {
		stopServer()
		select {
		case <-srvErr:
		case <-time.After(5 * time.Second):
			t.Error("server.Serve did not stop")
		}
	})

	waitListed := func(gw *gateway.Gateway, d time.Duration) {
		t.Helper()
		deadline := time.Now().Add(d)
		for time.Now().Before(deadline) {
			for _, e := range gw.ServerList() {
				if e.ServerID == serverID && e.Online {
					return
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("server %q never registered; goroutines:\n%s", serverID, dumpGoroutines())
	}
	waitListed(gw1, 10*time.Second)

	// Pin the generated files for a client, as an operator would.
	serverDir := conf.ServerDir(confDir, serverID)
	pub, err := conf.LoadPub(filepath.Join(serverDir, conf.PubFile))
	if err != nil {
		t.Fatal(err)
	}
	pw, err := conf.LoadPassword(filepath.Join(serverDir, conf.PasswordFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conf.SavePeer(confDir, serverID, pub, pw); err != nil {
		t.Fatal(err)
	}
	c, err := client.New(client.Options{
		GatewayURL: wsURL, Token: clientToken, ConfDir: confDir, ClientID: "caller",
		Logf: func(format string, args ...any) { t.Logf("cli: "+format, args...) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	call := func() error {
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+serverID+"/", nil)
		resp, err := c.HTTPClient(serverID).Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		return nil
	}
	if err := call(); err != nil {
		t.Fatalf("call before the restart: %v", err)
	}

	// Take the gateway away.
	stop1()
	ln.Close()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if err := call(); err != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Bring a fresh gateway up on the same address.
	var ln2 net.Listener
	for i := 0; i < 100; i++ {
		ln2, err = net.Listen("tcp", addr)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if ln2 == nil {
		t.Fatalf("could not rebind %s: %v", addr, err)
	}
	gw2, stop2 := mkGateway(t, ln2)
	defer stop2()
	waitListed(gw2, 15*time.Second)

	if err := call(); err != nil {
		t.Fatalf("call after the gateway came back: %v", err)
	}
}
