package tests

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sannysanoff/spagetti/gateway"
	"github.com/sannysanoff/spagetti/server"
)

// logBuf captures a component's log lines so a test can assert on lifecycle
// events that have no other observable effect.
type logBuf struct {
	mu    sync.Mutex
	lines []string
}

func (l *logBuf) Logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logBuf) contains(sub string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, ln := range l.lines {
		if strings.Contains(ln, sub) {
			return true
		}
	}
	return false
}

func (l *logBuf) dump() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// waitFor polls until cond holds or the deadline passes.
func waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

// TestGatewayShutdownDisconnectsServer pins the property a gateway restart
// depends on: when the relay goes away, the peer must find out at once instead
// of sitting on a dead socket until some timeout expires.
func TestGatewayShutdownDisconnectsServer(t *testing.T) {
	confDir := t.TempDir()
	serverTok := randToken(t)
	clientTok := randToken(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()

	gw, err := gateway.New(gateway.Config{
		Tokens: []gateway.Token{
			{Name: "srv", Kind: "server", Token: serverTok, Allow: []string{"*"}},
			{Name: "cli", Kind: "client", Token: clientTok, Allow: []string{"*"}},
		},
		Logf: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	gwCtx, stopGW := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- gw.ServeListener(gwCtx, ln) }()

	srvLog := &logBuf{}
	srvCtx, stopServer := context.WithCancel(context.Background())
	defer stopServer()
	srvErr := make(chan error, 1)
	go func() {
		srvErr <- server.Serve(srvCtx, server.Options{
			GatewayURL:   "ws://" + addr + "/ws",
			Token:        serverTok,
			ServerID:     "web1",
			ConfDir:      confDir,
			Handler:      http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
			ReconnectMin: 25 * time.Millisecond,
			ReconnectMax: 100 * time.Millisecond,
			Logf:         srvLog.Logf,
		})
	}()

	if !waitFor(10*time.Second, func() bool {
		for _, e := range gw.ServerList() {
			if e.ServerID == "web1" && e.Online {
				return true
			}
		}
		return false
	}) {
		t.Fatalf("server never registered:\n%s", srvLog.dump())
	}

	start := time.Now()
	stopGW()
	ln.Close()
	if err := <-served; err != nil {
		t.Fatalf("ServeListener returned %v", err)
	}

	if !waitFor(3*time.Second, func() bool { return srvLog.contains("gateway connection lost") }) {
		t.Fatalf("the server did not notice the gateway shutdown within 3s; log:\n%s", srvLog.dump())
	}
	t.Logf("server noticed the shutdown after %s", time.Since(start).Round(time.Millisecond))

	// And it must keep trying, so a gateway that comes back is picked up.
	ln2, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("could not rebind %s (%v); skipping the return leg", addr, err)
	}
	defer ln2.Close()
	gw2, err := gateway.New(gateway.Config{
		Tokens: []gateway.Token{
			{Name: "srv", Kind: "server", Token: serverTok, Allow: []string{"*"}},
			{Name: "cli", Kind: "client", Token: clientTok, Allow: []string{"*"}},
		},
		Logf: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	gw2Ctx, stopGW2 := context.WithCancel(context.Background())
	defer stopGW2()
	go func() { _ = gw2.ServeListener(gw2Ctx, ln2) }()

	start = time.Now()
	if !waitFor(5*time.Second, func() bool {
		for _, e := range gw2.ServerList() {
			if e.ServerID == "web1" && e.Online {
				return true
			}
		}
		return false
	}) {
		t.Fatalf("the server never came back to the replacement gateway; log:\n%s", srvLog.dump())
	}
	t.Logf("server re-registered after %s", time.Since(start).Round(time.Millisecond))

	stopServer()
	select {
	case err := <-srvErr:
		if err != nil {
			t.Fatalf("server.Serve returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server.Serve did not stop")
	}
}

// dumpGoroutines is a diagnostic helper for tests that would otherwise fail
// silently when a component stops making progress.
func dumpGoroutines() string {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return string(buf[:n])
}

// TestListenerCloseDisconnectsPeers covers the other way a gateway can go away:
// the listener is closed without the context being cancelled first. The relay
// must still disconnect its peers — http.Server.Serve returns a bare
// "closed network connection" error on that path, which is easy to mistake for
// a fatal error and skip the cleanup for.
func TestListenerCloseDisconnectsPeers(t *testing.T) {
	confDir := t.TempDir()
	serverTok := randToken(t)
	clientTok := randToken(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gw, err := gateway.New(gateway.Config{
		Tokens: []gateway.Token{
			{Name: "srv", Kind: "server", Token: serverTok, Allow: []string{"*"}},
			{Name: "cli", Kind: "client", Token: clientTok, Allow: []string{"*"}},
		},
		Logf: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	gwCtx, stopGW := context.WithCancel(context.Background())
	defer stopGW()
	go func() { _ = gw.ServeListener(gwCtx, ln) }()

	srvLog := &logBuf{}
	srvCtx, stopServer := context.WithCancel(context.Background())
	defer stopServer()
	go func() {
		_ = server.Serve(srvCtx, server.Options{
			GatewayURL:   "ws://" + ln.Addr().String() + "/ws",
			Token:        serverTok,
			ServerID:     "web1",
			ConfDir:      confDir,
			Handler:      http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
			ReconnectMin: 25 * time.Millisecond,
			ReconnectMax: 100 * time.Millisecond,
			Logf:         srvLog.Logf,
		})
	}()

	if !waitFor(10*time.Second, func() bool {
		for _, e := range gw.ServerList() {
			if e.ServerID == "web1" && e.Online {
				return true
			}
		}
		return false
	}) {
		t.Fatalf("server never registered:\n%s", srvLog.dump())
	}

	// The listener dies without the context being cancelled: the gateway must
	// still tear the sessions down.
	ln.Close()
	if !waitFor(3*time.Second, func() bool { return srvLog.contains("gateway connection lost") }) {
		t.Fatalf("the server was left on a dead gateway; log:\n%s", srvLog.dump())
	}
}
