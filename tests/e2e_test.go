package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/sannysanoff/spagetti/client"
	"github.com/sannysanoff/spagetti/server"
	"github.com/sannysanoff/spagetti/wire"
)

// echoHandler is a wrapped server with the endpoints the tests observe.
func echoHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "handler: %s %s?%s\n", r.Method, r.URL.Path, r.URL.RawQuery)
	})
	mux.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
		p, ok := server.PeerFromContext(r.Context())
		json.NewEncoder(w).Encode(map[string]any{
			"id": p.ID, "fingerprint": p.Fingerprint,
			"pubkey": hex.EncodeToString(p.PubKey), "authenticated": ok,
		})
	})
	mux.HandleFunc("/echo/body", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sum := sha256.Sum256(b)
		json.NewEncoder(w).Encode(map[string]any{
			"bytes": len(b), "sha256": hex.EncodeToString(sum[:]), "method": r.Method,
		})
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		f, _ := w.(http.Flusher)
		for i := 0; i < 5; i++ {
			fmt.Fprintf(w, "data: event %d\n\n", i)
			if f != nil {
				f.Flush()
			}
			time.Sleep(80 * time.Millisecond)
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
		if f != nil {
			f.Flush()
		}
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		chunk := bytes.Repeat([]byte("spagetti"), 4096)
		for i := 0; i < 8; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	})
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		for {
			mt, b, err := ws.ReadMessage()
			if err != nil {
				return
			}
			if err := ws.WriteMessage(mt, append([]byte("echo:"), b...)); err != nil {
				return
			}
		}
	})
	return mux
}

func TestListServers(t *testing.T) {
	h := startHarn(t, echoHandler(), nil)
	c := h.client()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	entries, err := c.ListServers(ctx)
	if err != nil {
		t.Fatalf("ListServers: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 server, got %+v", entries)
	}
	e := entries[0]
	if e.ServerID != h.serverID || !e.Online {
		t.Fatalf("unexpected entry %+v", e)
	}
	if e.Name != "web1" || len(e.Tags) != 1 || e.Tags[0] != "test" {
		t.Fatalf("metadata not registered: %+v", e)
	}
	if !bytes.Equal(e.PubKey, h.pub) {
		t.Fatalf("directory public key does not match the served key")
	}
}

func TestHTTPThroughTunnel(t *testing.T) {
	h := startHarn(t, echoHandler(), nil)
	c := h.client()
	hc := c.HTTPClient(h.serverID)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := hc.Get(h.url("/"))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "handler: GET /") {
		t.Fatalf("unexpected response %d %q", resp.StatusCode, body)
	}

	payload := []byte("hello spagetti")
	req, _ := http.NewRequestWithContext(ctx, "POST", h.url("/echo/body"), bytes.NewReader(payload))
	req.Header.Set("X-Canary", "canary-header-value")
	resp, err = hc.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	var got struct {
		Bytes  int    `json:"bytes"`
		SHA256 string `json:"sha256"`
		Method string `json:"method"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	resp.Body.Close()
	sum := sha256.Sum256(payload)
	if got.Bytes != len(payload) || got.SHA256 != hex.EncodeToString(sum[:]) || got.Method != "POST" {
		t.Fatalf("body did not survive the tunnel: %+v", got)
	}

	resp, err = hc.Get(h.url("/whoami"))
	if err != nil {
		t.Fatalf("whoami: %v", err)
	}
	var who struct {
		ID          string `json:"id"`
		Fingerprint string `json:"fingerprint"`
	}
	json.NewDecoder(resp.Body).Decode(&who)
	resp.Body.Close()
	if who.ID != "caller" {
		t.Fatalf("server did not see the authenticated caller id: %+v", who)
	}
	if len(c.Identity().Pub) == 0 {
		t.Fatal("client has no device key")
	}
}

func TestLargeBody(t *testing.T) {
	h := startHarn(t, echoHandler(), nil)
	c := h.client()
	payload := make([]byte, 3<<20)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	sum := sha256.Sum256(payload)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", h.url("/echo/body"), bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := c.HTTPClient(h.serverID).Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	var got struct {
		Bytes  int    `json:"bytes"`
		SHA256 string `json:"sha256"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Bytes != len(payload) || got.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("large body corrupted: %+v want %d bytes %s", got, len(payload), hex.EncodeToString(sum[:]))
	}

	// and the other direction: a large response
	req, _ = http.NewRequestWithContext(ctx, "GET", h.url("/big"), nil)
	resp, err = c.HTTPClient(h.serverID).Do(req)
	if err != nil {
		t.Fatalf("GET /big: %v", err)
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		t.Fatalf("read /big: %v", err)
	}
	if want := int64(8 * 8 * 4096); n != want {
		t.Fatalf("large response truncated: %d want %d", n, want)
	}
}

func TestSSEStreamsIncrementally(t *testing.T) {
	h := startHarn(t, echoHandler(), nil)
	c := h.client()
	start := time.Now()
	resp, err := c.HTTPClient(h.serverID).Get(h.url("/events"))
	if err != nil {
		t.Fatalf("GET /events: %v", err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content type %q", ct)
	}
	buf := make([]byte, 1024)
	var first time.Duration
	var total bytes.Buffer
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if first == 0 {
				first = time.Since(start)
			}
			total.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	elapsed := time.Since(start)
	if got := strings.Count(total.String(), "data: event"); got != 5 {
		t.Fatalf("want 5 events, got %d (%q)", got, total.String())
	}
	if !strings.Contains(total.String(), "[DONE]") {
		t.Fatalf("stream did not complete: %q", total.String())
	}
	if first >= elapsed/2 {
		t.Fatalf("stream looks buffered: first chunk at %s of %s total", first, elapsed)
	}
	t.Logf("first chunk at %s, total %s", first, elapsed)
}

func TestWebSocketThroughTunnel(t *testing.T) {
	h := startHarn(t, echoHandler(), nil)
	c := h.client()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ws, err := c.DialWS(ctx, h.serverID, "ws://"+h.serverID+"/ws", nil)
	if err != nil {
		t.Fatalf("DialWS: %v", err)
	}
	defer ws.Close()
	for i, msg := range []string{"one", "two"} {
		if err := ws.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		ws.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, b, err := ws.ReadMessage()
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if string(b) != "echo:"+msg {
			t.Fatalf("echo mismatch: %q", b)
		}
	}
}

func TestConcurrentChannels(t *testing.T) {
	h := startHarn(t, echoHandler(), nil)
	c := h.client()
	const n = 16
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			conn, err := c.Dial(ctx, h.serverID)
			if err != nil {
				errs <- fmt.Errorf("dial %d: %w", i, err)
				return
			}
			defer conn.Close()
			req := fmt.Sprintf("GET /?i=%d HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", i, h.serverID)
			if _, err := conn.Write([]byte(req)); err != nil {
				errs <- fmt.Errorf("write %d: %w", i, err)
				return
			}
			b, _ := io.ReadAll(conn)
			if !strings.Contains(string(b), fmt.Sprintf("i=%d", i)) {
				errs <- fmt.Errorf("response %d did not match: %q", i, b)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	_, _, _, opened, refused := h.gw.Stats()
	if opened < n {
		t.Errorf("gateway counted %d opens, want at least %d", opened, n)
	}
	if refused != 0 {
		t.Errorf("gateway refused %d channels", refused)
	}
}

func TestServerOfflineFailsFast(t *testing.T) {
	h := startHarn(t, echoHandler(), nil)
	c := h.client()
	h.stop()
	h.waitOffline(5 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	_, err := c.Dial(ctx, h.serverID)
	if err == nil {
		t.Fatal("dial to an offline server succeeded")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("offline dial took %s; it must fail fast, not hang", took)
	}
	if code, ok := wire.CodeOf(err); !ok || code != wire.CodeServerOffline {
		t.Fatalf("want server_offline, got %v", err)
	}
}

func TestEpochMismatchRefused(t *testing.T) {
	h := startHarn(t, echoHandler(), nil)
	// A client whose epoch never agrees with the server's must be refused: this
	// is what forces periodic re-authentication.
	c := h.client(func(o *client.Options) { o.EpochLifetime = time.Millisecond })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := c.Dial(ctx, h.serverID)
	if err == nil {
		t.Fatal("dial with a mismatched epoch succeeded")
	}
	if code, ok := wire.CodeOf(err); !ok || code != wire.CodeTimeout {
		t.Fatalf("want timeout refusal, got %v", err)
	}
}

func TestChannelLifetimeEndsChannel(t *testing.T) {
	h := startHarn(t, echoHandler(), withServerOptions(func(o *server.Options) {
		o.MaxChannelLifetime = 400 * time.Millisecond
	}))
	c := h.client()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := c.Dial(ctx, h.serverID)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	// An established channel must be retired by the server, so that even a busy
	// stream is re-authenticated.
	start := time.Now()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 64)); err == nil {
		t.Fatal("channel outlived its maximum lifetime")
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("channel lifetime was not enforced (waited %s)", took)
	}
	// and the next call transparently re-handshakes
	resp, err := c.HTTPClient(h.serverID).Get(h.url("/"))
	if err != nil {
		t.Fatalf("call after lifetime expiry: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d after re-handshake", resp.StatusCode)
	}
}

// TestHTTPKeepAliveReusesOneChannel proves the tunnel carries an ordinary
// persistent HTTP/1.1 connection: the pooling in net/http works, so repeated
// calls do not pay for a fresh handshake each time.
func TestHTTPKeepAliveReusesOneChannel(t *testing.T) {
	h := startHarn(t, echoHandler(), nil)
	before := func() int64 {
		_, _, _, opened, _ := h.gw.Stats()
		return opened
	}
	base := before()
	c := h.client()
	hc := c.HTTPClient(h.serverID)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequestWithContext(ctx, "GET", h.url("/"), nil)
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.Proto != "HTTP/1.1" {
			t.Fatalf("unexpected protocol %q", resp.Proto)
		}
	}
	if opened := before() - base; opened != 1 {
		t.Fatalf("5 pooled requests opened %d channels; keep-alive is not working", opened)
	}
	if hits := h.hits.Load(); hits != 5 {
		t.Fatalf("handler served %d requests, want 5", hits)
	}
}

// TestServerCapacityRefusal covers a refusal that comes from the server rather
// than the relay: the verdict travels back through the gateway, not from it.
func TestServerCapacityRefusal(t *testing.T) {
	h := startHarn(t, echoHandler(), withServerOptions(func(o *server.Options) {
		o.MaxChannels = 1
	}))
	c := h.client()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	first, err := c.Dial(ctx, h.serverID)
	if err != nil {
		t.Fatalf("first channel: %v", err)
	}
	defer first.Close()
	if _, err := c.Dial(ctx, h.serverID); err == nil {
		t.Fatal("a second channel was admitted although the server allows one")
	} else if code, ok := wire.CodeOf(err); !ok || code != wire.CodeTooManyChannels {
		t.Fatalf("want too_many_channels, got %v", err)
	}
}

// TestHijackSurvivesBackgroundRead pins the WebSocket-upgrade path. net/http
// keeps a background read on every connection and must abort it with a
// reactivated read deadline when a handler hijacks the connection (and again
// after every response). A conn whose read deadline cannot interrupt a read
// that is already blocked leaves the server's connection goroutine stuck, and
// the upgrade never completes. Repeated, because whether the background read is
// in flight at that moment is a race.
func TestHijackSurvivesBackgroundRead(t *testing.T) {
	h := startHarn(t, echoHandler(), nil)
	c := h.client()
	for i := 0; i < 10; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		ws, err := c.DialWS(ctx, h.serverID, "ws://"+h.serverID+"/ws", nil)
		if err != nil {
			cancel()
			t.Fatalf("upgrade %d: %v", i, err)
		}
		if err := ws.WriteMessage(websocket.TextMessage, []byte("ping")); err != nil {
			cancel()
			t.Fatalf("write %d: %v", i, err)
		}
		ws.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, b, err := ws.ReadMessage(); err != nil {
			cancel()
			t.Fatalf("read %d: %v", i, err)
		} else if string(b) != "echo:ping" {
			cancel()
			t.Fatalf("echo %d: %q", i, b)
		}
		ws.Close()
		cancel()
	}
}

// TestRequestResponseCyclesDoNotStall drives the response path the same way:
// each request ends with the server aborting its background read, and the
// connection must not stall behind it.
func TestRequestResponseCyclesDoNotStall(t *testing.T) {
	h := startHarn(t, echoHandler(), nil)
	c := h.client()
	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		conn, err := c.Dial(ctx, h.serverID)
		if err != nil {
			cancel()
			t.Fatalf("dial %d: %v", i, err)
		}
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		req := fmt.Sprintf("GET /?i=%d HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", i, h.serverID)
		if _, err := conn.Write([]byte(req)); err != nil {
			cancel()
			t.Fatalf("write %d: %v", i, err)
		}
		b, err := io.ReadAll(conn)
		if err != nil {
			cancel()
			t.Fatalf("read %d: %v", i, err)
		}
		if !strings.Contains(string(b), fmt.Sprintf("i=%d", i)) {
			cancel()
			t.Fatalf("response %d did not match: %q", i, b)
		}
		conn.Close()
		cancel()
	}
}
