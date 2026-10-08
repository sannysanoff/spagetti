package tests

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/sannysanoff/spagetti/client"
	"github.com/sannysanoff/spagetti/conf"
	"github.com/sannysanoff/spagetti/e2e"
	"github.com/sannysanoff/spagetti/gateway"
	"github.com/sannysanoff/spagetti/server"
	"github.com/sannysanoff/spagetti/tunnel"
	"github.com/sannysanoff/spagetti/wire"
)

// evilRelay is a hostile relay sitting in front of the real gateway: it sees
// exactly what a gateway sees (frames, never keys) and can record, drop, mutate,
// duplicate or forge them. This is how "the relay cannot read content" gets
// tested rather than asserted.
type evilRelay struct {
	t       *testing.T
	backend string

	mu       sync.Mutex
	recorded []byte
	frames   []wire.Frame
	raws     [][]byte
	dirs     []string

	// hook decides what is forwarded: nil drops the frame, otherwise every entry
	// is written in order (returning the same frame twice duplicates it).
	hook func(dir string, f wire.Frame, raw []byte) [][]byte
}

func newEvilRelay(t *testing.T, backend string) (*evilRelay, string) {
	e := &evilRelay{t: t, backend: backend}
	srv := httptest.NewServer(http.HandlerFunc(e.serve))
	t.Cleanup(srv.Close)
	return e, "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
}

func (e *evilRelay) serve(w http.ResponseWriter, r *http.Request) {
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	cws, err := up.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	hdr := http.Header{}
	hdr.Set("Authorization", r.Header.Get("Authorization"))
	sws, resp, err := websocket.DefaultDialer.Dial(e.backend, hdr)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		cws.Close()
		return
	}
	go e.pump("c2g", cws, sws)
	e.pump("g2c", sws, cws)
}

func (e *evilRelay) pump(dir string, from, to *websocket.Conn) {
	for {
		mt, b, err := from.ReadMessage()
		if err != nil {
			from.Close()
			to.Close()
			return
		}
		e.record(b, dir)
		out := [][]byte{b}
		if e.hook != nil {
			if f, err := wire.Parse(b); err == nil {
				out = e.hook(dir, f, b)
			}
		}
		for _, frame := range out {
			if err := to.WriteMessage(mt, frame); err != nil {
				from.Close()
				to.Close()
				return
			}
		}
	}
}

func (e *evilRelay) record(b []byte, dir string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.recorded = append(e.recorded, b...)
	if f, err := wire.Parse(b); err == nil {
		e.frames = append(e.frames, f)
		e.raws = append(e.raws, append([]byte(nil), b...))
		e.dirs = append(e.dirs, dir)
	}
}

func (e *evilRelay) snapshot() ([]byte, []wire.Frame, [][]byte, []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]byte(nil), e.recorded...), append([]wire.Frame(nil), e.frames...),
		append([][]byte(nil), e.raws...), append([]string(nil), e.dirs...)
}

func TestRelaySeesCiphertextOnly(t *testing.T) {
	const (
		canaryReq  = "CANARY-REQUEST-8f3a1c"
		canaryResp = "CANARY-RESPONSE-2b7d94"
	)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s body=%s", canaryResp, readSome(r))
	})
	h := startHarn(t, handler, nil)
	e, evilWS := newEvilRelay(t, h.gwWS)

	c := h.client(func(o *client.Options) { o.GatewayURL = evilWS })
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", h.url("/"), strings.NewReader(canaryReq))
	resp, err := c.HTTPClient(h.serverID).Do(req)
	if err != nil {
		t.Fatalf("call through the relay: %v", err)
	}
	body := readBody(resp)
	resp.Body.Close()
	if !strings.Contains(body, canaryResp) {
		t.Fatalf("response did not arrive: %q", body)
	}

	recorded, frames, _, _ := e.snapshot()
	if len(recorded) < 100 {
		t.Fatalf("the relay recorded only %d bytes; the recorder is broken", len(recorded))
	}
	// The end-to-end stream: every record payload that crossed the relay.
	var channelBytes []byte
	labels := 0
	for _, f := range frames {
		switch f.Type {
		case wire.TData:
			channelBytes = append(channelBytes, f.Data.Payload...)
		case wire.TOpen:
			// Positive control: the routing label must be visible, otherwise the
			// negative results below would just mean the recorder saw nothing.
			if bytes.Contains(recorded, f.Open.Channel[:]) {
				labels++
			}
		}
	}
	if labels == 0 {
		t.Fatal("no routing label in the recording: the test proves nothing")
	}
	if len(channelBytes) < 64 {
		t.Fatalf("only %d bytes of channel traffic recorded", len(channelBytes))
	}
	for _, secret := range []string{canaryReq, canaryResp} {
		if bytes.Contains(recorded, []byte(secret)) || bytes.Contains(channelBytes, []byte(secret)) {
			t.Fatalf("the relay saw request or response plaintext %q", secret)
		}
	}
	// Inside the channel, not even the routing metadata is in the clear: no
	// password, no pinned key, no caller label.
	for name, needle := range map[string][]byte{
		"access password": h.password,
		"pinned key":      h.pub,
		"caller label":    []byte("caller"),
	} {
		if bytes.Contains(channelBytes, needle) {
			t.Fatalf("the relay saw the %s inside the channel", name)
		}
	}
	// Identity hiding: the server key is a Noise pre-message, so it never travels
	// to the relay at all.
	if bytes.Contains(recorded, h.pub) {
		t.Fatal("the server's pinned key was transmitted to the relay")
	}
	// Honest about metadata: the caller's label is announced to the gateway in the
	// clear, exactly like the server id. It is a routing label, not content.
	if !bytes.Contains(recorded, []byte("caller")) {
		t.Log("note: the caller label did not appear in the clear; it is metadata, not a secret")
	}
	t.Logf("relay forwarded %d bytes in %d frames, %d bytes of them opaque channel traffic",
		len(recorded), len(frames), len(channelBytes))
}

func TestSubstitutedHandshakeFailsClosed(t *testing.T) {
	h := startHarn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("handler was reached through a forged handshake: %s", r.URL)
	}), withServerOptions(func(o *server.Options) { o.HandshakeTimeout = time.Second }))

	e, evilWS := newEvilRelay(t, h.gwWS)
	// Swallow the caller's handshake and answer with forged challenge bytes: the
	// relay has neither the server's key nor the password, so IKpsk2 cannot be
	// completed from its side.
	e.hook = func(dir string, f wire.Frame, raw []byte) [][]byte {
		switch {
		case dir == "c2g" && f.Type == wire.TData:
			return nil
		case dir == "g2c" && f.Type == wire.TData:
			junk := make([]byte, 64)
			rand.Read(junk)
			forged, _ := wire.Frame{Type: wire.TData, Data: wire.Data{
				Channel: f.Data.Channel, Seq: f.Data.Seq, Payload: junk,
			}}.Encode()
			return [][]byte{forged}
		}
		return [][]byte{raw}
	}
	c := h.client(func(o *client.Options) { o.GatewayURL = evilWS })
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := c.Dial(ctx, h.serverID)
	if err == nil {
		conn.Close()
		t.Fatal("dial through a forged handshake succeeded")
	}
	if code, ok := wire.CodeOf(err); !ok || code != wire.CodeAuthFailed {
		t.Fatalf("want auth_failed, got %v", err)
	}
	if hits := h.hits.Load(); hits != 0 {
		t.Fatalf("handler served %d requests without a valid handshake", hits)
	}
}

func TestWrongPasswordFailsClosed(t *testing.T) {
	h := startHarn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("handler reached with a wrong password: %s", r.URL)
	}), nil)
	wrong := append([]byte(nil), h.password...)
	wrong[0] ^= 0xff
	c := h.client(func(o *client.Options) {
		o.Pins = map[string]client.Pin{h.serverID: {PublicKey: h.pub, Password: wrong}}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := c.Dial(ctx, h.serverID)
	if err == nil {
		conn.Close()
		t.Fatal("dial with a wrong access password succeeded")
	}
	if code, ok := wire.CodeOf(err); !ok || code != wire.CodeAuthFailed {
		t.Fatalf("want auth_failed, got %v", err)
	}
	if hits := h.hits.Load(); hits != 0 {
		t.Fatalf("handler served %d requests behind a wrong password", hits)
	}
}

func TestWrongPinnedKeyFailsClosed(t *testing.T) {
	h := startHarn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("handler reached behind a substituted key: %s", r.URL)
	}), nil)
	other, err := conf.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	c := h.client(func(o *client.Options) {
		o.Pins = map[string]client.Pin{h.serverID: {PublicKey: other.Pub, Password: h.password}}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := c.Dial(ctx, h.serverID)
	if err == nil {
		conn.Close()
		t.Fatal("dial with a substituted pinned key succeeded")
	}
	if code, ok := wire.CodeOf(err); !ok || code != wire.CodeAuthFailed {
		t.Fatalf("want auth_failed, got %v", err)
	}
	if hits := h.hits.Load(); hits != 0 {
		t.Fatalf("handler served %d requests behind a substituted key", hits)
	}
}

func TestBearerTokenRequired(t *testing.T) {
	h := startHarn(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// A missing token is refused before a socket is opened at all.
	if _, err := tunnel.Dial(ctx, tunnel.Options{URL: h.gwWS, Kind: wire.KindClient, ID: "probe"}); err == nil {
		t.Fatal("a connection without a token was accepted")
	} else if !strings.Contains(err.Error(), "token is required") {
		t.Fatalf("want a local token error, got %v", err)
	}
	// A wrong token is refused by the gateway's HTTP layer.
	_, err := tunnel.Dial(ctx, tunnel.Options{URL: h.gwWS, Token: "not-the-token-aaaaaaaaaaaaaaaaaaaa", Kind: wire.KindClient, ID: "probe"})
	if err == nil {
		t.Fatal("a wrong token was accepted")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("want http 401, got %v", err)
	}
}

func TestRoleMismatchRefused(t *testing.T) {
	h := startHarn(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// A server token may not be presented in the client role.
	_, err := tunnel.Dial(ctx, tunnel.Options{URL: h.gwWS, Token: h.serverTok, Kind: wire.KindClient, ID: "probe"})
	if err == nil {
		t.Fatal("a server token was accepted in the client role")
	}
	if code, ok := wire.CodeOf(err); !ok || code != wire.CodeNotAllowed {
		t.Fatalf("want not_allowed, got %v", err)
	}
}

func TestTokenScopeEnforced(t *testing.T) {
	h := startHarn(t, nil, withClientScope("someone-else"))
	c := h.client()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := c.Dial(ctx, h.serverID)
	if err == nil {
		conn.Close()
		t.Fatal("a client token scoped to another server was allowed through")
	}
	if code, ok := wire.CodeOf(err); !ok || code != wire.CodeNotAllowed {
		t.Fatalf("want not_allowed, got %v", err)
	}
}

func TestRecordTamperingIsNotDelivered(t *testing.T) {
	h := startHarn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("handler served a request built from a tampered record: %s", r.URL)
	}), nil)
	e, evilWS := newEvilRelay(t, h.gwWS)
	e.hook = func(dir string, f wire.Frame, raw []byte) [][]byte {
		if dir == "c2g" && f.Type == wire.TData && f.Data.Seq == 2 {
			// seq 2 is the first transport record after the caller's ready
			// record: the HTTP request itself.
			payload := append([]byte(nil), f.Data.Payload...)
			payload[len(payload)/2] ^= 0x01
			forged, _ := wire.Frame{Type: wire.TData, Data: wire.Data{
				Channel: f.Data.Channel, Seq: f.Data.Seq, Payload: payload,
			}}.Encode()
			return [][]byte{forged}
		}
		return [][]byte{raw}
	}
	c := h.client(func(o *client.Options) { o.GatewayURL = evilWS })
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", h.url("/"), nil)
	resp, err := c.HTTPClient(h.serverID).Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("a tampered request succeeded")
	}
	if hits := h.hits.Load(); hits != 0 {
		t.Fatalf("handler served %d requests from tampered records", hits)
	}
}

func TestDuplicatedRecordIsRejected(t *testing.T) {
	h := startHarn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("handler served a channel with duplicated records: %s", r.URL)
	}), nil)
	e, evilWS := newEvilRelay(t, h.gwWS)
	e.hook = func(dir string, f wire.Frame, raw []byte) [][]byte {
		if dir == "c2g" && f.Type == wire.TData && f.Data.Seq == 1 {
			// Forward the caller's ready record twice: sequence checking must fail
			// the channel instead of delivering a duplicated byte.
			return [][]byte{raw, raw}
		}
		return [][]byte{raw}
	}
	c := h.client(func(o *client.Options) { o.GatewayURL = evilWS })
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", h.url("/"), nil)
	resp, err := c.HTTPClient(h.serverID).Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("a channel with a duplicated record succeeded")
	}
	if hits := h.hits.Load(); hits != 0 {
		t.Fatalf("handler served %d requests from a duplicated channel", hits)
	}
}

func TestCapturedHandshakeCannotBeReplayed(t *testing.T) {
	h := startHarn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	}), nil)
	e, evilWS := newEvilRelay(t, h.gwWS)
	c := h.client(func(o *client.Options) { o.GatewayURL = evilWS })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// The baseline call must not leave its channel behind: a pooled idle
	// connection would keep the routing label live at the gateway, and the
	// replay below would be refused as a duplicate before it started.
	req, _ := http.NewRequestWithContext(ctx, "GET", h.url("/"), nil)
	req.Close = true
	resp, err := c.HTTPClient(h.serverID).Do(req)
	if err != nil {
		t.Fatalf("baseline call: %v", err)
	}
	resp.Body.Close()

	// Pull the caller's records and the routing label out of the recording.
	_, frames, raws, dirs := e.snapshot()
	var channel wire.Channel
	var epoch int64
	var records [][]byte
	for i, f := range frames {
		switch f.Type {
		case wire.TOpen:
			channel = f.Open.Channel
			epoch = f.Open.Epoch
		case wire.TData:
			if dirs[i] == "c2g" && channel != (wire.Channel{}) && f.Data.Channel == channel {
				records = append(records, raws[i])
			}
		}
	}
	if len(records) < 2 {
		t.Fatalf("captured %d caller records, need the handshake and the ready record", len(records))
	}

	// Replay them onto the same label, epoch and key with a fresh connection.
	rc, err := tunnel.Dial(ctx, tunnel.Options{
		URL: h.gwWS, Token: h.clientTok, Kind: wire.KindClient, ID: "replayer",
	})
	if err != nil {
		t.Fatalf("replayer dial: %v", err)
	}
	defer rc.Close()
	// The gateway frees the label the moment the baseline channel died, but the
	// server clears its own serving map from another goroutine; a refusal to
	// serve "already being served" is teardown lag, not a verdict on the replay.
	deadline := time.Now().Add(5 * time.Second)
	var ch *tunnel.Channel
	for {
		ch, err = rc.OpenWithLabel(ctx, h.serverID, epoch, channel)
		if code, ok := wire.CodeOf(err); err == nil || !ok || code != wire.CodeDuplicateChannel || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("replayer open: %v", err)
	}
	for _, raw := range records[:2] {
		f, err := wire.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := ch.SendRecord(f.Data.Payload); err != nil {
			t.Fatalf("replay send: %v", err)
		}
	}
	var lastErr error
	for i := 0; i < 4; i++ {
		if _, err := ch.RecvRecord(ctx); err != nil {
			lastErr = err
			break
		}
	}
	if lastErr == nil {
		t.Fatal("a replayed handshake was accepted")
	}
	// The responder mints a fresh ephemeral every handshake, so the captured
	// records no longer decrypt; the replay dies at the AEAD, not at the cache.
	if code, ok := wire.CodeOf(lastErr); !ok || code != wire.CodeAuthFailed {
		t.Fatalf("want the replay to fail authentication, got %v", lastErr)
	}
	if hits := h.hits.Load(); hits != 1 {
		t.Fatalf("handler served %d requests; the replay must not reach it (baseline was 1)", hits)
	}
}

// TestReusedNonceRejected covers the other replay shape: a caller that completes
// a valid handshake but reuses a nonce it already spent.
func TestReusedNonceRejected(t *testing.T) {
	h := startHarn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	}), nil)
	fixed := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	identity, err := conf.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rc, err := tunnel.Dial(ctx, tunnel.Options{
		URL: h.gwWS, Token: h.clientTok, Kind: wire.KindClient, ID: "nonce-probe",
	})
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer rc.Close()
	handshake := func() error {
		ch, err := rc.Open(ctx, h.serverID, h.epoch())
		if err != nil {
			return err
		}
		conn, err := e2e.Connect(ctx, ch, e2e.ClientConfig{
			Identity:  identity,
			ClientID:  "nonce-probe",
			ServerID:  h.serverID,
			ServerPub: h.pub,
			Password:  h.password,
			Channel:   ch.ID(),
			Epoch:     h.epoch(),
			Nonce:     func() [16]byte { return fixed },
		})
		if err != nil {
			return err
		}
		conn.Close()
		return nil
	}
	if err := handshake(); err != nil {
		t.Fatalf("first handshake: %v", err)
	}
	// A second channel with the same nonce must be refused: the server keeps a
	// bounded cache of the nonces it has already seen.
	err = handshake()
	if err == nil {
		t.Fatal("a reused nonce was accepted")
	}
	if code, ok := wire.CodeOf(err); !ok || code != wire.CodeReplay {
		t.Fatalf("want a replay refusal, got %v", err)
	}
}

// TestPolicyRefusalIsSynchronous covers the server-side authorization hook: the
// caller learns the verdict from Dial, not from its first request.
func TestPolicyRefusalIsSynchronous(t *testing.T) {
	h := startHarn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("handler reached although policy denied the caller: %s", r.URL)
	}), withServerOptions(func(o *server.Options) {
		o.AllowClient = func(server.Peer) bool { return false }
	}))
	c := h.client()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := c.Dial(ctx, h.serverID)
	if err == nil {
		conn.Close()
		t.Fatal("dial succeeded although the server denied the caller")
	}
	if code, ok := wire.CodeOf(err); !ok || code != wire.CodeNotAllowed {
		t.Fatalf("want not_allowed, got %v", err)
	}
	if hits := h.hits.Load(); hits != 0 {
		t.Fatalf("handler served %d requests for a denied caller", hits)
	}
}

// TestGatewayReportsItsOwnFailureNotAServerVerdict pins the rule that the relay
// never answers for a server: a registered server that never replies must be
// reported as a relay timeout, not as a server refusal.
func TestGatewayReportsItsOwnFailureNotAServerVerdict(t *testing.T) {
	h := startHarn(t, nil, withServerAllow("web1", "silent"),
		withGatewayConfig(func(c *gateway.Config) { c.OpenTimeout = 300 * time.Millisecond }))
	if _, err := conf.SavePeer(h.confDir, "silent", h.pub, h.password); err != nil {
		t.Fatalf("pin silent: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	silent, err := tunnel.Dial(ctx, tunnel.Options{
		URL: h.gwWS, Token: h.serverTok, Kind: wire.KindServer, ID: "silent",
		PubKey: h.pub, Name: "silent", Fingerprint: conf.Fingerprint(h.pub),
		// Registered, reachable, and deliberately silent: it never answers an
		// open, so only the relay can report the failure.
		OnOpen: func(tunnel.Open) {},
	})
	if err != nil {
		t.Fatalf("silent server dial: %v", err)
	}
	defer silent.Close()

	c := h.client()
	conn, err := c.Dial(ctx, "silent")
	if err == nil {
		conn.Close()
		t.Fatal("dial to a silent server succeeded")
	}
	if code, ok := wire.CodeOf(err); !ok || code != wire.CodeTimeout {
		t.Fatalf("want a relay timeout, got %v", err)
	}
}

func readBody(resp *http.Response) string {
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func readSome(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	b := make([]byte, 4096)
	n, _ := r.Body.Read(b)
	return string(b[:n])
}
