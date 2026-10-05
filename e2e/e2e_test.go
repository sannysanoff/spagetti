package e2e

import (
	"bytes"
	"testing"
	"time"

	"github.com/flynn/noise"

	"github.com/sannysanoff/spagetti/wire"
)

func handshakePair(t *testing.T, clientPSK, serverPSK, clientPro, serverPro []byte) (*noise.HandshakeState, *noise.HandshakeState, noise.DHKey, noise.DHKey) {
	t.Helper()
	server, err := suite.GenerateKeypair(nil)
	if err != nil {
		t.Fatal(err)
	}
	client, err := suite.GenerateKeypair(nil)
	if err != nil {
		t.Fatal(err)
	}
	build := func(initiator bool, static noise.DHKey, peerStatic, prologue, psk []byte) *noise.HandshakeState {
		hs, err := noise.NewHandshakeState(noise.Config{
			CipherSuite:           suite,
			Pattern:               noise.HandshakeIK,
			Initiator:             initiator,
			Prologue:              prologue,
			PresharedKey:          psk,
			PresharedKeyPlacement: pskPlacement,
			StaticKeypair:         static,
			PeerStatic:            peerStatic,
		})
		if err != nil {
			t.Fatal(err)
		}
		return hs
	}
	return build(true, client, server.Public, clientPro, clientPSK), build(false, server, nil, serverPro, serverPSK), client, server
}

// TestPrimitivePropertiesThisLayerReliesOn pins the Noise semantics the design
// depends on. A future library change that moves the PSK or prologue mixing must
// break these tests rather than quietly weaken the protocol.
func TestPrimitivePropertiesThisLayerReliesOn(t *testing.T) {
	psk := bytes.Repeat([]byte{0x2a}, 32)
	wrongPSK := bytes.Repeat([]byte{0x2b}, 32)
	pro := []byte("spagetti/1\nserver=web1")
	otherPro := []byte("spagetti/1\nserver=web2")

	t.Run("matching key and password handshakes", func(t *testing.T) {
		c, s, _, server := handshakePair(t, psk, psk, pro, pro)
		m1, _, _, err := c.WriteMessage(nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := s.ReadMessage(nil, m1); err != nil {
			t.Fatal(err)
		}
		m2, _, _, err := s.WriteMessage(nil, []byte("ready"))
		if err != nil {
			t.Fatal(err)
		}
		payload, _, _, err := c.ReadMessage(nil, m2)
		if err != nil {
			t.Fatal(err)
		}
		if string(payload) != "ready" {
			t.Fatalf("payload %q", payload)
		}
		if !bytes.Equal(c.PeerStatic(), server.Public) {
			t.Fatal("the initiator did not see the pinned responder key as the peer static key")
		}
	})

	t.Run("a wrong password is caught by the caller reading the challenge response", func(t *testing.T) {
		c, s, _, _ := handshakePair(t, wrongPSK, psk, pro, pro)
		m1, _, _, err := c.WriteMessage(nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := s.ReadMessage(nil, m1); err != nil {
			t.Fatal(err)
		}
		m2, _, _, err := s.WriteMessage(nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := c.ReadMessage(nil, m2); err == nil {
			t.Fatal("a caller with the wrong password could read the server's challenge response")
		}
	})

	t.Run("a prologue mismatch is caught on the first message", func(t *testing.T) {
		c, s, _, _ := handshakePair(t, psk, psk, otherPro, pro)
		m1, _, _, err := c.WriteMessage(nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := s.ReadMessage(nil, m1); err == nil {
			t.Fatal("a handshake with a different prologue was accepted")
		}
	})
}

// TestResponderStatesAreReceiveThenSend guards the mapping that e2e.Accept
// depends on: the responder's WriteMessage returns (receive, send) while the
// initiator's ReadMessage returns (send, receive).
func TestResponderStatesAreReceiveThenSend(t *testing.T) {
	psk := bytes.Repeat([]byte{0x11}, 32)
	pro := []byte("prologue")
	c, s, _, _ := handshakePair(t, psk, psk, pro, pro)
	m1, _, _, err := c.WriteMessage(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.ReadMessage(nil, m1); err != nil {
		t.Fatal(err)
	}
	m2, sFirst, sSecond, err := s.WriteMessage(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, cFirst, cSecond, err := c.ReadMessage(nil, m2)
	if err != nil {
		t.Fatal(err)
	}
	// initiator send -> responder first
	ct, err := cFirst.Encrypt(nil, nil, []byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sFirst.Decrypt(nil, nil, ct); err != nil {
		t.Fatalf("responder's first state is not the receive state: %v", err)
	}
	// responder second -> initiator second
	st, err := sSecond.Encrypt(nil, nil, []byte("b"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cSecond.Decrypt(nil, nil, st); err != nil {
		t.Fatalf("responder's second state is not the send state: %v", err)
	}
}

func TestPrologueBindsRoute(t *testing.T) {
	key := bytes.Repeat([]byte{5}, 32)
	a, err := wire.RandomChannel()
	if err != nil {
		t.Fatal(err)
	}
	b, err := wire.RandomChannel()
	if err != nil {
		t.Fatal(err)
	}
	base := Prologue("web1", key, a, 7)
	if !bytes.Equal(base, Prologue("web1", key, a, 7)) {
		t.Fatal("prologue is not deterministic")
	}
	variants := map[string][]byte{
		"server":  Prologue("web2", key, a, 7),
		"key":     Prologue("web1", append([]byte(nil), key...)[:31], a, 7),
		"channel": Prologue("web1", key, b, 7),
		"epoch":   Prologue("web1", key, a, 8),
	}
	for name, p := range variants {
		if bytes.Equal(p, base) {
			t.Fatalf("prologue does not change with the %s", name)
		}
	}
	if bytes.Contains(base, key) {
		t.Fatal("the prologue must not carry raw key bytes")
	}
}

func TestNonceCache(t *testing.T) {
	now := time.Now()
	c := NewNonceCache(time.Minute)
	var n [16]byte
	n[0] = 1
	if !c.Use(n, now, now) {
		t.Fatal("a fresh nonce was rejected")
	}
	if c.Use(n, now, now) {
		t.Fatal("a repeated nonce was accepted")
	}
	old := [16]byte{2}
	if c.Use(old, now.Add(-2*time.Minute), now) {
		t.Fatal("a stale nonce was accepted")
	}
	future := [16]byte{3}
	if c.Use(future, now.Add(10*time.Minute), now) {
		t.Fatal("a nonce from the far future was accepted")
	}
	// Entries age out of the window.
	short := NewNonceCache(20 * time.Millisecond)
	for i := 0; i < 5; i++ {
		var m [16]byte
		m[0] = byte(i + 10)
		if !short.Use(m, now, now) {
			t.Fatalf("nonce %d rejected", i)
		}
	}
	short.prune(now.Add(time.Second))
	if len(short.seen) != 0 {
		t.Fatalf("stale nonces were not pruned: %d left", len(short.seen))
	}
}

func TestControlRecords(t *testing.T) {
	nonce := [16]byte{9, 8, 7}
	now := time.Unix(1700000000, 0)
	raw := encodeControl("caller", now, nonce)
	ctrl, ok := parseControl(raw)
	if !ok {
		t.Fatal("control record did not parse")
	}
	if ctrl.ID != "caller" || ctrl.Unix != now.Unix() || ctrl.Nonce != nonce {
		t.Fatalf("control record mismatch: %+v", ctrl)
	}
	for name, bad := range map[string][]byte{
		"empty":     nil,
		"short":     raw[:4],
		"trailing":  append(append([]byte(nil), raw...), 0),
		"wrong tag": append([]byte{ctrlAccepted}, raw[1:]...),
	} {
		if _, ok := parseControl(bad); ok {
			t.Fatalf("%s parsed as a control record", name)
		}
	}

	verdict := encodeVerdict(wire.CodeNotAllowed, "denied")
	code, msg, ok := parseVerdict(verdict)
	if !ok || code != wire.CodeNotAllowed || msg != "denied" {
		t.Fatalf("verdict mismatch: %v %q %v", code, msg, ok)
	}
	if _, _, ok := parseVerdict(raw); ok {
		t.Fatal("a ready record parsed as a verdict")
	}
	if _, _, ok := parseVerdict(verdict[:2]); ok {
		t.Fatal("a truncated verdict parsed")
	}
	long := encodeVerdict(wire.CodeOK, string(bytes.Repeat([]byte("x"), 400)))
	if code, msg, ok := parseVerdict(long); !ok || code != wire.CodeOK || len(msg) != 255 {
		t.Fatalf("long verdict: %v %d", code, len(msg))
	}
}
