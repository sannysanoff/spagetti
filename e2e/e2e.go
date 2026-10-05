// Package e2e is the end-to-end layer: it turns a relayed tunnel channel into a
// net.Conn whose bytes only the client and the server can read.
//
// Handshake: Noise IKpsk2_25519_ChaChaPoly_BLAKE2s (the shape WireGuard uses).
//   - The client already knows the server's static X25519 key and passes it as
//     the handshake pre-message, so the responder it talks to is that key's
//     holder or nobody.
//   - The access password is the Noise pre-shared key, mixed into the chaining
//     key, so a caller that does not hold it cannot produce or read a single
//     transport record.
//   - The prologue binds the handshake to the gateway-visible route label
//     (server id, server key, channel id, epoch), so a relay cannot rename,
//     splice or replay a channel into a different route.
//
// Records 0..n of a channel are handshake records; everything after is AEAD
// transport. There is no flag an intermediary could flip to make ciphertext be
// read as plaintext.
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"

	"github.com/sannysanoff/spagetti/conf"
	"github.com/sannysanoff/spagetti/tunnel"
	"github.com/sannysanoff/spagetti/wire"
)

// Defaults for handshake validation.
const (
	DefaultHandshakeTimeout = 15 * time.Second
	DefaultReplayWindow     = 2 * time.Minute
	DefaultNonceCacheSize   = 1 << 16
	// DefaultEpochLifetime is the re-authentication period: no channel may be
	// opened, and no channel may outlive, more than one epoch.
	DefaultEpochLifetime = 15 * time.Minute
	pskPlacement         = 2 // IKpsk2
	ctrlReady            = 1 // caller → server: identity, timestamp, nonce
	ctrlAccepted         = 2 // server → caller: the channel verdict
)

// Identity is this peer's static X25519 keypair.
type Identity = conf.Identity

var suite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

// SuiteName documents the negotiated protocol.
const SuiteName = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"

// Peer identifies the authenticated remote end of a channel.
type Peer struct {
	// ID is the peer's own label: the client id supplied at connect time, or
	// the server id from the prologue.
	ID string
	// PubKey is the peer's static public key, as proven by the handshake.
	PubKey []byte
	// Fingerprint is a short human-comparable form of PubKey.
	Fingerprint string
}

// Handshake failures. Both are deliberately indistinguishable in cause: a wrong
// password, a substituted server key and a tampering relay all end here.
var (
	ErrAuthFailed = &wire.Error{
		Code: wire.CodeAuthFailed,
		Msg:  "end-to-end handshake failed (wrong access password, key mismatch, or tampering relay)",
	}
	ErrPinMismatch = &wire.Error{
		Code: wire.CodeAuthFailed,
		Msg:  "server identity does not match the pinned key",
	}
)

// Prologue derives the handshake prologue. Both sides must compute it from
// values the other side can independently check.
func Prologue(serverID string, serverPub []byte, ch wire.Channel, epoch int64) []byte {
	return []byte(fmt.Sprintf("spagetti/%d\nserver=%s\nkey=%s\nchannel=%s\nepoch=%d",
		wire.Version, serverID, hex.EncodeToString(serverPub), ch.String(), epoch))
}

// ClientConfig drives the initiator side of one channel handshake.
type ClientConfig struct {
	Identity Identity
	// ClientID is the caller label the server will see. It defaults to the
	// device key fingerprint.
	ClientID     string
	ServerID     string
	ServerPub    []byte // pinned server key
	Password     []byte // access password, the Noise PSK
	Channel      wire.Channel
	Epoch        int64
	Timeout      time.Duration
	Now          func() time.Time
	ReplayWindow time.Duration
	// Nonce overrides the freshness nonce of the caller's ready record. Leaving
	// it nil uses crypto/rand; setting it is for tests and for callers that want
	// a deterministic source.
	Nonce    func() [16]byte
	Prologue []byte // test hook; normally derived
}

// ServerConfig drives the responder side of one channel handshake.
type ServerConfig struct {
	Identity     Identity
	ServerID     string
	Password     []byte
	Channel      wire.Channel
	Epoch        int64
	Timeout      time.Duration
	Now          func() time.Time
	ReplayWindow time.Duration
	Nonces       *NonceCache // required; shared across channels
	// Authorize decides whether an authenticated caller may use this channel.
	// The returned error's wire code (when it carries one) is reported to the
	// caller; otherwise not_allowed.
	Authorize func(Peer) error
	Prologue  []byte
}

func (c *ClientConfig) setDefaults() {
	if c.Timeout <= 0 {
		c.Timeout = DefaultHandshakeTimeout
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.ReplayWindow <= 0 {
		c.ReplayWindow = DefaultReplayWindow
	}
	if c.Prologue == nil {
		c.Prologue = Prologue(c.ServerID, c.ServerPub, c.Channel, c.Epoch)
	}
}

func (c *ServerConfig) setDefaults() {
	if c.Timeout <= 0 {
		c.Timeout = DefaultHandshakeTimeout
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.ReplayWindow <= 0 {
		c.ReplayWindow = DefaultReplayWindow
	}
	if c.Nonces == nil {
		c.Nonces = NewNonceCache(c.ReplayWindow)
	}
	if c.Prologue == nil {
		c.Prologue = Prologue(c.ServerID, c.Identity.Pub, c.Channel, c.Epoch)
	}
}

// Connect performs the initiator handshake over a relayed channel and returns a
// net.Conn carrying the authenticated byte stream.
func Connect(ctx context.Context, ch *tunnel.Channel, cfg ClientConfig) (*Conn, error) {
	cfg.setDefaults()
	if len(cfg.ServerPub) == 0 {
		return nil, fmt.Errorf("spagetti: pinned server key is required")
	}
	if len(cfg.Password) == 0 {
		return nil, fmt.Errorf("spagetti: access password is required")
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:           suite,
		Pattern:               noise.HandshakeIK,
		Initiator:             true,
		Prologue:              cfg.Prologue,
		PresharedKey:          cfg.Password,
		PresharedKeyPlacement: pskPlacement,
		StaticKeypair:         noise.DHKey{Private: cfg.Identity.Priv, Public: cfg.Identity.Pub},
		PeerStatic:            cfg.ServerPub,
	})
	if err != nil {
		return nil, fmt.Errorf("spagetti: handshake setup: %w", err)
	}
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("spagetti: handshake message: %w", err)
	}
	if err := ch.SendRecord(msg1); err != nil {
		return nil, err
	}
	rec, err := ch.RecvRecord(ctx)
	if err != nil {
		return nil, err
	}
	payload, send, recv, err := hs.ReadMessage(nil, rec)
	if err != nil {
		return nil, ErrAuthFailed
	}
	if !bytes.Equal(hs.PeerStatic(), cfg.ServerPub) {
		return nil, ErrPinMismatch
	}
	ctrl, ok := parseControl(payload)
	if !ok {
		return nil, fmt.Errorf("spagetti: server sent a malformed challenge response")
	}
	if cfg.ServerID != "" && ctrl.ID != cfg.ServerID {
		return nil, &wire.Error{Code: wire.CodeProtocolError,
			Msg: fmt.Sprintf("server identified itself as %q, expected %q", ctrl.ID, cfg.ServerID)}
	}
	if err := cfg.checkFreshness(ctrl.Unix); err != nil {
		return nil, err
	}
	// The server proves it holds the password with its response above; the
	// client proves the same with the first transport record.
	label := cfg.ClientID
	if label == "" {
		label = cfg.Identity.ID()
	}
	nonce := newNonce()
	if cfg.Nonce != nil {
		nonce = cfg.Nonce()
	}
	ready := encodeControl(label, cfg.Now(), nonce)
	ct, err := send.Encrypt(nil, nil, ready)
	if err != nil {
		return nil, fmt.Errorf("spagetti: handshake record: %w", err)
	}
	if err := ch.SendRecord(ct); err != nil {
		return nil, err
	}
	// The server answers with its verdict on the channel: accepted, or a code
	// saying why not. Waiting for it makes Dial deterministic instead of
	// discovering a refusal on first use.
	verdict, err := ch.RecvRecord(ctx)
	if err != nil {
		return nil, err
	}
	pt, err := recv.Decrypt(nil, nil, verdict)
	if err != nil {
		return nil, ErrAuthFailed
	}
	code, msg, ok := parseVerdict(pt)
	if !ok {
		return nil, &wire.Error{Code: wire.CodeMalformed, Msg: "malformed channel verdict"}
	}
	if code != wire.CodeOK {
		return nil, &wire.Error{Code: code, Msg: msg}
	}
	return &Conn{
		ch:     ch,
		send:   send,
		recv:   recv,
		peer:   Peer{ID: ctrl.ID, PubKey: append([]byte(nil), cfg.ServerPub...), Fingerprint: conf.Fingerprint(cfg.ServerPub)},
		local:  addr("client"),
		remote: addr("server=" + ctrl.ID),
	}, nil
}

func (c ClientConfig) checkFreshness(unix int64) error {
	if unix == 0 {
		return nil
	}
	skew := c.Now().Sub(time.Unix(unix, 0))
	if skew < 0 {
		skew = -skew
	}
	if skew > c.ReplayWindow {
		return &wire.Error{Code: wire.CodeReplay, Msg: "server challenge is stale"}
	}
	return nil
}

// Accept performs the responder handshake over a relayed channel. On success the
// returned Conn is positioned exactly at the start of the peer's byte stream and
// the returned Peer is the authenticated caller.
func Accept(ctx context.Context, ch *tunnel.Channel, cfg ServerConfig) (*Conn, Peer, error) {
	cfg.setDefaults()
	if len(cfg.Password) == 0 {
		return nil, Peer{}, fmt.Errorf("spagetti: access password is required")
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:           suite,
		Pattern:               noise.HandshakeIK,
		Initiator:             false,
		Prologue:              cfg.Prologue,
		PresharedKey:          cfg.Password,
		PresharedKeyPlacement: pskPlacement,
		StaticKeypair:         noise.DHKey{Private: cfg.Identity.Priv, Public: cfg.Identity.Pub},
	})
	if err != nil {
		return nil, Peer{}, fmt.Errorf("spagetti: handshake setup: %w", err)
	}
	msg1, err := ch.RecvRecord(ctx)
	if err != nil {
		return nil, Peer{}, err
	}
	if _, _, _, err := hs.ReadMessage(nil, msg1); err != nil {
		return nil, Peer{}, &wire.Error{Code: wire.CodeAuthFailed, Msg: "caller challenge is not decryptable"}
	}
	peerPub := append([]byte(nil), hs.PeerStatic()...)
	// The challenge response carries this server's identity, so the caller can
	// check it against its pinned key.
	// Noise returns the responder's states as (receive, send) — the mirror of the
	// initiator's (send, receive).
	msg2, recv, send, err := hs.WriteMessage(nil, encodeControl(cfg.ServerID, cfg.Now(), newNonce()))
	if err != nil {
		return nil, Peer{}, fmt.Errorf("spagetti: handshake message: %w", err)
	}
	if err := ch.SendRecord(msg2); err != nil {
		return nil, Peer{}, err
	}
	rec, err := ch.RecvRecord(ctx)
	if err != nil {
		return nil, Peer{}, err
	}
	refuse := func(code wire.Code, msg string) error {
		if ack, err := send.Encrypt(nil, nil, encodeVerdict(code, msg)); err == nil {
			ch.SendRecord(ack)
		}
		return &wire.Error{Code: code, Msg: msg}
	}
	ready, err := recv.Decrypt(nil, nil, rec)
	if err != nil {
		// Only a caller holding the password can produce this record.
		return nil, Peer{}, refuse(wire.CodeAuthFailed, "caller did not prove possession of the access password")
	}
	ctrl, ok := parseControl(ready)
	if !ok {
		return nil, Peer{}, refuse(wire.CodeMalformed, "malformed caller record")
	}
	if !cfg.Nonces.Use(ctrl.Nonce, time.Unix(ctrl.Unix, 0), cfg.Now()) {
		return nil, Peer{}, refuse(wire.CodeReplay, "caller record replayed or stale")
	}
	peer := Peer{ID: ctrl.ID, PubKey: peerPub, Fingerprint: conf.Fingerprint(peerPub)}
	if peer.ID == "" {
		peer.ID = peer.Fingerprint
	}
	if cfg.Authorize != nil {
		if err := cfg.Authorize(peer); err != nil {
			code := wire.CodeNotAllowed
			if c, ok := wire.CodeOf(err); ok {
				code = c
			}
			return nil, Peer{}, refuse(code, err.Error())
		}
	}
	ack, err := send.Encrypt(nil, nil, encodeVerdict(wire.CodeOK, ""))
	if err != nil {
		return nil, Peer{}, fmt.Errorf("spagetti: channel verdict: %w", err)
	}
	if err := ch.SendRecord(ack); err != nil {
		return nil, Peer{}, err
	}
	return &Conn{
		ch:     ch,
		send:   send,
		recv:   recv,
		peer:   peer,
		local:  addr("server=" + cfg.ServerID),
		remote: addr("client=" + peer.ID),
	}, peer, nil
}

// Conn is an authenticated, encrypted net.Conn carried by a relayed channel.
type Conn struct {
	ch     *tunnel.Channel
	send   *noise.CipherState
	recv   *noise.CipherState
	peer   Peer
	local  net.Addr
	remote net.Addr

	mu       sync.Mutex
	buf      []byte
	rd, wd   time.Time
	closed   bool
	closeErr error
	once     sync.Once
}

// Peer returns the authenticated remote peer.
func (c *Conn) Peer() Peer { return c.peer }

// Read implements net.Conn. A record that fails authentication fails the
// connection: corrupted bytes are never handed to the caller.
func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		c.mu.Unlock()
		return n, nil
	}
	closed, cerr, rd := c.closed, c.closeErr, c.rd
	c.mu.Unlock()
	if closed {
		return 0, cerr
	}
	// The deadline is enforced on the channel, which is also what lets a
	// SetReadDeadline reactivate a read that is already blocked: net/http
	// aborts its per-connection background read exactly that way.
	c.ch.SetReadDeadline(rd)
	rec, err := c.ch.RecvRecord(context.Background())
	if err != nil {
		if errors.Is(err, io.EOF) {
			c.markClosed(io.EOF)
			return 0, io.EOF
		}
		return 0, err
	}
	pt, err := c.recv.Decrypt(nil, nil, rec)
	if err != nil {
		ferr := &wire.Error{Code: wire.CodeMalformed, Msg: "end-to-end record failed authentication"}
		c.markClosed(ferr)
		return 0, ferr
	}
	c.mu.Lock()
	c.buf = pt
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	c.mu.Unlock()
	return n, nil
}

// Write implements net.Conn, chunking into transport records of at most
// wire.MaxChunk plaintext bytes.
func (c *Conn) Write(p []byte) (int, error) {
	c.mu.Lock()
	closed, cerr, wd := c.closed, c.closeErr, c.wd
	c.mu.Unlock()
	if closed {
		return 0, cerr
	}
	if !wd.IsZero() && time.Now().After(wd) {
		return 0, tunnel.ErrTimeout
	}
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > wire.MaxChunk {
			n = wire.MaxChunk
		}
		ct, err := c.send.Encrypt(nil, nil, p[:n])
		if err != nil {
			return written, fmt.Errorf("spagetti: encrypting record: %w", err)
		}
		if err := c.ch.SendRecord(ct); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// Close implements net.Conn, telling the peer why the channel ended.
func (c *Conn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.ch.Close(wire.CodeOK, "closed")
		c.markClosed(io.EOF)
	})
	return err
}

// Channel returns the underlying relayed channel.
func (c *Conn) Channel() *tunnel.Channel { return c.ch }

func (c *Conn) markClosed(err error) {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		c.closeErr = err
	}
	c.mu.Unlock()
}

// LocalAddr implements net.Conn.
func (c *Conn) LocalAddr() net.Addr { return c.local }

// RemoteAddr implements net.Conn.
func (c *Conn) RemoteAddr() net.Addr { return c.remote }

// SetDeadline implements net.Conn.
func (c *Conn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.rd, c.wd = t, t
	c.mu.Unlock()
	c.ch.SetDeadline(t)
	return nil
}

// SetReadDeadline implements net.Conn. A read deadline interrupts a read that
// is already blocked, which is what net/http relies on to abort the background
// read it keeps on every connection.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.rd = t
	c.mu.Unlock()
	c.ch.SetReadDeadline(t)
	return nil
}

// SetWriteDeadline implements net.Conn. It bounds the wait for room in the
// tunnel's outbound queue.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.wd = t
	c.mu.Unlock()
	c.ch.SetWriteDeadline(t)
	return nil
}

type addr string

func (a addr) Network() string { return "spagetti" }
func (a addr) String() string  { return string(a) }

type peerCtxKey struct{}

// WithPeer attaches an authenticated peer to a handler context.
func WithPeer(ctx context.Context, p Peer) context.Context {
	return context.WithValue(ctx, peerCtxKey{}, p)
}

// PeerFromContext returns the authenticated peer of a tunneled request.
func PeerFromContext(ctx context.Context) (Peer, bool) {
	p, ok := ctx.Value(peerCtxKey{}).(Peer)
	return p, ok
}

// control is the small authenticated record exchanged immediately after the
// handshake: the server's identity in the challenge response, and the caller's
// identity plus a fresh nonce in the first transport record.
type control struct {
	ID    string
	Unix  int64
	Nonce [16]byte
}

func encodeControl(id string, now time.Time, nonce [16]byte) []byte {
	if len(id) > 255 {
		id = id[:255]
	}
	b := make([]byte, 0, 1+2+len(id)+8+16)
	b = append(b, ctrlReady)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(id)))
	b = append(b, id...)
	b = binary.LittleEndian.AppendUint64(b, uint64(now.Unix()))
	return append(b, nonce[:]...)
}

func parseControl(b []byte) (control, bool) {
	var c control
	if len(b) < 1+2+8+16 || b[0] != ctrlReady {
		return c, false
	}
	n := int(binary.LittleEndian.Uint16(b[1:3]))
	if len(b) != 1+2+n+8+16 {
		return c, false
	}
	c.ID = string(b[3 : 3+n])
	c.Unix = int64(binary.LittleEndian.Uint64(b[3+n : 3+n+8]))
	copy(c.Nonce[:], b[3+n+8:])
	return c, true
}

// encodeVerdict is the server's authenticated answer to a caller's ready record.
func encodeVerdict(code wire.Code, msg string) []byte {
	if len(msg) > 255 {
		msg = msg[:255]
	}
	b := make([]byte, 0, 4+len(msg))
	b = append(b, ctrlAccepted)
	b = binary.LittleEndian.AppendUint16(b, uint16(code))
	b = append(b, byte(len(msg)))
	return append(b, msg...)
}

func parseVerdict(b []byte) (wire.Code, string, bool) {
	if len(b) < 4 || b[0] != ctrlAccepted {
		return 0, "", false
	}
	code := wire.Code(binary.LittleEndian.Uint16(b[1:3]))
	n := int(b[3])
	if len(b) != 4+n {
		return 0, "", false
	}
	return code, string(b[4:]), true
}

func newNonce() [16]byte {
	var n [16]byte
	if _, err := rand.Read(n[:]); err != nil {
		panic("spagetti: crypto/rand failed: " + err.Error())
	}
	return n
}

// NonceCache remembers caller nonces so a captured handshake cannot be replayed
// onto a fresh channel.
type NonceCache struct {
	mu     sync.Mutex
	window time.Duration
	max    int
	seen   map[[16]byte]time.Time
	order  [][16]byte
}

// NewNonceCache returns a bounded replay cache.
func NewNonceCache(window time.Duration) *NonceCache {
	if window <= 0 {
		window = DefaultReplayWindow
	}
	return &NonceCache{window: window, max: DefaultNonceCacheSize, seen: map[[16]byte]time.Time{}}
}

// Use records a nonce. It reports false when the nonce was seen inside the
// window or its timestamp is outside it.
func (n *NonceCache) Use(nonce [16]byte, ts, now time.Time) bool {
	skew := now.Sub(ts)
	if skew < 0 {
		skew = -skew
	}
	if skew > n.window {
		return false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, dup := n.seen[nonce]; dup {
		return false
	}
	n.seen[nonce] = now
	n.order = append(n.order, nonce)
	n.prune(now)
	return true
}

func (n *NonceCache) prune(now time.Time) {
	cut := now.Add(-n.window)
	keep := n.order[:0]
	for _, nonce := range n.order {
		if t, ok := n.seen[nonce]; ok && t.After(cut) {
			keep = append(keep, nonce)
			continue
		}
		delete(n.seen, nonce)
	}
	n.order = keep
	for len(n.order) > n.max {
		delete(n.seen, n.order[0])
		n.order = n.order[1:]
	}
}
