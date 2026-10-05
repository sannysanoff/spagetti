// Package tunnel carries a websocket connection to the spagetti gateway and
// multiplexes independent record streams ("channels") over it.
//
// Nothing in this package holds key material: a Channel is an ordered, reliable,
// sequence-checked carrier for opaque records. The end-to-end encryption happens
// one layer up, in package e2e. This is what lets the gateway share the framing
// without ever being able to read anything.
package tunnel

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/sannysanoff/spagetti/wire"
)

// Defaults used when an option is left zero.
const (
	DefaultHelloTimeout     = 10 * time.Second
	DefaultOpenTimeout      = 15 * time.Second
	DefaultListTimeout      = 10 * time.Second
	DefaultWriteTimeout     = 30 * time.Second
	DefaultMaxChannelBuffer = 4 << 20
	DefaultMaxOutBuffer     = 4 << 20
	DefaultInboxRecords     = 256
	// DefaultIdleTimeout is how long a gateway connection may go without a
	// single frame before it is treated as dead. It must stay comfortably above
	// the gateway's ping interval, which is what keeps an idle connection warm.
	DefaultIdleTimeout = 3 * time.Minute
)

// Open is delivered to Options.OnOpen when the gateway splices a new channel to
// this connection.
type Open struct {
	ServerID string
	Channel  wire.Channel
	Epoch    int64
}

// Options configures a gateway connection.
type Options struct {
	URL    string // ws:// or wss:// gateway endpoint
	Token  string // bearer token presented in the upgrade request
	Kind   wire.Kind
	ID     string // server id (server role) or client id (client role)
	PubKey []byte
	Name   string
	Tags   []string
	// Fingerprint is a display-only label announced for the directory. It is a
	// claim, not authentication: clients authenticate with their pinned key.
	Fingerprint string

	// Logf receives connection-level diagnostics. Never pass secrets to it.
	Logf func(format string, args ...any)

	HelloTimeout     time.Duration
	OpenTimeout      time.Duration
	ListTimeout      time.Duration
	IdleTimeout      time.Duration
	MaxChannelBuffer int
	MaxOutBuffer     int
	Dialer           *websocket.Dialer

	// OnOpen is called on the read loop when a client opens a channel to this
	// (server) connection. It must not block; hand work to a goroutine.
	OnOpen func(Open)
}

func (o *Options) setDefaults() {
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.HelloTimeout <= 0 {
		o.HelloTimeout = DefaultHelloTimeout
	}
	if o.OpenTimeout <= 0 {
		o.OpenTimeout = DefaultOpenTimeout
	}
	if o.ListTimeout <= 0 {
		o.ListTimeout = DefaultListTimeout
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = DefaultIdleTimeout
	}
	if o.MaxChannelBuffer <= 0 {
		o.MaxChannelBuffer = DefaultMaxChannelBuffer
	}
	if o.MaxOutBuffer <= 0 {
		o.MaxOutBuffer = DefaultMaxOutBuffer
	}
}

// Conn is a live gateway connection.
type Conn struct {
	o    Options
	ws   *websocket.Conn
	logf func(format string, args ...any)

	out      chan []byte
	outBytes atomic.Int64

	mu      sync.Mutex
	chans   map[wire.Channel]*Channel
	pending map[wire.Channel]chan openResult
	listers map[chan listResult]struct{}
	closed  bool
	err     error

	done      chan struct{}
	closeOnce sync.Once
}

type openResult struct {
	ch  *Channel
	err error
}

type listResult struct {
	entries []wire.ServerEntry
	err     error
}

// Dial connects to the gateway, performs the hello/register exchange and starts
// the reader and writer loops.
func Dial(ctx context.Context, o Options) (*Conn, error) {
	o.setDefaults()
	if o.URL == "" {
		return nil, fmt.Errorf("spagetti: gateway url is required")
	}
	if o.Token == "" {
		return nil, fmt.Errorf("spagetti: gateway bearer token is required")
	}
	if o.ID == "" {
		return nil, fmt.Errorf("spagetti: identity is required")
	}
	if o.Kind != wire.KindServer && o.Kind != wire.KindClient {
		return nil, fmt.Errorf("spagetti: connection kind is required")
	}
	d := o.Dialer
	if d == nil {
		d = &websocket.Dialer{HandshakeTimeout: o.HelloTimeout, Proxy: http.ProxyFromEnvironment}
	}
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+o.Token)
	ws, resp, err := d.DialContext(ctx, o.URL, hdr)
	if err != nil {
		if resp != nil {
			defer resp.Body.Close()
			return nil, fmt.Errorf("spagetti: gateway refused connection: %w (http %d)", err, resp.StatusCode)
		}
		return nil, fmt.Errorf("spagetti: gateway unreachable: %w", err)
	}
	ws.SetReadLimit(wire.MaxFrame)
	c := &Conn{
		o:       o,
		ws:      ws,
		logf:    o.Logf,
		out:     make(chan []byte, 256),
		chans:   map[wire.Channel]*Channel{},
		pending: map[wire.Channel]chan openResult{},
		listers: map[chan listResult]struct{}{},
		done:    make(chan struct{}),
	}
	if err := c.setup(ctx); err != nil {
		ws.Close()
		return nil, err
	}
	// The setup deadline must not outlive the handshake: the read loop owns the
	// connection's read deadline from here on.
	ws.SetReadDeadline(time.Time{})
	go c.writeLoop()
	go c.readLoop()
	o.Logf("tunnel: connected to %s as %s %q", o.URL, o.Kind, o.ID)
	return c, nil
}

func (c *Conn) setup(ctx context.Context) error {
	deadline := time.Now().Add(c.o.HelloTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.ws.SetWriteDeadline(deadline)
	hello, err := wire.Frame{Type: wire.THello, Hello: wire.Hello{
		Kind: c.o.Kind, ID: c.o.ID, PubKey: c.o.PubKey,
	}}.Encode()
	if err != nil {
		return err
	}
	if err := c.ws.WriteMessage(websocket.BinaryMessage, hello); err != nil {
		return fmt.Errorf("spagetti: hello failed: %w", err)
	}
	f, err := c.readFrame(deadline)
	if err != nil {
		return err
	}
	if f.Type != wire.THelloAck {
		return fmt.Errorf("spagetti: expected hello_ack, got %s", f.Type)
	}
	if f.Refuse.Code != wire.CodeOK {
		return &wire.Error{Code: f.Refuse.Code, Msg: "gateway rejected hello: " + f.Refuse.Message}
	}
	if c.o.Kind != wire.KindServer {
		return nil
	}
	c.ws.SetWriteDeadline(deadline)
	reg, err := wire.Frame{Type: wire.TRegister, Register: wire.Register{
		ServerID: c.o.ID, Name: c.o.Name, Tags: c.o.Tags, PubKey: c.o.PubKey,
		Fingerprint: c.o.Fingerprint,
	}}.Encode()
	if err != nil {
		return err
	}
	if err := c.ws.WriteMessage(websocket.BinaryMessage, reg); err != nil {
		return fmt.Errorf("spagetti: register failed: %w", err)
	}
	f, err = c.readFrame(deadline)
	if err != nil {
		return err
	}
	if f.Type != wire.TRegisterAck {
		return fmt.Errorf("spagetti: expected register_ack, got %s", f.Type)
	}
	if f.Refuse.Code != wire.CodeOK {
		return &wire.Error{Code: f.Refuse.Code, Msg: "gateway refused registration: " + f.Refuse.Message}
	}
	return nil
}

func (c *Conn) readFrame(deadline time.Time) (wire.Frame, error) {
	c.ws.SetReadDeadline(deadline)
	_, b, err := c.ws.ReadMessage()
	if err != nil {
		return wire.Frame{}, fmt.Errorf("spagetti: gateway handshake read: %w", err)
	}
	return wire.Parse(b)
}

// SendFrame encodes and queues a frame for the writer loop.
func (c *Conn) SendFrame(f wire.Frame) error {
	return c.sendFrame(f, nil)
}

// sendFrame queues a frame. When it belongs to a channel the channel's write
// deadline bounds the wait for room in the outbound queue, and a deadline set
// while that wait is in progress takes effect (net.Conn deadlines are
// reactivatable; a peer that stops reading must not block a writer forever).
func (c *Conn) sendFrame(f wire.Frame, ch *Channel) error {
	b, err := f.Encode()
	if err != nil {
		return err
	}
	for {
		var dl time.Time
		var wake <-chan struct{}
		if ch != nil {
			dl, wake = ch.writeDeadlines()
		}
		var timer *time.Timer
		var expired <-chan time.Time
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return ErrTimeout
			}
			timer = time.NewTimer(d)
			expired = timer.C
		}
		if c.outBytes.Load() > int64(c.o.MaxOutBuffer) {
			stopTimer(timer)
			err := &wire.Error{Code: wire.CodeOverload, Msg: "outbound queue full"}
			c.shutdown(err)
			return err
		}
		select {
		case c.out <- b:
			stopTimer(timer)
			c.outBytes.Add(int64(len(b)))
			return nil
		case <-c.done:
			stopTimer(timer)
			return c.Err()
		case <-expired:
			return ErrTimeout
		case <-wake:
			stopTimer(timer) // deadline changed: re-evaluate it
		}
	}
}

func (c *Conn) writeLoop() {
	for {
		select {
		case b := <-c.out:
			c.outBytes.Add(-int64(len(b)))
			c.ws.SetWriteDeadline(time.Now().Add(DefaultWriteTimeout))
			if err := c.ws.WriteMessage(websocket.BinaryMessage, b); err != nil {
				c.shutdown(fmt.Errorf("spagetti: gateway write: %w", err))
				return
			}
		case <-c.done:
			return
		}
	}
}

func (c *Conn) readLoop() {
	for {
		// Any frame renews the deadline; the gateway pings, so silence means the
		// connection is gone.
		c.ws.SetReadDeadline(time.Now().Add(c.o.IdleTimeout))
		_, b, err := c.ws.ReadMessage()
		if err != nil {
			c.shutdown(fmt.Errorf("spagetti: gateway read: %w", err))
			return
		}
		f, err := wire.Parse(b)
		if err != nil {
			c.shutdown(err)
			return
		}
		if err := c.dispatch(f); err != nil {
			c.logf("tunnel: %v", err)
		}
	}
}

func (c *Conn) dispatch(f wire.Frame) error {
	switch f.Type {
	case wire.TData:
		ch := c.channel(f.Data.Channel)
		if ch == nil {
			return c.SendFrame(wire.Frame{Type: wire.TClose, Close: wire.Close{
				Channel: f.Data.Channel, Code: wire.CodeProtocolError, Message: "unknown channel",
			}})
		}
		if err := ch.accept(f.Data.Seq, f.Data.Payload); err != nil {
			ch.fail(err)
			return err
		}
		return nil
	case wire.TOpen:
		if c.o.OnOpen == nil {
			return c.SendFrame(wire.Frame{Type: wire.TOpenRefused, Refuse: wire.Refuse{
				Channel: f.Open.Channel, Code: wire.CodeProtocolError, Message: "not a server connection",
			}})
		}
		c.newChannel(f.Open.Channel)
		c.o.OnOpen(Open{ServerID: f.Open.ServerID, Channel: f.Open.Channel, Epoch: f.Open.Epoch})
		return nil
	case wire.TOpenOK:
		c.resolveOpen(f.Refuse.Channel, nil)
		return nil
	case wire.TOpenRefused:
		c.resolveOpen(f.Refuse.Channel, &wire.Error{Code: f.Refuse.Code, Msg: f.Refuse.Message})
		return nil
	case wire.TClose:
		err := closeError(f.Close)
		c.resolveOpen(f.Close.Channel, err) // a refusal during setup must not hang the opener
		if ch := c.channel(f.Close.Channel); ch != nil {
			ch.fail(err)
		}
		return nil
	case wire.TListResp:
		c.mu.Lock()
		for w := range c.listers {
			select {
			case w <- listResult{entries: f.Entries}:
			default:
			}
			delete(c.listers, w)
		}
		c.mu.Unlock()
		return nil
	case wire.TPing:
		return c.SendFrame(wire.Frame{Type: wire.TPong, Nonce: f.Nonce})
	case wire.TPong:
		return nil
	case wire.THelloAck, wire.TRegisterAck:
		return fmt.Errorf("spagetti: unexpected %s outside setup", f.Type)
	}
	return nil
}

func closeError(f wire.Close) error {
	if f.Code == wire.CodeOK {
		return io.EOF
	}
	return &wire.Error{Code: f.Code, Msg: f.Message}
}

// List asks the gateway for its directory.
func (c *Conn) List(ctx context.Context) ([]wire.ServerEntry, error) {
	w := make(chan listResult, 1)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, c.Err()
	}
	c.listers[w] = struct{}{}
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.listers, w)
		c.mu.Unlock()
	}()
	if err := c.SendFrame(wire.Frame{Type: wire.TListReq}); err != nil {
		return nil, err
	}
	timeout := time.NewTimer(c.o.ListTimeout)
	defer timeout.Stop()
	select {
	case r := <-w:
		return r.entries, r.err
	case <-timeout.C:
		return nil, &wire.Error{Code: wire.CodeTimeout, Msg: "gateway did not answer list request"}
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		return nil, c.Err()
	}
}

// Open asks the gateway to splice a channel to serverID and waits for the
// server's answer. The returned Channel is a raw record carrier.
func (c *Conn) Open(ctx context.Context, serverID string, epoch int64) (*Channel, error) {
	id, err := wire.RandomChannel()
	if err != nil {
		return nil, err
	}
	return c.OpenWithLabel(ctx, serverID, epoch, id)
}

// OpenWithLabel is Open with a caller-chosen channel label. The label is bound
// into the end-to-end handshake, so it must be unique per live channel.
func (c *Conn) OpenWithLabel(ctx context.Context, serverID string, epoch int64, id wire.Channel) (*Channel, error) {
	ch := c.newChannel(id)
	w := make(chan openResult, 1)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, c.Err()
	}
	c.pending[id] = w
	c.mu.Unlock()
	cleanup := func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		c.removeChannel(id)
	}
	if err := c.SendFrame(wire.Frame{Type: wire.TOpen, Open: wire.Open{
		ServerID: serverID, Channel: id, Epoch: epoch,
	}}); err != nil {
		cleanup()
		return nil, err
	}
	timeout := time.NewTimer(c.o.OpenTimeout)
	defer timeout.Stop()
	select {
	case r := <-w:
		if r.err != nil {
			c.removeChannel(id)
			return nil, r.err
		}
		return ch, nil
	case <-timeout.C:
		cleanup()
		return nil, &wire.Error{Code: wire.CodeTimeout, Msg: "server " + serverID + " did not answer open"}
	case <-ctx.Done():
		cleanup()
		return nil, ctx.Err()
	case <-c.done:
		cleanup()
		return nil, c.Err()
	}
}

func (c *Conn) resolveOpen(id wire.Channel, err error) {
	c.mu.Lock()
	w := c.pending[id]
	delete(c.pending, id)
	c.mu.Unlock()
	if w == nil {
		return
	}
	select {
	case w <- openResult{err: err}:
	default:
	}
}

// AcceptOpen tells a client its channel is live (server role).
func (c *Conn) AcceptOpen(id wire.Channel) error {
	return c.SendFrame(wire.Frame{Type: wire.TOpenOK, Refuse: wire.Refuse{Channel: id}})
}

// RefuseOpen declines a channel (server role).
func (c *Conn) RefuseOpen(id wire.Channel, code wire.Code, msg string) error {
	return c.SendFrame(wire.Frame{Type: wire.TOpenRefused, Refuse: wire.Refuse{
		Channel: id, Code: code, Message: msg,
	}})
}

// Done is closed when the connection dies.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Err reports why the connection died, or nil while it is alive.
func (c *Conn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err == nil {
		return &wire.Error{Code: wire.CodePeerGone, Msg: "connection closed"}
	}
	return c.err
}

// Close shuts the connection down and fails every channel.
func (c *Conn) Close() error {
	c.shutdown(io.EOF)
	return nil
}

func (c *Conn) shutdown(err error) {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.err = err
		chans := make([]*Channel, 0, len(c.chans))
		for _, ch := range c.chans {
			chans = append(chans, ch)
		}
		pend := make([]chan openResult, 0, len(c.pending))
		for _, w := range c.pending {
			pend = append(pend, w)
		}
		c.pending = map[wire.Channel]chan openResult{}
		listers := make([]chan listResult, 0, len(c.listers))
		for w := range c.listers {
			listers = append(listers, w)
		}
		c.listers = map[chan listResult]struct{}{}
		c.mu.Unlock()
		close(c.done)
		for _, ch := range chans {
			ch.fail(err)
		}
		for _, w := range pend {
			select {
			case w <- openResult{err: err}:
			default:
			}
		}
		for _, w := range listers {
			select {
			case w <- listResult{err: err}:
			default:
			}
		}
		c.ws.Close()
	})
}

func (c *Conn) newChannel(id wire.Channel) *Channel {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ch, ok := c.chans[id]; ok {
		return ch
	}
	ch := &Channel{
		id:      id,
		c:       c,
		in:      make(chan []byte, DefaultInboxRecords),
		inMax:   c.o.MaxChannelBuffer,
		done:    make(chan struct{}),
		dlCh:    make(chan struct{}),
		inBytes: &atomic.Int64{},
	}
	c.chans[id] = ch
	return ch
}

func (c *Conn) channel(id wire.Channel) *Channel {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.chans[id]
}

func (c *Conn) removeChannel(id wire.Channel) {
	c.mu.Lock()
	delete(c.chans, id)
	c.mu.Unlock()
}

// Channel returns the record carrier for a route, creating it when needed. It is
// how the server side obtains the carrier for a channel the gateway just opened.
func (c *Conn) Channel(id wire.Channel) *Channel { return c.newChannel(id) }

// Channel is an ordered record carrier for one gateway route.
type Channel struct {
	id      wire.Channel
	c       *Conn
	in      chan []byte
	inBytes *atomic.Int64
	inMax   int

	mu        sync.Mutex
	sendSeq   uint64
	expectSeq uint64
	closed    bool
	err       error
	deadline  time.Time
	writeDl   time.Time
	// dlCh is closed and replaced whenever a deadline changes, so a read or a
	// queued write that is already blocked wakes up and re-evaluates it.
	dlCh chan struct{}

	done      chan struct{}
	closeOnce sync.Once
}

// ID returns the channel label.
func (ch *Channel) ID() wire.Channel { return ch.id }

// SendRecord queues one record (at most wire.MaxRecord bytes, which is one
// chunk of plaintext plus its AEAD tag) on the channel.
func (ch *Channel) SendRecord(p []byte) error {
	if len(p) > wire.MaxRecord {
		return fmt.Errorf("spagetti: record too large: %d > %d", len(p), wire.MaxRecord)
	}
	ch.mu.Lock()
	if ch.closed {
		err := ch.err
		ch.mu.Unlock()
		return err
	}
	seq := ch.sendSeq
	ch.sendSeq++
	ch.mu.Unlock()
	return ch.c.sendFrame(wire.Frame{Type: wire.TData, Data: wire.Data{
		Channel: ch.id, Seq: seq, Payload: p,
	}}, ch)
}

// RecvRecord returns the next record. It blocks until a record, a close, or the
// context/deadline expires. Records are returned in send order; a gap fails the
// channel rather than silently reordering plaintext.
func (ch *Channel) RecvRecord(ctx context.Context) ([]byte, error) {
	for {
		// Fast path: a queued record wins over an expired deadline.
		select {
		case p := <-ch.in:
			ch.inBytes.Add(-int64(len(p)))
			return p, nil
		default:
		}
		ch.mu.Lock()
		dl, wake := ch.deadline, ch.dlCh
		ch.mu.Unlock()
		var timer *time.Timer
		var expired <-chan time.Time
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return nil, ErrTimeout
			}
			timer = time.NewTimer(d)
			expired = timer.C
		}
		select {
		case p := <-ch.in:
			stopTimer(timer)
			ch.inBytes.Add(-int64(len(p)))
			return p, nil
		case <-ch.done:
			stopTimer(timer)
			select {
			case p := <-ch.in:
				ch.inBytes.Add(-int64(len(p)))
				return p, nil
			default:
			}
			return nil, ch.Err()
		case <-expired:
			return nil, ErrTimeout
		case <-wake:
			stopTimer(timer) // deadline changed: re-evaluate it
		case <-ctx.Done():
			stopTimer(timer)
			return nil, ctx.Err()
		}
	}
}

func stopTimer(t *time.Timer) {
	if t != nil {
		t.Stop()
	}
}

func (ch *Channel) accept(seq uint64, payload []byte) error {
	ch.mu.Lock()
	if ch.closed {
		ch.mu.Unlock()
		return nil
	}
	if seq != ch.expectSeq {
		ch.mu.Unlock()
		return &wire.Error{Code: wire.CodeProtocolError, Msg: fmt.Sprintf(
			"channel %s: record %d out of order, expected %d", ch.id, seq, ch.expectSeq)}
	}
	ch.expectSeq++
	ch.mu.Unlock()
	if ch.inBytes.Load() > int64(ch.inMax) {
		return &wire.Error{Code: wire.CodeOverload, Msg: "channel buffer overflow"}
	}
	select {
	case ch.in <- payload:
		ch.inBytes.Add(int64(len(payload)))
	case <-ch.done:
	}
	return nil
}

// Close ends the channel, telling the peer why.
func (ch *Channel) Close(code wire.Code, msg string) error {
	err := ch.c.SendFrame(wire.Frame{Type: wire.TClose, Close: wire.Close{
		Channel: ch.id, Code: code, Message: msg,
	}})
	if code == wire.CodeOK {
		ch.fail(io.EOF)
	} else {
		ch.fail(&wire.Error{Code: code, Msg: msg})
	}
	return err
}

func (ch *Channel) fail(err error) {
	ch.closeOnce.Do(func() {
		ch.mu.Lock()
		ch.closed = true
		ch.err = err
		ch.mu.Unlock()
		close(ch.done)
		ch.c.removeChannel(ch.id)
	})
}

// Done is closed when the channel is dead.
func (ch *Channel) Done() <-chan struct{} { return ch.done }

// Err reports why the channel died.
func (ch *Channel) Err() error {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	if ch.err == nil {
		return &wire.Error{Code: wire.CodePeerGone, Msg: "channel closed"}
	}
	return ch.err
}

// SetDeadline bounds RecvRecord calls made without their own deadline. It also
// applies to a read that is already blocked: net.Conn read deadlines are
// reactivatable, and net/http depends on that to abort the background read it
// keeps on every connection (without it, a handler that returns while that read
// is in flight deadlocks the connection, and a websocket upgrade cannot hijack).
func (ch *Channel) SetDeadline(t time.Time) {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	ch.armLocked(t, t)
}

// SetReadDeadline bounds reads on this channel.
func (ch *Channel) SetReadDeadline(t time.Time) {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	ch.armLocked(t, ch.writeDl)
}

// SetWriteDeadline bounds the wait for room in the outbound queue.
func (ch *Channel) SetWriteDeadline(t time.Time) {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	ch.armLocked(ch.deadline, t)
}

func (ch *Channel) armLocked(rd, wd time.Time) {
	if ch.deadline.Equal(rd) && ch.writeDl.Equal(wd) {
		return
	}
	ch.deadline, ch.writeDl = rd, wd
	close(ch.dlCh)
	ch.dlCh = make(chan struct{})
}

// writeDeadlines reports the current write deadline and the channel that is
// closed when any deadline changes.
func (ch *Channel) writeDeadlines() (time.Time, <-chan struct{}) {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	return ch.writeDl, ch.dlCh
}

// errTimeout is an i/o timeout that satisfies net.Error, which is how net/http
// tells a reactivated deadline apart from a dead connection.
type errTimeout struct{}

func (errTimeout) Error() string   { return "spagetti: i/o timeout" }
func (errTimeout) Timeout() bool   { return true }
func (errTimeout) Temporary() bool { return true }

// ErrTimeout is returned by a read or write that hit its deadline.
var ErrTimeout error = errTimeout{}

// Deadline reports the current read deadline.
func (ch *Channel) Deadline() time.Time {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	return ch.deadline
}
