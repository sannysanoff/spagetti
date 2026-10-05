// Package wire defines the spagetti relay frame format: the small, crypto-free
// envelope the gateway parses (type, channel, routing fields) and the opaque
// payloads that carry end-to-end encrypted bytes between a client and a server.
//
// The gateway understands only this package. It never sees keys and never sees
// plaintext; see the trust-boundary test in tests/trust_boundary_test.go.
package wire

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Protocol constants. Version is carried in every frame header.
const (
	Version    = 1
	ChannelLen = 16
	MaxFrame   = 1 << 20       // hard cap on one frame payload, both directions
	MaxChunk   = 16384         // plaintext bytes per transport record (Noise caps at 65519)
	MaxRecord  = MaxChunk + 16 // one Data payload: ciphertext plus the AEAD tag
	MaxString  = 4096
	MaxTags    = 64
	MaxEntries = 2048
	MaxPubKey  = 64
)

// Type is the frame discriminant.
type Type uint8

// Frame types. Client speaks TOpen, TListReq, TData, TClose. Server speaks
// TRegister, TOpenOK, TOpenRefused, TData, TClose. The gateway relays frames
// verbatim and never originates an answer that belongs to a server.
const (
	THello       Type = 1
	THelloAck    Type = 2
	TRegister    Type = 3
	TRegisterAck Type = 4
	TListReq     Type = 5
	TListResp    Type = 6
	TOpen        Type = 7
	TOpenOK      Type = 8
	TOpenRefused Type = 9
	TData        Type = 10
	TClose       Type = 11
	TPing        Type = 12
	TPong        Type = 13
)

func (t Type) String() string {
	switch t {
	case THello:
		return "hello"
	case THelloAck:
		return "hello_ack"
	case TRegister:
		return "register"
	case TRegisterAck:
		return "register_ack"
	case TListReq:
		return "list_req"
	case TListResp:
		return "list_resp"
	case TOpen:
		return "open"
	case TOpenOK:
		return "open_ok"
	case TOpenRefused:
		return "open_refused"
	case TData:
		return "data"
	case TClose:
		return "close"
	case TPing:
		return "ping"
	case TPong:
		return "pong"
	}
	return fmt.Sprintf("type(%d)", uint8(t))
}

// Kind distinguishes the two roles a connection can take on the gateway.
type Kind uint8

// Connection kinds.
const (
	KindServer Kind = 1
	KindClient Kind = 2
)

func (k Kind) String() string {
	switch k {
	case KindServer:
		return "server"
	case KindClient:
		return "client"
	}
	return fmt.Sprintf("kind(%d)", uint8(k))
}

// Code is a refusal/close reason. Codes below CodeLocalFirst are produced by the
// peers; the rest are transport-level conditions either side may report.
type Code uint16

// Reason codes.
const (
	CodeOK               Code = 0
	CodeServerOffline    Code = 1
	CodeNotAllowed       Code = 2
	CodeAuthFailed       Code = 3
	CodeDuplicateChannel Code = 4
	CodeTooManyChannels  Code = 5
	CodeOverload         Code = 6
	CodeMalformed        Code = 7
	CodePeerGone         Code = 8
	CodeTimeout          Code = 9
	CodeProtocolError    Code = 10
	CodeInternal         Code = 11
	CodeReplay           Code = 12
	CodeUnsupported      Code = 13
)

func (c Code) String() string {
	switch c {
	case CodeOK:
		return "ok"
	case CodeServerOffline:
		return "server_offline"
	case CodeNotAllowed:
		return "not_allowed"
	case CodeAuthFailed:
		return "auth_failed"
	case CodeDuplicateChannel:
		return "duplicate_channel"
	case CodeTooManyChannels:
		return "too_many_channels"
	case CodeOverload:
		return "overload"
	case CodeMalformed:
		return "malformed"
	case CodePeerGone:
		return "peer_gone"
	case CodeTimeout:
		return "timeout"
	case CodeProtocolError:
		return "protocol_error"
	case CodeInternal:
		return "internal"
	case CodeReplay:
		return "replay"
	case CodeUnsupported:
		return "unsupported"
	}
	return fmt.Sprintf("code(%d)", uint16(c))
}

// Error is a wire-level failure carrying a reason code, so callers can branch on
// the code instead of matching strings.
type Error struct {
	Code Code
	Msg  string
}

func (e *Error) Error() string {
	if e.Msg == "" {
		return "spagetti: " + e.Code.String()
	}
	return "spagetti: " + e.Code.String() + ": " + e.Msg
}

// CodeOf extracts the reason code from an error, if it carries one.
func CodeOf(err error) (Code, bool) {
	var we *Error
	if errors.As(err, &we) {
		return we.Code, true
	}
	return CodeOK, false
}

// Errors returned by the codec.
var (
	ErrMalformed = errors.New("spagetti: malformed frame")
	ErrVersion   = errors.New("spagetti: unsupported protocol version")
)

// Channel is a client-chosen, gateway-visible routing label. It is not a secret
// and carries no key material; it is bound into the end-to-end handshake so a
// relay cannot rename or splice it.
type Channel [ChannelLen]byte

func (c Channel) String() string { return hex.EncodeToString(c[:]) }

// RandomChannel returns a fresh 128-bit channel label.
func RandomChannel() (Channel, error) {
	var c Channel
	if _, err := rand.Read(c[:]); err != nil {
		return c, fmt.Errorf("spagetti: random channel: %w", err)
	}
	// All-zero is reserved so a zero-value Channel is never a live route.
	c[0] |= 1
	return c, nil
}

// ParseChannel decodes a 32-character hex channel label.
func ParseChannel(s string) (Channel, error) {
	var c Channel
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != ChannelLen {
		return c, fmt.Errorf("spagetti: bad channel %q", s)
	}
	copy(c[:], b)
	return c, nil
}

// Hello is the first frame on any connection to the gateway.
type Hello struct {
	Kind   Kind
	ID     string
	PubKey []byte
}

// Register announces a server (and its metadata) to the gateway. Fingerprint is
// the server's own claim and is only for display: a client authenticates the
// server with its pinned key, never with what the directory says.
type Register struct {
	ServerID    string
	Name        string
	Tags        []string
	PubKey      []byte
	Fingerprint string
}

// ServerEntry is one row of the gateway directory.
type ServerEntry struct {
	ServerID    string
	Name        string
	Tags        []string
	PubKey      []byte
	Fingerprint string
	Online      bool
	ConnectedAt time.Time
	Channels    int
}

// Open asks the gateway to splice a new channel to a named server.
type Open struct {
	ServerID string
	Channel  Channel
	Epoch    int64
}

// Data carries one record: end-to-end ciphertext for the peers, opaque to the
// gateway. Seq is per channel and per direction, starting at 0 (records 0..N are
// handshake records, the rest are transport records).
type Data struct {
	Channel Channel
	Seq     uint64
	Payload []byte
}

// Close tears a channel down.
type Close struct {
	Channel Channel
	Code    Code
	Message string
}

// Refuse declines an Open.
type Refuse struct {
	Channel Channel
	Code    Code
	Message string
}

// Frame is the single decoded envelope shape. Encode and Parse switch on Type.
type Frame struct {
	Type     Type
	Hello    Hello
	Register Register
	Entries  []ServerEntry
	Open     Open
	Data     Data
	Close    Close
	Refuse   Refuse
	Nonce    uint64
}

// Encode serialises the frame, including its 4-byte header.
func (f Frame) Encode() ([]byte, error) {
	b := make([]byte, 0, 64)
	b = append(b, Version, byte(f.Type), 0, 0)
	switch f.Type {
	case THello:
		b = appendU8(b, byte(f.Hello.Kind))
		b = appendStr(b, f.Hello.ID)
		b = appendBytes(b, f.Hello.PubKey)
	case THelloAck, TRegisterAck:
		b = appendCode(b, f.Refuse.Code)
		b = appendStr(b, f.Refuse.Message)
	case TRegister:
		b = appendStr(b, f.Register.ServerID)
		b = appendStr(b, f.Register.Name)
		b = appendTags(b, f.Register.Tags)
		b = appendBytes(b, f.Register.PubKey)
		b = appendStr(b, f.Register.Fingerprint)
	case TListReq:
	case TListResp:
		if len(f.Entries) > MaxEntries {
			return nil, fmt.Errorf("spagetti: too many entries: %d", len(f.Entries))
		}
		b = appendU32(b, uint32(len(f.Entries)))
		for _, e := range f.Entries {
			b = appendStr(b, e.ServerID)
			b = appendStr(b, e.Name)
			b = appendTags(b, e.Tags)
			b = appendBytes(b, e.PubKey)
			b = appendStr(b, e.Fingerprint)
			var online byte
			if e.Online {
				online = 1
			}
			b = append(b, online)
			b = appendU64(b, uint64(e.ConnectedAt.Unix()))
			b = appendU64(b, uint64(e.Channels))
		}
	case TOpen:
		b = appendStr(b, f.Open.ServerID)
		b = append(b, f.Open.Channel[:]...)
		b = appendU64(b, uint64(f.Open.Epoch))
	case TOpenOK:
		b = append(b, f.Refuse.Channel[:]...)
	case TOpenRefused:
		b = append(b, f.Refuse.Channel[:]...)
		b = appendCode(b, f.Refuse.Code)
		b = appendStr(b, f.Refuse.Message)
	case TData:
		b = append(b, f.Data.Channel[:]...)
		b = appendU64(b, f.Data.Seq)
		b = append(b, f.Data.Payload...)
	case TClose:
		b = append(b, f.Close.Channel[:]...)
		b = appendCode(b, f.Close.Code)
		b = appendStr(b, f.Close.Message)
	case TPing, TPong:
		b = appendU64(b, f.Nonce)
	default:
		return nil, fmt.Errorf("spagetti: cannot encode %s", f.Type)
	}
	if len(b) > MaxFrame {
		return nil, fmt.Errorf("spagetti: frame too large: %d", len(b))
	}
	return b, nil
}

// Parse decodes a frame. It never panics on hostile input.
func Parse(b []byte) (Frame, error) {
	var f Frame
	if len(b) < 4 {
		return f, ErrMalformed
	}
	if b[0] != Version {
		return f, fmt.Errorf("%w: %d", ErrVersion, b[0])
	}
	if b[2] != 0 || b[3] != 0 {
		return f, fmt.Errorf("%w: reserved flags set", ErrMalformed)
	}
	f.Type = Type(b[1])
	d := &dec{b: b[4:]}
	switch f.Type {
	case THello:
		f.Hello.Kind = Kind(d.u8())
		f.Hello.ID = d.str()
		f.Hello.PubKey = d.bytes(MaxPubKey)
	case THelloAck, TRegisterAck:
		f.Refuse.Code = d.code()
		f.Refuse.Message = d.str()
	case TRegister:
		f.Register.ServerID = d.str()
		f.Register.Name = d.str()
		f.Register.Tags = d.tags()
		f.Register.PubKey = d.bytes(MaxPubKey)
		f.Register.Fingerprint = d.str()
	case TListReq:
	case TListResp:
		n := d.u32()
		if d.err == nil && n > MaxEntries {
			d.fail(fmt.Sprintf("too many entries: %d", n))
		}
		for i := uint32(0); i < n && d.err == nil; i++ {
			var e ServerEntry
			e.ServerID = d.str()
			e.Name = d.str()
			e.Tags = d.tags()
			e.PubKey = d.bytes(MaxPubKey)
			e.Fingerprint = d.str()
			e.Online = d.u8() == 1
			e.ConnectedAt = time.Unix(int64(d.u64()), 0)
			e.Channels = int(d.u64())
			f.Entries = append(f.Entries, e)
		}
	case TOpen:
		f.Open.ServerID = d.str()
		c, err := d.channel()
		if err != nil {
			return f, err
		}
		f.Open.Channel = c
		f.Open.Epoch = int64(d.u64())
	case TOpenOK:
		c, err := d.channel()
		if err != nil {
			return f, err
		}
		f.Refuse.Channel = c
	case TOpenRefused:
		c, err := d.channel()
		if err != nil {
			return f, err
		}
		f.Refuse.Channel = c
		f.Refuse.Code = d.code()
		f.Refuse.Message = d.str()
	case TData:
		c, err := d.channel()
		if err != nil {
			return f, err
		}
		f.Data.Channel = c
		f.Data.Seq = d.u64()
		f.Data.Payload = d.rest()
	case TClose:
		c, err := d.channel()
		if err != nil {
			return f, err
		}
		f.Close.Channel = c
		f.Close.Code = d.code()
		f.Close.Message = d.str()
	case TPing, TPong:
		f.Nonce = d.u64()
	default:
		return f, fmt.Errorf("%w: unknown type %d", ErrMalformed, uint8(f.Type))
	}
	if d.err != nil {
		return f, fmt.Errorf("%w: %v", ErrMalformed, d.err)
	}
	if len(b) > MaxFrame {
		return f, fmt.Errorf("%w: frame too large", ErrMalformed)
	}
	return f, nil
}

func appendU8(b []byte, v uint8) []byte { return append(b, v) }
func appendU32(b []byte, v uint32) []byte {
	return binary.LittleEndian.AppendUint32(b, v)
}
func appendU64(b []byte, v uint64) []byte {
	return binary.LittleEndian.AppendUint64(b, v)
}
func appendCode(b []byte, c Code) []byte {
	return binary.LittleEndian.AppendUint16(b, uint16(c))
}
func appendStr(b []byte, s string) []byte {
	if len(s) > MaxString {
		s = s[:MaxString]
	}
	b = appendU32(b, uint32(len(s)))
	return append(b, s...)
}
func appendBytes(b []byte, p []byte) []byte {
	if len(p) > MaxPubKey {
		p = p[:MaxPubKey]
	}
	b = appendU32(b, uint32(len(p)))
	return append(b, p...)
}
func appendTags(b []byte, tags []string) []byte {
	if len(tags) > MaxTags {
		tags = tags[:MaxTags]
	}
	b = appendU32(b, uint32(len(tags)))
	for _, t := range tags {
		b = appendStr(b, t)
	}
	return b
}

type dec struct {
	b   []byte
	err error
}

func (d *dec) fail(msg string) {
	if d.err == nil {
		d.err = errors.New(msg)
	}
}

func (d *dec) take(n int) []byte {
	if d.err != nil {
		return nil
	}
	if n < 0 || len(d.b) < n {
		d.fail("short frame")
		return nil
	}
	out := d.b[:n]
	d.b = d.b[n:]
	return out
}

func (d *dec) u8() uint8 {
	b := d.take(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (d *dec) u16() uint16 {
	b := d.take(2)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint16(b)
}

func (d *dec) code() Code { return Code(d.u16()) }

func (d *dec) u32() uint32 {
	b := d.take(4)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(b)
}

func (d *dec) u64() uint64 {
	b := d.take(8)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint64(b)
}

func (d *dec) str() string {
	n := d.u32()
	if d.err != nil {
		return ""
	}
	if n > MaxString {
		d.fail("string too long")
		return ""
	}
	return string(d.take(int(n)))
}

func (d *dec) bytes(max int) []byte {
	n := d.u32()
	if d.err != nil {
		return nil
	}
	if n > uint32(max) {
		d.fail("byte field too long")
		return nil
	}
	b := d.take(int(n))
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}

func (d *dec) tags() []string {
	n := d.u32()
	if d.err != nil {
		return nil
	}
	if n > MaxTags {
		d.fail("too many tags")
		return nil
	}
	var out []string
	for i := uint32(0); i < n; i++ {
		out = append(out, d.str())
	}
	return out
}

func (d *dec) channel() (Channel, error) {
	var c Channel
	b := d.take(ChannelLen)
	if b == nil {
		return c, fmt.Errorf("%w: short channel", ErrMalformed)
	}
	copy(c[:], b)
	return c, nil
}

func (d *dec) rest() []byte {
	if d.err != nil {
		return nil
	}
	if len(d.b) > MaxFrame {
		d.fail("payload too large")
		return nil
	}
	return d.b
}
