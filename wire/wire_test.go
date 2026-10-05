package wire

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func sampleFrames(t *testing.T) []Frame {
	t.Helper()
	ch, err := RandomChannel()
	if err != nil {
		t.Fatal(err)
	}
	return []Frame{
		{Type: THello, Hello: Hello{Kind: KindServer, ID: "web1", PubKey: bytes.Repeat([]byte{7}, 32)}},
		{Type: THelloAck, Refuse: Refuse{Code: CodeNotAllowed, Message: "wrong role"}},
		{Type: TRegister, Register: Register{
			ServerID: "web1", Name: "Web One", Tags: []string{"a", "b"},
			PubKey: bytes.Repeat([]byte{3}, 32), Fingerprint: "spg1:deadbeef",
		}},
		{Type: TRegisterAck},
		{Type: TListReq},
		{Type: TListResp, Entries: []ServerEntry{{
			ServerID: "web1", Name: "Web One", Tags: []string{"x"},
			PubKey: bytes.Repeat([]byte{9}, 32), Fingerprint: "spg1:01", Online: true,
			ConnectedAt: time.Unix(1700000000, 0), Channels: 3,
		}}},
		{Type: TOpen, Open: Open{ServerID: "web1", Channel: ch, Epoch: 42}},
		{Type: TOpenOK, Refuse: Refuse{Channel: ch}},
		{Type: TOpenRefused, Refuse: Refuse{Channel: ch, Code: CodeNotAllowed, Message: "denied"}},
		{Type: TData, Data: Data{Channel: ch, Seq: 17, Payload: []byte("ciphertext")}},
		{Type: TClose, Close: Close{Channel: ch, Code: CodePeerGone, Message: "gone"}},
		{Type: TPing, Nonce: 12345},
		{Type: TPong, Nonce: 12345},
	}
}

func TestFrameRoundTrip(t *testing.T) {
	for _, f := range sampleFrames(t) {
		b, err := f.Encode()
		if err != nil {
			t.Fatalf("%s: encode: %v", f.Type, err)
		}
		got, err := Parse(b)
		if err != nil {
			t.Fatalf("%s: parse: %v", f.Type, err)
		}
		if got.Type != f.Type {
			t.Fatalf("type: got %s want %s", got.Type, f.Type)
		}
		switch f.Type {
		case THello:
			if got.Hello.Kind != f.Hello.Kind || got.Hello.ID != f.Hello.ID || !bytes.Equal(got.Hello.PubKey, f.Hello.PubKey) {
				t.Fatalf("hello mismatch: %+v", got.Hello)
			}
		case THelloAck, TRegisterAck:
			if got.Refuse.Code != f.Refuse.Code || got.Refuse.Message != f.Refuse.Message {
				t.Fatalf("ack mismatch: %+v", got.Refuse)
			}
		case TRegister:
			if got.Register.ServerID != f.Register.ServerID || got.Register.Fingerprint != f.Register.Fingerprint ||
				len(got.Register.Tags) != len(f.Register.Tags) || !bytes.Equal(got.Register.PubKey, f.Register.PubKey) {
				t.Fatalf("register mismatch: %+v", got.Register)
			}
		case TListResp:
			if len(got.Entries) != 1 {
				t.Fatalf("entries: %+v", got.Entries)
			}
			e, w := got.Entries[0], f.Entries[0]
			if e.ServerID != w.ServerID || e.Online != w.Online || e.Channels != w.Channels ||
				!e.ConnectedAt.Equal(w.ConnectedAt) || e.Fingerprint != w.Fingerprint {
				t.Fatalf("entry mismatch: %+v vs %+v", e, w)
			}
		case TOpen:
			if got.Open.ServerID != f.Open.ServerID || got.Open.Channel != f.Open.Channel || got.Open.Epoch != f.Open.Epoch {
				t.Fatalf("open mismatch: %+v", got.Open)
			}
		case TOpenOK, TOpenRefused:
			if got.Refuse.Channel != f.Refuse.Channel || got.Refuse.Code != f.Refuse.Code || got.Refuse.Message != f.Refuse.Message {
				t.Fatalf("refusal mismatch: %+v", got.Refuse)
			}
		case TData:
			if got.Data.Channel != f.Data.Channel || got.Data.Seq != f.Data.Seq || !bytes.Equal(got.Data.Payload, f.Data.Payload) {
				t.Fatalf("data mismatch: %+v", got.Data)
			}
		case TClose:
			if got.Close.Channel != f.Close.Channel || got.Close.Code != f.Close.Code || got.Close.Message != f.Close.Message {
				t.Fatalf("close mismatch: %+v", got.Close)
			}
		case TPing, TPong:
			if got.Nonce != f.Nonce {
				t.Fatalf("nonce mismatch: %d", got.Nonce)
			}
		}
	}
}

func TestParseRejectsHostileInput(t *testing.T) {
	ch, _ := RandomChannel()
	valid, _ := Frame{Type: TData, Data: Data{Channel: ch, Seq: 1, Payload: []byte("payload")}}.Encode()

	// A truncated frame, a bad version, reserved flags, an unknown type and
	// length-prefixed fields that run past the end.
	reg, err := Frame{Type: TRegister, Register: Register{
		ServerID: "web1", Name: "Web One", Tags: []string{"a"}, PubKey: bytes.Repeat([]byte{1}, 32),
	}}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	long := append([]byte(nil), valid...)
	long[4+16+8+3] = 0 // corrupt a payload byte: still parses, must not panic
	cases := map[string][]byte{
		"empty":          nil,
		"short":          {Version},
		"bad version":    {99, byte(TData), 0, 0},
		"flags":          {Version, byte(TData), 1, 0},
		"unknown":        {Version, 200, 0, 0},
		"cut register":   reg[:len(reg)-6],
		"empty open":     {Version, byte(TOpen), 0, 0},
		"long hello":     {Version, byte(THello), 0, 0, 1, 0xff, 0xff, 0xff, 0x7f},
		"short open":     {Version, byte(TOpen), 0, 0, 2, 0, 0, 0, 'a', 'b'},
		"short channel":  {Version, byte(TOpenOK), 0, 0, 1, 2, 3},
		"list truncated": {Version, byte(TListResp), 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 'x'},
	}
	for name, b := range cases {
		if _, err := Parse(b); err == nil {
			t.Fatalf("%s: parsed without error", name)
		}
	}
	if _, err := Parse(valid); err != nil {
		t.Fatalf("valid frame rejected: %v", err)
	}
	if _, err := Parse(long); err != nil {
		t.Fatalf("frame with a corrupt payload byte must still parse at this layer: %v", err)
	}
}

func TestParseDoesNotAllocateWildly(t *testing.T) {
	// A declared string length of 2 GiB must be rejected, not allocated.
	b := []byte{Version, byte(TListResp), 0, 0, 0xff, 0xff, 0xff, 0x7f}
	if _, err := Parse(b); err == nil {
		t.Fatal("an absurd entry count was accepted")
	}
}

func TestEncodeRejectsOversize(t *testing.T) {
	big := Frame{Type: TData, Data: Data{Payload: make([]byte, MaxFrame+1)}}
	if _, err := big.Encode(); err == nil {
		t.Fatal("an oversize frame was encoded")
	}
	tooMany := Frame{Type: TListResp, Entries: make([]ServerEntry, MaxEntries+1)}
	if _, err := tooMany.Encode(); err == nil {
		t.Fatal("an oversize directory was encoded")
	}
}

func TestChannelLabels(t *testing.T) {
	seen := map[Channel]bool{}
	for i := 0; i < 64; i++ {
		c, err := RandomChannel()
		if err != nil {
			t.Fatal(err)
		}
		if c == (Channel{}) {
			t.Fatal("random channel is the zero value")
		}
		if seen[c] {
			t.Fatal("duplicate random channel")
		}
		seen[c] = true
		back, err := ParseChannel(c.String())
		if err != nil || back != c {
			t.Fatalf("channel round trip failed: %v %v", back, err)
		}
	}
	for _, bad := range []string{"", "zz", "00112233445566778899aabbccddee", "00112233445566778899aabbccddeeff00"} {
		if _, err := ParseChannel(bad); err == nil {
			t.Fatalf("bad channel %q accepted", bad)
		}
	}
}

func TestErrorCodes(t *testing.T) {
	err := &Error{Code: CodeNotAllowed, Msg: "nope"}
	code, ok := CodeOf(err)
	if !ok || code != CodeNotAllowed {
		t.Fatalf("CodeOf: %v %v", code, ok)
	}
	if _, ok := CodeOf(errors.New("plain")); ok {
		t.Fatal("CodeOf claimed a plain error carries a code")
	}
	wrapped := &Error{Code: CodeReplay}
	if code, ok := CodeOf(wrapped); !ok || code != CodeReplay {
		t.Fatalf("code: %v %v", code, ok)
	}
	if wrapped.Error() != "spagetti: replay" {
		t.Fatalf("unexpected message %q", wrapped.Error())
	}
	for _, c := range []Code{CodeOK, CodeServerOffline, CodeUnsupported} {
		if c.String() == "" {
			t.Fatalf("code %d has no name", c)
		}
	}
}
