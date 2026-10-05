package tunnel

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// idleChannel builds a channel with no tunnel behind it: enough to exercise the
// read deadline and queue semantics on their own.
func idleChannel() *Channel {
	return &Channel{
		in:      make(chan []byte, DefaultInboxRecords),
		inBytes: &atomic.Int64{},
		inMax:   DefaultMaxChannelBuffer,
		done:    make(chan struct{}),
		dlCh:    make(chan struct{}),
	}
}

func timeout(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("the read returned no error, want a timeout")
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("%v is not a net.Error with Timeout() == true; net/http cannot tell it from a dead connection", err)
	}
}

// TestDeadlineInterruptsBlockedRead is the property net/http depends on: it
// aborts the background read it holds on every connection by setting a read
// deadline in the past and waiting for that read to return. A deadline applied
// before the read, and one applied while the read is already blocked, must both
// interrupt it.
func TestDeadlineInterruptsBlockedRead(t *testing.T) {
	t.Run("set before the read", func(t *testing.T) {
		ch := idleChannel()
		ch.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		timeout(t, mustErr(ch))
	})

	t.Run("set while the read is blocked", func(t *testing.T) {
		ch := idleChannel()
		done := make(chan error, 1)
		go func() { _, err := ch.RecvRecord(context.Background()); done <- err }()
		// Let the reader get into the select before the deadline lands.
		time.Sleep(30 * time.Millisecond)
		start := time.Now()
		ch.SetReadDeadline(time.Now().Add(-time.Hour))
		select {
		case err := <-done:
			timeout(t, err)
			if took := time.Since(start); took > time.Second {
				t.Fatalf("the blocked read took %s to notice the deadline", took)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("a blocked read ignored a deadline set after it started")
		}
	})
}

func mustErr(ch *Channel) error {
	_, err := ch.RecvRecord(context.Background())
	return err
}

// TestClearingDeadlineResumesBlocking guards the other half: net/http clears the
// deadline once its abort is done, and reads must then block normally again
// instead of failing immediately on a stale deadline.
func TestClearingDeadlineResumesBlocking(t *testing.T) {
	ch := idleChannel()
	ch.SetReadDeadline(time.Now().Add(-time.Hour))
	timeout(t, mustErr(ch))

	ch.SetReadDeadline(time.Time{})
	done := make(chan []byte, 1)
	go func() {
		p, err := ch.RecvRecord(context.Background())
		if err != nil {
			t.Errorf("read after clearing the deadline: %v", err)
		}
		done <- p
	}()
	select {
	case <-done:
		t.Fatal("a read with no deadline returned on its own")
	case <-time.After(100 * time.Millisecond):
	}
	if err := ch.accept(0, []byte("late")); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-done:
		if string(p) != "late" {
			t.Fatalf("got %q", p)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the reader did not resume after the deadline was cleared")
	}
}

// TestQueuedRecordWinsOverExpiredDeadline keeps a deadline from losing data that
// already arrived: an expired deadline must not steal a queued record.
func TestQueuedRecordWinsOverExpiredDeadline(t *testing.T) {
	ch := idleChannel()
	ch.SetReadDeadline(time.Now().Add(-time.Hour))
	if err := ch.accept(0, []byte("first")); err != nil {
		t.Fatal(err)
	}
	p, err := ch.RecvRecord(context.Background())
	if err != nil {
		t.Fatalf("the queued record was dropped in favour of the timeout: %v", err)
	}
	if string(p) != "first" {
		t.Fatalf("got %q", p)
	}
}

// TestDeadlinesArePerDirection: a read must not clear the write deadline or the
// other way round.
func TestDeadlinesArePerDirection(t *testing.T) {
	ch := idleChannel()
	rd := time.Now().Add(time.Minute).Truncate(time.Millisecond)
	wd := time.Now().Add(2 * time.Minute).Truncate(time.Millisecond)
	ch.SetReadDeadline(rd)
	ch.SetWriteDeadline(wd)
	if got, _ := ch.writeDeadlines(); !got.Equal(wd) {
		t.Fatalf("write deadline is %s, want %s", got, wd)
	}
	ch.SetReadDeadline(time.Now().Add(3 * time.Minute).Truncate(time.Millisecond))
	if got, _ := ch.writeDeadlines(); !got.Equal(wd) {
		t.Fatalf("setting the read deadline changed the write deadline to %s", got)
	}
	ch.SetDeadline(time.Time{})
	if got, _ := ch.writeDeadlines(); !got.IsZero() {
		t.Fatalf("SetDeadline(zero) left the write deadline at %s", got)
	}
	if dl := ch.Deadline(); !dl.IsZero() {
		t.Fatalf("SetDeadline(zero) left the read deadline at %s", dl)
	}
}

// TestWriteDeadlineWakesAQueuedWriter: a write that is waiting for room must
// notice a deadline that is set after the wait began.
func TestWriteDeadlineWakesAQueuedWriter(t *testing.T) {
	ch := idleChannel()
	seen := make(chan struct{})
	go func() {
		// No tunnel behind this channel: reading the deadlines is all the
		// writer needs to reach, and the wait itself is hand-rolled here so the
		// test does not need a websocket.
		for i := 0; i < 500; i++ {
			_, wake := ch.writeDeadlines()
			if wake == nil {
				t.Error("writeDeadlines returned no wake channel")
				break
			}
			time.Sleep(time.Millisecond)
			select {
			case <-wake:
				close(seen)
				return
			default:
			}
		}
	}()
	time.Sleep(20 * time.Millisecond)
	ch.SetWriteDeadline(time.Now().Add(time.Second))
	select {
	case <-seen:
	case <-time.After(2 * time.Second):
		t.Fatal("a writer waiting on the queue did not see the deadline change")
	}
}
