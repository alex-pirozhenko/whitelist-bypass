package tunnel

import (
	"io"
	"sync"
	"testing"
	"time"
)

type fakeRWC struct {
	writes [][]byte
	mu     sync.Mutex
}

func (f *fakeRWC) Read(p []byte) (int, error) {
	return 0, io.EOF
}

func (f *fakeRWC) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (f *fakeRWC) Close() error {
	return nil
}

func (f *fakeRWC) ReadDataChannel(p []byte) (int, bool, error) {
	// Block or return io.EOF to terminate the readLoop cleanly
	return 0, false, io.EOF
}

func (f *fakeRWC) WriteDataChannel(p []byte, isString bool) (int, error) {
	return f.Write(p)
}

func TestDCTunnel_ProfileKeepalive(t *testing.T) {
	readRaw := &fakeRWC{}
	writeRaw := &fakeRWC{}

	obf, err := NewTunnelObfuscator([]byte("test-secret-12345"))
	if err != nil {
		t.Fatalf("obfuscator err: %v", err)
	}

	// Construct using NewChunkedDCTunnelFromRaw which accepts two datachannel.ReadWriteClosers
	dc := NewChunkedDCTunnelFromRaw(readRaw, writeRaw, obf, 1024, t.Logf)

	// SetProfile with 30ms IdleKeepalive
	dc.SetProfile(Profile{IdleKeepalive: 30 * time.Millisecond})

	// Sleep ~120ms (generous enough to allow a few keepalives but avoid flakiness)
	time.Sleep(120 * time.Millisecond)

	writeRaw.mu.Lock()
	initialWritesCount := len(writeRaw.writes)
	writeRaw.mu.Unlock()

	// Since we sleep 120ms and keepalive check interval is 100ms, and IdleKeepalive is 30ms:
	// The first keepalive check tick at 100ms will see time.Since(lastSend) == 100ms > 30ms, so it sends a keepalive.
	// We want to be loose to avoid flakiness on slow virtual environments.
	t.Logf("Initial writes count (keepalives): %d", initialWritesCount)
	if initialWritesCount < 1 {
		t.Errorf("expected at least 1 keepalive, got %d", initialWritesCount)
	}

	// Now send a real message
	dc.SendData([]byte("hi"))

	writeRaw.mu.Lock()
	afterSendCount := len(writeRaw.writes)
	writeRaw.mu.Unlock()

	if afterSendCount != initialWritesCount+1 {
		t.Errorf("expected writes count to increase by exactly 1 after SendData, got %d (before: %d)", afterSendCount, initialWritesCount)
	}

	// Sleep a short window well under IdleKeepalive (e.g. 15ms)
	time.Sleep(15 * time.Millisecond)

	writeRaw.mu.Lock()
	afterShortSleepCount := len(writeRaw.writes)
	writeRaw.mu.Unlock()

	// Should not have sent any keepalives in this short window
	if afterShortSleepCount != afterSendCount {
		t.Errorf("expected no keepalives during short sleep window under IdleKeepalive, got %d (before: %d)", afterShortSleepCount, afterSendCount)
	}
}
