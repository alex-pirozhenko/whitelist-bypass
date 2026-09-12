package tunnel

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

func TestVP8Tunnel_Coalescing(t *testing.T) {
	obfSender, err := NewTunnelObfuscator([]byte("test-secret-12345"))
	if err != nil {
		t.Fatalf("obfuscator err: %v", err)
	}
	obfReceiver, err := NewTunnelObfuscator([]byte("test-secret-12345"))
	if err != nil {
		t.Fatalf("obfuscator err: %v", err)
	}

	var mu sync.Mutex
	var capture [][]byte
	tun := NewVP8DataTunnelWithQueue(nil, obfSender, t.Logf, 128)
	tun.WriteFrame = func(b []byte) error {
		mu.Lock()
		capture = append(capture, append([]byte(nil), b...))
		mu.Unlock()
		return nil
	}

	tun.SetProfile(Profile{FPS: 1000, Batch: 1, MaxFrameBytes: 10000})

	f1 := EncodeFrame(1, MsgData, []byte("frame-one"))
	f2 := EncodeFrame(2, MsgData, []byte("frame-two"))
	f3 := EncodeFrame(3, MsgData, []byte("frame-three"))

	tun.SendData(f1)
	tun.SendData(f2)
	tun.SendData(f3)

	tun.Start(1000, 1)
	time.Sleep(30 * time.Millisecond)
	tun.Stop()

	mu.Lock()
	localCapture := make([][]byte, len(capture))
	copy(localCapture, capture)
	mu.Unlock()

	if len(localCapture) == 0 {
		t.Fatalf("expected some frames to be captured, got 0")
	}

	foundCoalesced := false
	for i, raw := range localCapture {
		res := obfReceiver.Decode(raw)
		t.Logf("capture[%d]: HasFrame=%v, Keepalive=%v, PayloadLen=%d", i, res.HasFrame, res.Keepalive, len(res.Payload))
		if !res.HasFrame || res.Keepalive {
			continue
		}
		var decoded [][]byte
		DecodeFrames(res.Payload, func(connID uint32, msgType byte, payload []byte) {
			t.Logf("  decoded frame: connID=%d, msgType=%d, payload=%s", connID, msgType, string(payload))
			decoded = append(decoded, payload)
		})
		if len(decoded) == 3 {
			if bytes.Equal(decoded[0], []byte("frame-one")) &&
				bytes.Equal(decoded[1], []byte("frame-two")) &&
				bytes.Equal(decoded[2], []byte("frame-three")) {
				foundCoalesced = true
				break
			}
		}
	}

	if !foundCoalesced {
		t.Errorf("coalesced frame containing all three payloads not found in capture of length %d", len(localCapture))
	}
}

func TestVP8Tunnel_NoCoalescing(t *testing.T) {
	obfSender, err := NewTunnelObfuscator([]byte("test-secret-12345"))
	if err != nil {
		t.Fatalf("obfuscator err: %v", err)
	}
	obfReceiver, err := NewTunnelObfuscator([]byte("test-secret-12345"))
	if err != nil {
		t.Fatalf("obfuscator err: %v", err)
	}

	var mu sync.Mutex
	var capture [][]byte
	tun := NewVP8DataTunnelWithQueue(nil, obfSender, t.Logf, 128)
	tun.WriteFrame = func(b []byte) error {
		mu.Lock()
		capture = append(capture, append([]byte(nil), b...))
		mu.Unlock()
		return nil
	}

	tun.SetProfile(Profile{FPS: 1000, Batch: 1, MaxFrameBytes: 0})

	f1 := EncodeFrame(1, MsgData, []byte("frame-one"))
	f2 := EncodeFrame(2, MsgData, []byte("frame-two"))

	tun.SendData(f1)
	tun.SendData(f2)

	tun.Start(1000, 1)
	time.Sleep(50 * time.Millisecond)
	tun.Stop()

	mu.Lock()
	localCapture := make([][]byte, len(capture))
	copy(localCapture, capture)
	mu.Unlock()

	onePayloadSlicesCount := 0
	for i, raw := range localCapture {
		res := obfReceiver.Decode(raw)
		t.Logf("capture[%d]: HasFrame=%v, Keepalive=%v, PayloadLen=%d", i, res.HasFrame, res.Keepalive, len(res.Payload))
		if !res.HasFrame || res.Keepalive {
			continue
		}
		var decoded [][]byte
		DecodeFrames(res.Payload, func(connID uint32, msgType byte, payload []byte) {
			t.Logf("  decoded frame: connID=%d, msgType=%d, payload=%s", connID, msgType, string(payload))
			decoded = append(decoded, payload)
		})
		if len(decoded) == 1 {
			onePayloadSlicesCount++
		}
	}

	if onePayloadSlicesCount < 2 {
		t.Errorf("expected at least 2 separate frames with 1 payload each, got %d", onePayloadSlicesCount)
	}
}
