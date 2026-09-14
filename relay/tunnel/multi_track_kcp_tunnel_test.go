package tunnel

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
)

func TestKCPTunnelSatisfiesRateControllable(t *testing.T) {
	// Assert satisfies RateControllable
	var _ RateControllable = (*MultiTrackKCPTunnel)(nil)

	secret := []byte("pump-secret-key-12345")
	obf, _ := NewTunnelObfuscator(secret)
	carrier := NewVP8DataTunnelWithQueue(nil, obf, func(string, ...any) {}, 128)

	mt := NewMultiTrackTunnel([]*VP8DataTunnel{carrier})
	kcptun := NewMultiTrackKCPTunnel(mt, func(string, ...any) {})
	defer kcptun.Stop()

	// SetProfile reaches the sub-tunnel and sets currentWindow to computeKCPWindowFor(24, 30, 30000)
	kcptun.SetProfile(Profile{FPS: 24, Batch: 30, MaxFrameBytes: 30000})

	expectedWindow := computeKCPWindowFor(24, 30, 30000)
	curWindow := int(kcptun.currentWindow.Load())
	if curWindow != expectedWindow {
		t.Errorf("expected window=%d, got %d", expectedWindow, curWindow)
	}
}

func TestComputeKCPWindowFor(t *testing.T) {
	// (20,1,0)=64 floor
	w1 := computeKCPWindowFor(20, 1, 0)
	if w1 != 64 {
		t.Errorf("expected (20,1,0)=64, got %d", w1)
	}

	// (20,1,30000)=20*27*1=540
	w2 := computeKCPWindowFor(20, 1, 30000)
	if w2 != 540 {
		t.Errorf("expected (20,1,30000)=540, got %d", w2)
	}

	// (24,30,64000) clamps to 4096.
	w3 := computeKCPWindowFor(24, 30, 64000)
	if w3 != 4096 {
		t.Errorf("expected (24,30,64000)=4096, got %d", w3)
	}
}

func TestKCPSendControlBypassesKCP(t *testing.T) {
	secret := []byte("pump-secret-key-12345")
	obfA, _ := NewTunnelObfuscator(secret)
	obfB, _ := NewTunnelObfuscator(secret)

	carrierA := NewVP8DataTunnelWithQueue(nil, obfA, func(string, ...any) {}, 128)
	carrierB := NewVP8DataTunnelWithQueue(nil, obfB, func(string, ...any) {}, 128)

	mtA := NewMultiTrackTunnel([]*VP8DataTunnel{carrierA})
	mtB := NewMultiTrackTunnel([]*VP8DataTunnel{carrierB})

	kcptunA := NewMultiTrackKCPTunnel(mtA, func(string, ...any) {})
	kcptunB := NewMultiTrackKCPTunnel(mtB, func(string, ...any) {})
	defer kcptunA.Stop()
	defer kcptunB.Stop()

	// Direct wire back-to-back: WriteFrame feeds HandleFrame
	carrierA.WriteFrame = func(frame []byte) error {
		carrierB.HandleFrame(frame)
		return nil
	}
	carrierB.WriteFrame = func(frame []byte) error {
		carrierA.HandleFrame(frame)
		return nil
	}

	controlFrame := []byte("ping-control-frame")
	received := make(chan []byte, 10)
	kcptunB.SetOnData(func(data []byte) {
		if bytes.Equal(data, controlFrame) {
			received <- data
		}
	})

	// Fill A with MsgData until waitSnd() >= sndCap with B not draining
	// To stall A's reliable stream, we can temporarily disable the wire from A to B for reliable frames.
	obfDecoder, _ := NewTunnelObfuscator(secret)
	carrierA.WriteFrame = func(frame []byte) error {
		res := obfDecoder.Decode(frame)
		if res.HasFrame && len(res.Payload) > 0 && res.Payload[0] == kcpChannelReliable {
			// drop it to stall KCP!
			return nil
		}
		// raw (control) segment goes through!
		carrierB.HandleFrame(frame)
		return nil
	}

	carrierA.Start(1000, 1)
	carrierB.Start(1000, 1)
	defer carrierA.Stop()
	defer carrierB.Stop()

	// Now send a lot of reliable frames on A so waitSnd() goes up
	largeFrame := make([]byte, 1000)
	binary.BigEndian.PutUint32(largeFrame[4:8], 1) // connID 1
	largeFrame[8] = MsgData

	for i := 0; i < 500; i++ {
		kcptunA.TrySendData(largeFrame)
	}

	// SendControl(frame) bypasses the stalled KCP queue and arrives at B's onData unchanged
	kcptunA.SendControl(controlFrame)

	select {
	case msg := <-received:
		if !bytes.Equal(msg, controlFrame) {
			t.Errorf("expected control frame to bypass KCP and arrive unchanged, got %s", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for control frame")
	}
}

func TestKCPRecoversLostFrame(t *testing.T) {
	secret := []byte("pump-secret-key-12345")
	obfA, _ := NewTunnelObfuscator(secret)
	obfB, _ := NewTunnelObfuscator(secret)

	carrierA := NewVP8DataTunnelWithQueue(nil, obfA, func(string, ...any) {}, 128)
	carrierB := NewVP8DataTunnelWithQueue(nil, obfB, func(string, ...any) {}, 128)

	mtA := NewMultiTrackTunnel([]*VP8DataTunnel{carrierA})
	mtB := NewMultiTrackTunnel([]*VP8DataTunnel{carrierB})

	kcptunA := NewMultiTrackKCPTunnel(mtA, func(string, ...any) {})
	kcptunB := NewMultiTrackKCPTunnel(mtB, func(string, ...any) {})
	defer kcptunA.Stop()
	defer kcptunB.Stop()

	// Direct wire back-to-back but drop every 5th carrier frame
	writeCount := 0
	carrierA.WriteFrame = func(frame []byte) error {
		writeCount++
		if writeCount%5 == 0 {
			// drop!
			return nil
		}
		carrierB.HandleFrame(frame)
		return nil
	}
	carrierB.WriteFrame = func(frame []byte) error {
		carrierA.HandleFrame(frame)
		return nil
	}

	carrierA.Start(1000, 1)
	carrierB.Start(1000, 1)
	defer carrierA.Stop()
	defer carrierB.Stop()

	received := make(chan int, 200)
	kcptunB.SetOnData(func(data []byte) {
		if len(data) >= 13 {
			seq := int(binary.BigEndian.Uint32(data[9:13]))
			received <- seq
		}
	})

	// Send 200 MsgData frames of 3 KB with sequence numbers
	for i := 0; i < 200; i++ {
		frameData := make([]byte, 3000)
		binary.BigEndian.PutUint32(frameData[4:8], 1) // connID 1
		frameData[8] = MsgData
		binary.BigEndian.PutUint32(frameData[9:13], uint32(i)) // seq number
		kcptunA.SendData(frameData)
		// small sleep to not overload local CPU but fast enough for test
		time.Sleep(2 * time.Millisecond)
	}

	// Verify all 200 arrive at B strictly in order
	for i := 0; i < 200; i++ {
		select {
		case seq := <-received:
			if seq != i {
				t.Fatalf("expected frame sequence %d, got %d (strictly out of order!)", i, seq)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out at frame %d", i)
		}
	}
}

func TestKCPReceiveWindowIsCeiling(t *testing.T) {
	// Record calls to kcpWndSize
	type call struct {
		snd int
		rcv int
	}
	var calls []call
	oldHook := kcpWndSize
	defer func() { kcpWndSize = oldHook }()

	kcpWndSize = func(k *kcp.KCP, snd, rcv int) {
		calls = append(calls, call{snd: snd, rcv: rcv})
		oldHook(k, snd, rcv)
	}

	secret := []byte("pump-secret-key-12345")
	obf, _ := NewTunnelObfuscator(secret)
	carrier := NewVP8DataTunnelWithQueue(nil, obf, func(string, ...any) {}, 128)

	mt := NewMultiTrackTunnel([]*VP8DataTunnel{carrier})
	kcptun := NewMultiTrackKCPTunnel(mt, func(string, ...any) {})
	defer kcptun.Stop()

	// Initial construction sets a default window
	if len(calls) == 0 {
		t.Fatalf("expected kcpWndSize calls during construction")
	}
	initialCall := calls[len(calls)-1]
	if initialCall.rcv != kcpWindowCeiling {
		t.Errorf("expected initial rcv window to be %d, got %d", kcpWindowCeiling, initialCall.rcv)
	}

	// Reset recorded calls
	calls = nil

	// SetProfile with a tiny profile
	kcptun.SetProfile(Profile{FPS: 2, Batch: 1, MaxFrameBytes: 10})

	if len(calls) == 0 {
		t.Fatalf("expected kcpWndSize calls during SetProfile")
	}
	profileCall := calls[len(calls)-1]
	if profileCall.rcv != kcpWindowCeiling {
		t.Errorf("expected rcv window after SetProfile to be %d, got %d", kcpWindowCeiling, profileCall.rcv)
	}

	expectedSnd := computeKCPWindowFor(2, 1, 10)
	if profileCall.snd != expectedSnd {
		t.Errorf("expected snd window to be %d, got %d", expectedSnd, profileCall.snd)
	}
}
