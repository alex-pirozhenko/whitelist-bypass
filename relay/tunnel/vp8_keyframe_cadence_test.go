package tunnel

import (
	"bytes"
	"sync/atomic"
	"testing"
	"time"
)

// frameTag reports whether a wire frame carries the keyframe tag
// (frame[0] == vp8Keyframe[0]) as opposed to the interframe tag
// (frame[0] == vp8Interframe[0]); ok is false if frame[0] is neither. It
// mirrors the discriminant Decode() itself switches on. This is a plain
// function (no *testing.T) so it is safe to call from a non-test goroutine,
// e.g. from inside a WriteFrame callback that runs on the tunnel's writer
// goroutine -- t.Fatalf must only ever be called from the test's own
// goroutine.
func frameTag(frame []byte) (isKeyframe bool, ok bool) {
	if len(frame) < 1 {
		return false, false
	}
	switch frame[0] {
	case vp8Keyframe[0]:
		return true, true
	case vp8Interframe[0]:
		return false, true
	default:
		return false, false
	}
}

// isKeyframeTagged is frameTag for use on the test's own goroutine, where
// an unrecognized tag byte is a hard test failure.
func isKeyframeTagged(t *testing.T, frame []byte) bool {
	t.Helper()
	isKf, ok := frameTag(frame)
	if !ok {
		t.Fatalf("frame tag byte is neither the keyframe nor interframe tag (frame=%v)", frame)
	}
	return isKf
}

// TestKeyframeCadenceOnDataFrames sends far more data frames than a single
// keyframePeriod and asserts that on the wire, exactly 1-in-keyframePeriod
// of them are tagged as keyframes (EncodeDataKeyframe) and the rest are
// tagged as interframes (EncodeData). Before this fix, sendFrame hardcoded
// isKf := true unconditionally, so this test would see 100% keyframes.
func TestKeyframeCadenceOnDataFrames(t *testing.T) {
	obf, err := NewTunnelObfuscator([]byte("cadence-secret-12345"))
	if err != nil {
		t.Fatalf("NewTunnelObfuscator: %v", err)
	}

	const period = defaultKeyframeRate // 40
	const numFrames = period * 10      // 400

	tun := NewVP8DataTunnelWithQueue(nil, obf, func(string, ...any) {}, numFrames+1)
	if tun.keyframePeriod != period {
		t.Fatalf("test assumes default keyframePeriod=%d, got %d", period, tun.keyframePeriod)
	}

	captured := make(chan []byte, numFrames)
	tun.WriteFrame = func(frame []byte) error {
		// Copy: the tunnel may reuse/overwrite buffers after this returns.
		cp := make([]byte, len(frame))
		copy(cp, frame)
		select {
		case captured <- cp:
		default:
		}
		return nil
	}

	for i := 0; i < numFrames; i++ {
		tun.SendData([]byte{byte(i), byte(i >> 8)})
	}

	tun.Start(2000, 1) // fast tick so the test doesn't wait on wall-clock fps
	defer tun.Stop()

	frames := make([][]byte, 0, numFrames)
	for len(frames) < numFrames {
		select {
		case f := <-captured:
			frames = append(frames, f)
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out after capturing %d/%d frames", len(frames), numFrames)
		}
	}

	keyframeCount := 0
	for i, f := range frames {
		if isKeyframeTagged(t, f) {
			keyframeCount++
			// dueForKeyframe fires when the 0-indexed cadence counter n
			// satisfies n%period==0, i.e. on frames 0, period, 2*period, ...
			if i%period != 0 {
				t.Errorf("frame %d unexpectedly keyframe-tagged (period=%d)", i, period)
			}
		}
	}

	wantKeyframes := numFrames / period
	if keyframeCount != wantKeyframes {
		t.Errorf("keyframe count = %d, want exactly %d (1-in-%d of %d frames)",
			keyframeCount, wantKeyframes, period, numFrames)
	}
}

// TestKeyframeCadenceOnIdleKeepalives verifies that an idle stream -- no
// application data at all, only keepalives -- still carries the same I/P
// cadence: keepalives are interframe-tagged (EncodeKeepaliveInterframe)
// except every keyframePeriod-th one, which is keyframe-tagged
// (EncodeKeepalive). Before this fix, sendKeepalive hardcoded isKf := true
// unconditionally, so a real SFU/anti-fraud parser would see a 100%-keyframe
// stream even at idle.
func TestKeyframeCadenceOnIdleKeepalives(t *testing.T) {
	sender, err := NewTunnelObfuscator([]byte("cadence-idle-secret"))
	if err != nil {
		t.Fatalf("NewTunnelObfuscator sender: %v", err)
	}
	receiver, err := NewTunnelObfuscator([]byte("cadence-idle-secret"))
	if err != nil {
		t.Fatalf("NewTunnelObfuscator receiver: %v", err)
	}

	tun := NewVP8DataTunnelWithQueue(nil, sender, func(string, ...any) {}, 64)
	// Force a tight, deterministic keepalive cadence: with fps=2000 the
	// sample interval is 500us, and a 1ms idle-keepalive period yields a
	// keepalive roughly every 2 ticks -- fast enough to collect hundreds of
	// keepalives in well under a second.
	tun.profileIdleKeepalive = time.Millisecond

	const period = defaultKeyframeRate
	const numKeepalives = period * 5 // 200

	captured := make(chan []byte, numKeepalives*2)
	tun.WriteFrame = func(frame []byte) error {
		cp := make([]byte, len(frame))
		copy(cp, frame)
		select {
		case captured <- cp:
		default:
		}
		return nil
	}

	tun.Start(2000, 1)
	defer tun.Stop()

	frames := make([][]byte, 0, numKeepalives)
	for len(frames) < numKeepalives {
		select {
		case f := <-captured:
			frames = append(frames, f)
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out after capturing %d/%d idle keepalives", len(frames), numKeepalives)
		}
	}

	keyframeCount := 0
	for _, f := range frames {
		// Every idle-stream frame must decode as a keepalive on the
		// receiving side, regardless of which tag it carries -- this is
		// the "receiver must not care which tag arrived" requirement.
		res := receiver.Decode(f)
		if !res.HasFrame || !res.Keepalive {
			t.Fatalf("idle-stream frame did not decode as a keepalive: %+v (tag=0x%02x len=%d)", res, f[0], len(f))
		}
		if isKeyframeTagged(t, f) {
			keyframeCount++
		}
	}

	gotRatio := float64(keyframeCount) / float64(len(frames))
	wantRatio := 1.0 / float64(period)
	// Allow +/-30% tolerance: idle timing has jitter (nextKeepalive draws
	// from a jittered range), so the count of keepalives collected isn't an
	// exact multiple of the period the way the data-frame test's queue-fed
	// cadence is.
	if gotRatio < wantRatio*0.7 || gotRatio > wantRatio*1.3 {
		t.Errorf("idle keyframe ratio = %d/%d = %.4f, want ~%.4f (1/%d)",
			keyframeCount, len(frames), gotRatio, wantRatio, period)
	}
	if keyframeCount == 0 {
		t.Errorf("expected at least one keyframe-tagged keepalive among %d idle frames", len(frames))
	}
	if keyframeCount == len(frames) {
		t.Errorf("every idle frame was keyframe-tagged -- cadence is not being applied to keepalives")
	}
}

// TestObfuscatorInterframeKeepaliveRoundTrip covers the decode-path fix
// directly: EncodeKeepaliveInterframe's body is padLen random bytes, which
// for padLen >= nonceSize+aead.Overhead() reaches the AEAD Open() call and
// fails authentication by construction (it isn't real ciphertext). Decode
// must recognize that failure as a keepalive for the interframe tag exactly
// as it already did for the keyframe tag -- otherwise every interframe-
// tagged keepalive with a large-enough pad gets miscounted as a corrupt
// frame (res.HasFrame=false) instead of being recognized as a keepalive.
func TestObfuscatorInterframeKeepaliveRoundTrip(t *testing.T) {
	secret := []byte("interframe-keepalive-secret")
	sender, err := NewTunnelObfuscator(secret)
	if err != nil {
		t.Fatalf("NewTunnelObfuscator sender: %v", err)
	}
	receiver, err := NewTunnelObfuscator(secret)
	if err != nil {
		t.Fatalf("NewTunnelObfuscator receiver: %v", err)
	}

	// The obfuscator uses XChaCha20-Poly1305 (24-byte nonce, 16-byte tag),
	// so the short-body branch in Decode (len(body) < nonceSize+overhead)
	// covers padLen < 40; padLen >= 40 falls through to a real AEAD Open()
	// attempt on random bytes, which fails authentication by construction.
	// Straddle that boundary (39/40/41) plus the extremes (0, keepalivePadMax)
	// so both branches of Decode are exercised.
	shortBodyThreshold := sender.aead.NonceSize() + sender.aead.Overhead()
	if shortBodyThreshold != 40 {
		t.Fatalf("test assumes NonceSize()+Overhead()==40, got %d -- update the padLen cases below", shortBodyThreshold)
	}
	for _, padLen := range []int{0, 1, 39, 40, 41, keepalivePadMax} {
		frame := sender.EncodeKeepaliveInterframe(padLen)
		if isKeyframeTagged(t, frame) {
			t.Fatalf("padLen=%d: EncodeKeepaliveInterframe produced a keyframe-tagged frame", padLen)
		}
		res := receiver.Decode(frame)
		if !res.HasFrame {
			t.Errorf("padLen=%d: interframe-tagged keepalive was not recognized as a frame at all (res=%+v)", padLen, res)
			continue
		}
		if !res.Keepalive {
			t.Errorf("padLen=%d: interframe-tagged keepalive decoded with Keepalive=false (res=%+v)", padLen, res)
		}
		if len(res.Payload) != 0 {
			t.Errorf("padLen=%d: interframe-tagged keepalive carried a non-empty payload: %v", padLen, res.Payload)
		}
	}
}

// TestVP8DataTunnelDataPumpAcrossKeyframeBoundary is the round-trip
// equivalent of TestVP8DataTunnelDataPump, but sends enough messages to
// cross a keyframe boundary, so some are carried on interframe-tagged
// wire frames and at least one on a keyframe-tagged wire frame. The
// receiver must deliver all of them identically either way.
func TestVP8DataTunnelDataPumpAcrossKeyframeBoundary(t *testing.T) {
	secret := []byte("pump-secret-key-12345")
	obfSender, _ := NewTunnelObfuscator(secret)
	obfReceiver, _ := NewTunnelObfuscator(secret)

	senderTun := NewVP8DataTunnelWithQueue(nil, obfSender, func(string, ...any) {}, 128)
	receiverTun := NewVP8DataTunnelWithQueue(nil, obfReceiver, func(string, ...any) {}, 128)

	const period = defaultKeyframeRate
	const numMsgs = period + 5 // guaranteed to cross one keyframe boundary

	received := make(chan []byte, numMsgs)
	receiverTun.SetOnData(func(b []byte) {
		cp := make([]byte, len(b))
		copy(cp, b)
		received <- cp
	})

	var sawKeyframeTag, sawInterframeTag, sawUnknownTag atomic.Bool
	senderTun.WriteFrame = func(frame []byte) error {
		if isKf, ok := frameTag(frame); !ok {
			sawUnknownTag.Store(true)
		} else if isKf {
			sawKeyframeTag.Store(true)
		} else {
			sawInterframeTag.Store(true)
		}
		receiverTun.HandleFrame(frame)
		return nil
	}

	senderTun.Start(2000, 1)
	defer senderTun.Stop()
	defer receiverTun.Stop()

	want := make([][]byte, numMsgs)
	for i := 0; i < numMsgs; i++ {
		msg := []byte{byte('m'), byte(i), byte(i >> 8)}
		want[i] = msg
		senderTun.SendData(msg)
	}

	for i := 0; i < numMsgs; i++ {
		select {
		case got := <-received:
			if !bytes.Equal(got, want[i]) {
				t.Errorf("message %d mismatch: got %v, want %v", i, got, want[i])
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for message %d/%d", i, numMsgs)
		}
	}

	if sawUnknownTag.Load() {
		t.Errorf("saw a wire frame with an unrecognized tag byte")
	}
	if !sawKeyframeTag.Load() {
		t.Errorf("expected at least one keyframe-tagged data frame across %d messages (period=%d)", numMsgs, period)
	}
	if !sawInterframeTag.Load() {
		t.Errorf("expected at least one interframe-tagged data frame across %d messages (period=%d)", numMsgs, period)
	}
}
