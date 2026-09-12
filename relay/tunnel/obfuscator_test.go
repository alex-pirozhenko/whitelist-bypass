package tunnel

import (
	"bytes"
	"os/exec"
	"testing"
)

func TestObfuscatorKeyframeAndInterframeRoundTrip(t *testing.T) {
	secret := []byte("test-secret-12345")
	sender, err := NewTunnelObfuscator(secret)
	if err != nil {
		t.Fatalf("NewTunnelObfuscator sender: %v", err)
	}
	receiver, err := NewTunnelObfuscator(secret)
	if err != nil {
		t.Fatalf("NewTunnelObfuscator receiver: %v", err)
	}

	// 1. Keepalive (keyframe) round-trip
	keepalive := sender.EncodeKeepalive(16)
	if len(keepalive) != keyframeHdrLen+16 {
		t.Errorf("keepalive len=%d, want %d", len(keepalive), keyframeHdrLen+16)
	}
	res := receiver.Decode(keepalive)
	if !res.HasFrame || !res.Keepalive {
		t.Errorf("Decode keepalive failed: %+v", res)
	}
	if len(res.Payload) != 0 {
		t.Errorf("Decode keepalive unexpected payload: %v", res.Payload)
	}

	// 2. Data over interframe round-trip
	testPayload := []byte("Hello, WebRTC VP8 Tunnel! This is test payload.")
	interframePkt := sender.EncodeData(testPayload)
	if len(interframePkt) <= interframeHdrLen {
		t.Errorf("interframePkt too short: %d", len(interframePkt))
	}
	res2 := receiver.Decode(interframePkt)
	if !res2.HasFrame || res2.Keepalive {
		t.Errorf("Decode data over interframe failed: %+v", res2)
	}
	if !bytes.Equal(res2.Payload, testPayload) {
		t.Errorf("Decode payload mismatch: got %q, want %q", res2.Payload, testPayload)
	}

	// 3. Data over keyframe round-trip
	keyframePkt := sender.EncodeDataKeyframe(testPayload)
	if len(keyframePkt) <= keyframeHdrLen {
		t.Errorf("keyframePkt too short: %d", len(keyframePkt))
	}
	res3 := receiver.Decode(keyframePkt)
	if !res3.HasFrame || res3.Keepalive {
		t.Errorf("Decode data over keyframe failed: %+v", res3)
	}
	if !bytes.Equal(res3.Payload, testPayload) {
		t.Errorf("Decode keyframe payload mismatch: got %q, want %q", res3.Payload, testPayload)
	}

	// 4. Self echo detection
	selfRes := sender.Decode(interframePkt)
	if !selfRes.SelfEcho {
		t.Errorf("Expected SelfEcho=true, got %+v", selfRes)
	}
}

func TestVP8BitstreamDecodesInFFmpeg(t *testing.T) {
	ffmpegPath, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg not found, skipping bitstream validation")
	}

	secret := []byte("test-secret-ffmpeg")
	sender, err := NewTunnelObfuscator(secret)
	if err != nil {
		t.Fatalf("NewTunnelObfuscator: %v", err)
	}

	kf := sender.EncodeKeepalive(32)
	df := sender.EncodeData([]byte("test payload for ffmpeg"))

	// Build IVF container with 1 keyframe and 1 interframe
	var ivf bytes.Buffer
	// IVF header (32 bytes)
	ivf.WriteString("DKIF")                   // signature
	ivf.Write([]byte{0x00, 0x00})             // version 0
	ivf.Write([]byte{0x20, 0x00})             // header length 32
	ivf.WriteString("VP80")                   // codec FourCC
	ivf.Write([]byte{0x40, 0x01, 0xf0, 0x00}) // 320x240
	ivf.Write([]byte{0x14, 0x00, 0x00, 0x00}) // rate 20
	ivf.Write([]byte{0x01, 0x00, 0x00, 0x00}) // scale 1
	ivf.Write([]byte{0x02, 0x00, 0x00, 0x00}) // num frames: 2
	ivf.Write([]byte{0x00, 0x00, 0x00, 0x00}) // unused

	// Frame 1: Keyframe
	kfLen := uint32(len(kf))
	ivf.Write([]byte{byte(kfLen), byte(kfLen >> 8), byte(kfLen >> 16), byte(kfLen >> 24)})
	ivf.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0}) // pts 0
	ivf.Write(kf)

	// Frame 2: Interframe with data
	dfLen := uint32(len(df))
	ivf.Write([]byte{byte(dfLen), byte(dfLen >> 8), byte(dfLen >> 16), byte(dfLen >> 24)})
	ivf.Write([]byte{1, 0, 0, 0, 0, 0, 0, 0}) // pts 1
	ivf.Write(df)

	// Run ffmpeg to decode the IVF stream
	cmd := exec.Command(ffmpegPath, "-v", "error", "-f", "ivf", "-i", "-", "-f", "null", "-")
	cmd.Stdin = &ivf
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ffmpeg failed to decode synthetic VP8 frames: %v, output: %s", err, string(out))
	}
}
