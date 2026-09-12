package tunnel

import (
	"encoding/binary"
	"testing"
)

func TestEncodeDecodeVP8Config(t *testing.T) {
	// Case 1: Round-trip with all 6 params set to distinct non-zero values
	t.Run("AllParamsSet", func(t *testing.T) {
		frame := EncodeVP8Config(30, 2, 3, 5000, 500, 0x07)
		// Frame is formatted as EncodeFrame(ControlConnID, MsgConfig, payload)
		// DecodeVP8Config expects just the payload (the third field of the frame)
		// Let's extract the payload. The header of a frame contains connID(4), msgType(1), payloadLen(2).
		// Wait, let's verify header length. In protocol.go:
		// DecodeFrames decodes the data. Let's decode it or just look at header size.
		// Header size is 4 (connID) + 1 (msgType) + 2 (len) = 7 bytes.
		// Let's use DecodeFrames to extract the payload to be absolutely robust and independent of header size details!
		var decodedPayload []byte
		DecodeFrames(frame, func(connID uint32, msgType byte, payload []byte) {
			if connID == ControlConnID && msgType == MsgConfig {
				decodedPayload = payload
			}
		})

		if decodedPayload == nil {
			t.Fatalf("failed to decode frame payload using DecodeFrames")
		}

		fps, batch, trackCount, maxFrameBytes, idleKeepaliveMs, flags, ok := DecodeVP8Config(decodedPayload)
		if !ok {
			t.Fatalf("DecodeVP8Config returned ok=false")
		}

		if fps != 30 {
			t.Errorf("fps = %d, expected 30", fps)
		}
		if batch != 2 {
			t.Errorf("batch = %d, expected 2", batch)
		}
		if trackCount != 3 {
			t.Errorf("trackCount = %d, expected 3", trackCount)
		}
		if maxFrameBytes != 5000 {
			t.Errorf("maxFrameBytes = %d, expected 5000", maxFrameBytes)
		}
		if idleKeepaliveMs != 500 {
			t.Errorf("idleKeepaliveMs = %d, expected 500", idleKeepaliveMs)
		}
		if flags != 0x07 {
			t.Errorf("flags = %d, expected 0x07", flags)
		}
	})

	// Case 2: Round-trip with maxFrameBytes=0, idleKeepaliveMs=0, flags=0 (today's common case)
	t.Run("ZerosTrailingParams", func(t *testing.T) {
		frame := EncodeVP8Config(30, 2, 3, 0, 0, 0)
		var decodedPayload []byte
		DecodeFrames(frame, func(connID uint32, msgType byte, payload []byte) {
			if connID == ControlConnID && msgType == MsgConfig {
				decodedPayload = payload
			}
		})

		fps, batch, trackCount, maxFrameBytes, idleKeepaliveMs, flags, ok := DecodeVP8Config(decodedPayload)
		if !ok {
			t.Fatalf("DecodeVP8Config returned ok=false")
		}

		if fps != 30 || batch != 2 || trackCount != 3 {
			t.Errorf("mismatch: fps=%d batch=%d trackCount=%d", fps, batch, trackCount)
		}
		if maxFrameBytes != 0 || idleKeepaliveMs != 0 || flags != 0 {
			t.Errorf("expected trailing params to be 0, got maxFrameBytes=%d, idleKeepaliveMs=%d, flags=%d", maxFrameBytes, idleKeepaliveMs, flags)
		}
	})

	// Case 3: Decoding an OLD-STYLE short payload (6 bytes)
	t.Run("OldStyleShortPayload", func(t *testing.T) {
		oldPayload := make([]byte, 6)
		binary.BigEndian.PutUint16(oldPayload[0:2], uint16(25)) // fps
		binary.BigEndian.PutUint16(oldPayload[2:4], uint16(1))  // batch
		binary.BigEndian.PutUint16(oldPayload[4:6], uint16(2))  // trackCount

		fps, batch, trackCount, maxFrameBytes, idleKeepaliveMs, flags, ok := DecodeVP8Config(oldPayload)
		if !ok {
			t.Fatalf("expected ok=true for 6-byte old payload")
		}

		if fps != 25 {
			t.Errorf("fps = %d, expected 25", fps)
		}
		if batch != 1 {
			t.Errorf("batch = %d, expected 1", batch)
		}
		if trackCount != 2 {
			t.Errorf("trackCount = %d, expected 2", trackCount)
		}
		if maxFrameBytes != 0 || idleKeepaliveMs != 0 || flags != 0 {
			t.Errorf("expected trailing params to default to 0, got maxFrameBytes=%d, idleKeepaliveMs=%d, flags=%d", maxFrameBytes, idleKeepaliveMs, flags)
		}
	})

	// Case 4: A payload of length 5 (between the two thresholds)
	t.Run("Length5Payload", func(t *testing.T) {
		shortPayload := make([]byte, 5)
		binary.BigEndian.PutUint16(shortPayload[0:2], uint16(15)) // fps
		binary.BigEndian.PutUint16(shortPayload[2:4], uint16(5))  // batch
		shortPayload[4] = 0xAA

		fps, batch, trackCount, maxFrameBytes, idleKeepaliveMs, flags, ok := DecodeVP8Config(shortPayload)
		if !ok {
			t.Fatalf("expected ok=true for 5-byte payload")
		}

		if fps != 15 || batch != 5 {
			t.Errorf("mismatch: fps=%d, batch=%d", fps, batch)
		}
		if trackCount != 1 {
			t.Errorf("expected trackCount to default to 1 for payload shorter than 6 bytes, got %d", trackCount)
		}
		if maxFrameBytes != 0 || idleKeepaliveMs != 0 || flags != 0 {
			t.Errorf("expected trailing params to default to 0")
		}
	})

	// Case 5: A payload of length 2 (too short even for fps/batch)
	t.Run("TooShortPayload", func(t *testing.T) {
		tooShort := make([]byte, 2)
		binary.BigEndian.PutUint16(tooShort, uint16(10))

		_, _, _, _, _, _, ok := DecodeVP8Config(tooShort)
		if ok {
			t.Errorf("expected ok=false for 2-byte payload")
		}
	})
}
