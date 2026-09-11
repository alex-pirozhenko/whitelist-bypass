package tunnel

import (
	"bytes"
	"testing"
	"time"
)

func TestVP8PacketizerMatchesOptionA(t *testing.T) {
	p := NewVP8Packetizer()
	p.sequenceNumber = 100
	p.timestamp = 1000
	p.pictureID = 10
	p.tl0picidx = 5

	frame := []byte{0x30, 0x12, 0x00, 0x9d, 0x01, 0x2a} // sample keyframe prefix

	// 1. Packetize Keyframe with tsDelta 4500 (20 fps at 90kHz)
	pkts := p.Packetize(frame, true, 4500, 1200)
	if len(pkts) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(pkts))
	}
	pkt := pkts[0]
	if pkt.Header.SequenceNumber != 101 {
		t.Errorf("expected seq 101, got %d", pkt.Header.SequenceNumber)
	}
	if pkt.Header.Timestamp != 5500 {
		t.Errorf("expected ts 5500, got %d", pkt.Header.Timestamp)
	}
	if !pkt.Header.Marker {
		t.Errorf("expected Marker=true on complete frame")
	}

	// Verify VP8 Payload Descriptor (RFC 7741 5-byte extended header)
	if len(pkt.Payload) != 5+len(frame) {
		t.Fatalf("expected payload len %d, got %d", 5+len(frame), len(pkt.Payload))
	}
	// Byte 0: X=1 (0x80), S=1 (0x10) -> 0x90
	if pkt.Payload[0] != 0x90 {
		t.Errorf("expected descriptor byte 0 == 0x90, got 0x%02x", pkt.Payload[0])
	}
	// Byte 1: I=1, L=1, T=1 -> 0xe0
	if pkt.Payload[1] != 0xe0 {
		t.Errorf("expected descriptor byte 1 == 0xe0, got 0x%02x", pkt.Payload[1])
	}
	// Byte 2: PictureID == 11
	if pkt.Payload[2] != 11 {
		t.Errorf("expected PictureID 11, got %d", pkt.Payload[2])
	}
	// Byte 3: TL0PICIDX == 6 (incremented on keyframe)
	if pkt.Payload[3] != 6 {
		t.Errorf("expected TL0PICIDX 6, got %d", pkt.Payload[3])
	}
	// Byte 4: TID == 0x20
	if pkt.Payload[4] != 0x20 {
		t.Errorf("expected TID 0x20, got 0x%02x", pkt.Payload[4])
	}
	// Remainder matches frame data
	if !bytes.Equal(pkt.Payload[5:], frame) {
		t.Errorf("payload mismatch: got %x, want %x", pkt.Payload[5:], frame)
	}

	// 2. Packetize Interframe: TL0PICIDX must NOT increment
	interframe := []byte{0xd1, 0x02, 0x00}
	pkts2 := p.Packetize(interframe, false, 4500, 1200)
	if len(pkts2) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(pkts2))
	}
	pkt2 := pkts2[0]
	if pkt2.Header.Timestamp != 10000 {
		t.Errorf("expected ts 10000, got %d", pkt2.Header.Timestamp)
	}
	if pkt2.Payload[2] != 12 {
		t.Errorf("expected PictureID 12, got %d", pkt2.Payload[2])
	}
	if pkt2.Payload[3] != 6 {
		t.Errorf("expected TL0PICIDX unchanged at 6, got %d", pkt2.Payload[3])
	}
}

func TestVP8PacketizerMTUFragmentation(t *testing.T) {
	p := NewVP8Packetizer()
	largeFrame := make([]byte, 2500)
	for i := range largeFrame {
		largeFrame[i] = byte(i % 256)
	}

	pkts := p.Packetize(largeFrame, false, 4500, 1000)
	if len(pkts) < 3 {
		t.Fatalf("expected at least 3 packets for 2500 bytes at MTU 1000, got %d", len(pkts))
	}

	// First packet: S=1, Marker=false
	if pkts[0].Payload[0] != 0x90 {
		t.Errorf("expected packet 0 to have S=1 (0x90), got 0x%02x", pkts[0].Payload[0])
	}
	if pkts[0].Header.Marker {
		t.Errorf("expected packet 0 Marker=false")
	}

	// Intermediate packet: S=0, Marker=false
	if pkts[1].Payload[0] != 0x80 {
		t.Errorf("expected packet 1 to have S=0 (0x80), got 0x%02x", pkts[1].Payload[0])
	}
	if pkts[1].Header.Marker {
		t.Errorf("expected packet 1 Marker=false")
	}

	// Last packet: S=0, Marker=true
	lastIdx := len(pkts) - 1
	if pkts[lastIdx].Payload[0] != 0x80 {
		t.Errorf("expected last packet to have S=0 (0x80), got 0x%02x", pkts[lastIdx].Payload[0])
	}
	if !pkts[lastIdx].Header.Marker {
		t.Errorf("expected last packet Marker=true")
	}

	// Reassembled payload minus descriptors matches largeFrame
	var reassembled bytes.Buffer
	for _, pkt := range pkts {
		// Descriptor length is 5 bytes (PicID <= 127)
		reassembled.Write(pkt.Payload[5:])
	}
	if !bytes.Equal(reassembled.Bytes(), largeFrame) {
		t.Errorf("reassembled payload mismatch")
	}
}

func TestVP8DataTunnelDataPump(t *testing.T) {
	secret := []byte("pump-secret-key-12345")
	obfSender, _ := NewTunnelObfuscator(secret)
	obfReceiver, _ := NewTunnelObfuscator(secret)

	senderTun := NewVP8DataTunnelWithQueue(nil, obfSender, func(string, ...any) {}, 64)
	receiverTun := NewVP8DataTunnelWithQueue(nil, obfReceiver, func(string, ...any) {}, 64)

	received := make(chan []byte, 10)
	receiverTun.SetOnData(func(b []byte) {
		received <- b
	})

	// Direct wire simulation: sender WriteFrame feeds receiver HandleFrame
	senderTun.WriteFrame = func(frame []byte) error {
		receiverTun.HandleFrame(frame)
		return nil
	}

	senderTun.Start(20, 1)
	defer senderTun.Stop()
	defer receiverTun.Stop()

	// Send message
	testMsg := []byte("pion-cli-message-test-1")
	senderTun.SendData(testMsg)

	select {
	case msg := <-received:
		if !bytes.Equal(msg, testMsg) {
			t.Errorf("received message mismatch: got %q, want %q", msg, testMsg)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for data pump message")
	}
}
