package pion

import (
	"bytes"
	"testing"

	"github.com/alex-pirozhenko/whitelist-bypass/relay/tunnel"
	"github.com/pion/rtp"
)

func TestVP8FrameReassembler_Feed(t *testing.T) {
	var _ rtp.Packet
	// 1. Clean consecutive sequence
	t.Run("CleanConsecutive", func(t *testing.T) {
		p := tunnel.NewVP8Packetizer()
		frameData := []byte("hello beautiful vp8 frame data that needs to be packetized and reassembled")
		pkts := p.Packetize(frameData, true, 4500, 1200)
		if len(pkts) == 0 {
			t.Fatalf("expected some packets")
		}

		r := &vp8FrameReassembler{}
		var lastFrame []byte
		for _, pkt := range pkts {
			res := r.feed(pkt, false)
			if res.UnmarshalErr != nil {
				t.Fatalf("unmarshal err: %v", res.UnmarshalErr)
			}
			if res.IsDuplicate {
				t.Fatalf("expected not duplicate")
			}
			if res.Frame != nil {
				lastFrame = res.Frame
			}
		}

		if !bytes.Equal(lastFrame, frameData) {
			t.Errorf("expected reassembled frame to match frameData, got %s", lastFrame)
		}
		if r.stats.RecvPackets != uint64(len(pkts)) {
			t.Errorf("expected RecvPackets=%d, got %d", len(pkts), r.stats.RecvPackets)
		}
		if r.stats.Gaps != 0 {
			t.Errorf("expected Gaps=0, got %d", r.stats.Gaps)
		}
		if r.stats.LostPackets != 0 {
			t.Errorf("expected LostPackets=0, got %d", r.stats.LostPackets)
		}
	})

	// 2. Skipping a sequence number
	t.Run("SequenceGap", func(t *testing.T) {
		p := tunnel.NewVP8Packetizer()
		frameData1 := []byte("first frame payload that is relatively large to force multiple packets")
		pkts1 := p.Packetize(frameData1, true, 4500, 30) // small MTU to force multiple packets
		if len(pkts1) < 3 {
			t.Fatalf("expected at least 3 packets, got %d", len(pkts1))
		}

		r := &vp8FrameReassembler{}
		// Feed the first packet
		res := r.feed(pkts1[0], false)
		if res.Frame != nil {
			t.Fatalf("expected frame not to be completed yet")
		}

		// Skip pkts1[1] and feed pkts1[2]
		res = r.feed(pkts1[2], false)
		if res.Frame != nil {
			t.Fatalf("expected frame to be discarded and not completed")
		}

		// Assert stats
		if r.stats.RecvPackets != 2 {
			t.Errorf("expected RecvPackets=2, got %d", r.stats.RecvPackets)
		}
		if r.stats.Gaps != 1 {
			t.Errorf("expected Gaps=1, got %d", r.stats.Gaps)
		}
		expectedLost := uint64(pkts1[2].SequenceNumber - pkts1[0].SequenceNumber)
		if r.stats.LostPackets != expectedLost {
			t.Errorf("expected LostPackets=%d, got %d", expectedLost, r.stats.LostPackets)
		}
		if r.frameValid {
			t.Errorf("expected frameValid=false")
		}
		if len(r.frameBuf) != 0 {
			t.Errorf("expected frameBuf to be cleared, got len=%d", len(r.frameBuf))
		}
	})

	// 3. Duplicate sequence number
	t.Run("DuplicateSequence", func(t *testing.T) {
		p := tunnel.NewVP8Packetizer()
		frameData := []byte("duplicate sequence number test payload")
		pkts := p.Packetize(frameData, true, 4500, 1200)

		r := &vp8FrameReassembler{}
		// Feed first packet
		res1 := r.feed(pkts[0], false)
		if res1.IsDuplicate {
			t.Errorf("expected first packet not to be a duplicate")
		}

		// Feed the first packet AGAIN (duplicate)
		res2 := r.feed(pkts[0], false)
		if !res2.IsDuplicate {
			t.Errorf("expected second feed of same packet to be flagged as duplicate")
		}

		// Assert stats: RecvPackets is 2, but Gaps/LostPackets should be 0
		if r.stats.RecvPackets != 2 {
			t.Errorf("expected RecvPackets=2, got %d", r.stats.RecvPackets)
		}
		if r.stats.Gaps != 0 {
			t.Errorf("expected Gaps=0, got %d", r.stats.Gaps)
		}
		if r.stats.LostPackets != 0 {
			t.Errorf("expected LostPackets=0, got %d", r.stats.LostPackets)
		}
	})

	// 4. Sequence-number wrap
	t.Run("SequenceWrap", func(t *testing.T) {
		p := tunnel.NewVP8Packetizer()
		frameData := []byte("wrap sequence number test payload")
		pkts := p.Packetize(frameData, true, 4500, 1200)
		if len(pkts) == 0 {
			t.Fatalf("expected packet")
		}

		r := &vp8FrameReassembler{}
		// Setup the reassembler state with a lastSeq of 65535
		r.haveLastSeq = true
		r.lastSeq = 65535

		// Now force the packet sequence number to be 1
		pkts[0].SequenceNumber = 1

		res := r.feed(pkts[0], false)
		if res.UnmarshalErr != nil {
			t.Fatalf("unmarshal err: %v", res.UnmarshalErr)
		}

		// Jump should be computed as uint16(1 - 65535) = 2
		if r.stats.RecvPackets != 1 {
			t.Errorf("expected RecvPackets=1, got %d", r.stats.RecvPackets)
		}
		if r.stats.Gaps != 1 {
			t.Errorf("expected Gaps=1, got %d", r.stats.Gaps)
		}
		if r.stats.LostPackets != 2 {
			t.Errorf("expected LostPackets=2, got %d", r.stats.LostPackets)
		}
	})
}
