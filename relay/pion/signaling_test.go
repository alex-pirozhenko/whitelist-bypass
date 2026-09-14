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
		expectedLost := uint64(pkts1[2].SequenceNumber - pkts1[0].SequenceNumber - 1)
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
		if r.stats.LostPackets != 1 {
			t.Errorf("expected LostPackets=1, got %d", r.stats.LostPackets)
		}
	})

	// 5. Forward gap and late/reordered packet
	t.Run("GapAndLatePackets", func(t *testing.T) {
		r := &vp8FrameReassembler{}
		r.haveLastSeq = true
		r.lastSeq = 100

		// Forward gap from 100 to 105
		pkt := &rtp.Packet{}
		pkt.SequenceNumber = 105
		pkt.Payload = []byte{0x10, 0x20} // non-empty so Unmarshal is happy
		r.feed(pkt, false)

		if r.stats.Gaps != 1 {
			t.Errorf("expected Gaps=1, got %d", r.stats.Gaps)
		}
		if r.stats.LostPackets != 4 {
			t.Errorf("expected LostPackets=4, got %d", r.stats.LostPackets)
		}
		if r.lastSeq != 105 {
			t.Errorf("expected lastSeq=105, got %d", r.lastSeq)
		}

		// A late packet: seq 103 after 105
		pktLate := &rtp.Packet{}
		pktLate.SequenceNumber = 103
		pktLate.Payload = []byte{0x10, 0x20}
		r.feed(pktLate, false)

		if r.stats.Reordered != 1 {
			t.Errorf("expected Reordered=1, got %d", r.stats.Reordered)
		}
		// 103 filled part of the 101..104 gap: reordering, not loss.
		if r.stats.LostPackets != 3 {
			t.Errorf("expected LostPackets=3 after the late packet un-counted itself, got %d", r.stats.LostPackets)
		}
		if r.lastSeq != 105 {
			t.Errorf("expected lastSeq to stay 105, got %d", r.lastSeq)
		}
	})
}

// A stale re-send of an older packet (the SFU repeats earlier packets as
// padding/probing) must not end up inside the frame being assembled, and it
// must not reset the frame either: the frame that was in flight completes.
func TestLatePacketIgnoredMidFrame(t *testing.T) {
	r := &vp8FrameReassembler{}
	mk := func(seq uint16, s uint8, marker bool, body byte) *rtp.Packet {
		// VP8 payload descriptor: X=0, S bit, PID 0; then one payload byte.
		return &rtp.Packet{Header: rtp.Header{SequenceNumber: seq, Marker: marker}, Payload: []byte{s << 4, body}}
	}
	if res := r.feed(mk(100, 1, false, 0xA1), false); res.Frame != nil || res.IsLate {
		t.Fatalf("first packet: %+v", res)
	}
	// stale repeat of an older packet arrives mid-frame
	res := r.feed(mk(97, 1, true, 0xEE), false)
	if !res.IsLate || res.Frame != nil {
		t.Fatalf("stale packet should be ignored: %+v", res)
	}
	if r.stats.Reordered != 1 || r.stats.Gaps != 0 || r.stats.LostPackets != 0 {
		t.Fatalf("stats after stale packet: %+v", r.stats)
	}
	res = r.feed(mk(101, 0, true, 0xA2), false)
	if res.Frame == nil || len(res.Frame) != 2 || res.Frame[0] != 0xA1 || res.Frame[1] != 0xA2 {
		t.Fatalf("frame in flight should complete untouched: %+v", res)
	}
	if r.lastSeq != 101 {
		t.Fatalf("lastSeq moved by the stale packet: %d", r.lastSeq)
	}
}

// Reordering is not loss: a packet that arrives after the gap it belonged to
// was counted must un-count itself.
func TestReorderedPacketUncountsLoss(t *testing.T) {
	r := &vp8FrameReassembler{}
	mk := func(seq uint16) *rtp.Packet {
		return &rtp.Packet{Header: rtp.Header{SequenceNumber: seq, Marker: true}, Payload: []byte{0x10, 0x00}}
	}
	r.feed(mk(100), false)
	r.feed(mk(103), false) // 101, 102 missing
	if r.stats.LostPackets != 2 || r.stats.Gaps != 1 {
		t.Fatalf("after gap: %+v", r.stats)
	}
	r.feed(mk(101), false) // late
	r.feed(mk(102), false) // late
	if r.stats.LostPackets != 0 || r.stats.Reordered != 2 {
		t.Fatalf("after late arrivals: %+v", r.stats)
	}
	r.feed(mk(101), false) // a second copy is just a stale duplicate
	if r.stats.LostPackets != 0 || r.stats.Reordered != 3 {
		t.Fatalf("after stale duplicate: %+v", r.stats)
	}
}
