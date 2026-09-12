package tunnel

// This file closes the gap called out in ratectl.go's comment at the
// AIMDStats type: "Tests call applyAIMD directly with synthetic values --
// that's the seam." Every other ratectl test (ratectl_test.go) drives the
// congestion controller by handing it AIMDStats values a human typed in.
// That's a fine unit test for the AIMD arithmetic itself, but it never
// proves the REAL path works: a peer's MsgStats/MsgPing control messages
// arriving over an actual (lossy) DataTunnel, decoded by RelayBridge, fed
// into RateController.handlePeerStats, which computes loss%/RTT from
// genuinely-missing frames and a genuinely-round-tripped ping -- not from a
// number a test author asserted was true.
//
// TestEndToEndRealLossDrivesAIMD below wires two RelayBridges back to back
// over an in-memory lossyEndpoint pair (a minimal DataTunnel implementation
// that also serves as its receiving side's LossSource), pushes real
// application traffic through them, and asserts the sender's AIMD backs off
// and recovers in response to loss the receiver actually measured.

import (
	"encoding/binary"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- lossyLink: a configurable, seeded-RNG lossy/reordering "wire" -------
//
// Only the DATA plane (non-control frames) is ever routed through a
// lossyLink; control messages (MsgConfig/MsgConfigAck/MsgStats/MsgPing,
// connID == ControlConnID) are always delivered immediately and reliably by
// lossyEndpoint.SendData. This is a deliberate modeling choice, not an
// oversight: it keeps the AIMD stats-exchange itself deterministic (no
// flaky "did the stats message even arrive" failures) while still making
// the thing the AIMD actually reacts to -- measured application-data loss
// -- completely real. It also mirrors how the production transport is
// shaped: MsgStats/MsgPing/MsgConfig are the control-plane RateController
// needs to function at all, while loss is a property of the data plane.
type lossyLink struct {
	mu       sync.Mutex
	rng      *rand.Rand
	dropFrac float64
	window   int // reorder window: buffer this many in-flight items before releasing one out of order; 1 = strict in-order delivery
	buf      []pendingDelivery
}

type pendingDelivery struct {
	data    []byte
	deliver func([]byte)
}

func newLossyLink(rng *rand.Rand, dropFrac float64, window int) *lossyLink {
	if window < 1 {
		window = 1
	}
	return &lossyLink{rng: rng, dropFrac: dropFrac, window: window}
}

// SetDropFraction changes the drop probability applied to every subsequent
// send. Safe for concurrent use with send.
func (l *lossyLink) SetDropFraction(f float64) {
	l.mu.Lock()
	l.dropFrac = f
	l.mu.Unlock()
}

// send decides whether data is dropped outright (a genuine, permanent loss
// -- never retried, exactly like a lost UDP/RTP packet); if not dropped, it
// is buffered until `window` items are pending, then one item is picked at
// random out of the buffer and delivered -- creating genuine reordering
// bounded to roughly `window` items deep.
func (l *lossyLink) send(data []byte, deliver func([]byte)) {
	l.mu.Lock()
	if l.rng.Float64() < l.dropFrac {
		l.mu.Unlock()
		return
	}
	l.buf = append(l.buf, pendingDelivery{data, deliver})
	var ready []pendingDelivery
	for len(l.buf) >= l.window {
		idx := 0
		if len(l.buf) > 1 {
			idx = l.rng.Intn(len(l.buf))
		}
		ready = append(ready, l.buf[idx])
		l.buf = append(l.buf[:idx], l.buf[idx+1:]...)
	}
	l.mu.Unlock()
	// Delivered synchronously (not via a spawned goroutine): this test
	// pumps at a high rate, and a goroutine per delivered frame is enough
	// scheduling noise on a loaded machine to occasionally inflate the
	// measured RTT far past its true in-process value, which can spuriously
	// trip the RTT-based decrease rule in applyAIMD. Delivering inline on
	// the caller's own goroutine keeps this test about loss, not scheduler
	// jitter.
	for _, it := range ready {
		it.deliver(it.data)
	}
}

// Flush releases every item still sitting in the reorder buffer, in
// whatever order they happen to be in. A window>1 link always leaves up to
// window-1 items buffered in steady state (see send's doc comment) -- call
// Flush once no more sends are coming so those tail items are delivered
// instead of sitting there forever.
func (l *lossyLink) Flush() {
	l.mu.Lock()
	items := l.buf
	l.buf = nil
	l.mu.Unlock()
	for _, it := range items {
		it.deliver(it.data)
	}
}

// ---- lossyEndpoint: a minimal DataTunnel that is also its own LossSource -

// lossyEndpoint implements DataTunnel. Two of them, wired to each other's
// `peer` field with a shared *lossyLink for the data-plane direction of
// interest, form a back-to-back in-process tunnel pair. The RECEIVING
// endpoint of a lossy direction accumulates real recv/gap/lost counters
// from the sequence numbers it actually observes arriving (assigned by the
// SENDING endpoint, one per data-plane SendData call, independent of
// anything the relay-frame protocol itself does) -- exactly mirroring how a
// real LossSource (e.g. pion RTP stats) sits below the relay-frame
// protocol, oblivious to its message types.
type lossyEndpoint struct {
	mu      sync.Mutex
	onData  func([]byte)
	onClose func()

	peer *lossyEndpoint // set after construction
	link *lossyLink     // link THIS endpoint's outbound data-plane frames travel

	seqMu sync.Mutex
	seq   uint64

	statsMu    sync.Mutex
	received   map[uint64]struct{} // distinct data-plane sequence numbers actually delivered to this endpoint
	maxSeqSeen int64               // -1 = none yet
	gapEvents  uint64              // count of out-of-order arrivals (informational; NOT fed into lossPct, matching handlePeerStats which discards `gaps`)

	// controlDelay is an artificial, FIXED (not random) one-way delay applied
	// to control-plane delivery (MsgPing/MsgStats/MsgConfig/MsgConfigAck).
	// Zero (the default) delivers control messages synchronously and
	// instantly, which is fine for most uses of this type but produces a
	// true one-way latency of a few microseconds for TestEndToEndRealLossDrivesAIMD
	// -- see that test's setup comment for why a non-zero, stable baseline
	// RTT matters there.
	controlDelay time.Duration
}

func newLossyEndpoint(link *lossyLink) *lossyEndpoint {
	return &lossyEndpoint{link: link, received: make(map[uint64]struct{}), maxSeqSeen: -1}
}

func (e *lossyEndpoint) SendData(data []byte) {
	connID, ok := firstFrameConnID(data)
	if !ok || connID == ControlConnID {
		e.peer.deliverReliable(data)
		return
	}
	e.seqMu.Lock()
	seq := e.seq
	e.seq++
	e.seqMu.Unlock()

	wrapped := make([]byte, 8+len(data))
	binary.BigEndian.PutUint64(wrapped[:8], seq)
	copy(wrapped[8:], data)
	e.link.send(wrapped, e.peer.deliverData)
}

func (e *lossyEndpoint) SetOnData(fn func([]byte)) { e.mu.Lock(); e.onData = fn; e.mu.Unlock() }
func (e *lossyEndpoint) SetOnClose(fn func())      { e.mu.Lock(); e.onClose = fn; e.mu.Unlock() }
func (e *lossyEndpoint) Reconfigure(int, int)      {}

func (e *lossyEndpoint) deliverReliable(data []byte) {
	if e.controlDelay <= 0 {
		e.mu.Lock()
		cb := e.onData
		e.mu.Unlock()
		if cb != nil {
			cb(data)
		}
		return
	}
	time.AfterFunc(e.controlDelay, func() {
		e.mu.Lock()
		cb := e.onData
		e.mu.Unlock()
		if cb != nil {
			cb(data)
		}
	})
}

func (e *lossyEndpoint) deliverData(wrapped []byte) {
	seq := binary.BigEndian.Uint64(wrapped[:8])
	payload := wrapped[8:]

	e.statsMu.Lock()
	if _, dup := e.received[seq]; !dup {
		e.received[seq] = struct{}{}
	}
	if int64(seq) > e.maxSeqSeen {
		if e.maxSeqSeen >= 0 && int64(seq) != e.maxSeqSeen+1 {
			e.gapEvents++
		}
		e.maxSeqSeen = int64(seq)
	}
	e.statsMu.Unlock()

	e.mu.Lock()
	cb := e.onData
	e.mu.Unlock()
	if cb != nil {
		cb(payload)
	}
}

// RecvLossStats implements LossSource. recvPackets/lostPackets are computed
// from "highest sequence number ever seen" vs. "distinct sequence numbers
// actually delivered" so that a reordered-but-not-dropped packet (still
// arrives, just late) never inflates lostPackets -- only a sequence number
// that NEVER arrives counts as lost. gaps is purely informational (out-of-
// order arrival events), matching handlePeerStats which receives gaps but
// discards it (`_ = gaps`).
func (e *lossyEndpoint) RecvLossStats() (recvPackets, gaps, lostPackets uint64) {
	e.statsMu.Lock()
	defer e.statsMu.Unlock()
	recvPackets = uint64(len(e.received))
	gaps = e.gapEvents
	if e.maxSeqSeen >= 0 {
		total := uint64(e.maxSeqSeen) + 1
		if total > recvPackets {
			lostPackets = total - recvPackets
		}
	}
	return
}

func firstFrameConnID(data []byte) (uint32, bool) {
	var id uint32
	found := false
	DecodeFrames(data, func(connID uint32, _ byte, _ []byte) {
		if !found {
			id = connID
			found = true
		}
	})
	return id, found
}

// waitUntil polls cond every 2ms until it returns true, failing the test if
// timeout elapses first. Used instead of fixed sleeps so the test runs as
// fast as the real AIMD/stats timing allows on the machine it's running on,
// rather than a duration guessed in advance -- the ceiling is a generous
// upper bound for a slow/loaded CI box, not the expected running time.
func waitUntil(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for: %s", timeout, what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestEndToEndRealLossDrivesAIMD(t *testing.T) {
	rng := rand.New(rand.NewSource(42))

	// sender -> receiver is the direction under test: it's real loss on
	// THIS link, measured by the receiver, that must travel back to the
	// sender as MsgStats and move the sender's AIMD. window=1 (no
	// reordering) here deliberately: lossyLink's reorder buffer holds a
	// handful of in-flight items at any instant by design (see its doc
	// comment), which are indistinguishable from "lost" to a highest-seq-
	// seen accounting the moment a snapshot is taken mid-flight -- real,
	// but transient, noise that this test doesn't want competing with the
	// genuine, permanent loss it deliberately injects below. Reordering's
	// "eventually-arrives, never counted as permanently lost" behavior is
	// covered on its own in TestLossyLinkReorderIsNotPermanentLoss.
	forwardLink := newLossyLink(rng, 0.0, 1)
	// receiver -> sender never carries data-plane traffic in this test
	// (only control messages, which bypass links entirely), but every
	// lossyEndpoint needs one.
	backLink := newLossyLink(rng, 0.0, 1)

	sender := newLossyEndpoint(forwardLink)
	receiver := newLossyEndpoint(backLink)
	sender.peer = receiver
	receiver.peer = sender

	// A real, fixed one-way control-plane delay -- NOT zero. Without this,
	// the two sides' MsgPing/MsgStats round trip in low-single-digit
	// microseconds (true in-process latency), while handlePeerStats' RTT
	// still carries up to a full StatsPingInterval of jitter from
	// statsPingLoop's ping-arrival and stats-echo being two INDEPENDENT
	// periodic timers rather than one arming the other. minRTT (the
	// smallest RTT ever seen) then settles near that near-zero true
	// latency, and any later window that lands on the unlucky side of that
	// jitter looks like RTT more than doubling -- tripping applyAIMD's
	// RTT-based decrease rule for a reason that has nothing to do with
	// congestion. That is a real property of the production code (see
	// this task's final report), but it is NOT what this test is trying to
	// prove, and left alone it makes the loss-driven assertions below
	// flaky. Giving control messages a real, stable propagation delay large
	// relative to StatsPingInterval keeps minRTT anchored near that stable
	// floor instead of near zero, which is what a real deployment's actual
	// network RTT would do too.
	sender.controlDelay = 25 * time.Millisecond
	receiver.controlDelay = 25 * time.Millisecond

	noopLog := func(string, ...any) {}

	cfg := RateControllerConfig{
		ActiveProfile:   Profile{FPS: 20, Batch: 1, Tier: TierActive},
		DrainProfile:    Profile{FPS: 10, Batch: 1, IdleKeepalive: 500 * time.Millisecond, Tier: TierDrain},
		IdleProfile:     Profile{FPS: 2, Batch: 1, IdleKeepalive: time.Second, Tier: TierIdle},
		DeepIdleProfile: Profile{FPS: 1, Batch: 1, IdleKeepalive: 2 * time.Second, Tier: TierDeepIdle},
		// ActiveToDrain is deliberately short and DrainToIdle deliberately
		// very long: this test wants exactly ONE Active->Drain->Active
		// round trip before the real traffic starts (see the priming step
		// below), landing on TierIdle/TierDeepIdle is never wanted. Once
		// the pump is running at a 1ms send interval, 20ms of required
		// silence is never reached again, so this is a one-shot effect.
		ActiveToDrain: 20 * time.Millisecond,
		DrainToIdle:   30 * time.Second,
		CheckInterval: 5 * time.Millisecond,

		AIMDFloor:   1200,
		AIMDStart:   4800,
		AIMDCeiling: 64000,

		StatsPingInterval:    15 * time.Millisecond,
		AIMDHold:             30 * time.Millisecond,
		AIMDIncreaseInterval: 15 * time.Millisecond,
	}

	senderRB := NewRelayBridgeWithConfig(sender, "bench", 4096, noopLog, true, cfg)
	defer senderRB.Close()
	receiverRB := NewRelayBridgeWithConfig(receiver, "bench", 4096, noopLog, false, cfg)
	defer receiverRB.Close()

	// Wire the receiver's genuine, transport-level loss accounting into its
	// RateController -- this is the one call in this whole test that
	// corresponds to the "wiring a real LossSource... is left as follow-up
	// work" comment in ratectl.go. Everything downstream of this is
	// production code.
	receiverRB.SetLossSource(receiver)

	var delivered atomic.Int64
	receiverRB.SetOnBenchData(func([]byte) { delivered.Add(1) })

	// --- Phase 0: prime a known AIMD baseline via the real tier machinery --
	// A brand new RateController's aimd.maxFrameBytes starts at the zero
	// value, not AIMDStart, until its FIRST TierActive-entry EDGE (see
	// applyProfile): tier starts life already "TierActive", so a
	// RateController that is simply never idle never crosses that edge and
	// never gets AIMDStart "for free". Rather than assert against that
	// implementation detail, this test manufactures the edge for real,
	// through the public API: stay silent past ActiveToDrain (20ms) so the
	// tier machinery genuinely drops to TierDrain, then send one real
	// frame, which genuinely re-enters TierActive and resets
	// aimd.maxFrameBytes to cfg.AIMDStart via applyProfile -- exactly what
	// a real connection going idle and then busy again would do.
	time.Sleep(60 * time.Millisecond)
	if tier := senderRB.State(); tier != TierDrain {
		t.Fatalf("priming: expected sender to have idled into TierDrain, got %s", tier)
	}
	primer := make([]byte, 200)
	senderRB.SendBenchData(primer)
	if got := senderRB.MaxFrameBytes(); got != cfg.AIMDStart {
		t.Fatalf("priming: expected the TierDrain->TierActive edge to reset MaxFrameBytes to AIMDStart=%d, got %d", cfg.AIMDStart, got)
	}
	baseline := senderRB.MaxFrameBytes()

	stopPump := make(chan struct{})
	var pumpWG sync.WaitGroup
	pumpWG.Add(1)
	go func() {
		defer pumpWG.Done()
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		payload := make([]byte, 200)
		for {
			select {
			case <-stopPump:
				return
			case <-ticker.C:
				senderRB.SendBenchData(payload)
			}
		}
	}()
	defer func() {
		close(stopPump)
		pumpWG.Wait()
	}()

	// --- Phase 1: warm up with a clean link -------------------------------
	// Confirm the real control-message exchange actually happens: RTT > 0
	// means a MsgPing genuinely round-tripped through a real MsgStats
	// reply, not a synthetic AIMDStats value handed straight to applyAIMD.
	waitUntil(t, 5*time.Second, "sender observes a real peer RTT", func() bool {
		return senderRB.LastStats().RTT > 0
	})

	// Re-read baseline here (rather than trusting the value captured right
	// after priming): a clean window or two may already have nudged it up
	// while we were waiting for the first real RTT sample above, and phase
	// 2's "did it decrease" check should compare against wherever it
	// actually stood right before loss was induced.
	baseline = senderRB.MaxFrameBytes()
	t.Logf("phase1: baseline maxFrameBytes=%d lastStats=%+v", baseline, senderRB.LastStats())

	// --- Phase 2: induce real loss -----------------------------------------
	forwardLink.SetDropFraction(0.3)

	var lossAtBackoff float64
	var backedOff int
	waitUntil(t, 5*time.Second, "AIMD backs off in response to real measured loss", func() bool {
		st := senderRB.LastStats()
		cur := senderRB.MaxFrameBytes()
		if cur < baseline && st.LossPercent >= 2.0 {
			lossAtBackoff = st.LossPercent
			backedOff = cur
			return true
		}
		return false
	})
	// Stop inducing further loss the moment the backoff is observed, so
	// phase 3's cumulative loss% (see below) has as little to recover from
	// as possible -- keeping this test's wall-clock time bounded.
	forwardLink.SetDropFraction(0.0)

	recvPackets, gaps, lostPackets := receiver.RecvLossStats()
	t.Logf("phase2: receiver measured recvPackets=%d gaps=%d lostPackets=%d; sender saw lossPercent=%.2f and backed off %d -> %d",
		recvPackets, gaps, lostPackets, lossAtBackoff, baseline, backedOff)

	if lostPackets == 0 {
		t.Fatalf("expected the receiver to have genuinely lost at least one packet, got 0")
	}
	if backedOff >= baseline {
		t.Fatalf("expected MaxFrameBytes to have decreased from %d, got %d", baseline, backedOff)
	}
	if delivered.Load() == 0 {
		t.Fatalf("expected at least some bench payloads to have reached the receiver's real handleTunnelData dispatch")
	}

	// --- Phase 3: loss returns to ~0 -> AIMD additively recovers -----------
	// NOTE: LossSource counters are CUMULATIVE since creation (see
	// LossSource's doc comment), and handlePeerStats computes lossPercent
	// as lostPackets/(recvPackets+lostPackets) over that whole cumulative
	// history -- not a sliding recent window. So "loss returns to ~0" does
	// NOT mean the very next window reports ~0% the way the synthetic
	// ratectl_test.go tests do when they simply pass LossPercent: 0 to the
	// next applyAIMD call: the cumulative percentage only decays back
	// below the 1% increase threshold once enough additional loss-free
	// traffic has accumulated to dilute the earlier losses. That is a real,
	// measurable difference between the synthetic tests' implied recovery
	// speed and the real path's actual recovery speed -- see this task's
	// final report.
	waitUntil(t, 10*time.Second, "AIMD additively recovers once cumulative loss decays under 1%", func() bool {
		return senderRB.MaxFrameBytes() > backedOff
	})

	recovered := senderRB.MaxFrameBytes()
	finalStats := senderRB.LastStats()
	t.Logf("phase3: recovered maxFrameBytes=%d (was %d), lastStats=%+v", recovered, backedOff, finalStats)

	if recovered <= backedOff {
		t.Fatalf("expected MaxFrameBytes to have additively increased above %d, got %d", backedOff, recovered)
	}
	if finalStats.LossPercent >= 1.0 {
		t.Errorf("expected the increase to only have fired once cumulative lossPercent genuinely decayed under 1%%, got %.4f", finalStats.LossPercent)
	}
}

// TestLossyLinkReorderIsNotPermanentLoss exercises lossyLink/lossyEndpoint's
// reordering directly (no RelayBridge/RateController involved) to prove the
// harness's own claim: a window>1 link genuinely reorders frames (the
// receiver really does see out-of-order arrivals -- gaps>0) without ever
// permanently losing a frame that was never dropped. This is what justifies
// TestEndToEndRealLossDrivesAIMD using window=1 on the link its AIMD
// assertions depend on -- reordering-as-transient-noise is a property of
// THIS test harness's snapshot-based accounting, not of applyAIMD, and is
// verified in isolation here instead of muddying the AIMD assertions above.
func TestLossyLinkReorderIsNotPermanentLoss(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	link := newLossyLink(rng, 0.0, 5) // no drops, reorder window 5

	sender := newLossyEndpoint(link)
	receiver := newLossyEndpoint(newLossyLink(rng, 0.0, 1)) // unused reverse direction
	sender.peer = receiver
	receiver.peer = sender

	const n = 500
	for i := 0; i < n; i++ {
		payload := EncodeFrame(1, MsgData, []byte{byte(i), byte(i >> 8)})
		sender.SendData(payload)
	}
	link.Flush() // release whatever's still sitting in the reorder buffer

	recvPackets, gaps, lostPackets := receiver.RecvLossStats()
	t.Logf("sent=%d recvPackets=%d gaps=%d lostPackets=%d", n, recvPackets, gaps, lostPackets)

	if gaps == 0 {
		t.Errorf("expected the reorder window to actually produce out-of-order arrivals (gaps>0), got 0 -- the window may be too small or Flush too eager")
	}
	if recvPackets != n {
		t.Errorf("expected all %d frames to eventually arrive, got %d", n, recvPackets)
	}
	if lostPackets != 0 {
		t.Errorf("expected 0 permanent loss from pure reordering (nothing was dropped), got %d", lostPackets)
	}
}
