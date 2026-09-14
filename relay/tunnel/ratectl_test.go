package tunnel

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeTunnel struct {
	mu       sync.Mutex
	sent     [][]byte
	onData   func([]byte)
	onClose  func()
	profiles []Profile // every SetProfile call, in order
}

func (f *fakeTunnel) SendData(data []byte) {
	f.mu.Lock()
	f.sent = append(f.sent, append([]byte(nil), data...))
	f.mu.Unlock()
}
func (f *fakeTunnel) SetOnData(fn func([]byte))  { f.onData = fn }
func (f *fakeTunnel) SetOnClose(fn func())       { f.onClose = fn }
func (f *fakeTunnel) Reconfigure(fps, batch int) {}
func (f *fakeTunnel) SetProfile(p Profile) {
	f.mu.Lock()
	f.profiles = append(f.profiles, p)
	f.mu.Unlock()
}
func (f *fakeTunnel) Counters() Counters { return Counters{} }
func (f *fakeTunnel) lastProfile() (Profile, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.profiles) == 0 {
		return Profile{}, false
	}
	return f.profiles[len(f.profiles)-1], true
}

type fakeHinterTunnel struct {
	fakeTunnel
	hintsMu sync.Mutex
	hints   []Tier
}

func (f *fakeHinterTunnel) HintBandwidth(ctx context.Context, tier Tier) error {
	f.hintsMu.Lock()
	f.hints = append(f.hints, tier)
	f.hintsMu.Unlock()
	return nil
}

func testConfig() RateControllerConfig {
	return RateControllerConfig{
		ActiveProfile:   Profile{FPS: 20, Batch: 1, Tier: TierActive},
		DrainProfile:    Profile{FPS: 10, Batch: 1, IdleKeepalive: 500 * time.Millisecond, Tier: TierDrain},
		IdleProfile:     Profile{FPS: 2, Batch: 1, IdleKeepalive: 2 * time.Second, Tier: TierIdle},
		DeepIdleProfile: Profile{FPS: 1, Batch: 1, IdleKeepalive: 5 * time.Second, Tier: TierDeepIdle},
		ActiveToDrain:   30 * time.Millisecond,
		DrainToIdle:     60 * time.Millisecond,
		CheckInterval:   5 * time.Millisecond,
		AIMDFloor:       1200,
		AIMDStart:       4800,
		AIMDCeiling:     64000,
	}
}

func TestTierTransitions(t *testing.T) {
	fake := &fakeTunnel{}
	cfg := testConfig()

	rc := NewRateController(fake, cfg, true, nil)
	rc.Start()
	defer rc.Stop()

	if rc.State() != TierActive {
		t.Errorf("expected initial state to be TierActive, got %s", rc.State())
	}

	// Sleep past ActiveToDrain (30ms) -> should be TierDrain
	time.Sleep(50 * time.Millisecond)
	if rc.State() != TierDrain {
		t.Errorf("expected state TierDrain, got %s", rc.State())
	}

	// Sleep past DrainToIdle (ActiveToDrain + DrainToIdle = 90ms total) -> should be TierIdle
	time.Sleep(70 * time.Millisecond)
	if rc.State() != TierIdle {
		t.Errorf("expected state TierIdle, got %s", rc.State())
	}

	// Set AllowDeepIdle = true -> should transition to TierDeepIdle
	rc.SetPolicy(Policy{AllowDeepIdle: true})
	time.Sleep(20 * time.Millisecond)
	if rc.State() != TierDeepIdle {
		t.Errorf("expected state TierDeepIdle, got %s", rc.State())
	}
}

func TestImmediateActiveOnEnqueue(t *testing.T) {
	fake := &fakeTunnel{}
	cfg := testConfig()

	rc := NewRateController(fake, cfg, true, nil)
	rc.Start()
	defer rc.Stop()

	// Wait until TierIdle
	time.Sleep(120 * time.Millisecond)
	if rc.State() != TierIdle {
		t.Fatalf("expected state to settle on TierIdle first, got %s", rc.State())
	}

	// Call NoteSent()
	rc.NoteSent()

	// Assert immediately TierActive
	if rc.State() != TierActive {
		t.Errorf("expected state to immediately return to TierActive, got %s", rc.State())
	}
}

func TestIdleProfileNotEveryTick(t *testing.T) {
	fake := &fakeTunnel{}
	cfg := testConfig()

	rc := NewRateController(fake, cfg, true, nil)
	rc.Start()
	defer rc.Stop()

	// Wait until TierIdle
	time.Sleep(120 * time.Millisecond)
	if rc.State() != TierIdle {
		t.Fatalf("expected state TierIdle, got %s", rc.State())
	}

	lastP, ok := fake.lastProfile()
	if !ok {
		t.Fatalf("no profile was ever applied to the tunnel")
	}

	if lastP.Tier != TierIdle || lastP.FPS != cfg.IdleProfile.FPS || lastP.IdleKeepalive != cfg.IdleProfile.IdleKeepalive {
		t.Errorf("last applied profile %v does not match expected Idle profile %v", lastP, cfg.IdleProfile)
	}

	fake.mu.Lock()
	count := len(fake.profiles)
	fake.mu.Unlock()

	// It should only apply profile on transitions, so total count should be small (Active -> Drain -> Idle -> ~3 profile applications)
	if count > 4 {
		t.Errorf("SetProfile called too many times (%d), should only be called on edges", count)
	}
}

func TestBandwidthHinterCalledOnTierEdge(t *testing.T) {
	fake := &fakeHinterTunnel{}
	cfg := testConfig()

	rc := NewRateController(fake, cfg, true, nil)
	rc.Start()
	defer rc.Stop()

	// Wait for transition Active -> Drain
	time.Sleep(50 * time.Millisecond)

	fake.hintsMu.Lock()
	hintsCopy := append([]Tier(nil), fake.hints...)
	fake.hintsMu.Unlock()

	foundDrain := false
	for _, h := range hintsCopy {
		if h == TierDrain {
			foundDrain = true
		}
	}

	if !foundDrain {
		t.Errorf("expected HintBandwidth to be called on transition, got hints: %v", hintsCopy)
	}
}

func TestAIMDIncrease(t *testing.T) {
	fake := &fakeTunnel{}
	cfg := testConfig()

	rc := NewRateController(fake, cfg, true, nil)
	rc.mu.Lock()
	rc.tier = TierActive
	rc.aimd.maxFrameBytes = cfg.AIMDStart
	rc.activeFPS = cfg.ActiveProfile.FPS
	rc.mu.Unlock()

	// Call applyAIMD with low loss and RTT -> should increase after timing gate (1 second)
	rc.applyAIMD(AIMDStats{LossPercent: 0.1, RTT: 10 * time.Millisecond})

	fake.mu.Lock()
	p1Count := len(fake.profiles)
	fake.mu.Unlock()

	// It should grow immediately because lastIncreaseAt starts as zero (IsZero == true), so timing gate is satisfied!
	if p1Count != 1 {
		t.Fatalf("expected exactly 1 profile to be applied, got %d", p1Count)
	}
	p1, _ := fake.lastProfile()
	if p1.MaxFrameBytes != cfg.AIMDStart+aimdPacketBytes {
		t.Errorf("expected first increase to %d, got %d", cfg.AIMDStart+aimdPacketBytes, p1.MaxFrameBytes)
	}

	// Sleep 1.1s to pass the timing gate
	time.Sleep(1100 * time.Millisecond)

	rc.applyAIMD(AIMDStats{LossPercent: 0.1, RTT: 10 * time.Millisecond})
	p2, _ := fake.lastProfile()
	if p2.MaxFrameBytes != cfg.AIMDStart+2*aimdPacketBytes {
		t.Errorf("expected second increase to %d, got %d", cfg.AIMDStart+2*aimdPacketBytes, p2.MaxFrameBytes)
	}
}

func TestAIMDDecreaseAndHold(t *testing.T) {
	fake := &fakeTunnel{}
	cfg := testConfig()

	rc := NewRateController(fake, cfg, true, nil)
	rc.mu.Lock()
	rc.tier = TierActive
	rc.aimd.maxFrameBytes = 10000
	rc.activeFPS = cfg.ActiveProfile.FPS
	rc.mu.Unlock()

	// Trigger decrease with high loss
	rc.applyAIMD(AIMDStats{LossPercent: 5.0})

	p1, _ := fake.lastProfile()
	if p1.MaxFrameBytes != 6000 {
		t.Errorf("expected decrease to 6000 (0.6 * 10000), got %d", p1.MaxFrameBytes)
	}

	fake.mu.Lock()
	pCountBefore := len(fake.profiles)
	fake.mu.Unlock()

	// Call applyAIMD again immediately (inside 2s hold window) -> should ignore change
	rc.applyAIMD(AIMDStats{LossPercent: 0.0})

	fake.mu.Lock()
	pCountAfter := len(fake.profiles)
	fake.mu.Unlock()

	if pCountAfter != pCountBefore {
		t.Errorf("expected no profile to be applied during hold, count changed from %d to %d", pCountBefore, pCountAfter)
	}

	// Test floor clamping: set maxFrameBytes to 1500, clear hold
	rc.mu.Lock()
	rc.aimd.maxFrameBytes = 1500
	rc.aimd.holdUntil = time.Time{}
	rc.mu.Unlock()

	rc.applyAIMD(AIMDStats{LossPercent: 5.0})
	pFloor, _ := fake.lastProfile()
	if pFloor.MaxFrameBytes != cfg.AIMDFloor { // 1200
		t.Errorf("expected clamp to floor %d, got %d", cfg.AIMDFloor, pFloor.MaxFrameBytes)
	}
}

func TestAIMDCeiling(t *testing.T) {
	fake := &fakeTunnel{}
	cfg := testConfig()

	rc := NewRateController(fake, cfg, true, nil)
	rc.mu.Lock()
	rc.tier = TierActive
	rc.aimd.maxFrameBytes = cfg.AIMDCeiling - 200
	rc.activeFPS = cfg.ActiveProfile.FPS
	rc.mu.Unlock()

	// Clear timing gate for increase
	rc.mu.Lock()
	rc.aimd.lastIncreaseAt = time.Now().Add(-2 * time.Second)
	rc.mu.Unlock()

	rc.applyAIMD(AIMDStats{LossPercent: 0.0})
	pCeil, _ := fake.lastProfile()
	if pCeil.MaxFrameBytes != cfg.AIMDCeiling {
		t.Errorf("expected clamp to ceiling %d, got %d", cfg.AIMDCeiling, pCeil.MaxFrameBytes)
	}
}

func TestPushProfileResendsUntilAcked(t *testing.T) {
	fake := &fakeTunnel{}
	cfg := testConfig()

	rc := NewRateController(fake, cfg, true, nil)
	rc.pushProfile(Profile{FPS: 5, Batch: 1, IdleKeepalive: 100 * time.Millisecond})

	fake.mu.Lock()
	sentCount := len(fake.sent)
	fake.mu.Unlock()

	if sentCount != 1 {
		t.Fatalf("expected exactly 1 configuration push to be sent, got %d", sentCount)
	}

	rc.ackMu.Lock()
	acked := rc.acked
	rc.ackMu.Unlock()

	if acked == nil {
		t.Fatalf("expected acked channel to be armed/non-nil")
	}

	select {
	case <-acked:
		t.Errorf("acked channel should not be closed yet")
	default:
	}

	// simulate ack arrival
	rc.onPeerAck()

	select {
	case <-acked:
		// success: acked channel is closed
	default:
		t.Errorf("expected acked channel to be closed after onPeerAck")
	}
}

// TestPushProfileFrameRoundTrip is the regression guard for the double-framing
// bug: pushProfile wrapped EncodeVP8Config's return in a SECOND EncodeFrame,
// so the config message's payload was an entire encoded frame and the peer's
// DecodeVP8Config read the INNER frame's header as the config fields.
//
// It asserts on what the peer decodes, not on bytes, because the bug was
// invisible at the byte level -- both the broken and correct forms are
// well-formed frames that decode without error. What distinguishes them is
// that the broken one decodes to values nobody asked for.
//
// The pushed profile deliberately uses no value that could be confused with a
// framing artifact (the old bug always yielded fps=0 batch=16 trackCount=0
// maxFrameBytes=0 idleKeepaliveMs=2048, regardless of the profile).
func TestPushProfileFrameRoundTrip(t *testing.T) {
	tun := &fakeTunnel{}
	rc := NewRateController(tun, testConfig(), true, nil)
	// pushProfile spawns a resend goroutine that re-sends every
	// configPushResendPeriod until acked; without this it outlives the test,
	// and a resend landing inside the 3s window would also break the
	// exactly-one-frame assertion below. Stop is safe without Start.
	defer rc.Stop()

	want := Profile{FPS: 37, Batch: 5, MaxFrameBytes: 4800, IdleKeepalive: 1500 * time.Millisecond}
	rc.pushProfile(want)

	tun.mu.Lock()
	sent := append([][]byte(nil), tun.sent...)
	tun.mu.Unlock()
	if len(sent) != 1 {
		t.Fatalf("pushProfile sent %d frames, want 1", len(sent))
	}

	// Decode exactly the way a peer does: frame decoder first, then the
	// config decoder on that frame's payload.
	var (
		got     Profile
		decoded bool
	)
	DecodeFrames(sent[0], func(connID uint32, msgType byte, payload []byte) {
		if connID != ControlConnID || msgType != MsgConfig {
			t.Errorf("frame is connID=%d msgType=%d, want ControlConnID/MsgConfig", connID, msgType)
			return
		}
		fps, batch, trackCount, maxFB, idleMs, _, ok := DecodeVP8Config(payload)
		if !ok {
			t.Error("DecodeVP8Config reported not-ok")
			return
		}
		if trackCount != 1 {
			t.Errorf("trackCount = %d, want 1", trackCount)
		}
		got = Profile{FPS: fps, Batch: batch, MaxFrameBytes: maxFB, IdleKeepalive: time.Duration(idleMs) * time.Millisecond}
		decoded = true
	})
	if !decoded {
		t.Fatal("no MsgConfig frame decoded from what pushProfile sent")
	}

	if got.FPS != want.FPS || got.Batch != want.Batch ||
		got.MaxFrameBytes != want.MaxFrameBytes || got.IdleKeepalive != want.IdleKeepalive {
		t.Errorf("peer decoded fps=%d batch=%d maxFrameBytes=%d idleKeepalive=%s,\n"+
			"                   want fps=%d batch=%d maxFrameBytes=%d idleKeepalive=%s",
			got.FPS, got.Batch, got.MaxFrameBytes, got.IdleKeepalive,
			want.FPS, want.Batch, want.MaxFrameBytes, want.IdleKeepalive)
	}
}

// TestPushProfileDistinguishesProfiles is the sharper half of the guard. The
// double-framing bug decoded EVERY profile to the same constant, because every
// decoded field came from the inner frame's fixed header -- so a push carried
// no information at all. A test that only checked one profile could still pass
// against a future bug that clamps or drops values; this one fails unless
// distinct profiles actually arrive distinct.
func TestPushProfileDistinguishesProfiles(t *testing.T) {
	decode := func(t *testing.T, p Profile) (fps, batch int) {
		t.Helper()
		tun := &fakeTunnel{}
		rc := NewRateController(tun, testConfig(), true, nil)
		defer rc.Stop() // see TestPushProfileFrameRoundTrip: don't leak the resender
		rc.pushProfile(p)
		tun.mu.Lock()
		sent := append([][]byte(nil), tun.sent...)
		tun.mu.Unlock()
		if len(sent) != 1 {
			t.Fatalf("sent %d frames, want 1", len(sent))
		}
		var f, b int
		DecodeFrames(sent[0], func(_ uint32, _ byte, payload []byte) {
			f, b, _, _, _, _, _ = DecodeVP8Config(payload)
		})
		return f, b
	}

	activeFPS, activeBatch := decode(t, Profile{FPS: 40, Batch: 8})
	idleFPS, idleBatch := decode(t, Profile{FPS: 2, Batch: 1})

	if activeFPS == idleFPS && activeBatch == idleBatch {
		t.Fatalf("two different profiles both decoded to fps=%d batch=%d; "+
			"a config push is carrying no information (double-framing regression)",
			activeFPS, activeBatch)
	}
	if activeFPS != 40 || activeBatch != 8 {
		t.Errorf("active profile decoded fps=%d batch=%d, want 40/8", activeFPS, activeBatch)
	}
	if idleFPS != 2 || idleBatch != 1 {
		t.Errorf("idle profile decoded fps=%d batch=%d, want 2/1", idleFPS, idleBatch)
	}
}

func TestMasterPushesIdleNonMasterFollows(t *testing.T) {
	fakeMaster := &fakeTunnel{}
	cfgMaster := testConfig()
	rcMaster := NewRateController(fakeMaster, cfgMaster, true, nil)
	rcMaster.Start()
	defer rcMaster.Stop()

	fakeNonMaster := &fakeTunnel{}
	cfgNonMaster := testConfig()
	// ensure different active FPS/batch so we can distinguish profiles
	cfgNonMaster.IdleProfile.FPS = 3
	cfgNonMaster.IdleProfile.Batch = 2
	rcNonMaster := NewRateController(fakeNonMaster, cfgNonMaster, false, nil)
	rcNonMaster.Start()
	defer rcNonMaster.Stop()

	// Master transition to Idle -> push idle profile
	rcMaster.applyProfile(TierIdle)

	fakeMaster.mu.Lock()
	sentLen := len(fakeMaster.sent)
	fakeMaster.mu.Unlock()
	if sentLen == 0 {
		t.Fatalf("master did not send any configuration frames")
	}

	fakeMaster.mu.Lock()
	lastSentFrame := fakeMaster.sent[sentLen-1]
	fakeMaster.mu.Unlock()

	// Decode master's config frame
	var decodedPayload []byte
	DecodeFrames(lastSentFrame, func(connID uint32, msgType byte, payload []byte) {
		if connID == ControlConnID && msgType == MsgConfig {
			decodedPayload = payload
		}
	})
	if decodedPayload == nil {
		t.Fatalf("no MsgConfig frame found in master's sent frames")
	}

	fps, batch, _, maxFB, idleMs, flags, ok := DecodeVP8Config(decodedPayload)
	if !ok {
		t.Fatalf("failed to decode master's config payload")
	}

	p := profileFromConfig(fps, batch, maxFB, idleMs, flags)
	rcNonMaster.onPeerConfig(p)

	// Assert non-master is now in State() == TierIdle
	if rcNonMaster.State() != TierIdle {
		t.Errorf("expected non-master to transition to TierIdle, got %s", rcNonMaster.State())
	}

	// Assert non-master's tunnel received SetProfile with its OWN IdleProfile
	pLast, ok := fakeNonMaster.lastProfile()
	if !ok {
		t.Fatalf("non-master tunnel did not receive SetProfile")
	}
	if pLast.FPS != cfgNonMaster.IdleProfile.FPS || pLast.Batch != cfgNonMaster.IdleProfile.Batch {
		t.Errorf("non-master applied peer's fps/batch (%d/%d), expected own idle profile's (%d/%d)",
			pLast.FPS, pLast.Batch, cfgNonMaster.IdleProfile.FPS, cfgNonMaster.IdleProfile.Batch)
	}

	// Assert no MsgPing/MsgStats frames are sent afterwards for > a few ping intervals
	fakeNonMaster.mu.Lock()
	fakeNonMaster.sent = nil
	fakeNonMaster.mu.Unlock()

	time.Sleep(3 * cfgNonMaster.statsPingInterval())

	fakeNonMaster.mu.Lock()
	sentLenAfter := len(fakeNonMaster.sent)
	fakeNonMaster.mu.Unlock()
	if sentLenAfter > 0 {
		t.Errorf("expected no control frames to be sent from non-master in idle state, but got %d", sentLenAfter)
	}
}

func TestNonMasterNeverSelfDemotes(t *testing.T) {
	fake := &fakeTunnel{}
	cfg := testConfig()

	// Master with same setup -> Drain then Idle (existing behaviour)
	rcMaster := NewRateController(fake, cfg, true, nil)
	rcMaster.mu.Lock()
	rcMaster.lastActivity = time.Now().Add(-200 * time.Millisecond) // far in past
	rcMaster.mu.Unlock()

	rcMaster.tick() // first tick should go Drain
	if rcMaster.State() != TierDrain {
		t.Errorf("expected master to self-demote to TierDrain, got %s", rcMaster.State())
	}
	rcMaster.tick() // second tick should go Idle
	if rcMaster.State() != TierIdle {
		t.Errorf("expected master to self-demote to TierIdle, got %s", rcMaster.State())
	}

	// Non-master with same setup -> still Active
	rcNonMaster := NewRateController(fake, cfg, false, nil)
	rcNonMaster.mu.Lock()
	rcNonMaster.lastActivity = time.Now().Add(-200 * time.Millisecond) // far in past
	rcNonMaster.mu.Unlock()

	rcNonMaster.tick()
	if rcNonMaster.State() != TierActive {
		t.Errorf("expected non-master to remain TierActive, got %s", rcNonMaster.State())
	}
	rcNonMaster.tick()
	if rcNonMaster.State() != TierActive {
		t.Errorf("expected non-master to remain TierActive after multiple ticks, got %s", rcNonMaster.State())
	}
}

type fakeTrySendTunnel struct {
	fakeTunnel
	trySendResult bool
}

func (f *fakeTrySendTunnel) TrySendData(data []byte) bool {
	if f.trySendResult {
		f.SendData(data)
	}
	return f.trySendResult
}

func TestControlFramesDontBlock(t *testing.T) {
	// 1. TrySendData returns false -> drops increment
	fakeFull := &fakeTrySendTunnel{trySendResult: false}
	rcFull := NewRateController(fakeFull, testConfig(), true, nil)

	rcFull.pushProfile(Profile{FPS: 20})
	rcFull.sendPing()
	rcFull.sendStats()
	rcFull.onPeerConfig(Profile{Tier: TierIdle})

	if drops := rcFull.ctlDrops.Load(); drops < 4 {
		t.Errorf("expected at least 4 control drops, got %d", drops)
	}

	// 2. TrySendData returns true -> works normally
	fakeOk := &fakeTrySendTunnel{trySendResult: true}
	rcOk := NewRateController(fakeOk, testConfig(), true, nil)

	rcOk.pushProfile(Profile{FPS: 20})
	rcOk.sendPing()
	rcOk.sendStats()
	rcOk.onPeerConfig(Profile{Tier: TierIdle})

	if drops := rcOk.ctlDrops.Load(); drops != 0 {
		t.Errorf("expected 0 control drops when TrySendData returns true, got %d", drops)
	}

	// 3. Fallback to SendData if TrySendData is not implemented
	fakeFallback := &fakeTunnel{}
	rcFallback := NewRateController(fakeFallback, testConfig(), true, nil)

	rcFallback.pushProfile(Profile{FPS: 20})
	rcFallback.sendPing()
	rcFallback.sendStats()
	rcFallback.onPeerConfig(Profile{Tier: TierIdle})

	if drops := rcFallback.ctlDrops.Load(); drops != 0 {
		t.Errorf("expected 0 control drops on fallback, got %d", drops)
	}
	fakeFallback.mu.Lock()
	sentLen := len(fakeFallback.sent)
	fakeFallback.mu.Unlock()
	if sentLen == 0 {
		t.Errorf("expected frames to be sent via fallback SendData, but got 0")
	}
}

func TestStatsLine(t *testing.T) {
	fake := &fakeTunnel{}
	var lines []string
	var mu sync.Mutex
	logFn := func(format string, args ...any) {
		mu.Lock()
		lines = append(lines, fmt.Sprintf(format, args...))
		mu.Unlock()
	}

	cfg := testConfig()
	cfg.StatsLogInterval = 10 * time.Millisecond

	rc := NewRateController(fake, cfg, true, logFn)
	rc.Start()
	time.Sleep(30 * time.Millisecond)
	rc.Stop()
	time.Sleep(20 * time.Millisecond) // wait for stopped background goroutines to finish logging

	mu.Lock()
	hasStats := false
	for _, line := range lines {
		if strings.Contains(line, "ratectl: stats") && strings.Contains(line, "tier=") && strings.Contains(line, "queue=") {
			hasStats = true
			break
		}
	}
	mu.Unlock()

	if !hasStats {
		t.Errorf("expected ratectl: stats line with tier= and queue=, got logs:\n%v", lines)
	}

	// with a negative interval none appears
	mu.Lock()
	lines = nil
	mu.Unlock()

	cfgNeg := testConfig()
	cfgNeg.StatsLogInterval = -1 * time.Second
	rcNeg := NewRateController(fake, cfgNeg, true, logFn)
	rcNeg.Start()
	time.Sleep(30 * time.Millisecond)
	rcNeg.Stop()

	mu.Lock()
	hasStatsNeg := false
	for _, line := range lines {
		if strings.Contains(line, "ratectl: stats") {
			hasStatsNeg = true
			break
		}
	}
	mu.Unlock()

	if hasStatsNeg {
		t.Errorf("did not expect stats line with negative interval, got logs:\n%v", lines)
	}
}

func TestStaleEchoRejected(t *testing.T) {
	fake := &fakeTunnel{}
	cfg := testConfig()
	rc := NewRateController(fake, cfg, true, nil)

	// Send ping A
	rc.sendPing()
	rc.mu.Lock()
	pingANanos := rc.lastPingSentNanos
	rc.mu.Unlock()

	// Sleep 2ms, then send ping B
	time.Sleep(2 * time.Millisecond)
	rc.sendPing()
	rc.mu.Lock()
	pingBNanos := rc.lastPingSentNanos
	rc.mu.Unlock()

	if pingBNanos <= pingANanos {
		t.Fatalf("expected ping B nanos (%d) to be greater than ping A nanos (%d)", pingBNanos, pingANanos)
	}

	// Now send a stats frame echoing A after B was sent
	payloadA := make([]byte, 32)
	binary.BigEndian.PutUint64(payloadA[24:32], uint64(pingANanos))
	rc.handlePeerStats(payloadA)

	rc.mu.Lock()
	lastStats := rc.lastStats
	staleEchoes := rc.staleEchoes
	rc.mu.Unlock()

	if lastStats.RTT != 0 {
		t.Errorf("expected RTT to be 0 (unknown) for stale echo, got %v", lastStats.RTT)
	}
	if staleEchoes != 1 {
		t.Errorf("expected staleEchoes to be 1, got %d", staleEchoes)
	}

	// Now echo B
	payloadB := make([]byte, 32)
	binary.BigEndian.PutUint64(payloadB[24:32], uint64(pingBNanos))
	rc.handlePeerStats(payloadB)

	rc.mu.Lock()
	lastStatsB := rc.lastStats
	staleEchoesB := rc.staleEchoes
	rc.mu.Unlock()

	if lastStatsB.RTT <= 0 {
		t.Errorf("expected RTT to be > 0 for valid echo B, got %v", lastStatsB.RTT)
	}
	if staleEchoesB != 1 {
		t.Errorf("expected staleEchoes to remain 1, got %d", staleEchoesB)
	}
}

func TestAIMDDecreaseOnLossNotHighRTT(t *testing.T) {
	// Existing tests updated where the decrease rule changed:
	// No existing unit tests had to be modified for the decrease rule because none
	// of them relied on the old high-RTT-without-loss decrease trigger.
	fake := &fakeTunnel{}
	cfg := testConfig()
	rc := NewRateController(fake, cfg, true, nil)

	rc.mu.Lock()
	rc.tier = TierActive
	rc.aimd.maxFrameBytes = 10000
	rc.activeFPS = cfg.ActiveProfile.FPS
	rc.mu.Unlock()

	// Add some RTT samples so minRTT is non-zero
	now := time.Now()
	rc.aimd.rttSamples = []aimdRTTSample{
		{at: now, rtt: 10 * time.Millisecond},
	}

	// 1. Valid high RTT with zero loss does not decrease maxFrameBytes
	rc.applyAIMD(AIMDStats{LossPercent: 0.0, RTT: 30 * time.Millisecond})

	rc.mu.Lock()
	curBytes := rc.aimd.maxFrameBytes
	rc.mu.Unlock()

	if curBytes != 10000 {
		t.Errorf("expected maxFrameBytes to remain 10000 with zero loss, got %d", curBytes)
	}

	// 2. High RTT with loss >= 0.5 % does decrease
	rc.applyAIMD(AIMDStats{LossPercent: 0.5, RTT: 30 * time.Millisecond})

	rc.mu.Lock()
	curBytesDecrease := rc.aimd.maxFrameBytes
	rc.mu.Unlock()

	if curBytesDecrease >= 10000 {
		t.Errorf("expected maxFrameBytes to decrease below 10000 with high RTT and loss >= 0.5%%, got %d", curBytesDecrease)
	}
	expected := int(10000 * 0.6)
	if curBytesDecrease != expected {
		t.Errorf("expected decrease to %d, got %d", expected, curBytesDecrease)
	}
}

func TestLossPercentIsPerWindow(t *testing.T) {
	fake := &fakeTunnel{}
	cfg := testConfig()
	cfg.AIMDStart = 10000
	rc := NewRateController(fake, cfg, true, nil)
	rc.Start()
	defer rc.Stop()

	// Initial setting: make sure we are active and maxFrameBytes starts at 10000
	rc.mu.Lock()
	rc.tier = TierActive
	rc.aimd.maxFrameBytes = 10000
	rc.activeFPS = cfg.ActiveProfile.FPS
	rc.mu.Unlock()

	// 1. First peer stats frame: cumulative (1000,0)
	buf1 := make([]byte, 32)
	binary.BigEndian.PutUint64(buf1[0:8], 1000) // recv
	binary.BigEndian.PutUint64(buf1[8:16], 0)   // gaps
	binary.BigEndian.PutUint64(buf1[16:24], 0)  // lost
	binary.BigEndian.PutUint64(buf1[24:32], 0)  // echo
	rc.handlePeerStats(buf1)

	rc.mu.Lock()
	m1 := rc.aimd.maxFrameBytes
	stats1 := rc.lastStats
	rc.mu.Unlock()

	if m1 != 11200 {
		t.Errorf("expected maxFrameBytes=11200 after first frame, got %d", m1)
	}
	if stats1.LossPercent != 0 {
		t.Errorf("expected 0%% loss for first frame, got %f", stats1.LossPercent)
	}

	// 2. Second peer stats frame: cumulative (2000, 30) -> window is dRecv=1000, dLost=30
	// loss = 30 / 1030 * 100 = ~2.91% >= 2.0% (triggers decrease of maxFrameBytes to 60%)
	buf2 := make([]byte, 32)
	binary.BigEndian.PutUint64(buf2[0:8], 2000) // recv
	binary.BigEndian.PutUint64(buf2[8:16], 0)
	binary.BigEndian.PutUint64(buf2[16:24], 30) // lost
	binary.BigEndian.PutUint64(buf2[24:32], 0)
	rc.handlePeerStats(buf2)

	rc.mu.Lock()
	m2 := rc.aimd.maxFrameBytes
	stats2 := rc.lastStats
	rc.mu.Unlock()

	expectedDec := int(11200 * 0.6)
	if m2 != expectedDec {
		t.Errorf("expected maxFrameBytes to decrease to %d, got %d", expectedDec, m2)
	}
	if stats2.LossPercent < 2.9 || stats2.LossPercent > 3.0 {
		t.Errorf("expected ~2.9%% loss for second window, got %f", stats2.LossPercent)
	}

	// 3. Third peer stats frame: cumulative (3000, 30) -> window is dRecv=1000, dLost=0
	// loss = 0% < 1.0% -> no decrease. In fact, it might increase slightly, but definitely won't decrease.
	buf3 := make([]byte, 32)
	binary.BigEndian.PutUint64(buf3[0:8], 3000)
	binary.BigEndian.PutUint64(buf3[8:16], 0)
	binary.BigEndian.PutUint64(buf3[16:24], 30)
	binary.BigEndian.PutUint64(buf3[24:32], 0)
	rc.handlePeerStats(buf3)

	rc.mu.Lock()
	m3 := rc.aimd.maxFrameBytes
	stats3 := rc.lastStats
	rc.mu.Unlock()

	if m3 < expectedDec {
		t.Errorf("expected maxFrameBytes to not decrease further (was %d, now %d)", expectedDec, m3)
	}
	if stats3.LossPercent != 0 {
		t.Errorf("expected 0%% loss for third window, got %f", stats3.LossPercent)
	}
}

type dummyLossSource struct{}

func (d dummyLossSource) RecvLossStats() (uint64, uint64, uint64) { return 0, 0, 0 }

func TestSwapTunnelKeepsLossAndFeedbackSources(t *testing.T) {
	fake1 := &fakeTunnel{}
	cfg := testConfig()
	rb := NewRelayBridgeWithConfig(fake1, "socks", 0, t.Logf, true, cfg)

	lossSrc := dummyLossSource{}
	fbSrc := &RTCPFeedback{}

	rb.SetLossSource(lossSrc)
	rb.SetFeedbackSource(fbSrc)

	// Verify they are on the current rate controller
	ctl1 := rb.currentRateCtl()
	if ctl1 == nil {
		t.Fatalf("expected rate controller")
	}
	if ctl1.lossSource != lossSrc {
		t.Errorf("expected lossSource on ctl1")
	}
	if ctl1.feedback != fbSrc {
		t.Errorf("expected feedback on ctl1")
	}

	// Swap tunnel
	fake2 := &fakeTunnel{}
	rb.SwapTunnel(fake2)

	// Verify they are kept on the new rate controller
	ctl2 := rb.currentRateCtl()
	if ctl2 == nil {
		t.Fatalf("expected new rate controller")
	}
	if ctl2.lossSource != lossSrc {
		t.Errorf("expected lossSource to be preserved on ctl2")
	}
	if ctl2.feedback != fbSrc {
		t.Errorf("expected feedback to be preserved on ctl2")
	}
}
