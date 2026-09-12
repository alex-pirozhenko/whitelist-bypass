package tunnel

import (
	"context"
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
func (f *fakeTunnel) SetOnData(fn func([]byte)) { f.onData = fn }
func (f *fakeTunnel) SetOnClose(fn func())      { f.onClose = fn }
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
