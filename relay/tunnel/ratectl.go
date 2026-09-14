package tunnel

import (
	"context"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"
)

// Policy carries external, operator/device-level inputs that only the
// policy-master side of a RateController evaluates. The non-master side
// never originates a Policy decision of its own — it only ever receives
// what the master decides to push (see NewRateController's policyMaster
// parameter and pushProfile below).
type Policy struct {
	ScreenOn      bool
	Network       string // e.g. "wifi", "cellular", "" = unknown; informational, not yet used to change behavior beyond what AllowDeepIdle allows
	AllowDeepIdle bool
}

// RateControllerConfig is every timing/threshold knob a RateController
// needs. DefaultRateControllerConfig() returns the values this feature's
// design calls for (3s/10s tier timers, AIMD 1200/4800/64000 bytes); tests
// build their own RateControllerConfig with much smaller timers so they
// don't need to sleep for real seconds.
type RateControllerConfig struct {
	ActiveProfile   Profile // FPS/Batch the caller wants at full rate; MaxFrameBytes here is IGNORED — AIMD owns MaxFrameBytes whenever Tier==TierActive, always starting at AIMDStart (see applyProfile)
	DrainProfile    Profile
	IdleProfile     Profile
	DeepIdleProfile Profile

	ActiveToDrain time.Duration // TierActive -> TierDrain after this much time with no NoteSent/NoteRecv activity
	DrainToIdle   time.Duration // TierDrain -> TierIdle after this much MORE idle time (cumulative idle >= ActiveToDrain+DrainToIdle)
	CheckInterval time.Duration // how often the tier state machine re-evaluates; must be small relative to ActiveToDrain/DrainToIdle to transition promptly

	AIMDFloor   int // clamp floor, spec value 1200
	AIMDStart   int // value MaxFrameBytes resets to every time TierActive is (re)entered, spec value 4800
	AIMDCeiling int // clamp ceiling, spec value 64000 (configurable; this is just the default)

	// StatsPingInterval, AIMDHold and AIMDIncreaseInterval are the AIMD loop's
	// real-time knobs. Production wants ping/stats every second, a 2s hold
	// after a decrease, and a 1s gate between increases (DefaultRateControllerConfig
	// sets exactly that). Zero in any of these means "use that production
	// default" so a RateControllerConfig built by hand (as every existing
	// test does) keeps behaving exactly as before; a test that wants an
	// end-to-end run without burning real wall-clock seconds sets these to
	// small durations instead, the same way it already shrinks
	// ActiveToDrain/DrainToIdle/CheckInterval.
	StatsPingInterval    time.Duration
	AIMDHold             time.Duration
	AIMDIncreaseInterval time.Duration

	// StatsLogInterval is how often the periodic stats line is logged.
	// Zero means the default 5s interval is used. A negative duration
	// disables stats logging entirely.
	StatsLogInterval time.Duration
}

const (
	defaultStatsPingInterval    = time.Second
	defaultAIMDHold             = 2 * time.Second
	defaultAIMDIncreaseInterval = time.Second
)

func (c RateControllerConfig) statsPingInterval() time.Duration {
	if c.StatsPingInterval > 0 {
		return c.StatsPingInterval
	}
	return defaultStatsPingInterval
}

func (c RateControllerConfig) aimdHold() time.Duration {
	if c.AIMDHold > 0 {
		return c.AIMDHold
	}
	return defaultAIMDHold
}

func (c RateControllerConfig) aimdIncreaseInterval() time.Duration {
	if c.AIMDIncreaseInterval > 0 {
		return c.AIMDIncreaseInterval
	}
	return defaultAIMDIncreaseInterval
}

func DefaultRateControllerConfig() RateControllerConfig {
	return RateControllerConfig{
		ActiveProfile:   Profile{FPS: defaultVP8FPS, Batch: defaultVP8Batch, Tier: TierActive},
		DrainProfile:    Profile{FPS: 10, Batch: 1, IdleKeepalive: 500 * time.Millisecond, Tier: TierDrain},
		IdleProfile:     Profile{FPS: 2, Batch: 1, IdleKeepalive: 2 * time.Second, Tier: TierIdle},
		DeepIdleProfile: Profile{FPS: 1, Batch: 1, IdleKeepalive: 5 * time.Second, Tier: TierDeepIdle},
		ActiveToDrain:   3 * time.Second,
		DrainToIdle:     10 * time.Second,
		CheckInterval:   500 * time.Millisecond,
		AIMDFloor:       1200,
		AIMDStart:       4800,
		AIMDCeiling:     64000,
	}
}

// LossSource is an optional, caller-supplied source of receive-side loss
// counters. RateController never measures loss itself — it has no notion of
// sequence numbers at the DataTunnel level (relay-protocol frames aren't
// individually sequence-numbered; only a specific provider's underlying RTP
// transport might be, and that's provider code, not this file's concern).
// A caller that CAN measure loss somewhere (e.g. wiring pion's
// ReadTrackWithStats stats callback from step 1 of this feature into a tiny
// atomic-counter adapter) may call SetLossSource to feed it in; if never
// set, MsgStats always reports zero loss, and the AIMD controller behaves
// as if nothing is lost (a safe, honest default — this is NOT the same as
// verifying there IS no loss; it means loss is simply unmeasured for that
// deployment until a LossSource is wired). Wiring a real LossSource for the
// MAX/SFU joiner is intentionally left as follow-up work outside this step.
type LossSource interface {
	// RecvLossStats returns CUMULATIVE counters since this LossSource was
	// created: how many packets/units were observed, how many gap events,
	// and the summed size of those gaps. Same shape and semantics as
	// pion.RecvStats from step 1 of this feature (RecvPackets/Gaps/
	// LostPackets), deliberately duplicated here as a same-shaped-but-
	// independent type so this package never imports the pion package.
	RecvLossStats() (recvPackets, gaps, lostPackets uint64)
}

// AIMDStats is what the congestion controller reacts to each time it's
// invoked — one call = one "window" of observation. In production this is
// built from a peer's MsgStats reply plus RTT derived from an echoed
// MsgPing and this side's own FeedbackSource (see handlePeerStats below).
// Tests call applyAIMD directly with synthetic values — that's the seam
// this type exists to provide.
type AIMDStats struct {
	LossPercent  float64       // 0-100
	RTT          time.Duration // 0 = "unknown this window" (treated as non-blocking for increases, and never triggers the RTT-based decrease rule)
	KeyframeReqs int           // count of keyframe-request events observed since the PREVIOUS applyAIMD call
}

const aimdPacketBytes = 1200 // "one packet's worth" per the spec's increase step

type aimdRTTSample struct {
	at  time.Time
	rtt time.Duration
}

type aimdState struct {
	maxFrameBytes  int
	rttSamples     []aimdRTTSample // pruned to the trailing 60s on every applyAIMD call
	holdUntil      time.Time       // zero = not holding
	lastIncreaseAt time.Time
}

func (a *aimdState) pruneRTT(now time.Time) {
	cutoff := now.Add(-60 * time.Second)
	i := 0
	for ; i < len(a.rttSamples); i++ {
		if a.rttSamples[i].at.After(cutoff) {
			break
		}
	}
	a.rttSamples = a.rttSamples[i:]
}

func (a *aimdState) minRTT() time.Duration {
	var min time.Duration
	for _, s := range a.rttSamples {
		if min == 0 || s.rtt < min {
			min = s.rtt
		}
	}
	return min
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

type RateController struct {
	tun          DataTunnel
	rc           RateControllable // tun, if it implements this; nil otherwise
	hinter       BandwidthHinter  // tun, if it implements this; nil otherwise
	feedback     *RTCPFeedback    // set via SetFeedbackSource, nil until then
	lossSource   LossSource       // set via SetLossSource, nil until then
	cfg          RateControllerConfig
	policyMaster bool
	logFn        func(string, ...any)

	mu                    sync.Mutex
	tier                  Tier
	policy                Policy
	lastActivity          time.Time
	activeFPS             int
	aimd                  aimdState
	lastPeerPingNanos     int64
	lastKeyframeReqCount  uint64
	lastStats             AIMDStats     // most recent AIMDStats handlePeerStats computed, for introspection (LastStats)
	peerTier              Tier          // last tier received from the peer (TierActive if never)
	ctlDrops              atomic.Uint64 // counts control frames dropped due to full send queue
	lastPingSentNanos     int64         // nanos of the last ping sent by us
	lastAcceptedEchoNanos int64         // nanos of the last accepted ping echo
	staleEchoes           uint64        // count of rejected/stale echoes

	ackMu sync.Mutex
	acked chan struct{} // non-nil while a pushProfile()'d config is unacknowledged; see pushProfile/onPeerAck

	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewRateController builds a RateController for tun.
func NewRateController(tun DataTunnel, cfg RateControllerConfig, policyMaster bool, logFn func(string, ...any)) *RateController {
	rc := &RateController{
		tun:          tun,
		cfg:          cfg,
		policyMaster: policyMaster,
		logFn:        logFn,
		tier:         TierActive,
		peerTier:     TierActive,
		lastActivity: time.Now(),
		stopCh:       make(chan struct{}),
	}
	if v, ok := tun.(RateControllable); ok {
		rc.rc = v
	}
	if v, ok := tun.(BandwidthHinter); ok {
		rc.hinter = v
	}
	return rc
}

// SetFeedbackSource and SetLossSource are safe to call at any time,
// including concurrently with a running RateController (Start already
// launched its goroutines): both feedback and lossSource are read from
// applyAIMD/handlePeerStats/sendStats on those goroutines, so writes here
// go through rc.mu like every other field a background goroutine reads.
func (rc *RateController) SetFeedbackSource(f *RTCPFeedback) {
	rc.mu.Lock()
	rc.feedback = f
	rc.mu.Unlock()
}

func (rc *RateController) SetLossSource(src LossSource) {
	rc.mu.Lock()
	rc.lossSource = src
	rc.mu.Unlock()
}

// MaxFrameBytes reports the coalescing cap the controller is currently asking
// the tunnel for -- the number AIMD moves. Exposed for harnesses that need to
// record what the controller actually chose rather than what it was configured
// with; without it a benchmark can only report the default it started from,
// which is exactly the number that does not matter.
func (rc *RateController) MaxFrameBytes() int {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.aimd.maxFrameBytes
}

func (rc *RateController) State() Tier {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.tier
}

// LastStats reports the most recent AIMDStats handlePeerStats computed from a
// real peer MsgStats/MsgPing exchange (zero value if none has arrived yet).
// Exposed for harnesses/benchmarks that want to log the loss%/RTT the
// controller is actually reacting to, alongside MaxFrameBytes.
func (rc *RateController) LastStats() AIMDStats {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.lastStats
}

// SetPolicy applies a new Policy. Only meaningful on the policy-master side.
func (rc *RateController) SetPolicy(p Policy) {
	rc.mu.Lock()
	rc.policy = p
	rc.mu.Unlock()
}

func (rc *RateController) Start() {
	go rc.tierLoop()
	go rc.statsPingLoop()
	if rc.cfg.StatsLogInterval >= 0 {
		go rc.statsLogLoop()
	}
}

func (rc *RateController) Stop() {
	rc.stopOnce.Do(func() { close(rc.stopCh) })
}

// NoteSent must be called by the DataTunnel's owner BEFORE actually handing
// new application data to the tunnel's SendData.
func (rc *RateController) NoteSent() { rc.noteActivity() }

// NoteRecv is the same, for inbound application data.
func (rc *RateController) NoteRecv() { rc.noteActivity() }

func (rc *RateController) noteActivity() {
	rc.mu.Lock()
	rc.lastActivity = time.Now()
	wasActive := rc.tier == TierActive
	if !wasActive {
		rc.tier = TierActive
	}
	rc.mu.Unlock()
	if !wasActive {
		rc.applyProfile(TierActive)
	}
}

func (rc *RateController) tierLoop() {
	ticker := time.NewTicker(rc.cfg.CheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-rc.stopCh:
			return
		case <-ticker.C:
			rc.tick()
		}
	}
}

func (rc *RateController) tick() {
	if !rc.policyMaster {
		return
	}
	rc.mu.Lock()
	idleFor := time.Since(rc.lastActivity)
	tier := rc.tier
	allowDeep := rc.policy.AllowDeepIdle
	newTier := tier
	switch tier {
	case TierActive:
		if idleFor >= rc.cfg.ActiveToDrain {
			newTier = TierDrain
		}
	case TierDrain:
		if idleFor >= rc.cfg.ActiveToDrain+rc.cfg.DrainToIdle {
			newTier = TierIdle
		}
	case TierIdle:
		if allowDeep {
			newTier = TierDeepIdle
		}
	case TierDeepIdle:
		if !allowDeep {
			newTier = TierIdle
		}
	}
	if newTier != tier {
		rc.tier = newTier
	}
	rc.mu.Unlock()
	if newTier != tier {
		rc.applyProfile(newTier)
	}
}

// applyProfile is called on every tier EDGE.
func (rc *RateController) applyProfile(tier Tier) {
	rc.mu.Lock()
	var p Profile
	switch tier {
	case TierActive:
		p = rc.cfg.ActiveProfile
		p.MaxFrameBytes = rc.cfg.AIMDStart
		p.Tier = TierActive
		rc.aimd = aimdState{maxFrameBytes: rc.cfg.AIMDStart}
		if p.FPS > 0 {
			rc.activeFPS = p.FPS
		} else if rc.activeFPS == 0 {
			rc.activeFPS = 1
		}
	case TierDrain:
		p = rc.cfg.DrainProfile
	case TierIdle:
		p = rc.cfg.IdleProfile
	case TierDeepIdle:
		p = rc.cfg.DeepIdleProfile
	}
	isMaster := rc.policyMaster
	rc.mu.Unlock()

	if rc.logFn != nil {
		rc.logFn("ratectl: tier -> %s (fps=%d batch=%d maxFrameBytes=%d idleKeepalive=%s)",
			tier, p.FPS, p.Batch, p.MaxFrameBytes, p.IdleKeepalive)
	}
	if rc.rc != nil {
		rc.rc.SetProfile(p)
	}
	if isMaster {
		rc.pushProfile(p)
	}
	if rc.hinter != nil {
		go func(t Tier) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := rc.hinter.HintBandwidth(ctx, t); err != nil && rc.logFn != nil {
				rc.logFn("ratectl: HintBandwidth(%s) failed: %v", t, err)
			}
		}(tier)
	}
}

func (rc *RateController) applyMaxFrameBytesLocked() {
	if rc.rc == nil {
		return
	}
	p := Profile{
		FPS:           rc.activeFPS,
		Batch:         rc.cfg.ActiveProfile.Batch,
		MaxFrameBytes: rc.aimd.maxFrameBytes,
		IdleKeepalive: 0,
		Tier:          TierActive,
	}
	rc.mu.Unlock()
	rc.rc.SetProfile(p)
	rc.mu.Lock()
}

// applyAIMD is the whole congestion-control decision for one window.
func (rc *RateController) applyAIMD(stats AIMDStats) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.tier != TierActive {
		return
	}
	now := time.Now()
	rc.aimd.pruneRTT(now)
	if stats.RTT > 0 {
		rc.aimd.rttSamples = append(rc.aimd.rttSamples, aimdRTTSample{now, stats.RTT})
	}
	minRTT := rc.aimd.minRTT()

	ceiling := rc.cfg.AIMDCeiling
	if rc.feedback != nil {
		if bps, ok := rc.feedback.BandwidthEstimate(); ok && rc.activeFPS > 0 {
			estFrameBytes := int(float64(bps) / 8.0 / float64(rc.activeFPS))
			if estFrameBytes > 0 && estFrameBytes < ceiling {
				ceiling = estFrameBytes
			}
		}
	}

	if !rc.aimd.holdUntil.IsZero() && now.Before(rc.aimd.holdUntil) {
		return
	}

	rttTooHigh := minRTT > 0 && stats.RTT > 0 && stats.RTT > minRTT*2
	// Rationale: with paced sending the tunnel RTT is dominated by our own pacing;
	// loss is the real congestion signal (LossSource from the RTP reader;
	// when no LossSource is wired loss stays 0 and AIMD only ever increases
	// up to the ceiling — this is the intended behaviour until every joiner
	// wires ReadTrackWithStats). Thus, a valid high RTT alone no longer decreases
	// but blocks increases (by keeping rttOK for the increase gate).
	decrease := stats.LossPercent >= 2.0 || (rttTooHigh && stats.LossPercent >= 0.5) || stats.KeyframeReqs > 2
	if decrease {
		next := int(float64(rc.aimd.maxFrameBytes) * 0.6)
		rc.aimd.maxFrameBytes = clampInt(next, rc.cfg.AIMDFloor, ceiling)
		rc.aimd.holdUntil = now.Add(rc.cfg.aimdHold())
		rc.applyMaxFrameBytesLocked()
		return
	}

	rttOK := minRTT == 0 || stats.RTT == 0 || stats.RTT < (minRTT*3)/2
	increase := stats.LossPercent < 1.0 && rttOK
	if increase && now.Sub(rc.aimd.lastIncreaseAt) >= rc.cfg.aimdIncreaseInterval() {
		next := clampInt(rc.aimd.maxFrameBytes+aimdPacketBytes, rc.cfg.AIMDFloor, ceiling)
		rc.aimd.maxFrameBytes = next
		rc.aimd.lastIncreaseAt = now
		rc.applyMaxFrameBytesLocked()
	}
}

const configPushResendPeriod = 3 * time.Second

func (rc *RateController) pushProfile(p Profile) {
	rc.ackMu.Lock()
	if rc.acked != nil {
		select {
		case <-rc.acked:
		default:
			close(rc.acked)
		}
	}
	acked := make(chan struct{})
	rc.acked = acked
	rc.ackMu.Unlock()

	idleMs := int(p.IdleKeepalive / time.Millisecond)
	// EncodeVP8Config returns a COMPLETE frame, not a payload -- do not wrap
	// it again. Wrapping made the config message's payload an entire encoded
	// frame, so the peer's DecodeVP8Config read the inner frame's HEADER as
	// the config fields and every push, for every profile, decoded to the
	// same constant: fps=0 batch=16 trackCount=0 maxFrameBytes=0
	// idleKeepaliveMs=2048. Rate control has therefore never worked over the
	// wire. See TestPushProfileFrameRoundTrip.
	frame := EncodeVP8Config(p.FPS, p.Batch, 1, p.MaxFrameBytes, idleMs, ConfigFlagsForTier(p.Tier))
	send := func() { rc.sendControl(frame) }
	send()
	go func() {
		ticker := time.NewTicker(configPushResendPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-acked:
				return
			case <-rc.stopCh:
				return
			case <-ticker.C:
				send()
			}
		}
	}()
}

func (rc *RateController) onPeerAck() {
	rc.ackMu.Lock()
	defer rc.ackMu.Unlock()
	if rc.acked == nil {
		return
	}
	select {
	case <-rc.acked:
	default:
		close(rc.acked)
	}
}

// onPeerConfig processes a configuration profile pushed by the peer.
//
// Each side owns its own send rates (the exit's rate is server configuration,
// the phone's is the phone's). Therefore, we ignore the peer's actual FPS,
// batch size, and other rate limits, and only use the pushed Tier as a policy
// signal to switch our own rate profile tier.
func (rc *RateController) onPeerConfig(p Profile) {
	rc.mu.Lock()
	rc.tier = p.Tier
	rc.peerTier = p.Tier
	rc.mu.Unlock()

	rc.applyProfile(p.Tier)

	if rc.logFn != nil {
		rc.logFn("ratectl: peer tier -> %s (peer fps=%d batch=%d maxFrameBytes=%d idleKeepalive=%s ignored; using own profile)",
			p.Tier, p.FPS, p.Batch, p.MaxFrameBytes, p.IdleKeepalive)
	}

	rc.sendControl(EncodeFrame(ControlConnID, MsgConfigAck, nil))
}

// sendControl sends a control frame on the tunnel.
//
// If the tunnel supports SendControl, we prefer to use it to route control
// frames through a dedicated control lane. If the tunnel only supports TrySendData,
// we fall back to it to prevent blocking the read path if the queue is full.
// Periodic frames (pings, stats) or resending configurations and dropped acks
// can be dropped without stalling the entire data path.
func (rc *RateController) sendControl(frame []byte) {
	if sender, ok := rc.tun.(interface{ SendControl([]byte) bool }); ok {
		if !sender.SendControl(frame) {
			rc.ctlDrops.Add(1)
		}
	} else if tryer, ok := rc.tun.(interface{ TrySendData([]byte) bool }); ok {
		if !tryer.TrySendData(frame) {
			rc.ctlDrops.Add(1)
		}
	} else {
		rc.tun.SendData(frame)
	}
}

func (rc *RateController) statsPingLoop() {
	ticker := time.NewTicker(rc.cfg.statsPingInterval())
	defer ticker.Stop()
	for {
		select {
		case <-rc.stopCh:
			return
		case <-ticker.C:
			if rc.State() != TierActive {
				continue
			}
			rc.sendPing()
			rc.sendStats()
		}
	}
}

func (rc *RateController) sendPing() {
	nowNanos := time.Now().UnixNano()
	rc.mu.Lock()
	rc.lastPingSentNanos = nowNanos
	rc.mu.Unlock()

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(nowNanos))
	rc.sendControl(EncodeFrame(ControlConnID, MsgPing, buf[:]))
}

func (rc *RateController) handlePeerPing(payload []byte) {
	if len(payload) < 8 {
		return
	}
	rc.mu.Lock()
	rc.lastPeerPingNanos = int64(binary.BigEndian.Uint64(payload[:8]))
	rc.mu.Unlock()
}

func (rc *RateController) sendStats() {
	rc.mu.Lock()
	lossSource := rc.lossSource
	echo := rc.lastPeerPingNanos
	rc.mu.Unlock()

	var recvPackets, gaps, lostPackets uint64
	if lossSource != nil {
		recvPackets, gaps, lostPackets = lossSource.RecvLossStats()
	}
	buf := make([]byte, 32)
	binary.BigEndian.PutUint64(buf[0:8], recvPackets)
	binary.BigEndian.PutUint64(buf[8:16], gaps)
	binary.BigEndian.PutUint64(buf[16:24], lostPackets)
	binary.BigEndian.PutUint64(buf[24:32], uint64(echo))
	rc.sendControl(EncodeFrame(ControlConnID, MsgStats, buf))
}

func (rc *RateController) handlePeerStats(payload []byte) {
	if len(payload) < 32 {
		return
	}
	recvPackets := binary.BigEndian.Uint64(payload[0:8])
	gaps := binary.BigEndian.Uint64(payload[8:16])
	lostPackets := binary.BigEndian.Uint64(payload[16:24])
	echoNanos := int64(binary.BigEndian.Uint64(payload[24:32]))

	var lossPct float64
	total := recvPackets + lostPackets
	if total > 0 {
		lossPct = float64(lostPackets) / float64(total) * 100
	}

	var rtt time.Duration
	rc.mu.Lock()
	lastSent := rc.lastPingSentNanos
	lastAccepted := rc.lastAcceptedEchoNanos
	pingInterval := rc.cfg.statsPingInterval()
	rc.mu.Unlock()

	if echoNanos > 0 {
		computedRtt := time.Duration(time.Now().UnixNano() - echoNanos)
		if computedRtt < 0 {
			computedRtt = 0
		}

		if (echoNanos == lastSent || (lastAccepted > 0 && echoNanos > lastAccepted)) && computedRtt <= 3*pingInterval {
			rtt = computedRtt
			rc.mu.Lock()
			rc.lastAcceptedEchoNanos = echoNanos
			rc.mu.Unlock()
		} else {
			rtt = 0
			rc.mu.Lock()
			rc.staleEchoes++
			rc.mu.Unlock()
		}
	}

	rc.mu.Lock()
	feedback := rc.feedback
	rc.mu.Unlock()
	var kfReqs int
	if feedback != nil {
		cur := feedback.KeyframeRequests()
		rc.mu.Lock()
		prev := rc.lastKeyframeReqCount
		rc.lastKeyframeReqCount = cur
		rc.mu.Unlock()
		if cur > prev {
			kfReqs = int(cur - prev)
		}
	}
	stats := AIMDStats{LossPercent: lossPct, RTT: rtt, KeyframeReqs: kfReqs}
	rc.mu.Lock()
	rc.lastStats = stats
	rc.mu.Unlock()
	rc.applyAIMD(stats)
	_ = gaps
}

func (rc *RateController) policyForTransfer() Policy {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.policy
}

func (rc *RateController) statsLogLoop() {
	interval := rc.cfg.StatsLogInterval
	if interval == 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastCounters Counters
	for {
		select {
		case <-rc.stopCh:
			return
		case <-ticker.C:
			rc.logStatsLine(&lastCounters)
		}
	}
}

func (rc *RateController) logStatsLine(lastCounters *Counters) {
	if rc.logFn == nil {
		return
	}

	rc.mu.Lock()
	tier := rc.tier
	peerTier := rc.peerTier
	maxFB := rc.aimd.maxFrameBytes
	lastStats := rc.lastStats
	staleEchoes := rc.staleEchoes

	var bwe uint64
	if rc.feedback != nil {
		if est, ok := rc.feedback.BandwidthEstimate(); ok {
			bwe = est
		}
	}
	rc.mu.Unlock()

	fps := 0
	batch := 0
	if f, ok := rc.tun.(interface{ FPS() int }); ok {
		fps = f.FPS()
	}
	if b, ok := rc.tun.(interface{ Batch() int }); ok {
		batch = b.Batch()
	}

	queue := 0
	if q, ok := rc.tun.(interface{ QueueLen() int }); ok {
		queue = q.QueueLen()
	}

	ctlQueue := 0
	if cq, ok := rc.tun.(interface{ CtlQueueLen() int }); ok {
		ctlQueue = cq.CtlQueueLen()
	}

	ctlDrops := rc.ctlDrops.Load()

	var sentF, sentB, keepalives, recvF, recvB uint64
	if rc.rc != nil {
		current := rc.rc.Counters()
		sentF = current.SentFrames - lastCounters.SentFrames
		sentB = current.SentBytes - lastCounters.SentBytes
		keepalives = current.Keepalives - lastCounters.Keepalives
		recvF = current.RecvFrames - lastCounters.RecvFrames
		recvB = current.RecvBytes - lastCounters.RecvBytes
		*lastCounters = current
	}

	rc.logFn("ratectl: stats tier=%s peerTier=%s fps=%d batch=%d maxFB=%d bwe=%d rtt=%s loss=%.1f%% kfReqs=%d sent=+%d/+%dB keepalives=+%d recv=+%d/+%dB queue=%d ctlDrops=%d ctlQ=%d staleEchoes=%d",
		tier, peerTier, fps, batch, maxFB, bwe, lastStats.RTT, lastStats.LossPercent, lastStats.KeyframeReqs,
		sentF, sentB, keepalives, recvF, recvB, queue, ctlDrops, ctlQueue, staleEchoes)
}
