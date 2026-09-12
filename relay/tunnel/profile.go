package tunnel

import (
	"context"
	"time"
)

// Tier is a coarse activity level a DataTunnel's sender can be tuned to.
// TierActive is full-rate; TierDrain/TierIdle/TierDeepIdle progressively
// throttle frame rate and coalescing while keeping the tunnel alive with
// keepalives spaced further apart. See tunnel/ratectl.go (a later step in
// this feature) for the state machine that drives transitions between them.
type Tier int

const (
	TierActive Tier = iota
	TierDrain
	TierIdle
	TierDeepIdle
)

func (t Tier) String() string {
	switch t {
	case TierActive:
		return "active"
	case TierDrain:
		return "drain"
	case TierIdle:
		return "idle"
	case TierDeepIdle:
		return "deep-idle"
	default:
		return "unknown"
	}
}

// Profile is the sender-side tuning a rate controller (or a caller doing it
// by hand) hands to a DataTunnel implementation. Every field is a target,
// not a promise: an implementation applies what it understands and ignores
// the rest (e.g. DCTunnel has no frame-rate concept and only honors
// IdleKeepalive — see DCTunnel.SetProfile).
type Profile struct {
	// FPS/Batch are the VP8Packetizer/writer-loop knobs today's
	// Reconfigure(fps, batch) already exposes. Zero means "leave unchanged"
	// (matches Reconfigure's existing "zero = no-op for that field" rule).
	FPS   int
	Batch int
	// MaxFrameBytes caps a coalesced frame (see VP8DataTunnel.writerLoop).
	// Zero disables coalescing: one queued item is sent per tick, exactly
	// today's behavior.
	MaxFrameBytes int
	// IdleKeepalive is how long the writer waits with an empty queue before
	// emitting a keepalive. Zero means "use the tunnel's own default
	// jittered idle period" (VP8DataTunnel's keepaliveIdleMin/Max range).
	IdleKeepalive time.Duration
	// Tier is informational: which activity level this profile corresponds
	// to, for logging/introspection. It does not itself change behavior —
	// FPS/Batch/MaxFrameBytes/IdleKeepalive do that.
	Tier Tier
}

// RateControllable is the optional interface a DataTunnel implementation
// exposes if it can be tuned by a Profile and report its traffic counters.
// Not every DataTunnel needs this (e.g. plain socket-relay wrappers don't);
// callers that want rate control type-assert for it.
type RateControllable interface {
	SetProfile(Profile)
	Counters() Counters
}

// BandwidthHinter is the optional interface a DataTunnel (or something a
// caller has similarly-shaped access to) implements if it has a way to ask
// the FAR END for a different bandwidth allocation. Only one known provider
// implements this today (see MaxHeadlessJoiner.HintBandwidth in
// pion/headless-joiner-common) — everything else is a no-op via a plain
// interface type-assertion miss, not an error.
type BandwidthHinter interface {
	HintBandwidth(ctx context.Context, tier Tier) error
}
