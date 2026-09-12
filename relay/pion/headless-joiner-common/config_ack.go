package joiner

import (
	"sync"
	"time"

	"github.com/alex-pirozhenko/whitelist-bypass/relay/tunnel"
)

const configResendPeriod = 3 * time.Second

type configAckTracker struct {
	mu         sync.Mutex
	generation uint64 // bumped by every arm(); 0 = never armed
	ackedGen   uint64 // the generation mark() last recorded (0 = none yet)
	acked      chan struct{}
	cancel     chan struct{}
}

// acknowledged reports whether the MOST RECENTLY ARMED generation has been
// acknowledged. This used to be a permanent latch (once true, always true),
// which was wrong: it made a caller wanting to push a SECOND, later config
// change believe an ack for the FIRST one still satisfied it, so the
// resend-until-acked loop for the second push never even started. Comparing
// generations instead means each arm() cycle needs its own mark() to be
// considered acknowledged.
func (t *configAckTracker) acknowledged() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.generation > 0 && t.ackedGen == t.generation
}

func (t *configAckTracker) arm() (acked, cancel chan struct{}) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cancel != nil {
		close(t.cancel)
	}
	t.generation++
	t.acked = make(chan struct{})
	t.cancel = make(chan struct{})
	return t.acked, t.cancel
}

// mark records the CURRENTLY ARMED generation as acknowledged. (There is
// deliberately no way to mark an arbitrary generation from outside this
// file today — the only signal callers have is "an ack arrived", and it is
// always treated as acknowledging whatever is currently armed. A future
// step that needs to distinguish which of several in-flight generations an
// ack belongs to — e.g. a rate controller doing its OWN independent
// generation-numbered push/ack round trip over the wire — should build that
// as its own separate mechanism rather than extending this one; this
// tracker exists specifically for the single one-shot-per-session initial
// fps/batch handshake these joiners do right after connecting.)
func (t *configAckTracker) mark() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ackedGen = t.generation
	if t.acked == nil {
		return
	}
	select {
	case <-t.acked:
	default:
		close(t.acked)
	}
}

func sendVP8ConfigUntilAcked(acked, cancel <-chan struct{}, stopCh <-chan struct{}, tun tunnel.DataTunnel, fps, batch, trackCount int, logFn func(string, ...any), logPrefix string) {
	tun.SendData(tunnel.EncodeVP8Config(fps, batch, trackCount, 0, 0, 0))
	ticker := time.NewTicker(configResendPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-acked:
			return
		case <-cancel:
			return
		case <-stopCh:
			return
		case <-ticker.C:
			logFn("%s: resending vp8 config fps=%d batch=%d trackCount=%d, no ack yet",
				logPrefix, fps, batch, trackCount)
			tun.SendData(tunnel.EncodeVP8Config(fps, batch, trackCount, 0, 0, 0))
		}
	}
}
