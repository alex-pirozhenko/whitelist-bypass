package joiner

import (
	"context"
	"time"

	tmapi "github.com/alex-pirozhenko/whitelist-bypass/relay/telemost"
	"github.com/alex-pirozhenko/whitelist-bypass/relay/tunnel"
	"github.com/pion/rtcp"
)

type telemostTunnelWrapper struct {
	tunnel.DataTunnel
	j *TelemostHeadlessJoiner
}

func newTelemostTunnelWrapper(dt tunnel.DataTunnel, j *TelemostHeadlessJoiner) *telemostTunnelWrapper {
	return &telemostTunnelWrapper{
		DataTunnel: dt,
		j:          j,
	}
}

type rateControllable interface {
	SetProfile(tunnel.Profile)
	Counters() tunnel.Counters
}

type trySendDataer interface {
	TrySendData([]byte) bool
}

type fpser interface {
	FPS() int
}

type batcher interface {
	Batch() int
}

type queueLener interface {
	QueueLen() int
}

func (w *telemostTunnelWrapper) SetProfile(p tunnel.Profile) {
	if rc, ok := w.DataTunnel.(rateControllable); ok {
		rc.SetProfile(p)
	}
}

func (w *telemostTunnelWrapper) Counters() tunnel.Counters {
	if rc, ok := w.DataTunnel.(rateControllable); ok {
		return rc.Counters()
	}
	return tunnel.Counters{}
}

func (w *telemostTunnelWrapper) TrySendData(data []byte) bool {
	if tsd, ok := w.DataTunnel.(trySendDataer); ok {
		return tsd.TrySendData(data)
	}
	return false
}

func (w *telemostTunnelWrapper) FPS() int {
	if f, ok := w.DataTunnel.(fpser); ok {
		return f.FPS()
	}
	return 0
}

func (w *telemostTunnelWrapper) Batch() int {
	if b, ok := w.DataTunnel.(batcher); ok {
		return b.Batch()
	}
	return 0
}

func (w *telemostTunnelWrapper) QueueLen() int {
	if q, ok := w.DataTunnel.(queueLener); ok {
		return q.QueueLen()
	}
	return 0
}

func (w *telemostTunnelWrapper) HintBandwidth(ctx context.Context, tier tunnel.Tier) error {
	return w.j.HintBandwidth(ctx, tier)
}

func (j *TelemostHeadlessJoiner) HintBandwidth(ctx context.Context, tier tunnel.Tier) error {
	// REMB logic
	if j.idleRembBps > 0 || j.activeRembBps > 0 {
		var bps int
		if tier != tunnel.TierActive {
			bps = j.idleRembBps
			if bps == 0 {
				bps = j.activeRembBps
			}
		} else {
			bps = j.activeRembBps
		}

		j.rembLoopMu.Lock()
		oldBps := j.rembBps
		j.rembBps = bps
		if bps != oldBps {
			if bps > 0 {
				j.logFn("telemost-joiner: hint tier=%s remb=%d bps", tier, bps)
			} else {
				j.logFn("telemost-joiner: hint tier=%s remb=none", tier)
			}
		}
		if j.rembCancel == nil {
			rembCtx, cancel := context.WithCancel(context.Background())
			j.rembCancel = cancel
			go j.runRembLoop(rembCtx)
		}
		j.rembLoopMu.Unlock()

		if bps > 0 {
			j.sendRemb()
		}
	}

	// Slots logic
	if j.idleSlotWidth > 0 && j.idleSlotHeight > 0 {
		if tier != tunnel.TierActive {
			j.wsSend(tmapi.SetSlotsMessageWithSize(j.nextSlotsKey(), j.idleSlotWidth, j.idleSlotHeight))
			j.logFn("telemost-joiner: hint tier=%s slots=%dx%d", tier, j.idleSlotWidth, j.idleSlotHeight)
		} else {
			j.wsSend(tmapi.SetSlotsMessage(j.nextSlotsKey()))
			j.logFn("telemost-joiner: hint tier=%s slots=normal", tier)
		}
	}

	// Unsubscribe video logic
	if j.idleUnsubscribeVideo {
		if tier != tunnel.TierActive {
			if !j.getUnsubscribedVideo() {
				j.setUnsubscribedVideo(true)
				j.wsSend(tmapi.SetSlotsShutdownMessage(j.nextSlotsKey()))
				j.logFn("telemost-joiner: hint tier=%s video=unsubscribed", tier)
			}
		} else {
			if j.getUnsubscribedVideo() {
				j.setUnsubscribedVideo(false)
				j.wsSend(tmapi.SetSlotsMessage(j.nextSlotsKey()))
				j.logFn("telemost-joiner: hint tier=%s video=subscribed", tier)
			}
		}
	}

	return nil
}

func (j *TelemostHeadlessJoiner) runRembLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-j.stopCh:
			return
		case <-ticker.C:
			j.sendRemb()
		}
	}
}

func (j *TelemostHeadlessJoiner) sendRemb() {
	j.videoSSRCMu.Lock()
	videoSSRC := j.videoSSRC
	j.videoSSRCMu.Unlock()

	if videoSSRC == 0 {
		return
	}

	j.rembLoopMu.Lock()
	bps := j.rembBps
	j.rembLoopMu.Unlock()

	if bps == 0 {
		return
	}

	pkt := &rtcp.ReceiverEstimatedMaximumBitrate{
		SenderSSRC: 0,
		Bitrate:    float32(bps),
		SSRCs:      []uint32{videoSSRC},
	}

	j.wsMu.Lock()
	subPC := j.subPC
	j.wsMu.Unlock()

	if subPC == nil {
		return
	}

	_ = subPC.WriteRTCP([]rtcp.Packet{pkt})
}

func (j *TelemostHeadlessJoiner) getRembBps() int {
	j.rembLoopMu.Lock()
	defer j.rembLoopMu.Unlock()
	return j.rembBps
}

func (j *TelemostHeadlessJoiner) getUnsubscribedVideo() bool {
	j.slotsMu.Lock()
	defer j.slotsMu.Unlock()
	return j.videoUnsubscribed
}

func (j *TelemostHeadlessJoiner) setUnsubscribedVideo(v bool) {
	j.slotsMu.Lock()
	defer j.slotsMu.Unlock()
	j.videoUnsubscribed = v
}
