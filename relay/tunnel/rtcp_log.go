package tunnel

import (
	"sync/atomic"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/webrtc/v4"
)

// FeedbackSource is the read side of RTCP sender-feedback the AIMD
// congestion controller consumes: how many keyframe-request packets
// (PLI/FIR) have arrived cumulatively, and the most recent bandwidth
// estimate (REMB) if any has been seen. A REMB value is an upper bound
// only, never a target — the controller still probes for headroom below
// it rather than jumping straight to it (see ratectl.go's AIMD comments).
type FeedbackSource interface {
	KeyframeRequests() uint64
	// BandwidthEstimate returns the most recent REMB bitrate in bits/sec and
	// true, or (0, false) if none has been seen yet.
	BandwidthEstimate() (bps uint64, ok bool)
}

// RTCPFeedback is a concrete, thread-safe FeedbackSource that
// DrainSenderRTCPWithHandler populates directly — see the new `feedback`
// parameter added to that function below. Safe for concurrent use; a nil
// *RTCPFeedback behaves like an always-empty FeedbackSource would (both its
// methods have nil-receiver-safe zero-value behavior) so callers that don't
// care can pass nil without a guard.
type RTCPFeedback struct {
	keyframeReqs atomic.Uint64
	bwEstimate   atomic.Uint64 // bits/sec, 0 = "none seen" (0 bps is not a meaningful real estimate)
}

func (f *RTCPFeedback) KeyframeRequests() uint64 {
	if f == nil {
		return 0
	}
	return f.keyframeReqs.Load()
}

func (f *RTCPFeedback) BandwidthEstimate() (uint64, bool) {
	if f == nil {
		return 0, false
	}
	v := f.bwEstimate.Load()
	return v, v > 0
}

// DrainSenderRTCPLogging is DrainSenderRTCP plus a periodic summary of the
// feedback the far end sends our media sender (PLI/FIR keyframe requests,
// NACKs, REMB, transport-cc, receiver reports). An SFU that keeps asking for
// keyframes is telling us it does not accept the frames we produce.
func DrainSenderRTCPLogging(sender *webrtc.RTPSender, logFn func(string, ...any), tag string) {
	DrainSenderRTCPWithHandler(sender, logFn, tag, nil, nil)
}

func DrainSenderRTCPWithHandler(sender *webrtc.RTPSender, logFn func(string, ...any), tag string, onKeyframeReq func(), feedback *RTCPFeedback) {
	if sender == nil {
		return
	}
	counts := map[string]int{}
	last := time.Now()
	for {
		pkts, _, err := sender.ReadRTCP()
		if err != nil {
			logFn("%s: rtcp reader done (%v); totals=%v", tag, err, counts)
			return
		}
		for _, p := range pkts {
			switch p.(type) {
			case *rtcp.PictureLossIndication:
				counts["PLI"]++
				if onKeyframeReq != nil {
					onKeyframeReq()
				}
				if feedback != nil {
					feedback.keyframeReqs.Add(1)
				}
			case *rtcp.FullIntraRequest:
				counts["FIR"]++
				if onKeyframeReq != nil {
					onKeyframeReq()
				}
				if feedback != nil {
					feedback.keyframeReqs.Add(1)
				}
			case *rtcp.TransportLayerNack:
				counts["NACK"]++
			case *rtcp.ReceiverEstimatedMaximumBitrate:
				remb := p.(*rtcp.ReceiverEstimatedMaximumBitrate)
				counts["REMB"]++
				if feedback != nil {
					feedback.bwEstimate.Store(uint64(remb.Bitrate))
				}
			case *rtcp.TransportLayerCC:
				counts["TWCC"]++
			case *rtcp.ReceiverReport:
				counts["RR"]++
			case *rtcp.SenderReport:
				counts["SR"]++
			default:
				counts["other"]++
			}
		}
		if time.Since(last) >= 5*time.Second {
			logFn("%s: rtcp feedback last 5s: %v", tag, counts)
			for k := range counts {
				delete(counts, k)
			}
			last = time.Now()
		}
	}
}
