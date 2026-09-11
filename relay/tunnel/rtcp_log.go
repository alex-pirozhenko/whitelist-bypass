package tunnel

import (
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/webrtc/v4"
)

// DrainSenderRTCPLogging is DrainSenderRTCP plus a periodic summary of the
// feedback the far end sends our media sender (PLI/FIR keyframe requests,
// NACKs, REMB, transport-cc, receiver reports). An SFU that keeps asking for
// keyframes is telling us it does not accept the frames we produce.
func DrainSenderRTCPLogging(sender *webrtc.RTPSender, logFn func(string, ...any), tag string) {
	DrainSenderRTCPWithHandler(sender, logFn, tag, nil)
}

func DrainSenderRTCPWithHandler(sender *webrtc.RTPSender, logFn func(string, ...any), tag string, onKeyframeReq func()) {
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
			case *rtcp.FullIntraRequest:
				counts["FIR"]++
				if onKeyframeReq != nil {
					onKeyframeReq()
				}
			case *rtcp.TransportLayerNack:
				counts["NACK"]++
			case *rtcp.ReceiverEstimatedMaximumBitrate:
				counts["REMB"]++
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
