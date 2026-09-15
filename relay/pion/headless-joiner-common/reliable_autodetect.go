package joiner

import (
	"sync"

	"github.com/alex-pirozhenko/whitelist-bypass/relay/tunnel"
)

// selectActiveTunnel examines the first inbound payload on vp8 and decides whether
// the peer speaks KCP or raw relay frames.
func selectActiveTunnel(vp8 *tunnel.VP8DataTunnel, firstPayload []byte, logFn func(string, ...any), tag ...string) (tunnel.DataTunnel, *tunnel.MultiTrackKCPTunnel) {
	prefix := "telemost-joiner"
	if len(tag) > 0 && tag[0] != "" {
		prefix = tag[0]
	}
	if !tunnel.LooksLikeRelayFrame(firstPayload) {
		mt := tunnel.NewMultiTrackTunnel([]*tunnel.VP8DataTunnel{vp8})
		kcp := tunnel.NewMultiTrackKCPTunnel(mt, logFn)
		if logFn != nil {
			logFn("%s: peer speaks kcp; per-track kcp reliability active (auto)", prefix)
		}
		return kcp, kcp
	}
	if logFn != nil {
		logFn("%s: peer speaks raw relay frames; no kcp (auto)", prefix)
	}
	return vp8, nil
}

// armKCPAutoDetect peeks the peer's first payload on vp8tun and decides raw vs KCP for this session,
// re-deciding after every peer restart. activate is called with the chosen active tunnel each time; it must
// return the tunnel the peeked payload should be delivered to (the caller may wrap it). tag prefixes log lines.
func armKCPAutoDetect(vp8tun *tunnel.VP8DataTunnel, logFn func(string, ...any), tag string,
	activate func(active tunnel.DataTunnel, kcp *tunnel.MultiTrackKCPTunnel) tunnel.DataTunnel) {
	var mu sync.Mutex
	armed := true
	var first func([]byte)
	var rearm func()
	first = func(payload []byte) {
		mu.Lock()
		if !armed {
			mu.Unlock()
			return
		}
		armed = false
		mu.Unlock()

		activeTunnel, kcpTun := selectActiveTunnel(vp8tun, payload, logFn, tag)
		// NewMultiTrackTunnel re-wires the carrier's restart hook to itself; put
		// ours back so the next restart still re-arms detection.
		vp8tun.SetOnPeerRestart(rearm)

		delivered := activate(activeTunnel, kcpTun)

		if kcpTun != nil {
			kcpTun.InjectSegment(payload)
		} else if od, ok := delivered.(interface{ OnData([]byte) }); ok {
			od.OnData(payload)
		} else if onData := vp8tun.OnData; onData != nil {
			onData(payload)
		}
	}
	rearm = func() {
		mu.Lock()
		armed = true
		mu.Unlock()
		if logFn != nil {
			logFn("%s: peer restarted; re-detecting kcp/raw on its next frame (auto)", tag)
		}
		vp8tun.SetOnData(first)
	}
	vp8tun.SetOnData(first)
	vp8tun.SetOnPeerRestart(rearm)
}
