package android

import (
	"log"
	"strings"

	"github.com/alex-pirozhenko/whitelist-bypass/relay/common"
	"github.com/alex-pirozhenko/whitelist-bypass/relay/pion"
	joiner "github.com/alex-pirozhenko/whitelist-bypass/relay/pion/headless-joiner-common"
	"github.com/alex-pirozhenko/whitelist-bypass/relay/tunnel"
)

type MaxHeadlessJoiner struct {
	inner       *joiner.MaxHeadlessJoiner
	OnConnected func(tunnel.DataTunnel)
}

func NewMaxHeadlessJoiner(logFn func(string, ...any)) *MaxHeadlessJoiner {
	if logFn == nil {
		logFn = log.Printf
	}
	inner := joiner.NewMaxHeadlessJoiner(logFn, RequestResolve, StatusEmitter{}, PCConfigurer{}, pion.AddTunnelTracks, pion.ReadTrack)
	wrapper := &MaxHeadlessJoiner{inner: inner}
	inner.OnConnected = func(tun tunnel.DataTunnel) {
		if wrapper.OnConnected != nil {
			wrapper.OnConnected(tun)
		}
	}
	return wrapper
}

func (h *MaxHeadlessJoiner) MarkConfigAcked() { h.inner.MarkConfigAcked() }

func (h *MaxHeadlessJoiner) Run() {
	h.inner.Status.EmitStatus(common.StatusReady)
	for {
		line, err := ReadStdinLine()
		if err != nil {
			log.Printf("max-joiner: stdin closed: %v", err)
			return
		}
		if strings.HasPrefix(line, "JOIN:") {
			h.inner.RunWithParams(strings.TrimPrefix(line, "JOIN:"))
			return
		}
	}
}
