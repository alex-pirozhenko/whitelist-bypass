package joiner

import (
	"testing"

	"github.com/alex-pirozhenko/whitelist-bypass/relay/tunnel"
)

type profileSpy struct {
	tunnel.DataTunnel
	got              tunnel.Profile
	calls            int
	c                tunnel.Counters
	sendControlCalls int
	ctlQueueLenCalls int
}

func (s *profileSpy) SetProfile(p tunnel.Profile) { s.got = p; s.calls++ }
func (s *profileSpy) Counters() tunnel.Counters   { return s.c }
func (s *profileSpy) SendData([]byte)             {}
func (s *profileSpy) SetOnData(func([]byte))      {}
func (s *profileSpy) SetOnClose(func())           {}
func (s *profileSpy) Reconfigure(int, int)        {}
func (s *profileSpy) SendControl([]byte) bool     { s.sendControlCalls++; return true }
func (s *profileSpy) CtlQueueLen() int            { s.ctlQueueLenCalls++; return 42 }

// The wrapper embeds the DataTunnel INTERFACE, so Go promotes only that
// interface's methods. The rate controller reaches the tunnel through methods
// outside it, and when they are not forwarded its type assertions fail
// silently and it does nothing -- which is what happened on a live SFU run.
func TestSFUWrapperForwardsRateControlMethods(t *testing.T) {
	spy := &profileSpy{c: tunnel.Counters{SentFrames: 7, Keepalives: 3}}
	w := &sfuTunnelWrapper{DataTunnel: spy}

	if _, ok := interface{}(w).(tunnel.RateControllable); !ok {
		t.Fatal("wrapper does not satisfy RateControllable; the rate controller will silently skip it")
	}
	w.SetProfile(tunnel.Profile{FPS: 40, MaxFrameBytes: 12000})
	if spy.calls != 1 || spy.got.FPS != 40 || spy.got.MaxFrameBytes != 12000 {
		t.Fatalf("SetProfile not forwarded: calls=%d got=%+v", spy.calls, spy.got)
	}
	if c := w.Counters(); c.SentFrames != 7 || c.Keepalives != 3 {
		t.Fatalf("Counters not forwarded: %+v", c)
	}

	// Test SendControl and CtlQueueLen forwarding on sfuTunnelWrapper
	if _, ok := interface{}(w).(interface{ SendControl([]byte) bool }); !ok {
		t.Fatal("sfuTunnelWrapper does not satisfy sendController")
	}
	w.SendControl([]byte("ping"))
	if spy.sendControlCalls != 1 {
		t.Errorf("expected SendControl call, got %d", spy.sendControlCalls)
	}

	if _, ok := interface{}(w).(interface{ CtlQueueLen() int }); !ok {
		t.Fatal("sfuTunnelWrapper does not satisfy ctlQueueLener")
	}
	if q := w.CtlQueueLen(); q != 42 || spy.ctlQueueLenCalls != 1 {
		t.Errorf("expected CtlQueueLen 42, got %d (calls: %d)", q, spy.ctlQueueLenCalls)
	}
}

func TestTelemostWrapperForwardsRateControlMethods(t *testing.T) {
	spy := &profileSpy{c: tunnel.Counters{SentFrames: 7, Keepalives: 3}}
	w := &telemostTunnelWrapper{DataTunnel: spy}

	if _, ok := interface{}(w).(tunnel.RateControllable); !ok {
		t.Fatal("wrapper does not satisfy RateControllable; the rate controller will silently skip it")
	}
	w.SetProfile(tunnel.Profile{FPS: 40, MaxFrameBytes: 12000})
	if spy.calls != 1 || spy.got.FPS != 40 || spy.got.MaxFrameBytes != 12000 {
		t.Fatalf("SetProfile not forwarded: calls=%d got=%+v", spy.calls, spy.got)
	}
	if c := w.Counters(); c.SentFrames != 7 || c.Keepalives != 3 {
		t.Fatalf("Counters not forwarded: %+v", c)
	}

	// Test SendControl and CtlQueueLen forwarding on telemostTunnelWrapper
	if _, ok := interface{}(w).(interface{ SendControl([]byte) bool }); !ok {
		t.Fatal("telemostTunnelWrapper does not satisfy sendController")
	}
	w.SendControl([]byte("ping"))
	if spy.sendControlCalls != 1 {
		t.Errorf("expected SendControl call, got %d", spy.sendControlCalls)
	}

	if _, ok := interface{}(w).(interface{ CtlQueueLen() int }); !ok {
		t.Fatal("telemostTunnelWrapper does not satisfy ctlQueueLener")
	}
	if q := w.CtlQueueLen(); q != 42 || spy.ctlQueueLenCalls != 1 {
		t.Errorf("expected CtlQueueLen 42, got %d (calls: %d)", q, spy.ctlQueueLenCalls)
	}
}
