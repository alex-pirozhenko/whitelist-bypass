package joiner

import (
	"strings"
	"testing"

	"github.com/alex-pirozhenko/whitelist-bypass/relay/maxproto"
	"github.com/alex-pirozhenko/whitelist-bypass/relay/tunnel"
	"github.com/pion/webrtc/v4"
)

type stubMaxStatusEmitter struct{}

func (stubMaxStatusEmitter) EmitStatus(status string)   {}
func (stubMaxStatusEmitter) EmitStatusError(msg string) {}

type stubMaxPCConfigurer struct{}

func (stubMaxPCConfigurer) ConfigureSettingEngine(se *webrtc.SettingEngine) {}

func stubMaxResolve(hostname string) (string, error) { return "127.0.0.1", nil }

func stubMaxAddTracks(pc *webrtc.PeerConnection, logFn func(string, ...any), prefix string) *webrtc.TrackLocalStaticSample {
	return nil
}

func stubMaxReadTrack(track *webrtc.TrackRemote, handler func([]byte), logFn func(string, ...any), prefix string) {
}

// TestNewMaxHeadlessJoinerShape proves MaxHeadlessJoiner's constructor and
// public surface match the VK/Telemost headless-joiner family: same
// New...(logFn, ResolveFunc, StatusEmitter, PeerConnectionConfigurer,
// AddTunnelTracksFunc, ReadTrackFunc) constructor shape, same OnConnected /
// OnRemoteCandidate hooks, and a MarkConfigAcked/Close pair that is safe to
// call before RunWithParams.
func TestNewMaxHeadlessJoinerShape(t *testing.T) {
	var logged []string
	logFn := func(format string, args ...any) { logged = append(logged, format) }

	h := NewMaxHeadlessJoiner(logFn, stubMaxResolve, stubMaxStatusEmitter{}, stubMaxPCConfigurer{}, stubMaxAddTracks, stubMaxReadTrack)
	if h == nil {
		t.Fatal("NewMaxHeadlessJoiner returned nil")
	}
	if h.ResolveFn == nil {
		t.Error("ResolveFn not wired")
	}
	if h.Status == nil {
		t.Error("Status not wired")
	}
	if h.PCConfig == nil {
		t.Error("PCConfig not wired")
	}
	if h.AddTracks == nil {
		t.Error("AddTracks not wired")
	}
	if h.ReadTrackFn == nil {
		t.Error("ReadTrackFn not wired")
	}

	h.OnConnected = func(tunnel.DataTunnel) {}
	h.OnRemoteCandidate = func(target int, candidateOrSDP string) {}

	h.MarkConfigAcked() // must be a safe no-op
	h.Close()           // must not panic even before RunWithParams
	h.Close()           // must be idempotent (stopOnce)
}

func TestMaxHeadlessAuthParamsApplyDefaults(t *testing.T) {
	p := &MaxHeadlessAuthParams{}
	p.applyDefaults()

	cases := map[string]string{
		p.APIHost:         maxDefaultAPIHost,
		p.AppVersion:      maxDefaultAppVersion,
		p.ProtocolVersion: maxDefaultProtocolVersion,
		p.Capabilities:    maxDefaultCapabilities,
		p.ClientType:      maxDefaultClientType,
		p.Device:          maxDefaultDevice,
		p.Locale:          maxDefaultLocale,
		p.OSVersion:       maxDefaultOSVersion,
		p.Role:            maxRoleAnswerer,
		p.TunnelMode:      maxDefaultTunnelMode,
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("applyDefaults: got %q, want %q (full params: %+v)", got, want, p)
		}
	}

	// Explicit values must survive applyDefaults untouched.
	p2 := &MaxHeadlessAuthParams{Role: maxRoleOfferer, TunnelMode: "dc", Device: "custom-device"}
	p2.applyDefaults()
	if p2.Role != maxRoleOfferer || p2.Device != "custom-device" {
		t.Errorf("applyDefaults overwrote explicit values: %+v", p2)
	}
}

// TestBuildWSURL locks in the critical ws2 URL-augmentation behaviour: the
// server upgrades the connection but replies
// {"type":"error","error":"invalid-request"} unless these client params are
// appended to CallInfo.Endpoint.
func TestBuildWSURL(t *testing.T) {
	h := &MaxHeadlessJoiner{}
	params := &MaxHeadlessAuthParams{}
	params.applyDefaults()
	h.params = params
	h.ci = &maxproto.CallInfo{Endpoint: "wss://example.max/ws2?tgt=join"}

	got := h.buildWSURL()

	if !strings.HasPrefix(got, "wss://example.max/ws2?tgt=join&") {
		t.Fatalf("buildWSURL() = %q, want existing query extended with '&'", got)
	}
	for _, want := range []string{
		"version=5", "capabilities=1877f", "platform=ANDROID", "clientType=ONE_ME",
		"appVersion=26.30.1", "device=Google%2FPixel+8", "locale=en", "osVersion=34",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("buildWSURL() = %q, missing %q", got, want)
		}
	}

	// No existing query string -> "?" separator, and clientType falls back to
	// CallInfo.ClientType when the auth params didn't override it.
	h2 := &MaxHeadlessJoiner{}
	params2 := &MaxHeadlessAuthParams{}
	params2.applyDefaults()
	params2.ClientType = ""
	h2.params = params2
	h2.ci = &maxproto.CallInfo{Endpoint: "wss://example.max/ws2", ClientType: "FROM_CALLINFO"}
	got2 := h2.buildWSURL()
	if !strings.HasPrefix(got2, "wss://example.max/ws2?") {
		t.Fatalf("buildWSURL() = %q, want '?' separator with no pre-existing query", got2)
	}
	if !strings.Contains(got2, "clientType=FROM_CALLINFO") {
		t.Errorf("buildWSURL() = %q, want clientType fallback to CallInfo.ClientType", got2)
	}
}

// TestLearnPeer matches okcalls_peer.py Peer.learn_peer: scan top-level then
// data.participantId, skip our own uid, and let data.participantId win when
// both are present (it's inspected after the top-level field).
func TestLearnPeer(t *testing.T) {
	h := &MaxHeadlessJoiner{selfUID: "100"}
	msg := map[string]interface{}{
		"notification":  "transmitted-data",
		"participantId": "200",
		"data": map[string]interface{}{
			"participantId": "300",
		},
	}
	h.learnPeer(msg)

	h.peerMu.Lock()
	addr := h.peerAddr
	h.peerMu.Unlock()
	if addr == nil || addr.ParticipantID != "300" {
		t.Fatalf("learnPeer: got %+v, want data.participantId (300) to win", addr)
	}
	if addr.ParticipantType != "USER" || addr.DeviceIdx != 0 {
		t.Errorf("learnPeer: got %+v, want participantType=USER deviceIdx=0", addr)
	}
}

func TestLearnPeerIgnoresSelf(t *testing.T) {
	h := &MaxHeadlessJoiner{selfUID: "100"}
	h.learnPeer(map[string]interface{}{"participantId": "100"})

	h.peerMu.Lock()
	defer h.peerMu.Unlock()
	if h.peerAddr != nil {
		t.Fatalf("learnPeer: should not learn our own uid, got %+v", h.peerAddr)
	}
}

// TestOnLocalICECandidateBuffersUntilPeerKnown covers the ICE-buffering rule:
// local candidates gathered before the peer is learned must be queued, then
// flushed (as individual transmit-data sends) once setPeerAddr runs.
func TestOnLocalICECandidateBuffersUntilPeerKnown(t *testing.T) {
	h := &MaxHeadlessJoiner{selfUID: "100"}

	h.peerMu.Lock()
	h.pendingLocalICE = append(h.pendingLocalICE, "cand-1")
	h.peerMu.Unlock()

	// No ws connected, so sendTransmitData -> send is a no-op, but setPeerAddr
	// must still drain pendingLocalICE and leave peerAddr set.
	h.setPeerAddr(&maxPeerAddr{ParticipantID: "999", ParticipantType: "USER", DeviceIdx: 0})

	h.peerMu.Lock()
	defer h.peerMu.Unlock()
	if h.peerAddr == nil || h.peerAddr.ParticipantID != "999" {
		t.Fatalf("setPeerAddr: peerAddr = %+v, want participantId=999", h.peerAddr)
	}
	if len(h.pendingLocalICE) != 0 {
		t.Fatalf("setPeerAddr: pendingLocalICE not drained, got %v", h.pendingLocalICE)
	}
}
