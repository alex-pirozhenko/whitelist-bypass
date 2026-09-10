package joiner

import (
	"fmt"
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

// TestExtractSSRCs covers the "ssrcs" derivation for accept-producer: unique
// a=ssrc:<id> values, in first-seen order, as decimal strings.
func TestExtractSSRCs(t *testing.T) {
	sdp := "v=0\r\n" +
		"m=video 9 UDP/TLS/RTP/SAVPF 96\r\n" +
		"a=ssrc:1111 cname:abc\r\n" +
		"a=ssrc:1111 msid:x y\r\n" +
		"a=ssrc:2222 cname:abc\r\n"
	got := extractSSRCs(sdp)
	want := []string{"1111", "2222"}
	if len(got) != len(want) {
		t.Fatalf("extractSSRCs() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("extractSSRCs() = %v, want %v", got, want)
		}
	}
}

// TestParseSFUDescription covers both shapes the spec says producer-updated's
// "description" field may arrive as: a raw SDP string, or a {type,sdp} object.
func TestParseSFUDescription(t *testing.T) {
	desc, ok := parseSFUDescription("v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\n")
	if !ok || desc.Type != webrtc.SDPTypeOffer || desc.SDP == "" {
		t.Fatalf("parseSFUDescription(string) = %+v, ok=%v, want offer with non-empty SDP", desc, ok)
	}

	desc2, ok2 := parseSFUDescription(map[string]interface{}{"type": "offer", "sdp": "v=0\r\n"})
	if !ok2 || desc2.Type != webrtc.SDPTypeOffer || desc2.SDP != "v=0\r\n" {
		t.Fatalf("parseSFUDescription(object) = %+v, ok=%v, want offer with sdp=%q", desc2, ok2, "v=0\r\n")
	}

	if _, ok3 := parseSFUDescription(nil); ok3 {
		t.Fatalf("parseSFUDescription(nil) should fail")
	}
	if _, ok4 := parseSFUDescription(map[string]interface{}{}); ok4 {
		t.Fatalf("parseSFUDescription({}) should fail (no sdp)")
	}
}

// TestHandleProducerUpdatedSendsAcceptProducer exercises the real
// SFU-negotiation path end to end against real (loopback) pion
// PeerConnections: a synthetic "SFU" PC creates an offer asking to receive
// video (mirroring the SFU's producer-updated offer), and our joiner's
// handleProducerUpdated answers it and emits accept-producer with the
// sessionId and SSRCs of what we're sending. Uses a stubbed send (h.sendFn)
// to capture the outgoing command without a real WebSocket.
func TestHandleProducerUpdatedSendsAcceptProducer(t *testing.T) {
	sfuPC, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("sfu PC: %v", err)
	}
	defer sfuPC.Close()
	if _, err := sfuPC.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, webrtc.RTPTransceiverInit{
		Direction: webrtc.RTPTransceiverDirectionRecvonly,
	}); err != nil {
		t.Fatalf("add transceiver: %v", err)
	}
	sfuOffer, err := sfuPC.CreateOffer(nil)
	if err != nil {
		t.Fatalf("sfu create offer: %v", err)
	}
	if err := sfuPC.SetLocalDescription(sfuOffer); err != nil {
		t.Fatalf("sfu set local: %v", err)
	}
	<-webrtc.GatheringCompletePromise(sfuPC)
	offerSDP := sfuPC.LocalDescription().SDP

	pc, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("client PC: %v", err)
	}
	defer pc.Close()
	track, err := webrtc.NewTrackLocalStaticSample(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8, ClockRate: 90000}, "video", "max-joiner")
	if err != nil {
		t.Fatalf("new track: %v", err)
	}
	if _, err := pc.AddTrack(track); err != nil {
		t.Fatalf("add track: %v", err)
	}

	type sentCmd struct {
		command string
		fields  map[string]interface{}
	}
	var sent []sentCmd

	h := &MaxHeadlessJoiner{
		logFn:  func(string, ...any) {},
		stopCh: make(chan struct{}),
		pc:     pc,
		sendFn: func(command string, fields map[string]interface{}) {
			sent = append(sent, sentCmd{command, fields})
		},
	}

	h.handleProducerUpdated(map[string]interface{}{
		"description": offerSDP,
		"sessionId":   "sess-1",
	})

	if len(sent) != 1 || sent[0].command != "accept-producer" {
		t.Fatalf("expected exactly one accept-producer send, got %+v", sent)
	}
	fields := sent[0].fields
	if got := fmt.Sprint(fields["sessionId"]); got != "sess-1" {
		t.Errorf("sessionId = %v, want sess-1", fields["sessionId"])
	}
	ssrcs, _ := fields["ssrcs"].([]string)
	if len(ssrcs) == 0 {
		t.Errorf("ssrcs empty, want at least one derived from the answer SDP")
	}
	descSDP, ok := fields["description"].(string)
	if !ok || descSDP == "" {
		t.Errorf("description missing/empty: %+v", fields["description"])
	}
	if h.producerSessionID != "sess-1" {
		t.Errorf("producerSessionID = %q, want sess-1", h.producerSessionID)
	}

	// A repeated producer-updated with the same sessionId is a
	// duplicate/keepalive, not a new negotiation, and must not re-send.
	h.handleProducerUpdated(map[string]interface{}{
		"description": offerSDP,
		"sessionId":   "sess-1",
	})
	if len(sent) != 1 {
		t.Fatalf("duplicate sessionId should not re-send accept-producer, got %d sends", len(sent))
	}
}
