package joiner

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alex-pirozhenko/whitelist-bypass/relay/maxproto"
	"github.com/alex-pirozhenko/whitelist-bypass/relay/tunnel"
	"github.com/gorilla/websocket"
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

// TestApplyDefaultsPlatform: android is the default; "web" (case-insensitive)
// switches the ws2 defaults to the web client's (device=browser, appVersion
// from maxproto.WebUA) and leaves ClientType empty so CallInfo's wins.
func TestApplyDefaultsPlatform(t *testing.T) {
	p := &MaxHeadlessAuthParams{}
	p.applyDefaults()
	if p.Platform != maxPlatformAndroid {
		t.Fatalf("default Platform = %q, want android", p.Platform)
	}

	w := &MaxHeadlessAuthParams{Platform: " WEB "}
	w.applyDefaults()
	if w.Platform != maxPlatformWeb {
		t.Fatalf("Platform = %q, want web", w.Platform)
	}
	if w.Device != maxDefaultWebDevice {
		t.Errorf("web Device = %q, want %q", w.Device, maxDefaultWebDevice)
	}
	if w.ClientType != "" {
		t.Errorf("web ClientType = %q, want empty (CallInfo must win)", w.ClientType)
	}
	// Captured web client: appVersion=1.1, capabilities=2A03F (not the Android
	// 26.30.1 / 1877f, and not maxproto.WebUA's HTTP-API appVersion).
	if w.AppVersion != "1.1" {
		t.Errorf("web AppVersion = %q, want 1.1", w.AppVersion)
	}
	if w.Capabilities != "2A03F" {
		t.Errorf("web Capabilities = %q, want 2A03F", w.Capabilities)
	}
	if w.SFUVideoWidth != 320 || w.SFUVideoHeight != 240 {
		t.Errorf("SFU video size = %dx%d, want 320x240", w.SFUVideoWidth, w.SFUVideoHeight)
	}
	// Explicit overrides survive on web too.
	w2 := &MaxHeadlessAuthParams{Platform: "web", Device: "custom", ClientType: "X"}
	w2.applyDefaults()
	if w2.Device != "custom" || w2.ClientType != "X" {
		t.Errorf("applyDefaults overwrote explicit web values: %+v", w2)
	}
}

// TestBuildWSURLWeb reproduces the captured web client URL tail exactly
// (2026-09-11, /tmp/golden/D3.jsonl ws open):
// platform=WEB&appVersion=1.1&version=5&device=browser&capabilities=2A03F&clientType=ONE_ME
// clientType comes from CallInfo when present; no locale/osVersion params.
func TestBuildWSURLWeb(t *testing.T) {
	h := &MaxHeadlessJoiner{}
	params := &MaxHeadlessAuthParams{Platform: "web"}
	params.applyDefaults()
	h.params = params
	h.ci = &maxproto.CallInfo{Endpoint: "wss://example.max/ws2?tgt=join", ClientType: "FROM_CALLINFO"}

	got := h.buildWSURL()
	if want := "wss://example.max/ws2?tgt=join&platform=WEB&appVersion=1.1&version=5&device=browser&capabilities=2A03F&clientType=FROM_CALLINFO"; got != want {
		t.Errorf("buildWSURL() = %q\n                want %q", got, want)
	}

	// No CallInfo clientType -> ONE_ME, exactly as captured.
	h.ci = &maxproto.CallInfo{Endpoint: "wss://example.max/ws2"}
	if want := "wss://example.max/ws2?platform=WEB&appVersion=1.1&version=5&device=browser&capabilities=2A03F&clientType=ONE_ME"; h.buildWSURL() != want {
		t.Errorf("buildWSURL() = %q, want %q", h.buildWSURL(), want)
	}
	for _, reject := range []string{"locale=", "osVersion=", "platform=ANDROID", "PORTAL"} {
		if strings.Contains(h.buildWSURL(), reject) {
			t.Errorf("buildWSURL() = %q, must not contain %q on web", h.buildWSURL(), reject)
		}
	}
}

// TestHandleMessagePingRepliesPong: the ws2 server's bare text "ping" must be
// answered with a bare text "pong" (not dropped by the JSON decode), logged
// once, and both frames must land in the transcript.
func TestHandleMessagePingRepliesPong(t *testing.T) {
	upgrader := websocket.Upgrader{}
	got := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for i := 0; i < 2; i++ {
			mt, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			if mt != websocket.TextMessage {
				got <- fmt.Sprintf("non-text frame type %d", mt)
				return
			}
			got <- string(msg)
		}
	}))
	defer srv.Close()

	var logs []string
	h := NewMaxHeadlessJoiner(func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) },
		stubMaxResolve, stubMaxStatusEmitter{}, stubMaxPCConfigurer{}, stubMaxAddTracks, stubMaxReadTrack)
	var buf bytes.Buffer
	h.Transcript = NewJSONLTranscript(&buf, "pion-test")

	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer ws.Close()
	h.ws = ws

	h.handleMessage([]byte("ping"))
	h.handleMessage([]byte("ping"))
	for i := 0; i < 2; i++ {
		select {
		case m := <-got:
			if m != "pong" {
				t.Fatalf("server got %q, want bare text pong", m)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("server never received pong")
		}
	}

	pongLogs := 0
	for _, l := range logs {
		if strings.Contains(l, "ping -> pong") {
			pongLogs++
		}
	}
	if pongLogs != 1 {
		t.Errorf("keepalive logged %d times, want exactly once: %v", pongLogs, logs)
	}
	if n := strings.Count(buf.String(), `"raw":"pong"`); n != 2 {
		t.Errorf("transcript has %d tx pong lines, want 2:\n%s", n, buf.String())
	}
	// The log line is mirrored into the transcript as kind:"log".
	if !strings.Contains(buf.String(), `"kind":"log"`) {
		t.Errorf("transcript missing mirrored log line:\n%s", buf.String())
	}
}

func TestSanitizeCandidateAndSDP(t *testing.T) {
	cand := "candidate:3381240166 1 udp 2130706431 10.0.0.1 50992 typ host ufrag oldUfrag"
	sanitized := sanitizeCandidate(cand, "newUfrag")
	want := "candidate:3381240166 1 udp 2130706431 10.0.0.1 50992 typ host ufrag newUfrag"
	if sanitized != want {
		t.Errorf("sanitizeCandidate = %q, want %q", sanitized, want)
	}

	sdp := "v=0\r\na=ice-ufrag:sess123\r\na=candidate:1 1 udp 100 1.2.3.4 5000 typ host ufrag old123\r\na=candidate:2 1 udp 100 1.2.3.4 5001 typ host\r\n"
	sanitizedSDP := sanitizeSDPCandidates(sdp)
	if !strings.Contains(sanitizedSDP, "ufrag sess123") {
		t.Errorf("sanitizedSDP missing rewritten ufrag:\n%s", sanitizedSDP)
	}
	if strings.Contains(sanitizedSDP, "old123") {
		t.Errorf("sanitizedSDP still contains old ufrag:\n%s", sanitizedSDP)
	}
}
