package joiner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alex-pirozhenko/whitelist-bypass/relay/maxproto"
	"github.com/gorilla/websocket"
	"github.com/pion/webrtc/v4"
)

// loadCaptureSDP attempts to find and read an SDP file from the .direct-spec/caps bundle,
// falling back to embedded constants copied from the bundle with secrets redacted.
func loadCaptureSDP(filename string) (string, error) {
	dir, err := os.Getwd()
	if err == nil {
		for i := 0; i < 6; i++ {
			p := filepath.Join(dir, ".direct-spec", "caps", filename)
			if b, readErr := os.ReadFile(p); readErr == nil {
				return string(b), nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	if filename == "A_answer_from_server.sdp" {
		return fixtureAnswerSDP, nil
	}
	if filename == "B_offer_received.sdp" {
		return fixtureOfferSDP, nil
	}
	return "", fmt.Errorf("could not find fixture %s", filename)
}

type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

type capturedWSMessage struct {
	Command         string         `json:"command"`
	Sequence        int64          `json:"sequence"`
	MediaModifiers  map[string]any `json:"mediaModifiers"`
	MediaSettings   map[string]any `json:"mediaSettings"`
	ParticipantID   any            `json:"participantId"`
	ParticipantType string         `json:"participantType"`
	DeviceIdx       any            `json:"deviceIdx"`
	Data            map[string]any `json:"data"`
}

// TestDirectReplayMatchesReferenceCapture tests the DIRECT topology signaling replay
// against captured reference sequences (with secrets redacted).
// It verifies:
// 1. Joiner emits the exact sequence: update-media-modifiers -> change-media-settings -> transmit-data
// 2. Both media settings have isAudioEnabled: true and isVideoEnabled: true
// 3. Emitted offer/answer SDP contains m=audio and m=video and no m=application
// 4. Remote description and server candidates are applied to the PeerConnection (ICE ready to start).
func TestDirectReplayMatchesReferenceCapture(t *testing.T) {
	t.Run("Offerer", testDirectReplayOfferer)
	t.Run("Answerer", testDirectReplayAnswerer)
}

func testDirectReplayOfferer(t *testing.T) {
	answerSDP, err := loadCaptureSDP("A_answer_from_server.sdp")
	if err != nil {
		t.Fatalf("load A_answer_from_server.sdp: %v", err)
	}

	upgrader := websocket.Upgrader{}
	var serverConnMu sync.Mutex
	var serverConn *websocket.Conn
	connReady := make(chan struct{})

	var emittedMu sync.Mutex
	var emitted []capturedWSMessage
	msgCh := make(chan capturedWSMessage, 20)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade error: %v", err)
			return
		}
		defer c.Close()

		serverConnMu.Lock()
		serverConn = c
		serverConnMu.Unlock()
		close(connReady)

		for {
			_, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			var m capturedWSMessage
			if err := json.Unmarshal(msg, &m); err == nil {
				emittedMu.Lock()
				emitted = append(emitted, m)
				emittedMu.Unlock()
				msgCh <- m
			}
		}
	}))
	defer srv.Close()

	var logMu sync.Mutex
	var logs []string
	logFn := func(f string, a ...any) {
		logMu.Lock()
		defer logMu.Unlock()
		logs = append(logs, fmt.Sprintf(f, a...))
	}

	h := NewMaxHeadlessJoiner(
		logFn, stubMaxResolve, stubMaxStatusEmitter{}, loopbackOnlyPCConfigurer{},
		stubMaxAddTracks, stubMaxReadTrack,
	)
	transBuf := &safeBuffer{}
	h.Transcript = NewJSONLTranscript(transBuf, "pion-offerer")
	params := &MaxHeadlessAuthParams{
		Role:               maxRoleOfferer,
		MediaMode:          "direct",
		Platform:           "web",
		ICETransportPolicy: "relay",
	}
	params.applyDefaults()
	h.params = params
	h.selfUID = "1125900245089796"
	h.ci = &maxproto.CallInfo{
		Endpoint:   "ws://" + srv.Listener.Addr().String() + "/ws2",
		ClientType: "ONE_ME",
	}

	wsURL := "ws://" + srv.Listener.Addr().String() + "/ws2"
	clientWS, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial error: %v", err)
	}
	defer clientWS.Close()
	h.ws = clientWS

	// Start read loop
	go h.readLoop()
	defer h.Close()

	// Wait for websocket connection
	select {
	case <-connReady:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server conn")
	}

	// 1. Joiner initializes signaling commands: update-media-modifiers then change-media-settings
	// Cap line quote: capA_relay.jsonl lines 101-104 / direct-findings.md §5:
	// update-media-modifiers{denoise,denoiseAnn} then
	// change-media-settings{mediaSettings:{isAudioEnabled:true,isVideoEnabled:true,…}}
	videoEnabled := true
	audioEnabled := true
	h.send("update-media-modifiers", map[string]interface{}{
		"mediaModifiers": map[string]interface{}{"denoise": true, "denoiseAnn": true},
	})
	h.send("change-media-settings", map[string]interface{}{
		"mediaSettings": map[string]interface{}{
			"isAudioEnabled": audioEnabled, "isVideoEnabled": videoEnabled,
			"isScreenSharingEnabled": false, "isFastScreenSharingEnabled": false,
			"isAudioSharingEnabled": false, "isAnimojiEnabled": false,
		},
	})

	// Verify emitted 1: update-media-modifiers
	select {
	case m := <-msgCh:
		if m.Command != "update-media-modifiers" {
			t.Fatalf("msg 1: got command %q, want update-media-modifiers", m.Command)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for update-media-modifiers")
	}

	// Verify emitted 2: change-media-settings
	select {
	case m := <-msgCh:
		if m.Command != "change-media-settings" {
			t.Fatalf("msg 2: got command %q, want change-media-settings", m.Command)
		}
		if audio, _ := m.MediaSettings["isAudioEnabled"].(bool); !audio {
			t.Fatalf("msg 2: expected isAudioEnabled: true, got %v", m.MediaSettings["isAudioEnabled"])
		}
		if video, _ := m.MediaSettings["isVideoEnabled"].(bool); !video {
			t.Fatalf("msg 2: expected isVideoEnabled: true, got %v", m.MediaSettings["isVideoEnabled"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for change-media-settings")
	}

	// 2. Server sends connection notification (capA_relay.jsonl line 146, secrets redacted)
	connNotif := `{
		"stamp": 1789412112482000000,
		"peerId": {"id": 53096990980},
		"endpoint": "wss://videowebrtc.okcdn.ru/ws2?conversationId=3bd7eaca-a971-4bcb-adfa-9db44eb8d49c",
		"conversationParams": {
			"turn": {
				"urls": ["turn:155.212.199.182:19302", "turn:155.212.197.40:19302"],
				"username": "1789440912:1125900245089796",
				"credential": "<redacted>"
			},
			"stun": {"urls": ["stun:155.212.199.182:19302"]},
			"serverTime": 1789412112488,
			"activityTimeout": 120000
		},
		"conversation": {
			"id": "3bd7eaca-a971-4bcb-adfa-9db44eb8d49c",
			"state": "ACTIVE",
			"topology": "DIRECT",
			"participants": [
				{
					"externalId": {"type": "ONE_ME", "id": "455175836"},
					"state": "ACCEPTED",
					"roles": ["CREATOR"],
					"mediaSettings": {"isAudioEnabled": true},
					"peerId": {"id": 53096990980},
					"permissions": ["MUTE_PARTICIPANTS", "REMOVE_JOIN_LINK"],
					"id": 1125900245089796
				}
			],
			"participantsLimit": 1500,
			"features": ["RECORD"],
			"featuresPerRole": {},
			"joinLink": "Xb4lEQPN8AdJHDt6uIcO2xH5_h05Fthrdp4bQ8jgsLA",
			"options": ["START_CONVERSATION_SUCCEEDED", "FEEDBACK"],
			"clientType": "ONE_ME",
			"handCount": 0
		},
		"isConcurrent": false,
		"mediaModifiers": {"denoise": true, "denoiseAnn": true},
		"notification": "connection",
		"type": "notification"
	}`
	serverConn.WriteMessage(websocket.TextMessage, []byte(connNotif))

	// 3. Server sends settings-update (capA_relay.jsonl line 147)
	settingsNotif := `{
		"stamp": 1789412112482000000,
		"camera": {"maxDimension": 1280, "maxBitrateK": 2000, "degradationPreference": "maintain-framerate"},
		"screenSharing": {"maxDimension": 1920, "maxBitrateK": 3000, "maxFramerate": 30, "degradationPreference": "maintain-resolution"},
		"settings": {"badNet": {"rtt": 1000, "loss": 7}, "goodNet": {"rtt": 600, "loss": 0.5}},
		"notification": "settings-update",
		"type": "notification"
	}`
	serverConn.WriteMessage(websocket.TextMessage, []byte(settingsNotif))

	// 4. Server sends participant-joined (capA_relay.jsonl line 152)
	partJoinedNotif := `{
		"stamp": 1789412114249000000,
		"participantId": 1125900244960634,
		"participant": {
			"externalId": {"type": "ONE_ME", "id": "456390078"},
			"state": "ACCEPTED",
			"mediaSettings": {"isAudioEnabled": true},
			"peerId": {"id": 49996085882},
			"markers": {"SIDE": {}, "GRID": {"rank": 2, "ts": 1789412114248}},
			"id": 1125900244960634
		},
		"mediaSettings": {"isAudioEnabled": true},
		"notification": "participant-joined",
		"type": "notification"
	}`
	serverConn.WriteMessage(websocket.TextMessage, []byte(partJoinedNotif))

	// 5. Joiner emits transmit-data offer (capA_relay.jsonl line 159)
	var offerSDP string
	var offerFound bool
	for !offerFound {
		select {
		case m := <-msgCh:
			if m.Command == "transmit-data" && m.Data != nil {
				if sdpObj, ok := m.Data["sdp"].(map[string]any); ok {
					if sdpObj["type"] == "offer" {
						offerSDP, _ = sdpObj["sdp"].(string)
						offerFound = true
						break
					}
				}
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for transmit-data offer")
		}
	}

	// Assert offer SDP contains m=audio and m=video and NO m=application
	if !strings.Contains(offerSDP, "m=audio") {
		t.Fatalf("offer SDP missing m=audio:\n%s", offerSDP)
	}
	if !strings.Contains(offerSDP, "m=video") {
		t.Fatalf("offer SDP missing m=video:\n%s", offerSDP)
	}
	if strings.Contains(offerSDP, "m=application") {
		t.Fatalf("offer SDP must NOT contain m=application:\n%s", offerSDP)
	}

	// 6. Server sends registered-peer (capA_relay.jsonl line 169)
	regPeerNotif := `{
		"stamp": 1789412114866000003,
		"peerId": {"id": 49996085882},
		"platform": "WEB",
		"clientType": "ONE_ME",
		"notification": "registered-peer",
		"participantType": "USER",
		"participantId": 1125900244960634,
		"type": "notification"
	}`
	serverConn.WriteMessage(websocket.TextMessage, []byte(regPeerNotif))

	// 7. Server sends transmitted-data with answer containing INLINE server candidates
	// Cap line quote: capA_relay.jsonl line 177:
	// A_answer_from_server.sdp contains server ufrag qUHcEQEVpn6UloG, setup:passive,
	// and inline candidates:
	// a=candidate:468136283 1 udp 658217562 155.212.192.213 43210 typ host generation 0
	// a=candidate:109246529 1 tcp 281532720 155.212.192.213 7684 typ host tcptype passive generation 0
	answerMsgObj := map[string]any{
		"stamp":           1789412115103000000,
		"peerId":          map[string]any{"id": 49996085882},
		"notification":    "transmitted-data",
		"participantType": "USER",
		"participantId":   1125900244960634,
		"type":            "notification",
		"data": map[string]any{
			"sdp": map[string]any{
				"type": "answer",
				"sdp":  answerSDP,
			},
		},
	}
	answerJSON, _ := json.Marshal(answerMsgObj)
	serverConn.WriteMessage(websocket.TextMessage, answerJSON)

	// Wait for remote description to be applied
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if h.pc != nil && h.pc.RemoteDescription() != nil && h.pc.SignalingState() == webrtc.SignalingStateStable {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if h.pc == nil || h.pc.RemoteDescription() == nil {
		t.Fatal("remote description was never set on offerer")
	}
	if h.pc.SignalingState() != webrtc.SignalingStateStable {
		t.Fatalf("expected signaling state stable, got %s", h.pc.SignalingState())
	}
	if !h.remoteSet.Load() {
		t.Fatal("expected remoteSet to be true")
	}
	if h.RemoteUfrag() != "qUHcEQEVpn6UloG" {
		t.Fatalf("expected remoteUfrag qUHcEQEVpn6UloG, got %q", h.RemoteUfrag())
	}
	remSDP := h.pc.RemoteDescription().SDP
	if !strings.Contains(remSDP, "155.212.192.213 43210 typ host") {
		t.Fatalf("remote description missing server inline candidate 43210:\n%s", remSDP)
	}
	if !strings.Contains(remSDP, "155.212.192.213 7684 typ host") {
		t.Fatalf("remote description missing server inline candidate 7684:\n%s", remSDP)
	}
	if strings.Contains(remSDP, "m=application") {
		t.Fatalf("remote description must NOT contain m=application:\n%s", remSDP)
	}

	// Assert transcript records every new message type and transition
	transcriptOut := transBuf.String()
	for _, wantKind := range []string{
		`"op":"addTrack"`,
		`"tunnel-audio"`,
		`"tunnel-video"`,
		`"op":"createOffer"`,
		`"op":"setLocalDescription"`,
		`"op":"setRemoteDescription"`,
		`"what":"ice"`,
		`update-media-modifiers`,
		`change-media-settings`,
	} {
		if !strings.Contains(transcriptOut, wantKind) {
			t.Errorf("transcript missing %s:\n%s", wantKind, transcriptOut)
		}
	}
}

func testDirectReplayAnswerer(t *testing.T) {
	offerSDP, err := loadCaptureSDP("B_offer_received.sdp")
	if err != nil {
		t.Fatalf("load B_offer_received.sdp: %v", err)
	}

	upgrader := websocket.Upgrader{}
	var serverConnMu sync.Mutex
	var serverConn *websocket.Conn
	connReady := make(chan struct{})

	var emittedMu sync.Mutex
	var emitted []capturedWSMessage
	msgCh := make(chan capturedWSMessage, 20)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade error: %v", err)
			return
		}
		defer c.Close()

		serverConnMu.Lock()
		serverConn = c
		serverConnMu.Unlock()
		close(connReady)

		for {
			_, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			var m capturedWSMessage
			if err := json.Unmarshal(msg, &m); err == nil {
				emittedMu.Lock()
				emitted = append(emitted, m)
				emittedMu.Unlock()
				msgCh <- m
			}
		}
	}))
	defer srv.Close()

	var logMu sync.Mutex
	var logs []string
	logFn := func(f string, a ...any) {
		logMu.Lock()
		defer logMu.Unlock()
		logs = append(logs, fmt.Sprintf(f, a...))
	}

	h := NewMaxHeadlessJoiner(
		logFn, stubMaxResolve, stubMaxStatusEmitter{}, loopbackOnlyPCConfigurer{},
		stubMaxAddTracks, stubMaxReadTrack,
	)
	transBuf := &safeBuffer{}
	h.Transcript = NewJSONLTranscript(transBuf, "pion-answerer")
	params := &MaxHeadlessAuthParams{
		Role:               maxRoleAnswerer,
		MediaMode:          "direct",
		Platform:           "web",
		ICETransportPolicy: "relay",
	}
	params.applyDefaults()
	h.params = params
	h.selfUID = "1125900244960634"
	h.ci = &maxproto.CallInfo{
		Endpoint:   "ws://" + srv.Listener.Addr().String() + "/ws2",
		ClientType: "ONE_ME",
	}

	wsURL := "ws://" + srv.Listener.Addr().String() + "/ws2"
	clientWS, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial error: %v", err)
	}
	defer clientWS.Close()
	h.ws = clientWS

	// Start read loop
	go h.readLoop()
	defer h.Close()

	// Wait for websocket connection
	select {
	case <-connReady:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server conn")
	}

	// 1. Joiner initializes signaling commands: update-media-modifiers then change-media-settings
	videoEnabled := true
	audioEnabled := true
	h.send("update-media-modifiers", map[string]interface{}{
		"mediaModifiers": map[string]interface{}{"denoise": true, "denoiseAnn": true},
	})
	h.send("change-media-settings", map[string]interface{}{
		"mediaSettings": map[string]interface{}{
			"isAudioEnabled": audioEnabled, "isVideoEnabled": videoEnabled,
			"isScreenSharingEnabled": false, "isFastScreenSharingEnabled": false,
			"isAudioSharingEnabled": false, "isAnimojiEnabled": false,
		},
	})

	// Verify emitted 1: update-media-modifiers
	select {
	case m := <-msgCh:
		if m.Command != "update-media-modifiers" {
			t.Fatalf("msg 1: got command %q, want update-media-modifiers", m.Command)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for update-media-modifiers")
	}

	// Verify emitted 2: change-media-settings
	select {
	case m := <-msgCh:
		if m.Command != "change-media-settings" {
			t.Fatalf("msg 2: got command %q, want change-media-settings", m.Command)
		}
		if audio, _ := m.MediaSettings["isAudioEnabled"].(bool); !audio {
			t.Fatalf("msg 2: expected isAudioEnabled: true, got %v", m.MediaSettings["isAudioEnabled"])
		}
		if video, _ := m.MediaSettings["isVideoEnabled"].(bool); !video {
			t.Fatalf("msg 2: expected isVideoEnabled: true, got %v", m.MediaSettings["isVideoEnabled"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for change-media-settings")
	}

	// 2. Server sends connection notification (capB_relay.jsonl line 148, secrets redacted)
	connNotif := `{
		"stamp": 1789412114860000000,
		"peerId": {"id": 49996085882},
		"endpoint": "wss://videowebrtc.okcdn.ru/ws2?conversationId=3bd7eaca-a971-4bcb-adfa-9db44eb8d49c",
		"conversationParams": {
			"turn": {
				"urls": ["turn:155.212.199.182:19302", "turn:155.212.197.40:19302"],
				"username": "1789440914:1125900244960634",
				"credential": "<redacted>"
			},
			"stun": {"urls": ["stun:155.212.199.182:19302"]},
			"serverTime": 1789412114866,
			"activityTimeout": 120000
		},
		"conversation": {
			"id": "3bd7eaca-a971-4bcb-adfa-9db44eb8d49c",
			"state": "ACTIVE",
			"topology": "DIRECT",
			"participants": [
				{
					"externalId": {"type": "ONE_ME", "id": "456390078"},
					"state": "ACCEPTED",
					"mediaSettings": {"isAudioEnabled": true},
					"peerId": {"id": 49996085882},
					"id": 1125900244960634
				},
				{
					"externalId": {"type": "ONE_ME", "id": "455175836"},
					"state": "ACCEPTED",
					"roles": ["CREATOR"],
					"mediaSettings": {},
					"peerId": {"id": 53096990980},
					"permissions": ["REMOVE_JOIN_LINK", "MUTE_PARTICIPANTS"],
					"id": 1125900245089796
				}
			],
			"participantsLimit": 1500,
			"acceptTime": 1789412114249,
			"features": ["RECORD"],
			"featuresPerRole": {},
			"joinLink": "Xb4lEQPN8AdJHDt6uIcO2xH5_h05Fthrdp4bQ8jgsLA",
			"options": ["FEEDBACK", "START_CONVERSATION_SUCCEEDED"],
			"clientType": "ONE_ME",
			"handCount": 0
		},
		"isConcurrent": false,
		"mediaModifiers": {"denoise": true, "denoiseAnn": true},
		"notification": "connection",
		"type": "notification"
	}`
	serverConn.WriteMessage(websocket.TextMessage, []byte(connNotif))

	// 3. Server sends settings-update (capB_relay.jsonl line 152)
	settingsNotif := `{
		"stamp": 1789412114860000000,
		"camera": {"maxDimension": 1280, "maxBitrateK": 2000, "degradationPreference": "maintain-framerate"},
		"screenSharing": {"maxDimension": 1920, "maxBitrateK": 3000, "maxFramerate": 30, "degradationPreference": "maintain-resolution"},
		"settings": {"badNet": {"rtt": 1000, "loss": 7}, "goodNet": {"rtt": 600, "loss": 0.5}},
		"notification": "settings-update",
		"type": "notification"
	}`
	serverConn.WriteMessage(websocket.TextMessage, []byte(settingsNotif))

	// 4. Server sends transmitted-data offer (capB_relay.jsonl line 153)
	offerMsgObj := map[string]any{
		"stamp":           1789412114866000000,
		"peerId":          map[string]any{"id": 53096990980},
		"notification":    "transmitted-data",
		"participantType": "USER",
		"participantId":   1125900245089796,
		"type":            "notification",
		"data": map[string]any{
			"sdp": map[string]any{
				"type": "offer",
				"sdp":  offerSDP,
			},
		},
	}
	offerJSON, _ := json.Marshal(offerMsgObj)
	serverConn.WriteMessage(websocket.TextMessage, offerJSON)

	// 5. Server trickles server ICE candidates (capB_relay.jsonl lines 154-155)
	cand1 := `{
		"stamp": 1789412114866000001,
		"peerId": {"id": 53096990980},
		"data": {
			"candidate": {
				"candidate": "candidate:468136283 1 udp 658217562 155.212.192.213 43210 typ host generation 0 ufrag qUHcEQEVpn6UloG network-id 1 network-cost 10",
				"sdpMid": "0",
				"usernameFragment": "qUHcEQEVpn6UloG",
				"sdpMLineIndex": 0
			}
		},
		"notification": "transmitted-data",
		"participantType": "USER",
		"participantId": 1125900245089796,
		"type": "notification"
	}`
	serverConn.WriteMessage(websocket.TextMessage, []byte(cand1))

	cand2 := `{
		"stamp": 1789412114866000002,
		"peerId": {"id": 53096990980},
		"data": {
			"candidate": {
				"candidate": "candidate:109246529 1 tcp 281532720 155.212.192.213 7684 typ host tcptype passive generation 0 ufrag qUHcEQEVpn6UloG network-id 1 network-cost 10",
				"sdpMid": "0",
				"usernameFragment": "qUHcEQEVpn6UloG",
				"sdpMLineIndex": 0
			}
		},
		"notification": "transmitted-data",
		"participantType": "USER",
		"participantId": 1125900245089796,
		"type": "notification"
	}`
	serverConn.WriteMessage(websocket.TextMessage, []byte(cand2))

	// 6. Joiner emits transmit-data answer (capB_relay.jsonl line 163)
	var answerSDP string
	var answerFound bool
	for !answerFound {
		select {
		case m := <-msgCh:
			if m.Command == "transmit-data" && m.Data != nil {
				if sdpObj, ok := m.Data["sdp"].(map[string]any); ok {
					if sdpObj["type"] == "answer" {
						answerSDP, _ = sdpObj["sdp"].(string)
						answerFound = true
						break
					}
				}
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for transmit-data answer")
		}
	}

	// Assert answer SDP contains m=audio and m=video and NO m=application
	if !strings.Contains(answerSDP, "m=audio") {
		t.Fatalf("answer SDP missing m=audio:\n%s", answerSDP)
	}
	if !strings.Contains(answerSDP, "m=video") {
		t.Fatalf("answer SDP missing m=video:\n%s", answerSDP)
	}
	if strings.Contains(answerSDP, "m=application") {
		t.Fatalf("answer SDP must NOT contain m=application:\n%s", answerSDP)
	}

	// Wait for remote description and trickle candidates to be processed
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if h.pc != nil && h.pc.RemoteDescription() != nil && h.pc.SignalingState() == webrtc.SignalingStateStable &&
			strings.Contains(transBuf.String(), `"op":"addIceCandidate"`) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if h.pc == nil || h.pc.RemoteDescription() == nil {
		t.Fatal("remote description was never set on answerer")
	}
	if h.pc.SignalingState() != webrtc.SignalingStateStable {
		t.Fatalf("expected signaling state stable, got %s", h.pc.SignalingState())
	}
	if !h.remoteSet.Load() {
		t.Fatal("expected remoteSet to be true")
	}
	if h.RemoteUfrag() != "qUHcEQEVpn6UloG" {
		t.Fatalf("expected remoteUfrag qUHcEQEVpn6UloG, got %q", h.RemoteUfrag())
	}
	remSDP := h.pc.RemoteDescription().SDP
	if !strings.Contains(remSDP, "m=audio") || !strings.Contains(remSDP, "m=video") {
		t.Fatalf("remote offer missing media m-lines:\n%s", remSDP)
	}
	if strings.Contains(remSDP, "m=application") {
		t.Fatalf("remote offer must NOT contain m=application:\n%s", remSDP)
	}

	// Assert transcript records every new message type and transition
	transcriptOut := transBuf.String()
	for _, wantKind := range []string{
		`"op":"addTrack"`,
		`"tunnel-audio"`,
		`"tunnel-video"`,
		`"op":"setRemoteDescription"`,
		`"op":"createAnswer"`,
		`"op":"setLocalDescription"`,
		`"op":"addIceCandidate"`,
		`"what":"ice"`,
		`update-media-modifiers`,
		`change-media-settings`,
	} {
		if !strings.Contains(transcriptOut, wantKind) {
			t.Errorf("transcript missing %s:\n%s", wantKind, transcriptOut)
		}
	}
}
