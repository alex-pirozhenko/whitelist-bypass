package joiner

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	tmapi "github.com/alex-pirozhenko/whitelist-bypass/relay/telemost"
	"github.com/alex-pirozhenko/whitelist-bypass/relay/tunnel"
	"github.com/pion/webrtc/v4"
)

type stubStatusEmitter struct{}

func (stubStatusEmitter) EmitStatus(status string)   {}
func (stubStatusEmitter) EmitStatusError(err string) {}

type mockTransport struct{}

func (mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, errors.New("mocked network call")
}

func TestTelemostParamsParsing(t *testing.T) {
	j := NewTelemostHeadlessJoiner(
		func(string, ...any) {}, // logFn
		nil,                     // resolveFn
		stubStatusEmitter{},     // status
		nil,                     // pcConfig
		nil,                     // addTracks
		nil,                     // readTrackFn
	)
	j.httpClient = &http.Client{Transport: mockTransport{}}

	jsonParams := `{
		"joinLink": "https://telemost.yandex.ru/j/1234567890",
		"displayName": "TestUser",
		"disableSubscriberAudio": true,
		"idleUnsubscribeVideo": true,
		"subscriberAudioOff": true,
		"idleRembBps": 100000,
		"activeRembBps": 500000,
		"idleSlotWidth": 160,
		"idleSlotHeight": 90
	}`

	j.RunWithParams(jsonParams)

	if j.disableSubscriberAudio != true {
		t.Errorf("expected disableSubscriberAudio to be true, got false")
	}
	if j.idleUnsubscribeVideo != true {
		t.Errorf("expected idleUnsubscribeVideo to be true, got false")
	}
	if j.subscriberAudioOff != true {
		t.Errorf("expected subscriberAudioOff to be true, got false")
	}
	if j.idleRembBps != 100000 {
		t.Errorf("expected idleRembBps to be 100000, got %d", j.idleRembBps)
	}
	if j.activeRembBps != 500000 {
		t.Errorf("expected activeRembBps to be 500000, got %d", j.activeRembBps)
	}
	if j.idleSlotWidth != 160 {
		t.Errorf("expected idleSlotWidth to be 160, got %d", j.idleSlotWidth)
	}
	if j.idleSlotHeight != 90 {
		t.Errorf("expected idleSlotHeight to be 90, got %d", j.idleSlotHeight)
	}
}

func TestTelemostParamsParsingDefaults(t *testing.T) {
	j := NewTelemostHeadlessJoiner(
		func(string, ...any) {}, // logFn
		nil,                     // resolveFn
		stubStatusEmitter{},     // status
		nil,                     // pcConfig
		nil,                     // addTracks
		nil,                     // readTrackFn
	)
	j.httpClient = &http.Client{Transport: mockTransport{}}

	jsonParams := `{
		"joinLink": "https://telemost.yandex.ru/j/1234567890",
		"displayName": "TestUser"
	}`

	j.RunWithParams(jsonParams)

	if j.disableSubscriberAudio != false {
		t.Errorf("expected default disableSubscriberAudio to be false, got true")
	}
	if j.idleUnsubscribeVideo != false {
		t.Errorf("expected default idleUnsubscribeVideo to be false, got true")
	}
	if j.subscriberAudioOff != false {
		t.Errorf("expected default subscriberAudioOff to be false, got true")
	}
	if j.idleRembBps != 0 {
		t.Errorf("expected default idleRembBps to be 0, got %d", j.idleRembBps)
	}
	if j.activeRembBps != 0 {
		t.Errorf("expected default activeRembBps to be 0, got %d", j.activeRembBps)
	}
	if j.idleSlotWidth != 0 {
		t.Errorf("expected default idleSlotWidth to be 0, got %d", j.idleSlotWidth)
	}
	if j.idleSlotHeight != 0 {
		t.Errorf("expected default idleSlotHeight to be 0, got %d", j.idleSlotHeight)
	}
}

type fakeInnerTunnel struct {
	tunnel.DataTunnel
	profileGot   tunnel.Profile
	profileCalls int
	countersVal  tunnel.Counters
	sendDataGot  []byte
	trySendVal   bool
	fpsVal       int
	batchVal     int
	queueLenVal  int
}

func (f *fakeInnerTunnel) SetProfile(p tunnel.Profile) {
	f.profileGot = p
	f.profileCalls++
}

func (f *fakeInnerTunnel) Counters() tunnel.Counters {
	return f.countersVal
}

func (f *fakeInnerTunnel) TrySendData(data []byte) bool {
	f.sendDataGot = data
	return f.trySendVal
}

func (f *fakeInnerTunnel) FPS() int {
	return f.fpsVal
}

func (f *fakeInnerTunnel) Batch() int {
	return f.batchVal
}

func (f *fakeInnerTunnel) QueueLen() int {
	return f.queueLenVal
}

func TestTelemostTunnelWrapperForwarding(t *testing.T) {
	fake := &fakeInnerTunnel{
		countersVal: tunnel.Counters{SentFrames: 10, Keepalives: 5},
		trySendVal:  true,
		fpsVal:      30,
		batchVal:    4,
		queueLenVal: 2,
	}

	j := NewTelemostHeadlessJoiner(
		func(string, ...any) {},
		nil,
		stubStatusEmitter{},
		nil,
		nil,
		nil,
	)

	w := newTelemostTunnelWrapper(fake, j)

	// Verify interfaces
	if _, ok := interface{}(w).(tunnel.RateControllable); !ok {
		t.Fatal("wrapper does not satisfy RateControllable")
	}
	if _, ok := interface{}(w).(tunnel.BandwidthHinter); !ok {
		t.Fatal("wrapper does not satisfy BandwidthHinter")
	}

	// Test forwarding
	w.SetProfile(tunnel.Profile{FPS: 25, MaxFrameBytes: 8000})
	if fake.profileCalls != 1 || fake.profileGot.FPS != 25 || fake.profileGot.MaxFrameBytes != 8000 {
		t.Errorf("SetProfile not forwarded correctly: %+v", fake.profileGot)
	}

	counters := w.Counters()
	if counters.SentFrames != 10 || counters.Keepalives != 5 {
		t.Errorf("Counters not forwarded correctly: %+v", counters)
	}

	ok := w.TrySendData([]byte("hello"))
	if !ok || string(fake.sendDataGot) != "hello" {
		t.Errorf("TrySendData not forwarded correctly")
	}

	if w.FPS() != 30 {
		t.Errorf("FPS not forwarded: expected 30, got %d", w.FPS())
	}

	if w.Batch() != 4 {
		t.Errorf("Batch not forwarded: expected 4, got %d", w.Batch())
	}

	if w.QueueLen() != 2 {
		t.Errorf("QueueLen not forwarded: expected 2, got %d", w.QueueLen())
	}
}

func TestHintBandwidthRembAndSlots(t *testing.T) {
	j := NewTelemostHeadlessJoiner(
		func(string, ...any) {},
		nil,
		stubStatusEmitter{},
		nil,
		nil,
		nil,
	)

	// Set up hints params
	j.idleRembBps = 150000
	j.activeRembBps = 600000
	j.idleSlotWidth = 160
	j.idleSlotHeight = 90

	// 1. Test TierActive with both REMB and slot-size enabled
	// Active should map to activeRembBps
	err := j.HintBandwidth(context.Background(), tunnel.TierActive)
	if err != nil {
		t.Fatalf("HintBandwidth failed: %v", err)
	}

	if gotBps := j.getRembBps(); gotBps != 600000 {
		t.Errorf("expected REMB Bps for Active to be 600000, got %d", gotBps)
	}

	// 2. Test TierIdle with both REMB and slot-size enabled
	// Idle should map to idleRembBps
	err = j.HintBandwidth(context.Background(), tunnel.TierIdle)
	if err != nil {
		t.Fatalf("HintBandwidth failed: %v", err)
	}

	if gotBps := j.getRembBps(); gotBps != 150000 {
		t.Errorf("expected REMB Bps for Idle to be 150000, got %d", gotBps)
	}

	// 3. Test TierIdle when idleRembBps == 0 -> should fallback to activeRembBps
	j.idleRembBps = 0
	err = j.HintBandwidth(context.Background(), tunnel.TierIdle)
	if err != nil {
		t.Fatalf("HintBandwidth failed: %v", err)
	}

	if gotBps := j.getRembBps(); gotBps != 600000 {
		t.Errorf("expected REMB Bps fallback to ActiveRembBps (600000), got %d", gotBps)
	}

	// Clean up goroutine
	j.resetSessionState()
}

func TestHintBandwidthIdleUnsubscribeVideo(t *testing.T) {
	j := NewTelemostHeadlessJoiner(
		func(string, ...any) {},
		nil,
		stubStatusEmitter{},
		nil,
		nil,
		nil,
	)

	j.idleUnsubscribeVideo = true

	// Initially, it should be subscribed (false)
	if j.getUnsubscribedVideo() {
		t.Errorf("expected initially unsubscribed video to be false")
	}

	// 1. Call with TierIdle -> should become unsubscribed (true)
	err := j.HintBandwidth(context.Background(), tunnel.TierIdle)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !j.getUnsubscribedVideo() {
		t.Errorf("expected video to be unsubscribed (true) after TierIdle")
	}

	// 2. Call again with TierIdle -> should remain unsubscribed and not crash/panic with nil ws
	err = j.HintBandwidth(context.Background(), tunnel.TierIdle)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !j.getUnsubscribedVideo() {
		t.Errorf("expected video to remain unsubscribed")
	}

	// 3. Call with TierActive -> should become subscribed (false)
	err = j.HintBandwidth(context.Background(), tunnel.TierActive)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if j.getUnsubscribedVideo() {
		t.Errorf("expected video to be subscribed (false) after TierActive")
	}
}

func TestSubscriberAudioOff(t *testing.T) {
	cannedOffer := "v=0\r\n" +
		"o=- 0 0 IN IP4 127.0.0.1\r\n" +
		"s=-\r\n" +
		"t=0 0\r\n" +
		"a=ice-ufrag:foo\r\n" +
		"a=ice-pwd:bar\r\n" +
		"a=fingerprint:sha-256 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF\r\n" +
		"m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" +
		"c=IN IP4 127.0.0.1\r\n" +
		"a=mid:0\r\n" +
		"a=setup:actpass\r\n" +
		"a=rtpmap:111 opus/48000/2\r\n" +
		"a=sendrecv\r\n" +
		"m=video 9 UDP/TLS/RTP/SAVPF 96\r\n" +
		"c=IN IP4 127.0.0.1\r\n" +
		"a=mid:1\r\n" +
		"a=setup:actpass\r\n" +
		"a=rtpmap:96 VP8/90000\r\n" +
		"a=sendrecv\r\n"

	// Pion NewPeerConnection works offline
	pc, err := tmapi.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("failed to create PeerConnection: %v", err)
	}
	defer pc.Close()

	err = pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer,
		SDP:  cannedOffer,
	})
	if err != nil {
		t.Fatalf("SetRemoteDescription failed: %v", err)
	}

	// Apply rejection helper for the audio transceiver
	transceivers := pc.GetTransceivers()
	foundAudio := false
	for _, tr := range transceivers {
		if tr.Kind() == webrtc.RTPCodecTypeAudio {
			foundAudio = true
			err := setTransceiverDirection(tr, webrtc.RTPTransceiverDirectionInactive)
			if err != nil {
				_ = tr.Stop()
			}
		}
	}

	if !foundAudio {
		t.Fatalf("audio transceiver not found")
	}

	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		t.Fatalf("CreateAnswer failed: %v", err)
	}

	sdpStr := answer.SDP
	t.Logf("Generated Answer SDP:\n%s", sdpStr)

	// Verify that audio is inactive and video is active
	lines := strings.Split(sdpStr, "\n")
	audioInactive := false
	videoInactive := false
	inAudio := false
	inVideo := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "m=audio") {
			inAudio = true
			inVideo = false
		} else if strings.HasPrefix(line, "m=video") {
			inAudio = false
			inVideo = true
		}
		if line == "a=inactive" {
			if inAudio {
				audioInactive = true
			}
			if inVideo {
				videoInactive = true
			}
		}
	}

	if !audioInactive {
		t.Errorf("expected audio section to be inactive")
	}
	if videoInactive {
		t.Errorf("expected video section to NOT be inactive")
	}
}
