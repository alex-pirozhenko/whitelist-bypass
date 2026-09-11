package joiner

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

// TestJSONLTranscriptLines checks the sink stamps t/who, emits exactly one
// JSON object per line, and preserves the caller's fields for each kind.
func TestJSONLTranscriptLines(t *testing.T) {
	var buf bytes.Buffer
	tr := NewJSONLTranscript(&buf, "pion-answerer")
	// Deterministic clock: each call advances 100ms from the start.
	base := tr.start
	calls := 0
	tr.now = func() time.Time { calls++; return base.Add(time.Duration(calls) * 100 * time.Millisecond) }

	cases := []struct {
		name string
		in   map[string]any
		want map[string]any // subset of expected decoded fields
	}{
		{"ws open", map[string]any{"kind": "ws", "dir": "open", "url": "wss://x/ws2?a=1"},
			map[string]any{"kind": "ws", "dir": "open", "url": "wss://x/ws2?a=1"}},
		{"ws rx ping", map[string]any{"kind": "ws", "dir": "rx", "raw": "ping"},
			map[string]any{"kind": "ws", "dir": "rx", "raw": "ping"}},
		{"pc call", map[string]any{"kind": "pc", "op": "createAnswer", "args": nil, "result": map[string]any{"type": "answer", "sdp": "v=0\r\n"}, "err": nil},
			map[string]any{"kind": "pc", "op": "createAnswer", "err": nil}},
		{"state dc", map[string]any{"kind": "state", "what": "dc", "value": "open", "label": "producerCommand"},
			map[string]any{"what": "dc", "value": "open", "label": "producerCommand"}},
		{"log", map[string]any{"kind": "log", "msg": "hello"},
			map[string]any{"kind": "log", "msg": "hello"}},
		{"who cannot be spoofed", map[string]any{"kind": "log", "msg": "x", "who": "evil", "t": 1},
			map[string]any{"who": "pion-answerer"}},
	}
	for _, c := range cases {
		tr.Line(c.in)
	}
	tr.Line(nil) // must be a no-op

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != len(cases) {
		t.Fatalf("got %d lines, want %d:\n%s", len(lines), len(cases), buf.String())
	}
	for i, c := range cases {
		var got map[string]any
		if err := json.Unmarshal([]byte(lines[i]), &got); err != nil {
			t.Fatalf("%s: line %d is not JSON: %v (%q)", c.name, i, err, lines[i])
		}
		if got["who"] != "pion-answerer" {
			t.Errorf("%s: who=%v, want pion-answerer", c.name, got["who"])
		}
		wantT := float64((i + 1) * 100)
		if got["t"] != wantT {
			t.Errorf("%s: t=%v, want %v", c.name, got["t"], wantT)
		}
		for k, v := range c.want {
			if gv, ok := got[k]; !ok || gv != v {
				t.Errorf("%s: field %q = %v (present=%v), want %v", c.name, k, gv, ok, v)
			}
		}
	}
}

// TestFilterStats keeps only the TRANSCRIPT.md report types/fields.
func TestFilterStats(t *testing.T) {
	report := webrtc.StatsReport{
		"pair1": webrtc.ICECandidatePairStats{Type: webrtc.StatsTypeCandidatePair, ID: "pair1",
			State: webrtc.StatsICECandidatePairStateSucceeded, Nominated: true, RequestsSent: 3, ResponsesReceived: 2,
			BytesSent: 10, BytesReceived: 20, LocalCandidateID: "l1", RemoteCandidateID: "r1"},
		"l1":  webrtc.ICECandidateStats{Type: webrtc.StatsTypeLocalCandidate, ID: "l1", CandidateType: webrtc.ICECandidateTypeRelay, Protocol: "udp", IP: "10.0.0.1", Port: 5000},
		"in1": webrtc.InboundRTPStreamStats{Type: webrtc.StatsTypeInboundRTP, SSRC: 42, Kind: "video", Mid: "4", BytesReceived: 7, PacketsReceived: 1, FramesDecoded: 1},
		"out": webrtc.OutboundRTPStreamStats{Type: webrtc.StatsTypeOutboundRTP, SSRC: 43, Kind: "video", Mid: "3", BytesSent: 9, PacketsSent: 2, FramesEncoded: 2},
		"tp":  webrtc.TransportStats{Type: webrtc.StatsTypeTransport, ID: "tp"}, // must be dropped
	}
	got := filterStats(report)
	if len(got) != 4 {
		t.Fatalf("filterStats kept %d reports, want 4: %v", len(got), got)
	}
	byType := map[string]map[string]any{}
	for _, r := range got {
		byType[r["type"].(string)] = r
	}
	if p := byType["candidate-pair"]; p == nil || p["responsesReceived"] != uint64(2) || p["localCandidateId"] != "l1" || p["state"] != "succeeded" {
		t.Errorf("candidate-pair = %v", p)
	}
	if c := byType["local-candidate"]; c == nil || c["candidateType"] != "relay" || c["address"] != "10.0.0.1" || c["port"] != int32(5000) {
		t.Errorf("local-candidate = %v", c)
	}
	if in := byType["inbound-rtp"]; in == nil || in["ssrc"] != uint32(42) || in["mid"] != "4" || in["framesDecoded"] != uint32(1) {
		t.Errorf("inbound-rtp = %v", in)
	}
	if out := byType["outbound-rtp"]; out == nil || out["ssrc"] != uint32(43) || out["bytesSent"] != uint64(9) {
		t.Errorf("outbound-rtp = %v", out)
	}
	if _, ok := byType["transport"]; ok {
		t.Error("transport report must be filtered out")
	}
}

// TestPCConfigArgsRedactsCredential: TURN credentials never land in a transcript.
func TestPCConfigArgsRedactsCredential(t *testing.T) {
	args := pcConfigArgs(webrtc.Configuration{
		ICEServers:         []webrtc.ICEServer{{URLs: []string{"turn:1.2.3.4:3478"}, Username: "u", Credential: "secret"}},
		ICETransportPolicy: webrtc.ICETransportPolicyRelay,
	})
	raw, _ := json.Marshal(args)
	if strings.Contains(string(raw), "secret") {
		t.Fatalf("credential leaked: %s", raw)
	}
	if !strings.Contains(string(raw), `"iceTransportPolicy":"relay"`) || !strings.Contains(string(raw), `"username":"u"`) {
		t.Fatalf("unexpected config args: %s", raw)
	}
}
