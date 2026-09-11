package joiner

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
)

// Transcript is the optional JSONL transcript sink for the MAX joiner (see
// tools/maxref/TRANSCRIPT.md in letmeout): every ws2 frame, PeerConnection API
// call, state transition, periodic getStats() snapshot and log line is handed
// to Line as one map. A nil Transcript on MaxHeadlessJoiner disables it.
//
// Implementations must be safe for concurrent use: Line is called from the ws
// read loop, pion callbacks, the stats ticker and the send path (under wsMu).
type Transcript interface {
	Line(fields map[string]any)
}

// JSONLTranscript writes one JSON object per line to w, stamping every line
// with "t" (milliseconds since the transcript was created) and "who" (the
// participant label, e.g. "pion-answerer").
type JSONLTranscript struct {
	mu    sync.Mutex
	w     io.Writer
	who   string
	start time.Time
	now   func() time.Time
}

// NewJSONLTranscript returns a transcript that appends JSONL lines to w.
func NewJSONLTranscript(w io.Writer, who string) *JSONLTranscript {
	t := &JSONLTranscript{w: w, who: who, now: time.Now}
	t.start = t.now()
	return t
}

// Line stamps and writes one transcript line. Fields "t" and "who" are always
// overwritten so callers cannot mislabel a line. Marshal or write errors are
// swallowed: the transcript is a diagnostic side-channel and must never affect
// the call it is observing.
func (t *JSONLTranscript) Line(fields map[string]any) {
	if t == nil || fields == nil {
		return
	}
	line := make(map[string]any, len(fields)+2)
	for k, v := range fields {
		line[k] = v
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	line["t"] = t.now().Sub(t.start).Milliseconds()
	line["who"] = t.who
	raw, err := json.Marshal(line)
	if err != nil {
		return
	}
	_, _ = t.w.Write(append(raw, '\n'))
}

// --- MaxHeadlessJoiner emit helpers (no-ops when Transcript is nil) ---

func (h *MaxHeadlessJoiner) tr(fields map[string]any) {
	if h.Transcript != nil {
		h.Transcript.Line(fields)
	}
}

// trWS records a ws2 frame: dir is "tx" or "rx" and raw is the exact text frame.
func (h *MaxHeadlessJoiner) trWS(dir, raw string) {
	h.tr(map[string]any{"kind": "ws", "dir": dir, "raw": raw})
}

// trWSOpen records the ws2 URL the joiner dialled, once per connection.
func (h *MaxHeadlessJoiner) trWSOpen(url string) {
	h.tr(map[string]any{"kind": "ws", "dir": "open", "url": url})
}

// trPC records a PeerConnection API call. result/args are logged as-is; err is
// rendered as a string (null when nil) so a diff can pair pion's and the
// browser's failures.
func (h *MaxHeadlessJoiner) trPC(op string, args, result any, err error) {
	var errStr any
	if err != nil {
		errStr = err.Error()
	}
	h.tr(map[string]any{"kind": "pc", "op": op, "args": args, "result": result, "err": errStr})
}

// trState records a state transition; label is set only for what=="dc".
func (h *MaxHeadlessJoiner) trState(what, value, label string) {
	m := map[string]any{"kind": "state", "what": what, "value": value}
	if what == "dc" {
		m["label"] = label
	}
	h.tr(m)
}

// sdpArgs renders a SessionDescription as the {type,sdp} object the
// transcript expects for createOffer/createAnswer/set*Description.
func sdpArgs(d webrtc.SessionDescription) map[string]any {
	return map[string]any{"type": d.Type.String(), "sdp": d.SDP}
}

// pcConfigArgs renders the configuration passed to NewPeerConnection. TURN
// credentials are redacted: the transcript is meant to be shared and diffed.
func pcConfigArgs(cfg webrtc.Configuration) map[string]any {
	servers := make([]map[string]any, 0, len(cfg.ICEServers))
	for _, s := range cfg.ICEServers {
		e := map[string]any{"urls": s.URLs}
		if s.Username != "" {
			e["username"] = s.Username
		}
		if s.Credential != nil {
			e["credential"] = "<redacted>"
		}
		servers = append(servers, e)
	}
	return map[string]any{
		"iceServers":         servers,
		"iceTransportPolicy": cfg.ICETransportPolicy.String(),
	}
}

// trackArgs renders a local track for the addTrack line ({kind,id,label});
// pion has no device label, so the stream id stands in for it.
func trackArgs(t webrtc.TrackLocal) map[string]any {
	return map[string]any{"kind": t.Kind().String(), "id": t.ID(), "label": t.StreamID()}
}

// filterStats keeps only the report types and fields TRANSCRIPT.md lists:
// candidate-pair, local-/remote-candidate, inbound-rtp, outbound-rtp.
func filterStats(report webrtc.StatsReport) []map[string]any {
	out := make([]map[string]any, 0, len(report))
	for _, s := range report {
		switch v := s.(type) {
		case webrtc.ICECandidatePairStats:
			out = append(out, map[string]any{
				"type":              string(v.Type),
				"id":                v.ID,
				"state":             string(v.State),
				"nominated":         v.Nominated,
				"requestsSent":      v.RequestsSent,
				"responsesReceived": v.ResponsesReceived,
				"bytesSent":         v.BytesSent,
				"bytesReceived":     v.BytesReceived,
				"localCandidateId":  v.LocalCandidateID,
				"remoteCandidateId": v.RemoteCandidateID,
			})
		case webrtc.ICECandidateStats:
			out = append(out, map[string]any{
				"type":          string(v.Type),
				"id":            v.ID,
				"candidateType": v.CandidateType.String(),
				"protocol":      v.Protocol,
				"ip":            v.IP,
				"address":       v.IP,
				"port":          v.Port,
			})
		case webrtc.InboundRTPStreamStats:
			out = append(out, map[string]any{
				"type":            string(v.Type),
				"ssrc":            uint32(v.SSRC),
				"kind":            v.Kind,
				"mid":             v.Mid,
				"bytesReceived":   v.BytesReceived,
				"packetsReceived": v.PacketsReceived,
				"framesDecoded":   v.FramesDecoded,
			})
		case webrtc.OutboundRTPStreamStats:
			out = append(out, map[string]any{
				"type":          string(v.Type),
				"ssrc":          uint32(v.SSRC),
				"kind":          v.Kind,
				"mid":           v.Mid,
				"bytesSent":     v.BytesSent,
				"packetsSent":   v.PacketsSent,
				"framesEncoded": v.FramesEncoded,
			})
		}
	}
	return out
}

// startStatsLoop emits a "stats" line every 2 s for pc until it is closed or
// the joiner stops. Keyed on the pc pointer, so a recreated PeerConnection
// gets its own loop and the old one drains out on its own.
func (h *MaxHeadlessJoiner) startStatsLoop(pc *webrtc.PeerConnection) {
	if h.Transcript == nil || pc == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-h.stopCh:
				return
			case <-ticker.C:
			}
			if pc.ConnectionState() == webrtc.PeerConnectionStateClosed {
				return
			}
			h.tr(map[string]any{"kind": "stats", "reports": filterStats(pc.GetStats())})
		}
	}()
}

// attachTranscriptStateHandlers installs the gathering/signaling handlers
// (which nothing else in the joiner uses) so their transitions are recorded.
// ICE/connection state lines are emitted from the joiner's own handlers, since
// pion keeps a single callback per event.
func (h *MaxHeadlessJoiner) attachTranscriptStateHandlers(pc *webrtc.PeerConnection) {
	pc.OnICEGatheringStateChange(func(s webrtc.ICEGatheringState) {
		h.trState("gathering", s.String(), "")
	})
	pc.OnSignalingStateChange(func(s webrtc.SignalingState) {
		h.trState("signaling", s.String(), "")
	})
}

// attachDCStateHandlers records open/close of a datachannel we created.
func (h *MaxHeadlessJoiner) attachDCStateHandlers(dc *webrtc.DataChannel) {
	label := dc.Label()
	dc.OnOpen(func() { h.trState("dc", "open", label) })
	dc.OnClose(func() { h.trState("dc", "close", label) })
}

// closePC closes pc and records the call. Safe on nil.
func (h *MaxHeadlessJoiner) closePC(pc *webrtc.PeerConnection) {
	if pc == nil {
		return
	}
	err := pc.Close()
	h.trPC("close", nil, nil, err)
}

// logAndTranscript wraps a logFn so every log line is mirrored into the
// transcript as {"kind":"log","msg":...} when a Transcript is attached.
func (h *MaxHeadlessJoiner) logAndTranscript(base func(string, ...any)) func(string, ...any) {
	return func(format string, args ...any) {
		if base != nil {
			base(format, args...)
		}
		if h.Transcript != nil {
			h.Transcript.Line(map[string]any{"kind": "log", "msg": fmt.Sprintf(format, args...)})
		}
	}
}
