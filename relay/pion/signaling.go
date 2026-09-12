package pion

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/alex-pirozhenko/whitelist-bypass/relay/common"
	"github.com/alex-pirozhenko/whitelist-bypass/relay/tunnel"
	"github.com/gorilla/websocket"
	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
	"github.com/pion/webrtc/v4"
)

type SignalingMessage struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
	ID   int             `json:"id,omitempty"`
	Role string          `json:"role,omitempty"`
}

type ICEServerConfig struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

type SDPMessage struct {
	Type string `json:"type"`
	SDP  string `json:"sdp"`
}

type ICECandidateMessage struct {
	Candidate     string `json:"candidate"`
	SDPMid        string `json:"sdpMid"`
	SDPMLineIndex uint16 `json:"sdpMLineIndex"`
}

var WsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

var iceLogFn func(string, ...any)

func ParseICEServers(data json.RawMessage) ([]webrtc.ICEServer, error) {
	var servers []ICEServerConfig
	if err := json.Unmarshal(data, &servers); err != nil {
		return nil, err
	}
	iceServers := make([]webrtc.ICEServer, len(servers))
	for i, s := range servers {
		urls := make([]string, len(s.URLs))
		for j, u := range s.URLs {
			fixed := common.FixICEURL(u)
			if iceLogFn != nil && fixed != u {
				iceLogFn("ice: fix URL %q -> %q", u, fixed)
			}
			urls[j] = fixed
		}
		if iceLogFn != nil {
			iceLogFn("ice: server %d: urls=%v", i, urls)
		}
		iceServers[i] = webrtc.ICEServer{
			URLs: urls, Username: s.Username, Credential: s.Credential,
		}
	}
	return iceServers, nil
}

func NewPionAPI(localIP string) *webrtc.API {
	se := webrtc.SettingEngine{}
	se.SetNet(&common.AndroidNet{LocalIP: localIP})
	// Telemost SFU is DTLS-active for subscribers; Pion must answer passive.
	se.SetAnsweringDTLSRole(webrtc.DTLSRoleServer)
	return webrtc.NewAPI(webrtc.WithSettingEngine(se))
}

type WSHelper struct {
	wsConn *websocket.Conn
	mu     sync.Mutex
}

func (h *WSHelper) SetConn(ws *websocket.Conn) {
	h.mu.Lock()
	h.wsConn = ws
	h.mu.Unlock()
}

func (h *WSHelper) SendToHook(msgType string, data any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.wsConn == nil {
		return
	}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return
	}
	msg := SignalingMessage{Type: msgType, Data: dataBytes}
	msgBytes, _ := json.Marshal(msg)
	h.wsConn.WriteMessage(websocket.TextMessage, msgBytes)
}

func (h *WSHelper) SendToHookWithRole(msgType string, data any, role string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.wsConn == nil {
		return
	}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return
	}
	msg := SignalingMessage{Type: msgType, Data: dataBytes, Role: role}
	msgBytes, _ := json.Marshal(msg)
	h.wsConn.WriteMessage(websocket.TextMessage, msgBytes)
}

func (h *WSHelper) SendResponse(id int, data any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.wsConn == nil {
		return
	}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return
	}
	msg := SignalingMessage{Type: "response", Data: dataBytes, ID: id}
	msgBytes, _ := json.Marshal(msg)
	h.wsConn.WriteMessage(websocket.TextMessage, msgBytes)
}

func (h *WSHelper) ReadMessages(handler func([]byte), onDisconnect func()) {
	for {
		_, msg, err := h.wsConn.ReadMessage()
		if err != nil {
			onDisconnect()
			return
		}
		handler(msg)
	}
}

func AddTunnelTracks(pc *webrtc.PeerConnection, logFn func(string, ...any), prefix string) *webrtc.TrackLocalStaticSample {
	sampleTrack, _ := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8},
		"video", "tunnel-video",
	)
	audioTrack, _ := webrtc.NewTrackLocalStaticRTP(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus},
		"audio", "tunnel-audio",
	)
	audioSender, audioErr := pc.AddTrack(audioTrack)
	videoSender, videoErr := pc.AddTrack(sampleTrack)
	logFn("%s: AddTrack audio: sender=%v err=%v", prefix, audioSender != nil, audioErr)
	logFn("%s: AddTrack video: sender=%v err=%v", prefix, videoSender != nil, videoErr)
	logFn("%s: senders count: %d", prefix, len(pc.GetSenders()))
	go tunnel.DrainSenderRTCP(videoSender)
	return sampleTrack
}

func ParseSDPType(t string) webrtc.SDPType {
	if t == "offer" {
		return webrtc.SDPTypeOffer
	}
	return webrtc.SDPTypeAnswer
}

// RecvStats is a cumulative snapshot of what readVP8Track has observed on
// one track: how many RTP packets it processed, how many times the sequence
// number was non-consecutive (a "gap"), and the summed size of those jumps
// (e.g. seeing 105 after 100 is a jump of 5, i.e. 4 packets never arrived or
// arrived out of the window we track — LostPackets is that sum across all
// gaps seen so far, not a count of distinct gap EVENTS; Gaps is the count of
// gap events).
type RecvStats struct {
	RecvPackets uint64
	Gaps        uint64
	LostPackets uint64
}

// ReadTrackWithStats is ReadTrack plus a stats callback invoked after every
// RTP packet is processed (whether or not it completed a frame), with a
// cumulative RecvStats snapshot. onStats may be nil.
func ReadTrackWithStats(track *webrtc.TrackRemote, handler func([]byte), logFn func(string, ...any), prefix string, onStats func(RecvStats)) {
	if track.Codec().MimeType != webrtc.MimeTypeVP8 {
		buf := make([]byte, common.UDPBufSize)
		for {
			if _, _, err := track.Read(buf); err != nil {
				return
			}
		}
	}
	readVP8Track(track, handler, logFn, prefix, false, onStats)
}

// ReadTrackForceVP8WithStats is ReadTrackForceVP8 plus the same stats callback.
func ReadTrackForceVP8WithStats(track *webrtc.TrackRemote, handler func([]byte), logFn func(string, ...any), prefix string, onStats func(RecvStats)) {
	logFn("%s: reading track ssrc=%d pt=%d codec=%s as VP8 (forced)", prefix, track.SSRC(), track.PayloadType(), track.Codec().MimeType)
	readVP8Track(track, handler, logFn, prefix, true, onStats)
}

func ReadTrack(track *webrtc.TrackRemote, handler func([]byte), logFn func(string, ...any), prefix string) {
	if track.Codec().MimeType != webrtc.MimeTypeVP8 {
		buf := make([]byte, common.UDPBufSize)
		for {
			if _, _, err := track.Read(buf); err != nil {
				return
			}
		}
	}
	readVP8Track(track, handler, logFn, prefix, false, nil)
}

// ReadTrackForceVP8 is ReadTrack without the codec check. The OK-Calls SFU
// forwards our VP8 RTP with the payload type we sent, but the consumer
// m-line it hands us maps that payload type to a different codec (observed:
// pion labels the forwarded track VP9), so the MimeType lookup lies. The bytes
// are our own VP8 tunnel frames; parse them as such. Also logs the first
// frames unconditionally so a live run shows whether anything decodes.
func ReadTrackForceVP8(track *webrtc.TrackRemote, handler func([]byte), logFn func(string, ...any), prefix string) {
	logFn("%s: reading track ssrc=%d pt=%d codec=%s as VP8 (forced)", prefix, track.SSRC(), track.PayloadType(), track.Codec().MimeType)
	readVP8Track(track, handler, logFn, prefix, true, nil)
}

// vpX reports the VP8 payload descriptor's extension bit as an int for logging.
func vpX(p codecs.VP8Packet) int {
	if p.X == 1 {
		return 1
	}
	return 0
}

// vp8FrameReassembler holds the per-track mutable state readVP8Track uses to
// turn a stream of RTP packets back into VP8 frames, plus the loss counters
// from Section 2 above. Split out of readVP8Track so it can be unit-tested
// with synthetic *rtp.Packet values instead of a live *webrtc.TrackRemote.
type vp8FrameReassembler struct {
	vp8Pkt       codecs.VP8Packet
	frameBuf     []byte
	lastSeq      uint16
	haveLastSeq  bool
	frameValid   bool
	recvCount    int
	recvPkts     int
	badCount     int
	stats        RecvStats
}

type feedResult struct {
	Frame        []byte
	IsDuplicate  bool
	UnmarshalErr error
	LogFirstPkts bool
	VP8S         uint8
	VP8PID       uint8
	VP8N         uint8
	VP8X         int
	LogFrame     bool
}

// feed processes one already-unmarshalled *rtp.Packet. It returns the
// completed frame (nil if none completed) and whether the packet was a
// valid VP8 packet.
func (r *vp8FrameReassembler) feed(pkt *rtp.Packet, verbose bool) (res feedResult) {
	r.stats.RecvPackets++

	if r.haveLastSeq {
		if pkt.SequenceNumber == r.lastSeq {
			res.IsDuplicate = true
			return res
		}
		if pkt.SequenceNumber != r.lastSeq+1 {
			r.stats.Gaps++
			r.stats.LostPackets += uint64(uint16(pkt.SequenceNumber - r.lastSeq))
			r.frameValid = false
			r.frameBuf = r.frameBuf[:0]
		}
	}
	r.lastSeq = pkt.SequenceNumber
	r.haveLastSeq = true

	vp8Payload, err := r.vp8Pkt.Unmarshal(pkt.Payload)
	if err != nil {
		res.UnmarshalErr = err
		r.badCount++
		r.frameValid = false
		r.frameBuf = r.frameBuf[:0]
		return res
	}

	res.LogFirstPkts = verbose && r.recvPkts < 6
	r.recvPkts++
	res.VP8S = r.vp8Pkt.S
	res.VP8PID = r.vp8Pkt.PID
	res.VP8N = r.vp8Pkt.N
	res.VP8X = vpX(r.vp8Pkt)

	if r.vp8Pkt.S == 1 {
		r.frameBuf = r.frameBuf[:0]
		r.frameValid = true
	}
	if !r.frameValid {
		return res
	}
	r.frameBuf = append(r.frameBuf, vp8Payload...)
	if !pkt.Marker {
		return res
	}
	r.recvCount++
	res.LogFrame = (common.Debug || verbose) && (r.recvCount <= 3 || r.recvCount%200 == 0)

	res.Frame = make([]byte, len(r.frameBuf))
	copy(res.Frame, r.frameBuf)

	r.frameBuf = r.frameBuf[:0]
	r.frameValid = false
	return res
}

func readVP8Track(track *webrtc.TrackRemote, handler func([]byte), logFn func(string, ...any), prefix string, verbose bool, onStats func(RecvStats)) {
	r := &vp8FrameReassembler{}
	buf := make([]byte, common.RTPBufSize)
	for {
		n, _, err := track.Read(buf)
		if err != nil {
			return
		}
		pkt := &rtp.Packet{}
		if pkt.Unmarshal(buf[:n]) != nil {
			continue
		}
		if len(pkt.Payload) == 0 {
			continue
		}

		res := r.feed(pkt, verbose)
		if res.IsDuplicate {
			continue
		}

		if onStats != nil {
			onStats(r.stats)
		}

		if res.UnmarshalErr != nil {
			if verbose && r.badCount <= 3 {
				logFn("%s: rtp pt=%d seq=%d marker=%v payload=%d bytes: not a VP8 packet: %v", prefix, pkt.PayloadType, pkt.SequenceNumber, pkt.Marker, len(pkt.Payload), res.UnmarshalErr)
			}
			continue
		}

		if res.LogFirstPkts {
			head := pkt.Payload
			if len(head) > 16 {
				head = head[:16]
			}
			logFn("%s: rtp pt=%d seq=%d ts=%d marker=%v S=%d X=%d N=%d PID=%d payload=%d bytes head=%x", prefix, pkt.PayloadType, pkt.SequenceNumber, pkt.Timestamp, pkt.Marker, res.VP8S, res.VP8X, res.VP8N, res.VP8PID, len(pkt.Payload), head)
		}

		if res.Frame != nil {
			if res.LogFrame {
				logFn("%s: recv vp8 frame #%d %d bytes", prefix, r.recvCount, len(res.Frame))
			}
			if handler != nil {
				handler(res.Frame)
			}
		}
	}
}
