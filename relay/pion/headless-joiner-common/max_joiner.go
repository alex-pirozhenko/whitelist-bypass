package joiner

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alex-pirozhenko/whitelist-bypass/relay/common"
	"github.com/alex-pirozhenko/whitelist-bypass/relay/maxproto"
	"github.com/alex-pirozhenko/whitelist-bypass/relay/tunnel"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/pion/webrtc/v4"
)

const maxMaxReconnectAttempts = 10

const (
	maxDefaultAPIHost         = "api2.oneme.ru"
	maxDefaultAppVersion      = "26.30.1"
	maxDefaultProtocolVersion = "5"
	maxDefaultCapabilities    = "1877f"
	maxDefaultClientType      = "ONE_ME"
	maxDefaultDevice          = "Google/Pixel 8"
	maxDefaultLocale          = "en"
	maxDefaultOSVersion       = "34"
	maxDefaultTunnelMode      = "dc"
)

// maxRoleAnswerer/maxRoleOfferer are vestigial: MAX/OK-Calls is a media-only
// SFU, not a symmetric peer, so there is no offerer/answerer distinction any
// more — the SFU is always the offerer for producer negotiation and the
// client is always the answerer (see MAX_OKCALLS_NOTES.md). The constants and
// MaxHeadlessAuthParams.Role are kept only so JSON payloads that still set
// "role" (e.g. from core/internal/joiner, server/internal/exitd in the
// letmeout repo, or cmd/maxjoin) keep decoding; the value is no longer read
// anywhere in the media/signaling logic below.
// OK-Calls conversation topologies. DIRECT = peer-to-peer (server is not a
// media relay); SERVER = SFU relays media. We always want SERVER.
const (
	maxTopologyDirect = "DIRECT"
	maxTopologyServer = "SERVER"
)

const (
	maxRoleOfferer  = "offerer"
	maxRoleAnswerer = "answerer"
)

// maxAuthRottenError mirrors vkAuthRottenError: wrapping a joinCall error in
// this type tells RunWithParams to surrender instead of looping forever on a
// dead token/device pairing.
type maxAuthRottenError struct {
	Msg string
}

func (e *maxAuthRottenError) Error() string {
	return fmt.Sprintf("auth rotten: %s", e.Msg)
}

// detectMaxAuthRotten is a heuristic over the unstructured error text
// maxproto.Client.Cmd produces (it folds the server's "error"/"localizedMessage"
// fields into one string), since MAX doesn't hand back a structured error code
// the way VK's HTTP join response does.
func detectMaxAuthRotten(err error) *maxAuthRottenError {
	if err == nil {
		return nil
	}
	lower := strings.ToLower(err.Error())
	markers := []string{
		"session_expired", "session expired",
		"auth_login", "session_not_found", "session not found",
		"invalid_session", "invalid session",
		"unauthorized", "token_expired", "token expired", "invalid token",
	}
	for _, marker := range markers {
		if strings.Contains(lower, marker) {
			return &maxAuthRottenError{Msg: err.Error()}
		}
	}
	return nil
}

// MaxHeadlessAuthParams is the JSON payload sent over the JOIN: stdin line to
// drive the MAX/OK-Calls joiner.
type MaxHeadlessAuthParams struct {
	Token          string `json:"token"`
	DeviceID       string `json:"deviceId"`
	APIHost        string `json:"apiHost"`
	JoinLink       string `json:"joinLink"`
	ConversationID string `json:"conversationId"`
	// Role is no longer read by the media layer (see maxRoleAnswerer doc
	// comment above) — kept for wire-compat with existing callers.
	Role string `json:"role"`
	// TunnelMode is no longer read: MAX is video-tunnel-only now (an SFU
	// cannot carry a DataChannel) — kept for wire-compat with existing callers.
	TunnelMode   string `json:"tunnelMode"`
	TunnelSecret string `json:"tunnelSecret"`

	// VP8FPS/VP8Batch configure the outbound VP8 tunnel track, mirroring
	// VKHeadlessAuthParams/TelemostHeadlessJoiner's RunWithParams fields. Zero
	// values fall back to tunnel.VP8DataTunnel's own defaults.
	VP8FPS   int `json:"vp8Fps"`
	VP8Batch int `json:"vp8Batch"`

	// CreateRoom, when true, makes joinCall create the room itself via op76
	// (VideoChatStart) on the same session before op166-joining it, then fills
	// JoinLink/ConversationID from the result. Used by the room-owning side
	// (the exit/offerer or a standalone room test). CalleeUID takes precedence
	// over CalleePhone (resolved via op46) for the op76 calleeIds.
	CreateRoom  bool   `json:"createRoom"`
	CalleePhone string `json:"calleePhone"`
	CalleeUID   int64  `json:"calleeUid"`

	// ws2 client params (all have defaults; only override if set).
	AppVersion      string `json:"appVersion"`
	ProtocolVersion string `json:"protocolVersion"`
	Capabilities    string `json:"capabilities"`
	ClientType      string `json:"clientType"`
	Device          string `json:"device"`
	Locale          string `json:"locale"`
	OSVersion       string `json:"osVersion"`
}

func (p *MaxHeadlessAuthParams) applyDefaults() {
	if p.APIHost == "" {
		p.APIHost = maxDefaultAPIHost
	}
	if p.AppVersion == "" {
		p.AppVersion = maxDefaultAppVersion
	}
	if p.ProtocolVersion == "" {
		p.ProtocolVersion = maxDefaultProtocolVersion
	}
	if p.Capabilities == "" {
		p.Capabilities = maxDefaultCapabilities
	}
	if p.ClientType == "" {
		p.ClientType = maxDefaultClientType
	}
	if p.Device == "" {
		p.Device = maxDefaultDevice
	}
	if p.Locale == "" {
		p.Locale = maxDefaultLocale
	}
	if p.OSVersion == "" {
		p.OSVersion = maxDefaultOSVersion
	}
	if p.Role == "" {
		p.Role = maxRoleAnswerer
	}
	if p.TunnelMode == "" {
		p.TunnelMode = maxDefaultTunnelMode
	}
}

type MaxHeadlessJoiner struct {
	logFn       func(string, ...any)
	OnConnected func(tunnel.DataTunnel)
	// OnRemoteCandidate is fired once for the SFU's producer-updated SDP offer
	// (target=-1) so callers can extract any inline candidates — e.g. the
	// Windows joiner installs /32 bypass routes to the SFU's own address
	// before applying the description. There is no more standalone trickle:
	// OK-Calls' SFU inlines every candidate in its offer.
	OnRemoteCandidate func(target int, candidateOrSDP string)
	ResolveFn         ResolveFunc
	Status            StatusEmitter
	PCConfig          PeerConnectionConfigurer
	AddTracks         AddTunnelTracksFunc
	ReadTrackFn       ReadTrackFunc

	params *MaxHeadlessAuthParams
	obf    *tunnel.TunnelObfuscator

	ctl *maxproto.Client
	ci  *maxproto.CallInfo

	selfUID    string
	selfAltUID string

	ws   *websocket.Conn
	wsMu sync.Mutex
	seq  int

	// sendFn, when non-nil, replaces the ws2 write in send() — used by tests
	// to capture outgoing commands without a real WebSocket connection.
	sendFn func(command string, fields map[string]interface{})

	pc          *webrtc.PeerConnection
	sampleTrack *webrtc.TrackLocalStaticSample
	vp8tunnel   *tunnel.VP8DataTunnel

	// producerSessionID is the last sessionId we accepted via accept-producer.
	// A producer-updated notification carrying the same sessionId again is a
	// duplicate/keepalive and must not re-trigger O/A; a different sessionId
	// is a new negotiation (mirrors the web client's
	// `producerSessionId !== e.sessionId` reconnect check).
	producerSessionID string

	configAck configAckTracker

	reconnectAttempt atomic.Int32
	stopCh           chan struct{}
	stopOnce         sync.Once
}

func NewMaxHeadlessJoiner(logFn func(string, ...any), resolveFn ResolveFunc, status StatusEmitter, pcConfig PeerConnectionConfigurer, addTracks AddTunnelTracksFunc, readTrackFn ReadTrackFunc) *MaxHeadlessJoiner {
	return &MaxHeadlessJoiner{
		logFn:       logFn,
		ResolveFn:   resolveFn,
		Status:      status,
		PCConfig:    pcConfig,
		AddTracks:   addTracks,
		ReadTrackFn: readTrackFn,
		stopCh:      make(chan struct{}),
	}
}

func (h *MaxHeadlessJoiner) MarkConfigAcked() { h.configAck.mark() }

func (h *MaxHeadlessJoiner) RunWithParams(jsonParams string) {
	var params MaxHeadlessAuthParams
	if err := json.Unmarshal([]byte(jsonParams), &params); err != nil {
		h.logFn("max-joiner: failed to parse auth params: %v", err)
		h.Status.EmitStatusError("bad params: " + err.Error())
		return
	}
	params.applyDefaults()
	h.params = &params

	// Validate an explicit tunnelSecret early (fast failure), but defer building
	// the obfuscator to joinCall: when CreateRoom is set the JoinLink — the
	// derive key when no explicit secret is given — is only known after op76.
	if params.TunnelSecret != "" {
		if _, err := base64.StdEncoding.DecodeString(params.TunnelSecret); err != nil {
			h.logFn("max-joiner: bad tunnelSecret: %v", err)
			h.Status.EmitStatusError("bad tunnelSecret: " + err.Error())
			return
		}
	}
	h.logFn("max-joiner: auth params received vp8Fps=%d vp8Batch=%d", params.VP8FPS, params.VP8Batch)

	h.Status.EmitStatus(common.StatusConnecting)
	if err := h.runOnce(); err != nil {
		h.logFn("max-joiner: %v", err)
		h.Status.EmitStatusError(err.Error())
		return
	}

	for {
		if h.isClosed() {
			return
		}
		h.Status.EmitStatus(common.StatusTunnelLost)
		if !h.waitBeforeRetry(int(h.reconnectAttempt.Load())) {
			return
		}
		attempt := h.reconnectAttempt.Add(1)
		if h.isClosed() {
			return
		}
		if int(attempt) > maxMaxReconnectAttempts {
			h.logFn("max-joiner: gave up after %d consecutive reconnect attempts", maxMaxReconnectAttempts)
			h.Status.EmitStatusError("reconnect attempts exhausted")
			return
		}
		h.logFn("max-joiner: reconnect attempt #%d", attempt)
		h.Status.EmitStatus(common.StatusReconnecting)
		if err := h.runOnce(); err != nil {
			var authRotten *maxAuthRottenError
			if errors.As(err, &authRotten) {
				h.logFn("max-joiner: %v, surrendering", err)
				h.Status.EmitStatusError("call failed: " + err.Error())
				return
			}
			h.logFn("max-joiner: %v, will retry", err)
		}
	}
}

func (h *MaxHeadlessJoiner) runOnce() error {
	h.resetSessionState()
	if err := h.joinCall(); err != nil {
		return err
	}
	return h.connectSignaling()
}

func (h *MaxHeadlessJoiner) waitBeforeRetry(attempt int) bool {
	return waitReconnectBackoff(attempt, h.logFn, "max-joiner", h.stopCh, h.isClosed)
}

func (h *MaxHeadlessJoiner) isClosed() bool {
	select {
	case <-h.stopCh:
		return true
	default:
		return false
	}
}

func (h *MaxHeadlessJoiner) resetSessionState() {
	h.wsMu.Lock()
	ws := h.ws
	h.ws = nil
	h.seq = 0
	h.wsMu.Unlock()
	if ws != nil {
		ws.Close()
	}
	if h.vp8tunnel != nil {
		h.vp8tunnel.Stop()
		h.vp8tunnel = nil
	}
	if h.pc != nil {
		h.pc.Close()
		h.pc = nil
	}
	if h.ctl != nil {
		h.ctl.Close()
		h.ctl = nil
	}
	h.sampleTrack = nil
	h.producerSessionID = ""
	h.ci = nil
	h.selfUID = ""
	h.selfAltUID = ""
}

func (h *MaxHeadlessJoiner) Close() {
	h.stopOnce.Do(func() { close(h.stopCh) })
	h.wsMu.Lock()
	ws := h.ws
	h.ws = nil
	h.wsMu.Unlock()
	if ws != nil {
		ws.Close()
	}
	if h.vp8tunnel != nil {
		h.vp8tunnel.Stop()
	}
	if h.pc != nil {
		h.pc.Close()
	}
	if h.ctl != nil {
		h.ctl.Close()
	}
}

func (h *MaxHeadlessJoiner) closeTransport() {
	h.wsMu.Lock()
	ws := h.ws
	h.wsMu.Unlock()
	if ws != nil {
		ws.Close()
	}
}

// joinCall drives the maxproto control connection: connect, session-init,
// login, then op166 (VideoChatJoin) to obtain the ws2 CallInfo.
// buildObfuscator constructs the tunnel obfuscator from an explicit
// TunnelSecret (base64) or, failing that, derives it from the final JoinLink.
// Called from joinCall after JoinLink is known (so CreateRoom works).
func (h *MaxHeadlessJoiner) buildObfuscator() error {
	var secret []byte
	if h.params.TunnelSecret != "" {
		decoded, err := base64.StdEncoding.DecodeString(h.params.TunnelSecret)
		if err != nil {
			return fmt.Errorf("bad tunnelSecret: %w", err)
		}
		secret = decoded
	} else {
		secret = tunnel.DeriveSecretFromJoinLink(h.params.JoinLink)
	}
	obf, err := tunnel.NewTunnelObfuscator(secret)
	if err != nil {
		return fmt.Errorf("obfuscator init: %w", err)
	}
	h.obf = obf
	h.logFn("max-joiner: obf key-source=%q localEpoch=0x%08x", h.params.JoinLink, obf.LocalEpoch())
	return nil
}

func (h *MaxHeadlessJoiner) joinCall() error {
	p := h.params
	h.ctl = maxproto.New(p.Token, p.DeviceID)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if err := h.ctl.Connect(ctx, maxproto.ResolveFunc(h.ResolveFn)); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	if _, err := h.ctl.SessionInit(ctx); err != nil {
		return fmt.Errorf("session init: %w", err)
	}
	if _, err := h.ctl.Login(ctx); err != nil {
		if rotten := detectMaxAuthRotten(err); rotten != nil {
			return rotten
		}
		return fmt.Errorf("login: %w", err)
	}

	if p.CreateRoom {
		calleeUID := p.CalleeUID
		if calleeUID == 0 && p.CalleePhone != "" {
			uid, rerr := h.ctl.ResolveUID(ctx, p.CalleePhone)
			if rerr != nil {
				return fmt.Errorf("resolve callee %s: %w", p.CalleePhone, rerr)
			}
			calleeUID = uid
		}
		if calleeUID == 0 {
			return fmt.Errorf("createRoom set but no calleeUid/calleePhone resolved")
		}
		if p.ConversationID == "" {
			p.ConversationID = uuid.NewString()
		}
		startResp, serr := h.ctl.VideoChatStart(ctx, []int64{calleeUID}, p.ConversationID)
		if serr != nil {
			return fmt.Errorf("video chat start (op76): %w", serr)
		}
		jl, _ := startResp["joinLink"].(string)
		if jl == "" {
			return fmt.Errorf("op76 returned no joinLink")
		}
		p.JoinLink = jl
		h.logFn("max-joiner: created room joinLink=%s conv=%s", jl, p.ConversationID)
	}

	// Build the obfuscator now that JoinLink is final (both peers must derive
	// the same secret: an explicit TunnelSecret, else DeriveSecretFromJoinLink).
	if err := h.buildObfuscator(); err != nil {
		return err
	}

	resp, err := h.ctl.VideoChatJoin(ctx, p.JoinLink, maxproto.BuildInternalParams(p.DeviceID), p.ConversationID)
	if err != nil {
		return fmt.Errorf("video chat join: %w", err)
	}
	ci, err := maxproto.ParseCallInfo(resp)
	if err != nil {
		return fmt.Errorf("parse call info: %w", err)
	}
	if ci.Endpoint == "" {
		return fmt.Errorf("empty endpoint in call info")
	}
	h.ci = ci
	// ws2 notifications address participants by their INTERNAL id (the same
	// value as the endpoint's userId=), not the external one.
	h.selfUID = fmt.Sprint(ci.ID.Internal)
	h.selfAltUID = fmt.Sprint(ci.ID.External)
	h.logFn("max-joiner: joined call self=%s endpoint=%s turn=%v", h.selfUID, ci.Endpoint, ci.Turn.URLs)
	return nil
}

// buildWSURL augments CallInfo.Endpoint with the client query params the
// server requires to accept the ws2 upgrade (see okcalls_peer.py
// _full_ws_url). Without these the server accepts the handshake but then
// replies {"type":"error","error":"invalid-request"}.
func (h *MaxHeadlessJoiner) buildWSURL() string {
	p := h.params
	base := h.ci.Endpoint

	clientType := p.ClientType
	if clientType == "" {
		clientType = h.ci.ClientType
	}
	if clientType == "" {
		clientType = maxDefaultClientType
	}

	values := url.Values{}
	values.Set("version", p.ProtocolVersion)
	values.Set("capabilities", p.Capabilities)
	values.Set("platform", "ANDROID")
	values.Set("clientType", clientType)
	values.Set("appVersion", p.AppVersion)
	values.Set("device", p.Device)
	values.Set("locale", p.Locale)
	values.Set("osVersion", p.OSVersion)

	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + values.Encode()
}

func (h *MaxHeadlessJoiner) connectSignaling() error {
	wsURL := h.buildWSURL()
	parsed, err := url.Parse(wsURL)
	if err != nil {
		return fmt.Errorf("bad ws url: %w", err)
	}
	hostname := parsed.Hostname()
	resolvedIP, err := h.ResolveFn(hostname)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", hostname, err)
	}
	h.logFn("max-joiner: resolved %s -> %s", common.MaskAddr(hostname), common.MaskAddr(resolvedIP))

	wsHeader := http.Header{}
	wsHeader.Set("User-Agent", common.UserAgent)

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		WriteBufferSize:  65536,
		// The ws2 host (videowebrtc.okcdn.ru) is issued by a publicly trusted CA
		// (HARICA), so it verifies against the system roots — no special CA and
		// no InsecureSkipVerify here. Only api2.oneme.ru needs the scoped
		// Russian CA pool, which lives in maxproto and applies to that dial alone.
		// We connect to a pre-resolved IP, so ServerName drives verification.
		TLSClientConfig: &tls.Config{ServerName: hostname},
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(addr)
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, resolvedIP+":"+port)
		},
	}

	h.logFn("max-joiner: connecting to %s", wsURL)
	ws, resp, err := dialer.Dial(wsURL, wsHeader)
	if err != nil {
		status := "?"
		body := ""
		if resp != nil {
			status = resp.Status
			if b, readErr := io.ReadAll(resp.Body); readErr == nil {
				body = string(b)
			}
			resp.Body.Close()
		}
		h.logFn("max-joiner: ws dial failed: %s (status=%s body=%s)", common.MaskError(err), status, body)
		return fmt.Errorf("ws connect: %w", err)
	}
	h.wsMu.Lock()
	h.ws = ws
	h.seq = 0
	h.wsMu.Unlock()
	h.logFn("max-joiner: ws2 connected self=%s", h.selfUID)

	// Declare media settings immediately, mirroring vk_joiner (VK Calls == this
	// OK-Calls stack). The SFU does not begin ICE/media until the client states
	// its media settings; without this, connectivity checks go unanswered and
	// ICE fails. isVideoEnabled MUST be true: the tunnel now rides a VP8 video
	// track through the SFU (an SFU is media-only, it cannot carry a
	// DataChannel — see MAX_OKCALLS_NOTES.md).
	h.send("update-media-modifiers", map[string]interface{}{
		"mediaModifiers": map[string]interface{}{"denoise": true, "denoiseAnn": true},
	})
	h.send("change-media-settings", map[string]interface{}{
		"mediaSettings": map[string]interface{}{
			"isAudioEnabled": false, "isVideoEnabled": true,
			"isScreenSharingEnabled": false, "isFastScreenSharingEnabled": false,
			"isAudioSharingEnabled": false, "isAnimojiEnabled": false,
		},
	})

	// NOTE: the PeerConnection is NOT built here. The ws2 "connection"
	// notification carries the TURN/STUN credentials that are actually valid
	// for this ws2 session (op166's CallInfo ones are a different, earlier
	// grant), and using the stale pair makes the TURN server answer
	// CreatePermission with "403 Forbidden IP". handleConnection overrides the
	// ICE servers and then calls initPC — same order as vk_joiner.go.

	h.readLoop()
	return nil
}

// handleConnection processes the ws2 "connection" notification, which is the
// authoritative source of this session's ICE servers: conversationParams.turn
// carries time-and-user-bound credentials ("<expiry>:<userId>") that differ
// from the ones op166's CallInfo returned. Building the PeerConnection with
// the stale CallInfo pair makes TURN reject CreatePermission with "403
// Forbidden IP", so ICE can never leave checking. Mirrors vk_joiner.go: adopt
// the credentials, then build the PC, then kick off the SFU's producer/
// consumer allocation with allocate-consumer.
func (h *MaxHeadlessJoiner) handleConnection(m map[string]interface{}) {
	topology := ""
	if conv, ok := m["conversation"].(map[string]interface{}); ok {
		topology, _ = conv["topology"].(string)
		h.logFn("max-joiner: <- connection topology=%v state=%v", conv["topology"], conv["state"])
	}

	if cp, ok := m["conversationParams"].(map[string]interface{}); ok {
		if turn, ok := cp["turn"].(map[string]interface{}); ok {
			urls := toStringSlice(turn["urls"])
			if len(urls) > 0 {
				h.ci.Turn.URLs = urls
				h.ci.Turn.Username, _ = turn["username"].(string)
				h.ci.Turn.Credential, _ = turn["credential"].(string)
				h.logFn("max-joiner: TURN from connection: %v", urls)
			}
		}
		if stun, ok := cp["stun"].(map[string]interface{}); ok {
			if urls := toStringSlice(stun["urls"]); len(urls) > 0 {
				h.ci.Stun.URLs = urls
			}
		}
	}

	if h.pc == nil {
		h.initPC()
		// A 2-party call starts in DIRECT (peer-to-peer) topology, where the
		// server is NOT a media relay — so it never produces anything for us to
		// consume and no producer-updated ever arrives. Ask it to switch to
		// SERVER, which is both the only topology whose producer/consumer flow
		// we can drive and the only one we want: under a censor's allowlist just
		// the MAX/OK servers are reachable, never the peer. The web client does
		// exactly this as its p2p fallback ("Unable to switch topology DIRECT to
		// SERVER"): switchTopology(topology, force) -> {topology, force}.
		if topology != maxTopologyServer {
			h.sendSwitchTopology()
		}
		h.sendAllocateConsumer()
	}
}

// sendSwitchTopology asks the conversation to move to SERVER (SFU) topology.
func (h *MaxHeadlessJoiner) sendSwitchTopology() {
	h.send("switch-topology", map[string]interface{}{
		"topology": maxTopologyServer,
		"force":    true,
	})
	h.logFn("max-joiner: -> switch-topology %s (force)", maxTopologyServer)
}

// toStringSlice converts a decoded JSON array into []string, skipping non-strings.
func toStringSlice(v interface{}) []string {
	raw, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// initPC builds the single PeerConnection used for the whole SFU session:
// MAX/OK-Calls is a media-only SFU (mediasoup-style), the SFU is always the
// OFFERER, and the client is always the answerer — there is no peer
// offerer/answerer role any more. Tunnel bytes ride a VP8 media track
// (AddTracks/ReadTrackFn), mirroring telemost_joiner.go's video mode and
// vk_joiner.go's "video" TunnelMode branch. There is no DataChannel: an SFU
// cannot carry SCTP.
func (h *MaxHeadlessJoiner) initPC() {
	var iceServers []webrtc.ICEServer
	if len(h.ci.Stun.URLs) > 0 {
		iceServers = append(iceServers, webrtc.ICEServer{URLs: h.ci.Stun.URLs})
	}
	if len(h.ci.Turn.URLs) > 0 {
		iceServers = append(iceServers, webrtc.ICEServer{
			URLs:       h.ci.Turn.URLs,
			Username:   h.ci.Turn.Username,
			Credential: h.ci.Turn.Credential,
		})
	}

	settingEngine := webrtc.SettingEngine{}
	settingEngine.DisableCloseByDTLS(true)
	// No DetachDataChannels(): there is no DataChannel any more.
	if h.PCConfig != nil {
		h.PCConfig.ConfigureSettingEngine(&settingEngine)
	}

	pc, err := webrtc.NewAPI(webrtc.WithSettingEngine(settingEngine)).NewPeerConnection(webrtc.Configuration{
		ICEServers: iceServers,
	})
	if err != nil {
		h.logFn("max-joiner: failed to create PC: %v", err)
		return
	}
	h.pc = pc

	h.sampleTrack = h.AddTracks(pc, h.logFn, "max-joiner")

	pc.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		h.logFn("max-joiner: remote track: codec=%s ssrc=%d", track.Codec().MimeType, track.SSRC())
		go h.ReadTrackFn(track, func(frame []byte) {
			if h.vp8tunnel != nil {
				h.vp8tunnel.HandleFrame(frame)
			}
		}, h.logFn, "max-joiner")
	})

	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		h.logFn("max-joiner: PC state: %s", state.String())
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateDisconnected {
			h.logFn("max-joiner: PC %s, closing transport to trigger reconnect", state.String())
			h.closeTransport()
			return
		}
		if state == webrtc.PeerConnectionStateConnected && h.vp8tunnel == nil {
			h.reconnectAttempt.Store(0)
			h.logFn("max-joiner: === VP8 TUNNEL CONNECTED ===")
			h.Status.EmitStatus(common.StatusTunnelConnected)
			h.vp8tunnel = tunnel.NewVP8DataTunnel(h.sampleTrack, h.obf, h.logFn)
			vp8tun := h.vp8tunnel
			vp8tun.Start(h.params.VP8FPS, h.params.VP8Batch)
			if !h.configAck.acknowledged() {
				acked, cancel := h.configAck.arm()
				go sendVP8ConfigUntilAcked(acked, cancel, h.stopCh, vp8tun,
					vp8tun.FPS(), vp8tun.Batch(), 1, h.logFn, "max-joiner")
				h.logFn("max-joiner: pushed vp8 config to creator fps=%d batch=%d", vp8tun.FPS(), vp8tun.Batch())
			}
			if h.OnConnected != nil {
				h.OnConnected(vp8tun)
			}
		}
	})

	h.logFn("max-joiner: PC ready with %d ICE servers, waiting for SFU producer offer", len(iceServers))
}

// sendAllocateConsumer sets up the receive side of the SFU session. The web
// client's allocateConsumer(desc, capabilities) sends
// {capabilities, description: desc?.sdp} — on the very first call desc is
// null, and JSON.stringify drops the resulting undefined "description" key
// entirely, so the wire payload is just {"capabilities": ...} (see
// MAX_OKCALLS_NOTES.md).
//
// "capabilities" is a STRUCTURED feature descriptor, not the hex bitmask used
// in the ws2 URL/internalParams — sending the hex string gets
// {"error":"invalid-request","message":"Invalid message format"}. The exact
// shape below is taken from the web client's capabilities getter (web.max.ru
// bundle: `function t(){return{estimatedPerformanceIndex:...,transparentAudio:...}}`).
// We advertise a single video track (our VP8 tunnel) and disable everything we
// do not implement (screen share, simulcast, audio share, animoji, ASR).
func (h *MaxHeadlessJoiner) sfuCapabilities() map[string]interface{} {
	return map[string]interface{}{
		"estimatedPerformanceIndex": 1,
		"audioMix":                  true,
		"consumerUpdate":            true,
		// DataChannel protocol versions the SFU negotiates for its own control
		// channels; mirror the web client's values verbatim.
		"producerNotificationDataChannelVersion": 8,
		"producerCommandDataChannelVersion":      3,
		"consumerScreenDataChannelVersion":       1,
		"producerScreenDataChannelVersion":       1,
		"asrDataChannelVersion":                  0,
		"animojiDataChannelVersion":              1,
		"animojiBackendRender":                   false,
		"onDemandTracks":                         true,
		"unifiedPlan":                            true,
		"singleSession":                          true,
		"videoTracksCount":                       1,
		"red":                                    true,
		"audioShare":                             false,
		"fastScreenShare":                        false,
		"videoSuspend":                           false,
		"simulcast":                              false,
		"simulcastNativeOrder":                   true,
		"consumerFastScreenShare":                false,
		"consumerFastScreenShareQualityOnDemand": false,
		"transparentAudio":                       false,
	}
}

func (h *MaxHeadlessJoiner) sendAllocateConsumer() {
	h.send("allocate-consumer", map[string]interface{}{
		"capabilities": h.sfuCapabilities(),
	})
	h.logFn("max-joiner: -> allocate-consumer (structured capabilities)")
}

// parseSFUDescription decodes a producer-updated notification's "description"
// field. GUESS (per spec): it may arrive as a raw SDP string or as a
// {type, sdp} object; either way it is the SFU's SDP OFFER (the SFU is always
// the offerer for producer negotiation) unless an explicit "type" says
// otherwise.
func parseSFUDescription(raw interface{}) (webrtc.SessionDescription, bool) {
	switch v := raw.(type) {
	case string:
		if v == "" {
			return webrtc.SessionDescription{}, false
		}
		return webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: v}, true
	case map[string]interface{}:
		sdpStr, _ := v["sdp"].(string)
		if sdpStr == "" {
			return webrtc.SessionDescription{}, false
		}
		sdpType := webrtc.SDPTypeOffer
		if typeStr, ok := v["type"].(string); ok && typeStr != "" {
			if t := webrtc.NewSDPType(typeStr); t != webrtc.SDPTypeUnknown {
				sdpType = t
			}
		}
		return webrtc.SessionDescription{Type: sdpType, SDP: sdpStr}, true
	default:
		return webrtc.SessionDescription{}, false
	}
}

// extractSSRCs pulls every distinct SSRC advertised in an SDP's "a=ssrc:<id>
// ..." attribute lines, in first-seen order, as decimal strings. Mirrors the
// web client's `Object.keys(ssrcMap)` for acceptProducer's "ssrcs" field (see
// MAX_OKCALLS_NOTES.md) — GUESS: deriving from our own answer SDP rather than
// from the sender's RTCRtpSender parameters, which pion does not expose as
// directly; VERIFY LIVE that the SFU accepts SSRCs sourced this way.
func extractSSRCs(sdp string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, line := range strings.Split(sdp, "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, "a=ssrc:") {
			continue
		}
		rest := strings.TrimPrefix(line, "a=ssrc:")
		id := rest
		if i := strings.IndexByte(rest, ' '); i >= 0 {
			id = rest[:i]
		}
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// gatheredLocalDescription blocks until ICE gathering finishes and returns the
// local description with every candidate inlined in the SDP (non-trickle).
// Falls back to the ungathered description if gathering stalls.
func (h *MaxHeadlessJoiner) gatheredLocalDescription(fallback webrtc.SessionDescription) webrtc.SessionDescription {
	select {
	case <-webrtc.GatheringCompletePromise(h.pc):
		if ld := h.pc.LocalDescription(); ld != nil {
			h.logFn("max-joiner: ICE gathering complete, sending full SDP")
			return *ld
		}
	case <-time.After(15 * time.Second):
		h.logFn("max-joiner: ICE gathering timed out, sending SDP as-is")
	case <-h.stopCh:
	}
	return fallback
}

// handleProducerUpdated implements the SFU's producer/consumer offer-answer:
// the SFU sends its SDP offer (asking us to send our VP8 tunnel track), we
// answer, then push the answer back as accept-producer along with the SSRCs
// of what we're sending. A repeated sessionId is a duplicate/keepalive
// notification, not a new negotiation, and is ignored (mirrors the web
// client's `producerSessionId !== e.sessionId` reconnect check — see spec).
func (h *MaxHeadlessJoiner) handleProducerUpdated(m map[string]interface{}) {
	if h.pc == nil {
		h.logFn("max-joiner: producer-updated but PC not ready, ignoring")
		return
	}
	sessionID := fmt.Sprint(m["sessionId"])
	if sessionID != "" && sessionID == h.producerSessionID {
		h.logFn("max-joiner: producer-updated duplicate sessionId=%s, ignoring", sessionID)
		return
	}
	desc, ok := parseSFUDescription(m["description"])
	if !ok {
		h.logFn("max-joiner: producer-updated missing/unparseable description")
		return
	}
	if h.OnRemoteCandidate != nil {
		h.OnRemoteCandidate(-1, desc.SDP)
	}
	h.logFn("max-joiner: <- producer-updated sessionId=%s [%s]", sessionID, sdpUfragSummary(desc.SDP))
	if os.Getenv("MAX_SDP_DEBUG") != "" {
		h.logFn("max-joiner: SFU OFFER SDP:\n%s", desc.SDP)
	}

	if err := h.pc.SetRemoteDescription(desc); err != nil {
		h.logFn("max-joiner: set remote description (producer offer) failed: %v", err)
		return
	}
	answer, err := h.pc.CreateAnswer(nil)
	if err != nil {
		h.logFn("max-joiner: create answer failed: %v", err)
		return
	}
	if err := h.pc.SetLocalDescription(answer); err != nil {
		h.logFn("max-joiner: set local description failed: %v", err)
		return
	}

	final := h.gatheredLocalDescription(answer)
	ssrcs := extractSSRCs(final.SDP)
	h.producerSessionID = sessionID
	h.logFn("max-joiner: -> accept-producer sessionId=%s ssrcs=%v [%s]", sessionID, ssrcs, sdpUfragSummary(final.SDP))
	h.send("accept-producer", map[string]interface{}{
		"description": final.SDP,
		"sessionId":   m["sessionId"],
		"ssrcs":       ssrcs,
	})
}

// sdpUfragSummary reports an SDP's session ice-ufrag and the distinct "ufrag"
// attributes on its candidate lines, for diagnostic logging.
func sdpUfragSummary(sdp string) string {
	sess := "?"
	seen := map[string]int{}
	for _, line := range strings.Split(sdp, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "a=ice-ufrag:") {
			sess = strings.TrimPrefix(line, "a=ice-ufrag:")
			continue
		}
		if strings.HasPrefix(line, "a=candidate:") {
			if i := strings.Index(line, " ufrag "); i >= 0 {
				f := strings.Fields(line[i+7:])
				if len(f) > 0 {
					seen[f[0]]++
					continue
				}
			}
			seen["(none)"]++
		}
	}
	return fmt.Sprintf("sessUfrag=%s candUfrags=%v", sess, seen)
}

// send is the generic ws2 command sender: {"command":cmd,"sequence":n, ...fields}.
func (h *MaxHeadlessJoiner) send(command string, fields map[string]interface{}) {
	h.wsMu.Lock()
	defer h.wsMu.Unlock()
	if h.sendFn == nil && h.ws == nil {
		return
	}
	h.seq++
	fields["command"] = command
	fields["sequence"] = h.seq
	if h.sendFn != nil {
		h.sendFn(command, fields)
		return
	}
	if err := h.ws.WriteJSON(fields); err != nil {
		h.logFn("max-joiner: ws write failed: %v", err)
	}
}

func (h *MaxHeadlessJoiner) readLoop() {
	h.wsMu.Lock()
	ws := h.ws
	h.wsMu.Unlock()
	if ws == nil {
		return
	}
	for {
		_, raw, err := ws.ReadMessage()
		if err != nil {
			h.logFn("max-joiner: ws read error: %s", common.MaskError(err))
			h.Status.EmitStatus(common.StatusTunnelLost)
			return
		}
		h.handleMessage(raw)
	}
}

// handleMessage dispatches ws2 notifications. Unlike the old peer-transport
// design, there is no more per-peer address to learn (learnPeer/peerAddr are
// gone): every notification is either about the SFU session itself
// (connection, producer-updated, consumer-answered, topology-changed) or is
// informational.
func (h *MaxHeadlessJoiner) handleMessage(raw []byte) {
	// UseNumber so a peer's 16-digit internal participantId keeps its exact
	// integer form: a plain interface{} decode yields float64, and fmt.Sprint
	// of that renders scientific notation ("1.125...e+15").
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]interface{}
	if err := dec.Decode(&m); err != nil {
		return
	}

	if msgType, ok := m["type"].(string); ok && msgType == "error" {
		h.logFn("max-joiner: ERROR from server: %v (raw=%s)", m["error"], string(raw))
		return
	}

	notif, _ := m["notification"].(string)
	if notif == "" {
		return
	}

	switch notif {
	case "connection":
		h.handleConnection(m)
	case "producer-updated":
		h.handleProducerUpdated(m)
	case "consumer-answered":
		// Confirms our allocate-consumer; nothing else to do.
		h.logFn("max-joiner: <- consumer-answered sessionId=%v", m["sessionId"])
	case "topology-changed":
		// Unlike VK (which forces a reconnect off-DIRECT), we WANT the SFU's
		// server topology here — do not force-close. A 2-party call runs in
		// DIRECT, where the server relays no media and never produces anything;
		// it flips to SERVER on its own once a third participant joins. The
		// allocate-consumer we sent while still in DIRECT does not carry over,
		// so re-allocate now that an SFU actually exists — otherwise no
		// producer-updated ever arrives.
		topo, _ := m["topology"].(string)
		h.logFn("max-joiner: <- topology-changed topology=%v", m["topology"])
		if topo == maxTopologyServer {
			h.logFn("max-joiner: SERVER topology active, re-allocating consumer")
			h.sendAllocateConsumer()
		}
	case "settings-update":
		h.logFn("max-joiner: <- %s", notif)
	default:
		h.logFn("max-joiner: <- notification %s", notif)
	}
}
