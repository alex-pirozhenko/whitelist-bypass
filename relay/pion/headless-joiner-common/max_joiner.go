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
	Role           string `json:"role"`
	TunnelMode     string `json:"tunnelMode"`
	TunnelSecret   string `json:"tunnelSecret"`

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

// maxPeerAddr is the ws2 "address" of the remote participant, learned from
// notifications (see learnPeer) and used on every transmit-data send.
type maxPeerAddr struct {
	ParticipantID   string
	ParticipantType string
	DeviceIdx       int
}

type MaxHeadlessJoiner struct {
	logFn       func(string, ...any)
	OnConnected func(tunnel.DataTunnel)
	// OnRemoteCandidate is fired for every trickle ICE candidate the OK-Calls
	// server relays, and once per incoming SDP (target=-1) so callers can
	// extract any candidates carried inline.
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

	peerMu          sync.Mutex
	peerAddr        *maxPeerAddr
	pendingLocalICE []interface{}

	pc         *webrtc.PeerConnection
	dc         *webrtc.DataChannel
	remoteSet  bool
	pendingICE []webrtc.ICECandidateInit

	offerOnce sync.Once

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

// MarkConfigAcked is a no-op: DC tunnel mode (the only mode MAX supports)
// never pushes a VP8 config, but the method is kept for interface parity
// with the VK/Telemost joiners.
func (h *MaxHeadlessJoiner) MarkConfigAcked() {}

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
	h.logFn("max-joiner: auth params received role=%s tunnelMode=%s", params.Role, params.TunnelMode)

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
	if h.dc != nil {
		h.dc.Close()
		h.dc = nil
	}
	if h.pc != nil {
		h.pc.Close()
		h.pc = nil
	}
	if h.ctl != nil {
		h.ctl.Close()
		h.ctl = nil
	}
	h.remoteSet = false
	h.pendingICE = nil
	h.peerMu.Lock()
	h.peerAddr = nil
	h.pendingLocalICE = nil
	h.peerMu.Unlock()
	h.offerOnce = sync.Once{}
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
	// value as the endpoint's userId=), not the external one. Track both so
	// learnPeer can never mistake one of our own ids for the peer's — getting
	// this wrong makes a peer send its ICE candidates to itself and ICE fails.
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
	// ICE fails. Data-only tunnel, so audio/video/screen are all disabled.
	h.send("update-media-modifiers", map[string]interface{}{
		"mediaModifiers": map[string]interface{}{"denoise": true, "denoiseAnn": true},
	})
	h.send("change-media-settings", map[string]interface{}{
		"mediaSettings": map[string]interface{}{
			"isAudioEnabled": false, "isVideoEnabled": false,
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

	if h.params.Role == maxRoleOfferer {
		go func() {
			select {
			case <-time.After(3 * time.Second):
				h.maybeSendOffer()
			case <-h.stopCh:
			}
		}()
	}

	h.readLoop()
	return nil
}

// initPC mirrors vk_joiner.go's DC-mode PC setup, but uses a NON-negotiated
// DataChannel (offerer creates "tunnel", answerer waits on OnDataChannel) —
// this matches the proven okcalls_peer.py PoC. VK's negotiated id=2 approach
// is unproven on the OK-Calls SFU and must not be used here.
// handleConnection processes the ws2 "connection" notification, which is the
// authoritative source of this session's ICE servers: conversationParams.turn
// carries time-and-user-bound credentials ("<expiry>:<userId>") that differ
// from the ones op166's CallInfo returned. Building the PeerConnection with
// the stale CallInfo pair makes TURN reject CreatePermission with "403
// Forbidden IP", so ICE can never leave checking. Mirrors vk_joiner.go:
// adopt the credentials, then build the PC.
func (h *MaxHeadlessJoiner) handleConnection(m map[string]interface{}) {
	if conv, ok := m["conversation"].(map[string]interface{}); ok {
		// DIRECT is the peer-to-peer topology this transport relies on.
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
	}
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
	settingEngine.DetachDataChannels()
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

	h.logFn("max-joiner: role=%s tunnelMode=%s", h.params.Role, h.params.TunnelMode)

	if h.params.Role == maxRoleOfferer {
		dc, err := pc.CreateDataChannel("tunnel", nil)
		if err != nil {
			h.logFn("max-joiner: warning: could not create tunnel DC: %v", err)
		} else {
			h.onTunnelDC(dc)
		}
	} else {
		pc.OnDataChannel(func(dc *webrtc.DataChannel) {
			h.logFn("max-joiner: remote DataChannel: label=%q id=%v", dc.Label(), dc.ID())
			if dc.Label() == "tunnel" {
				h.onTunnelDC(dc)
			}
		})
	}

	pc.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			return
		}
		h.onLocalICECandidate(candidate)
	})
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		h.logFn("max-joiner: PC state: %s", state.String())
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateDisconnected {
			h.logFn("max-joiner: PC %s, closing transport to trigger reconnect", state.String())
			h.closeTransport()
		}
	})

	h.logFn("max-joiner: PC ready, role=%s", h.params.Role)
}

func (h *MaxHeadlessJoiner) onTunnelDC(dc *webrtc.DataChannel) {
	h.dc = dc
	dc.OnOpen(func() {
		h.logFn("max-joiner: tunnel DC open")
		h.reconnectAttempt.Store(0)
		h.logFn("max-joiner: === DC TUNNEL CONNECTED ===")
		h.Status.EmitStatus(common.StatusTunnelConnected)
		if h.OnConnected != nil {
			h.OnConnected(tunnel.NewDCTunnel(dc, h.obf, common.RTPBufSize, h.logFn))
		}
	})
	dc.OnClose(func() {
		h.logFn("max-joiner: tunnel DC closed")
	})
}

func (h *MaxHeadlessJoiner) onLocalICECandidate(candidate *webrtc.ICECandidate) {
	candidateJSON := candidate.ToJSON()
	raw, _ := json.Marshal(candidateJSON)
	var parsed interface{}
	json.Unmarshal(raw, &parsed)

	// Trickle every local candidate to the SFU, mirroring the proven vk_joiner
	// (VK Calls runs on this same OK-Calls stack): OK-Calls terminates ICE at
	// the server, and the server needs our candidates to run connectivity
	// checks toward us. Buffer until the peer/SFU address is learned, then flush.
	h.peerMu.Lock()
	addr := h.peerAddr
	if addr == nil {
		h.pendingLocalICE = append(h.pendingLocalICE, parsed)
		h.peerMu.Unlock()
		h.logFn("max-joiner: local ICE candidate buffered (peer unknown): %s", candidate.Typ)
		return
	}
	h.peerMu.Unlock()
	h.logFn("max-joiner: -> local ICE candidate (%s)", candidate.Typ)
	h.sendTransmitData(addr, map[string]interface{}{"candidate": parsed})
}

// maybeSendOffer sends the initial offer exactly once, and only once the
// peer's participantId has been learned (or, as a last resort, derived from
// CallInfo.PeerID). Guarded by offerOnce so concurrent triggers (the 3s
// timer, learnPeer, and participant-joined/registered-peer notifications)
// only produce a single offer per session.
func (h *MaxHeadlessJoiner) maybeSendOffer() {
	if h.params == nil || h.params.Role != maxRoleOfferer {
		return
	}
	h.peerMu.Lock()
	addr := h.peerAddr
	h.peerMu.Unlock()
	if addr == nil {
		if h.ci != nil && h.ci.PeerID != nil {
			addr = &maxPeerAddr{ParticipantID: fmt.Sprint(h.ci.PeerID), ParticipantType: "USER", DeviceIdx: 0}
		} else {
			return
		}
	}
	h.offerOnce.Do(func() {
		h.sendOffer(addr)
	})
}

// sdpUfragSummary reports an SDP's session ice-ufrag and the distinct "ufrag"
// attributes on its candidate lines. They must match: a peer's ICE agent drops
// every candidate whose ufrag differs from the session's.
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

// gatheredLocalDescription blocks until ICE gathering finishes and returns the
// local description with every candidate inlined in the SDP (non-trickle).
//
// OK-Calls does NOT reliably relay standalone trickle candidates: a
// transmit-data carrying only {"candidate":...} has no sdp object and so no
// p2pRelay marker, and peers observably receive few or none of them. The proven
// reference implementation (aiortc) is non-trickle and puts all candidates in
// the offer/answer, so we do the same. Falls back to the ungathered description
// if gathering stalls.
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

func (h *MaxHeadlessJoiner) sendOffer(addr *maxPeerAddr) {
	if h.pc == nil {
		return
	}
	offer, err := h.pc.CreateOffer(nil)
	if err != nil {
		h.logFn("max-joiner: create offer failed: %v", err)
		return
	}
	if err := h.pc.SetLocalDescription(offer); err != nil {
		h.logFn("max-joiner: set local description failed: %v", err)
		return
	}
	h.sendTransmitData(addr, map[string]interface{}{
		"sdp": map[string]interface{}{
			"type":     "offer",
			"sdp":      offer.SDP,
			"p2pRelay": "true",
		},
		"label": "call",
	})
	h.logFn("max-joiner: sent OFFER [%s]", sdpUfragSummary(offer.SDP))
}

// send is the generic ws2 command sender: {"command":cmd,"sequence":n, ...fields}.
func (h *MaxHeadlessJoiner) send(command string, fields map[string]interface{}) {
	h.wsMu.Lock()
	defer h.wsMu.Unlock()
	if h.ws == nil {
		return
	}
	h.seq++
	fields["command"] = command
	fields["sequence"] = h.seq
	if err := h.ws.WriteJSON(fields); err != nil {
		h.logFn("max-joiner: ws write failed: %v", err)
	}
}

// sendTransmitData mirrors okcalls_peer.py Peer.transmit: the participantId/
// participantType/deviceIdx fields address a specific peer, "data" carries
// the SDP or candidate payload.
func (h *MaxHeadlessJoiner) sendTransmitData(addr *maxPeerAddr, data map[string]interface{}) {
	h.send("transmit-data", map[string]interface{}{
		"participantId":   addr.ParticipantID,
		"participantType": addr.ParticipantType,
		"deviceIdx":       addr.DeviceIdx,
		"data":            data,
	})
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

// handleMessage mirrors okcalls_peer.py Peer.reader/learn_peer exactly:
// learn the sender's participantId from EVERY notification (including
// transmitted-data — the answerer needs it to address the answer back to
// the offerer), then dispatch.
func (h *MaxHeadlessJoiner) handleMessage(raw []byte) {
	// UseNumber so a peer's 16-digit internal participantId keeps its exact
	// integer form: a plain interface{} decode yields float64, and fmt.Sprint
	// of that renders scientific notation ("1.125...e+15"), which the server
	// rejects as "invalid-request" when it comes back in a transmit-data.
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

	h.learnPeer(m)

	switch notif {
	case "transmitted-data":
		if data, ok := m["data"].(map[string]interface{}); ok {
			h.onTransmittedData(data)
		}
	case "participant-joined", "registered-peer":
		pid := m["participantId"]
		if pid == nil {
			if data, ok := m["data"].(map[string]interface{}); ok {
				pid = data["participantId"]
			}
		}
		h.logFn("max-joiner: <- %s participantId=%v", notif, pid)
		h.maybeSendOffer()
	case "connection":
		h.handleConnection(m)
	case "settings-update":
		h.logFn("max-joiner: <- %s", notif)
	default:
		h.logFn("max-joiner: <- notification %s", notif)
	}
}

// learnPeer scans the top-level participantId and, if present, the nested
// data.participantId — the first non-empty value that isn't our own uid
// becomes the peer address. Matches okcalls_peer.py Peer.learn_peer exactly,
// including that a data.participantId overrides a top-level one when both
// are present (data is inspected after m, so it wins on overwrite).
func (h *MaxHeadlessJoiner) learnPeer(m map[string]interface{}) {
	sources := []map[string]interface{}{m}
	if data, ok := m["data"].(map[string]interface{}); ok {
		sources = append(sources, data)
	}
	for _, src := range sources {
		v, ok := src["participantId"]
		if !ok || v == nil {
			continue
		}
		s := fmt.Sprint(v)
		if s == "" || s == h.selfUID || s == h.selfAltUID {
			continue
		}
		h.setPeerAddr(&maxPeerAddr{ParticipantID: s, ParticipantType: "USER", DeviceIdx: 0})
	}
}

func (h *MaxHeadlessJoiner) setPeerAddr(addr *maxPeerAddr) {
	h.peerMu.Lock()
	h.peerAddr = addr
	pending := h.pendingLocalICE
	h.pendingLocalICE = nil
	h.peerMu.Unlock()

	for _, cand := range pending {
		h.sendTransmitData(addr, map[string]interface{}{"candidate": cand})
	}

	if h.params != nil && h.params.Role == maxRoleOfferer {
		h.maybeSendOffer()
	}
}

// onTransmittedData mirrors vk_joiner.go's onTransmittedData / okcalls_peer.py
// handle_transmitted: candidate and sdp payloads, offerer receives "answer",
// answerer receives "offer" and replies with its own "answer".
func (h *MaxHeadlessJoiner) onTransmittedData(data map[string]interface{}) {
	if h.pc == nil {
		return
	}

	if candidate, ok := data["candidate"]; ok {
		// These standalone candidates are the SERVER's (OK-Calls terminates ICE
		// itself: it rewrites the relayed SDP to its own ice-ufrag/pwd and then
		// trickles the SFU's own candidates, which carry that same ufrag). They
		// are essential — ICE/DTLS runs client<->SFU, not peer-to-peer — so
		// apply them once the (server-rewritten) remote description is set,
		// buffering until then.
		candidateJSON, _ := json.Marshal(candidate)
		var candidateInit webrtc.ICECandidateInit
		if err := json.Unmarshal(candidateJSON, &candidateInit); err == nil {
			if h.OnRemoteCandidate != nil {
				h.OnRemoteCandidate(0, candidateInit.Candidate)
			}
			if h.remoteSet {
				h.logFn("max-joiner: <- server ICE candidate")
				h.pc.AddICECandidate(candidateInit)
			} else {
				h.pendingICE = append(h.pendingICE, candidateInit)
				h.logFn("max-joiner: server ICE candidate buffered (no remote desc yet)")
			}
		}
	}

	sdp, ok := data["sdp"].(map[string]interface{})
	if !ok {
		return
	}
	sdpType, _ := sdp["type"].(string)
	sdpStr, _ := sdp["sdp"].(string)
	if h.OnRemoteCandidate != nil {
		h.OnRemoteCandidate(-1, sdpStr)
	}
	h.logFn("max-joiner: remote SDP: %s [%s]", sdpType, sdpUfragSummary(sdpStr))

	switch sdpType {
	case "answer":
		h.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: sdpStr})
		h.remoteSet = true
		for _, candidate := range h.pendingICE {
			h.pc.AddICECandidate(candidate)
		}
		h.pendingICE = nil

	case "offer":
		h.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: sdpStr})
		h.remoteSet = true
		for _, candidate := range h.pendingICE {
			h.pc.AddICECandidate(candidate)
		}
		h.pendingICE = nil

		answer, err := h.pc.CreateAnswer(nil)
		if err != nil {
			h.logFn("max-joiner: create answer failed: %v", err)
			return
		}
		if err := h.pc.SetLocalDescription(answer); err != nil {
			h.logFn("max-joiner: set local description failed: %v", err)
			return
		}
		h.peerMu.Lock()
		addr := h.peerAddr
		h.peerMu.Unlock()
		if addr == nil {
			h.logFn("max-joiner: cannot send answer, peer not learned yet")
			return
		}
		h.sendTransmitData(addr, map[string]interface{}{
			"sdp": map[string]interface{}{
				"type":     "answer",
				"sdp":      answer.SDP,
				"p2pRelay": "true",
			},
			"label": "call",
		})
		h.logFn("max-joiner: sent ANSWER [%s]", sdpUfragSummary(answer.SDP))
	}
}
