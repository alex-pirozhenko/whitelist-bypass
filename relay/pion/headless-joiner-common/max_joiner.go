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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alex-pirozhenko/whitelist-bypass/relay/common"
	"github.com/alex-pirozhenko/whitelist-bypass/relay/maxproto"
	"github.com/alex-pirozhenko/whitelist-bypass/relay/tunnel"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	plog "github.com/pion/logging"
	"github.com/pion/stun/v3"
	"github.com/pion/turn/v4"
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

	// WEB-platform ws2 defaults. The reference bundle's SDK defaults are
	// platform:"WEB", device:"browser", clientType:"PORTAL" (MAX_WS2_REFERENCE.md
	// "Open items"); web.max.ru may override them, and op166's CallInfo
	// clientType wins when present. appVersion follows maxproto.WebUA.
	maxDefaultWebDevice     = "browser"
	maxDefaultWebClientType = "PORTAL"

	maxPlatformAndroid = "android"
	maxPlatformWeb     = "web"
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

	// Platform is the session platform the Token belongs to: "android" (the
	// default; a master token) or "web" (a session derived from a master via
	// maxproto.DeriveWebSession). Operator rule: Android master tokens are never
	// used as call participants — participants run on WEB sessions. "web" makes
	// the control client identify as WEB (maxproto.NewWeb) and the ws2 URL carry
	// the web client's platform/device/clientType instead of the ANDROID ones.
	Platform string `json:"platform"`

	// CreateRoom, when true, makes joinCall create the room itself via op76
	// (VideoChatStart) on the same session before op166-joining it, then fills
	// JoinLink/ConversationID from the result. Used by the room-owning side
	// (the exit/offerer or a standalone room test). CalleeUID takes precedence
	// over CalleePhone (resolved via op46) for the op76 calleeIds.
	CreateRoom  bool   `json:"createRoom"`
	CalleePhone string `json:"calleePhone"`
	CalleeUID   int64  `json:"calleeUid"`

	// ICETransportPolicy selects the WebRTC ICE policy, mirroring the web
	// client's `iceTransportPolicy: forceRelayPolicy ? "relay" : "all"`.
	// "relay" (default) forces all media through OK's TURN — whitelist-safe;
	// "all" also tries host/srflx, useful on an open network for diagnosing
	// whether DIRECT completes at all. Configurable per the topology work.
	ICETransportPolicy string `json:"iceTransportPolicy"`

	// MediaMode selects the media topology: "direct" (default, 1:1 p2p with
	// server-terminated ICE) or "sfu" (SERVER topology, producer/consumer VP8).
	MediaMode string `json:"mediaMode"`

	// VP8FPS/VP8Batch tune the VP8 data-tunnel (SFU mode only), mirroring the
	// VK/Telemost joiners. Zero uses the tunnel's own defaults.
	VP8FPS   int `json:"vp8Fps"`
	VP8Batch int `json:"vp8Batch"`

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
	p.Platform = strings.ToLower(strings.TrimSpace(p.Platform))
	if p.Platform == "" {
		p.Platform = maxPlatformAndroid
	}
	web := p.Platform == maxPlatformWeb
	if p.APIHost == "" {
		p.APIHost = maxDefaultAPIHost
	}
	if p.AppVersion == "" {
		p.AppVersion = maxDefaultAppVersion
		if web {
			if v, ok := maxproto.WebUA["appVersion"].(string); ok && v != "" {
				p.AppVersion = v
			}
		}
	}
	if p.ProtocolVersion == "" {
		p.ProtocolVersion = maxDefaultProtocolVersion
	}
	if p.Capabilities == "" {
		p.Capabilities = maxDefaultCapabilities
	}
	// ClientType: android defaults to ONE_ME here; web leaves it empty so
	// buildWSURL can prefer the clientType op166's CallInfo reports, falling
	// back to the web SDK default (PORTAL).
	if p.ClientType == "" && !web {
		p.ClientType = maxDefaultClientType
	}
	if p.Device == "" {
		p.Device = maxDefaultDevice
		if web {
			p.Device = maxDefaultWebDevice
		}
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
	if p.ICETransportPolicy == "" {
		p.ICETransportPolicy = "relay"
	}
	if p.MediaMode == "" {
		p.MediaMode = "direct"
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
	// Transcript, when non-nil, receives the JSONL diagnostic transcript
	// (ws frames, pc calls, state changes, stats, logs). See max_transcript.go.
	Transcript Transcript

	params *MaxHeadlessAuthParams
	obf    *tunnel.TunnelObfuscator

	ctl *maxproto.Client
	ci  *maxproto.CallInfo

	selfUID    string
	selfAltUID string

	ws         *websocket.Conn
	wsMu       sync.Mutex
	seq        int
	pongLogged bool // ws2 keepalive: log the first ping->pong per session only

	peerMu          sync.Mutex
	peerAddr        *maxPeerAddr
	pendingLocalICE []interface{}
	pendingEmptyICE bool // ICE gathering completed before peer was learned; send end-of-candidates on flush

	pc         *webrtc.PeerConnection
	dc         *webrtc.DataChannel
	remoteSet  bool
	pendingICE []webrtc.ICECandidateInit

	offerOnce sync.Once

	// SFU (MediaMode=="sfu") media plane: the tunnel rides a VP8 media track
	// through the SERVER-topology SFU (an SFU cannot carry an SCTP DataChannel).
	sampleTrack       *webrtc.TrackLocalStaticSample
	sampleAudioTrack  *webrtc.TrackLocalStaticSample
	sfuTrackBound     bool
	vp8tunnel         *tunnel.VP8DataTunnel
	producerSessionID string
	configAck         configAckTracker

	reconnectAttempt atomic.Int32
	stopCh           chan struct{}
	stopOnce         sync.Once
}

// maxTopologyServer is the SFU/producer-consumer topology (vs "DIRECT" p2p).
const maxTopologyServer = "SERVER"

func NewMaxHeadlessJoiner(logFn func(string, ...any), resolveFn ResolveFunc, status StatusEmitter, pcConfig PeerConnectionConfigurer, addTracks AddTunnelTracksFunc, readTrackFn ReadTrackFunc) *MaxHeadlessJoiner {
	h := &MaxHeadlessJoiner{
		ResolveFn:   resolveFn,
		Status:      status,
		PCConfig:    pcConfig,
		AddTracks:   addTracks,
		ReadTrackFn: readTrackFn,
		stopCh:      make(chan struct{}),
	}
	// Every log line is mirrored into the Transcript (if one is attached later).
	h.logFn = h.logAndTranscript(logFn)
	return h
}

// MarkConfigAcked confirms the peer received our VP8 tunnel config (SFU mode).
// The DIRECT/DataChannel mode never pushes a VP8 config, so this is harmless
// there.
func (h *MaxHeadlessJoiner) MarkConfigAcked() { h.configAck.mark() }

func (h *MaxHeadlessJoiner) RunWithParams(jsonParams string) {
	var params MaxHeadlessAuthParams
	if err := json.Unmarshal([]byte(jsonParams), &params); err != nil {
		h.logFn("max-joiner: failed to parse auth params: %v", err)
		h.Status.EmitStatusError("bad params: " + err.Error())
		return
	}
	params.applyDefaults()
	if params.Platform != maxPlatformAndroid && params.Platform != maxPlatformWeb {
		h.logFn("max-joiner: unknown platform %q (want android|web)", params.Platform)
		h.Status.EmitStatusError("bad params: unknown platform " + params.Platform)
		return
	}
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

// CallInfoOnly performs the control-plane join only — connect, session-init,
// login and op166 VideoChatJoin via the same joinCall path RunWithParams uses
// (so Platform, CreateRoom etc. are honoured) — then closes the control
// connection and returns the parsed CallInfo plus the joinLink/conversationId
// that were actually used. It never opens ws2 or builds a PeerConnection: the
// caller (maxjoin -mode callinfo) hands the CallInfo to something else, e.g. a
// browser page that opens the ws2 socket itself.
func (h *MaxHeadlessJoiner) CallInfoOnly(jsonParams string) (ci *maxproto.CallInfo, joinLink, conversationID string, err error) {
	var params MaxHeadlessAuthParams
	if err := json.Unmarshal([]byte(jsonParams), &params); err != nil {
		return nil, "", "", fmt.Errorf("parse params: %w", err)
	}
	params.applyDefaults()
	if params.Platform != maxPlatformAndroid && params.Platform != maxPlatformWeb {
		return nil, "", "", fmt.Errorf("unknown platform %q (want android|web)", params.Platform)
	}
	h.params = &params
	defer func() {
		if h.ctl != nil {
			h.ctl.Close()
			h.ctl = nil
		}
	}()
	if err := h.joinCall(); err != nil {
		return nil, "", "", err
	}
	return h.ci, h.params.JoinLink, h.params.ConversationID, nil
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
	h.pongLogged = false
	h.wsMu.Unlock()
	if ws != nil {
		ws.Close()
	}
	if h.dc != nil {
		h.dc.Close()
		h.dc = nil
	}
	if h.pc != nil {
		h.closePC(h.pc)
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
	h.pendingEmptyICE = false
	h.peerMu.Unlock()
	h.offerOnce = sync.Once{}
	// SFU media plane.
	h.sampleTrack = nil
	h.sfuTrackBound = false
	h.vp8tunnel = nil
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
	if h.pc != nil {
		h.closePC(h.pc)
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
	// A WEB session (derived from a master) must be used over a WEB-identified
	// connection, exactly like the web client; an ANDROID master uses New.
	if p.Platform == maxPlatformWeb {
		h.ctl = maxproto.NewWeb(p.Token, p.DeviceID)
	} else {
		h.ctl = maxproto.New(p.Token, p.DeviceID)
	}

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
//
// Platform "web" mirrors the web client's _buildUrl (MAX_WS2_REFERENCE.md §2b):
// platform=WEB, device=browser, clientType from CallInfo (else the SDK default
// PORTAL), and no locale/osVersion — the web client never appends those two.
// Android keeps the values the ANDROID app sends.
func (h *MaxHeadlessJoiner) buildWSURL() string {
	p := h.params
	base := h.ci.Endpoint
	web := p.Platform == maxPlatformWeb

	clientType := p.ClientType
	if clientType == "" {
		clientType = h.ci.ClientType
	}
	if clientType == "" {
		clientType = maxDefaultClientType
		if web {
			clientType = maxDefaultWebClientType
		}
	}
	platform := "ANDROID"
	if web {
		platform = "WEB"
	}

	values := url.Values{}
	values.Set("version", p.ProtocolVersion)
	values.Set("capabilities", p.Capabilities)
	values.Set("platform", platform)
	values.Set("clientType", clientType)
	values.Set("appVersion", p.AppVersion)
	values.Set("device", p.Device)
	if !web {
		values.Set("locale", p.Locale)
		values.Set("osVersion", p.OSVersion)
	}

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
	if h.params.Platform == maxPlatformWeb {
		if ua, ok := maxproto.WebUA["headerUserAgent"].(string); ok && ua != "" {
			wsHeader.Set("User-Agent", ua)
		}
	}

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
	h.trWSOpen(wsURL)
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
	// ICE fails. In SFU mode the tunnel rides a VP8 VIDEO track, so video MUST be
	// enabled; the DIRECT/DataChannel mode is data-only (all media disabled).
	videoEnabled := h.params.MediaMode == "sfu"
	// In SFU mode we bind a (silent) audio track on mid:2, so we must advertise
	// audio enabled — otherwise the SFU media core sees an active audio producer
	// slot with the participant reporting audio disabled and rejects the layout.
	audioEnabled := h.params.MediaMode == "sfu"
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

	// NOTE: the PeerConnection is NOT built here. The ws2 "connection"
	// notification carries the TURN/STUN credentials that are actually valid
	// for this ws2 session (op166's CallInfo ones are a different, earlier
	// grant), and using the stale pair makes the TURN server answer
	// CreatePermission with "403 Forbidden IP". handleConnection overrides the
	// ICE servers and then calls initPC — same order as vk_joiner.go.

	// DIRECT mode only: the offerer sends its p2p offer over transmit-data. In
	// SFU mode there is no peer offerer/answerer — the SFU is always the offerer
	// (producer-updated), so no transmit-data offer is sent.
	if h.params.MediaMode != "sfu" && h.params.Role == maxRoleOfferer {
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
		// SFU mode: a 2-party call starts in DIRECT, where the server never
		// produces anything to consume. Nudge it to SERVER (best-effort; force
		// is rejected as feature-is-disabled until a 3rd participant joins, at
		// which point the server flips topology on its own — see
		// handleMessage's topology-changed case), then set up the receive side.
		if h.params.MediaMode == "sfu" {
			if topology != maxTopologyServer {
				h.sendSwitchTopology()
			}
			h.sendAllocateConsumer()
		}
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

// sfuCapabilities is the STRUCTURED capabilities feature-descriptor the SFU
// requires in allocate-consumer (the hex bitmask is rejected "Invalid message
// format"). Shape taken verbatim from the web.max.ru bundle's capabilities
// getter; we advertise one video track (the VP8 tunnel) and disable everything
// unimplemented. See MAX_OKCALLS_NOTES.md.
func (h *MaxHeadlessJoiner) sfuCapabilities() map[string]interface{} {
	return map[string]interface{}{
		"estimatedPerformanceIndex":              1,
		"audioMix":                               true,
		"consumerUpdate":                         true,
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

// sendAllocateConsumer sets up the SFU receive side. First call carries no
// description, so the wire payload is just {"capabilities": ...}.
func (h *MaxHeadlessJoiner) sendAllocateConsumer() {
	h.send("allocate-consumer", map[string]interface{}{
		"capabilities": h.sfuCapabilities(),
	})
	h.logFn("max-joiner: -> allocate-consumer (structured capabilities)")
}

// parseSFUDescription decodes a producer-updated "description" (raw SDP string
// or {type,sdp}) — the SFU's SDP OFFER unless an explicit type says otherwise.
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

// extractSSRCs pulls distinct "a=ssrc:<id> ..." SSRCs from an SDP in first-seen
// order, for accept-producer's "ssrcs" field (web client's Object.keys(ssrcMap)).
func extractSSRCs(sdp string) []int64 {
	seen := make(map[int64]bool)
	var out []int64
	for _, line := range strings.Split(sdp, "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, "a=ssrc:") {
			continue
		}
		rest := strings.TrimPrefix(line, "a=ssrc:")
		idStr := rest
		if i := strings.IndexByte(rest, ' '); i >= 0 {
			idStr = rest[:i]
		}
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// extractOfferSSRCs pulls the SFU's OFFERED ssrcs — the ones carrying a
// label: attribute (audio-mix, video-pat-0, …) in the producer-updated offer.
// accept-producer must echo THESE back so the SFU knows which of its producers
// we accept. Echoing our own answer ssrcs (or, when our answer has none, an
// empty list) makes the SFU conclude we accepted no media, tear down, and
// re-offer a fresh sessionId every ~14s. Mirrors the web client's
// _updateSSRCMap(remoteOffer) → acceptProducer(answer, Object.keys(ssrcMap)).
// The SFU's accept-producer ssrcs field must be an array of STRING tokens
// (the web client sends Object.keys(ssrcMap) = ["1598412891", …]). Sending
// JSON numbers ([]int64) trips the SFU media core's strict List<String> schema
// validation, so it discards the accepted-producer list, never arms the ICE
// socket, and re-offers on the 20s watchdog. Match only the labeled producer
// ssrcs (label:audio-/video-…), excluding RTX/FID secondaries.
func extractOfferSSRCs(offerSDP string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, line := range strings.Split(offerSDP, "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, "a=ssrc:") || !strings.Contains(line, " label:") {
			continue
		}
		rest := strings.TrimPrefix(line, "a=ssrc:")
		idStr := rest
		if i := strings.IndexByte(rest, ' '); i >= 0 {
			idStr = rest[:i]
		}
		if idStr == "" || seen[idStr] {
			continue
		}
		if _, err := strconv.ParseInt(idStr, 10, 64); err != nil {
			continue
		}
		seen[idStr] = true
		out = append(out, idStr)
	}
	return out
}

// stripSDPCandidates removes all a=candidate: and a=end-of-candidates lines
// from an SDP. The real MAX app sends the SDP answer before ICE gathering, so
// its accept-producer never contains candidate lines. Including them confuses
// the OK-Calls SFU (which discovers us via peer-reflexive candidates from our
// STUN binding requests, not from the SDP).
func stripSDPCandidates(sdp string) string {
	var b strings.Builder
	for _, line := range strings.Split(sdp, "\n") {
		trimmed := strings.TrimRight(line, "\r")
		if strings.HasPrefix(trimmed, "a=candidate:") || trimmed == "a=end-of-candidates" {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// extractSDPCandidates parses candidate lines from the first media section
// of an SDP and returns them as ICECandidateInit values suitable for
// AddICECandidate. Only the BUNDLE-master section (mid:0) is used.
func extractSDPCandidates(sdp string) []webrtc.ICECandidateInit {
	var candidates []webrtc.ICECandidateInit
	inFirstMedia := false
	mediaCount := 0
	sdpMid := "0"
	sdpMLineIndex := uint16(0)
	for _, line := range strings.Split(sdp, "\n") {
		trimmed := strings.TrimRight(line, "\r")
		if strings.HasPrefix(trimmed, "m=") {
			mediaCount++
			if mediaCount == 1 {
				inFirstMedia = true
			} else {
				break
			}
			continue
		}
		if inFirstMedia && strings.HasPrefix(trimmed, "a=candidate:") {
			cand := strings.TrimPrefix(trimmed, "a=")
			candidates = append(candidates, webrtc.ICECandidateInit{
				Candidate:     cand,
				SDPMid:        &sdpMid,
				SDPMLineIndex: &sdpMLineIndex,
			})
		}
	}
	return candidates
}

// fixSFUAnswerSDP patches the gathered answer SDP for SFU compatibility:
//  1. setup:passive → setup:active — with ice-lite remote the SFU is DTLS
//     server (passive), so our answer must be active (DTLS client).
//  2. Strip component-2 candidates — pion emits them even with rtcp-mux,
//     but the SFU only has component-1 candidates and may choke on ours.
func fixSFUAnswerSDP(sdp string) string {
	var b strings.Builder
	for _, line := range strings.Split(sdp, "\n") {
		trimmed := strings.TrimRight(line, "\r")
		if trimmed == "a=setup:passive" {
			b.WriteString("a=setup:active\r\n")
			continue
		}
		if strings.HasPrefix(trimmed, "a=candidate:") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 && parts[1] == "2" {
				continue
			}
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// handleProducerUpdated drives the SFU producer/consumer offer-answer: the SFU
// offers (asking us to send our VP8 tunnel track on the us->SFU video m-line),
// we answer and push accept-producer with our SSRCs. Duplicate sessionId = a
// keepalive, ignored.
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
	h.logFn("max-joiner: <- producer-updated sessionId=%s [%s]", sessionID, sdpUfragSummary(desc.SDP))
	h.logFn("max-joiner: SFU offer SDP:\n%s", desc.SDP)

	// Re-offer with a NEW sessionId = the SFU tore down the previous media
	// session and re-allocated with fresh ICE ufrag/pwd. Reusing the existing
	// PeerConnection makes pion perform an in-place ICE restart, and across the
	// SFU's rapid re-offers pion desyncs the outgoing STUN USERNAME/
	// MESSAGE-INTEGRITY (a ufrag from one generation paired with a pwd from
	// another) — every packet is then silently dropped by the ice-lite SFU.
	// The web client rebuilds its RTCPeerConnection on every sessionId change
	// (ServerTransport._reconnect). Mirror that: tear the PC down and build a
	// clean one so its ICE agent uses exactly one ufrag/pwd generation.
	if h.producerSessionID != "" {
		h.logFn("max-joiner: sessionId changed %s -> %s, recreating PeerConnection",
			h.producerSessionID, sessionID)
		if h.pc != nil {
			h.closePC(h.pc)
		}
		h.sfuTrackBound = false
		h.initPCSFU()
		if h.pc == nil {
			h.logFn("max-joiner: PC recreation failed, aborting producer-updated")
			return
		}
	}

	// Bind our VP8 sampleTrack to the SFU's us→SFU video m-line BEFORE
	// applying the remote description. The SFU's 5-m-line offer includes:
	//   mid:3  video  recvonly  (SFU perspective — it wants to receive our VP8)
	// By adding the track via AddTrack FIRST, pion creates a sendonly video
	// transceiver that gets matched to mid:3 during SetRemoteDescription.
	// This ensures the answer SDP carries real SSRCs (not ssrcs=[]) and the
	// SFU does not re-offer every ~14s. On repeat offers (realloc) the track
	// is already bound so we just ReplaceTrack on the existing sender.
	if h.sampleTrack != nil && !h.sfuTrackBound {
		sender, addErr := h.pc.AddTrack(h.sampleTrack)
		h.trPC("addTrack", trackArgs(h.sampleTrack), nil, addErr)
		if addErr != nil {
			h.logFn("max-joiner: AddTrack (pre-SRD) failed: %v", addErr)
		} else {
			h.sfuTrackBound = true
			go tunnel.DrainSenderRTCP(sender)
			h.logFn("max-joiner: AddTrack VP8 sampleTrack (pre-SRD), sender=%v", sender != nil)
		}
		// Bind the silent audio track too, so the SFU's audio-send m-line (mid:2)
		// is answered sendonly with a real SSRC (see initPCSFU rationale).
		if h.sampleAudioTrack != nil {
			asender, aErr := h.pc.AddTrack(h.sampleAudioTrack)
			h.trPC("addTrack", trackArgs(h.sampleAudioTrack), nil, aErr)
			if aErr != nil {
				h.logFn("max-joiner: AddTrack audio (pre-SRD) failed: %v", aErr)
			} else {
				go tunnel.DrainSenderRTCP(asender)
				h.logFn("max-joiner: AddTrack Opus audio (pre-SRD), sender=%v", asender != nil)
			}
		}
	}

	// Apply the SFU offer WITH its inline host candidates. The SFU is ice-lite
	// and advertises its candidate(s) inline in the offer; the web client never
	// strips them. Keeping them lets pion form the candidate pair and (as the
	// controlling agent) begin STUN checks immediately after SetLocalDescription.
	// pion retransmits binding requests (SetICEMaxBindingRequests(50)), so the
	// brief window before the SFU processes our accept-producer answer — and
	// thus learns our ufrag/pwd — is covered by retries rather than an
	// artificial sleep + manual candidate injection (which broke ICE restart).
	if err := h.pc.SetRemoteDescription(desc); err != nil {
		h.trPC("setRemoteDescription", sdpArgs(desc), nil, err)
		h.logFn("max-joiner: set remote description (producer offer) failed: %v", err)
		return
	}
	h.trPC("setRemoteDescription", sdpArgs(desc), nil, nil)

	for _, tr := range h.pc.GetTransceivers() {
		h.logFn("max-joiner: transceiver mid=%s kind=%s dir=%s sender=%v",
			tr.Mid(), tr.Kind(), tr.Direction(), tr.Sender() != nil)
	}

	answer, err := h.pc.CreateAnswer(nil)
	if err != nil {
		h.trPC("createAnswer", nil, nil, err)
		h.logFn("max-joiner: create answer failed: %v", err)
		return
	}
	h.trPC("createAnswer", nil, sdpArgs(answer), nil)
	if err := h.pc.SetLocalDescription(answer); err != nil {
		h.trPC("setLocalDescription", sdpArgs(answer), nil, err)
		h.logFn("max-joiner: set local description failed: %v", err)
		return
	}
	h.trPC("setLocalDescription", sdpArgs(answer), nil, nil)

	// Build accept-producer. The ssrcs field MUST echo the SFU's OFFERED
	// producer ssrcs (the a=ssrc lines carrying label:audio-/video- in the
	// offer), NOT our answer's ssrcs — the SFU keys the producers we accept by
	// those ids. An empty list (our answer often has none for recvonly slots)
	// makes the SFU conclude we accepted nothing and re-offer a new sessionId
	// every ~14s. Preserve our local candidates in the answer (fixSFUAnswerSDP
	// only forces setup:active and drops stray component-2 candidates); the SFU
	// needs our host candidate to complete the pair.
	answerSDP := strings.TrimRight(fixSFUAnswerSDP(answer.SDP), "\r\n") + "\r\n"
	ssrcs := extractOfferSSRCs(desc.SDP)
	h.producerSessionID = sessionID
	h.logFn("max-joiner: answer SDP:\n%s", answerSDP)
	h.logFn("max-joiner: -> accept-producer sessionId=%s ssrcs=%v [%s]", sessionID, ssrcs, sdpUfragSummary(answerSDP))
	h.send("accept-producer", map[string]interface{}{
		"description": answerSDP,
		"sessionId":   m["sessionId"],
		"ssrcs":       ssrcs,
	})

	// Diagnostic: log ICE transport stats every 2s for the first 10s
	go func() {
		for i := 0; i < 5; i++ {
			time.Sleep(2 * time.Second)
			stats := h.pc.GetStats()
			for _, s := range stats {
				switch v := s.(type) {
				case webrtc.ICECandidatePairStats:
					h.logFn("max-joiner: [diag] pair local=%s remote=%s state=%s nominated=%v reqSent=%d respRecv=%d firstReq=%v lastReq=%v lastResp=%v",
						v.LocalCandidateID, v.RemoteCandidateID, v.State, v.Nominated,
						v.RequestsSent, v.ResponsesReceived,
						v.FirstRequestTimestamp, v.LastRequestTimestamp, v.LastResponseTimestamp)
				case webrtc.ICECandidateStats:
					h.logFn("max-joiner: [diag] candidate id=%s type=%s ip=%s port=%d protocol=%s statsType=%s",
						v.ID, v.CandidateType, v.IP, v.Port, v.Protocol, v.Type)
				}
			}
			h.logFn("max-joiner: [diag] ICE connection=%s gathering=%s",
				h.pc.ICEConnectionState().String(), h.pc.ICEGatheringState().String())
		}
	}()

	// Extract ICE credentials from offer and answer for authenticated STUN test
	sfuUfrag, sfuPwd := extractICECredentials(desc.SDP)
	ourUfrag, ourPwd := extractICECredentials(answer.SDP)
	h.logFn("max-joiner: ICE creds for diag: sfu=%s/%s our=%s/%s", sfuUfrag, sfuPwd, ourUfrag, ourPwd)

	// Standalone TURN relay diagnostic — bypasses pion's ICE stack entirely
	go h.diagTURNRelay(sfuUfrag, sfuPwd, ourUfrag, ourPwd)
}

func extractICECredentials(sdp string) (ufrag, pwd string) {
	for _, line := range strings.Split(sdp, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "a=ice-ufrag:") {
			ufrag = strings.TrimPrefix(line, "a=ice-ufrag:")
		}
		if strings.HasPrefix(line, "a=ice-pwd:") {
			pwd = strings.TrimPrefix(line, "a=ice-pwd:")
		}
		if ufrag != "" && pwd != "" {
			return
		}
	}
	return
}

func (h *MaxHeadlessJoiner) diagTURNRelay(sfuUfrag, sfuPwd, ourUfrag, ourPwd string) {
	if len(h.ci.Turn.URLs) == 0 {
		h.logFn("max-joiner: [turn-diag] no TURN URLs, skipping")
		return
	}
	turnURL := h.ci.Turn.URLs[0]
	turnAddr := strings.TrimPrefix(turnURL, "turn:")
	turnAddr = strings.TrimPrefix(turnAddr, "turns:")
	sfuAddr := "155.212.199.76:43210"

	h.logFn("max-joiner: [turn-diag] === STANDALONE TURN RELAY TEST ===")
	h.logFn("max-joiner: [turn-diag] TURN server: %s", turnAddr)
	h.logFn("max-joiner: [turn-diag] TURN user: %s", h.ci.Turn.Username)
	h.logFn("max-joiner: [turn-diag] SFU target: %s", sfuAddr)

	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		h.logFn("max-joiner: [turn-diag] ListenPacket failed: %v", err)
		return
	}
	defer conn.Close()

	turnUDP, err := net.ResolveUDPAddr("udp4", turnAddr)
	if err != nil {
		h.logFn("max-joiner: [turn-diag] resolve TURN addr failed: %v", err)
		return
	}

	cfg := &turn.ClientConfig{
		STUNServerAddr: turnAddr,
		TURNServerAddr: turnAddr,
		Conn:           &diagPacketConn{inner: conn, raddr: turnUDP, logFn: h.logFn},
		Username:       h.ci.Turn.Username,
		Password:       h.ci.Turn.Credential,
		LoggerFactory:  &diagLoggerFactory{logFn: h.logFn},
	}

	client, err := turn.NewClient(cfg)
	if err != nil {
		h.logFn("max-joiner: [turn-diag] NewClient failed: %v", err)
		return
	}
	defer client.Close()

	if err := client.Listen(); err != nil {
		h.logFn("max-joiner: [turn-diag] Listen failed: %v", err)
		return
	}

	h.logFn("max-joiner: [turn-diag] calling Allocate...")
	relayConn, err := client.Allocate()
	if err != nil {
		h.logFn("max-joiner: [turn-diag] Allocate FAILED: %v", err)
		return
	}
	defer relayConn.Close()
	h.logFn("max-joiner: [turn-diag] Allocate OK, relay addr: %s", relayConn.LocalAddr())

	sfuUDP, err := net.ResolveUDPAddr("udp4", sfuAddr)
	if err != nil {
		h.logFn("max-joiner: [turn-diag] resolve SFU addr failed: %v", err)
		return
	}

	// Build a bare STUN binding request
	msg, err := stun.Build(stun.TransactionID, stun.BindingRequest)
	if err != nil {
		h.logFn("max-joiner: [turn-diag] stun.Build failed: %v", err)
		return
	}

	for i := 0; i < 5; i++ {
		h.logFn("max-joiner: [turn-diag] [%d] sending %d-byte STUN via relay to %s", i+1, len(msg.Raw), sfuAddr)
		n, err := relayConn.WriteTo(msg.Raw, sfuUDP)
		if err != nil {
			h.logFn("max-joiner: [turn-diag] [%d] WriteTo FAILED: %v", i+1, err)
			continue
		}
		h.logFn("max-joiner: [turn-diag] [%d] WriteTo OK, sent %d bytes", i+1, n)

		buf := make([]byte, 1500)
		if err := relayConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			h.logFn("max-joiner: [turn-diag] [%d] SetReadDeadline failed: %v", i+1, err)
		}
		rn, from, rerr := relayConn.ReadFrom(buf)
		if rerr != nil {
			h.logFn("max-joiner: [turn-diag] [%d] ReadFrom timeout/error: %v", i+1, rerr)
		} else {
			h.logFn("max-joiner: [turn-diag] [%d] GOT RESPONSE! %d bytes from %s", i+1, rn, from)
			return
		}
	}
	h.logFn("max-joiner: [turn-diag] === NO RESPONSES from bare STUN via TURN relay ===")

	// Now try authenticated STUN with proper ICE credentials
	if sfuUfrag != "" && ourUfrag != "" {
		h.logFn("max-joiner: [turn-diag] === Testing AUTHENTICATED STUN via relay ===")
		h.logFn("max-joiner: [turn-diag] USERNAME=%s:%s, key=%s", sfuUfrag, ourUfrag, sfuPwd)
		username := sfuUfrag + ":" + ourUfrag
		for i := 0; i < 5; i++ {
			authMsg, err := stun.Build(
				stun.TransactionID,
				stun.BindingRequest,
				stun.NewUsername(username),
				stun.NewShortTermIntegrity(sfuPwd),
				stun.Fingerprint,
			)
			if err != nil {
				h.logFn("max-joiner: [turn-diag] [auth-%d] stun.Build failed: %v", i+1, err)
				break
			}
			h.logFn("max-joiner: [turn-diag] [auth-%d] sending %d-byte authenticated STUN via relay to %s", i+1, len(authMsg.Raw), sfuAddr)
			if _, err := relayConn.WriteTo(authMsg.Raw, sfuUDP); err != nil {
				h.logFn("max-joiner: [turn-diag] [auth-%d] WriteTo FAILED: %v", i+1, err)
				continue
			}
			buf := make([]byte, 1500)
			relayConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			rn, from, rerr := relayConn.ReadFrom(buf)
			if rerr != nil {
				h.logFn("max-joiner: [turn-diag] [auth-%d] no response: %v", i+1, rerr)
			} else {
				h.logFn("max-joiner: [turn-diag] [auth-%d] GOT RESPONSE! %d bytes from %s", i+1, rn, from)
				break
			}
		}
	}

	// Test: does the relay forward to a PUBLIC STUN server?
	h.logFn("max-joiner: [turn-diag] === Testing relay to PUBLIC STUN (stun.l.google.com:19302) ===")
	pubSTUN, err := net.ResolveUDPAddr("udp4", "stun.l.google.com:19302")
	if err != nil {
		h.logFn("max-joiner: [turn-diag] resolve public STUN failed: %v", err)
	} else {
		pubMsg, _ := stun.Build(stun.TransactionID, stun.BindingRequest)
		for i := 0; i < 3; i++ {
			h.logFn("max-joiner: [turn-diag] [pub-%d] sending %d-byte STUN via relay to %s", i+1, len(pubMsg.Raw), pubSTUN)
			if _, err := relayConn.WriteTo(pubMsg.Raw, pubSTUN); err != nil {
				h.logFn("max-joiner: [turn-diag] [pub-%d] WriteTo FAILED: %v", i+1, err)
				continue
			}
			buf := make([]byte, 1500)
			relayConn.SetReadDeadline(time.Now().Add(3 * time.Second))
			rn, from, rerr := relayConn.ReadFrom(buf)
			if rerr != nil {
				h.logFn("max-joiner: [turn-diag] [pub-%d] no response: %v", i+1, rerr)
			} else {
				h.logFn("max-joiner: [turn-diag] [pub-%d] GOT RESPONSE! %d bytes from %s — RELAY FORWARDS OK!", i+1, rn, from)
				break
			}
		}
	}

	// Also test TURN-over-TCP
	h.logFn("max-joiner: [turn-diag] === Now trying TURN-over-TCP ===")
	tcpConn, err := net.DialTimeout("tcp4", turnAddr, 5*time.Second)
	if err != nil {
		h.logFn("max-joiner: [turn-diag] TCP dial to TURN server failed: %v", err)
		return
	}
	defer tcpConn.Close()
	h.logFn("max-joiner: [turn-diag] TCP connected to TURN server from %s", tcpConn.LocalAddr())

	tcpCfg := &turn.ClientConfig{
		TURNServerAddr: turnAddr,
		Conn:           turn.NewSTUNConn(tcpConn),
		Username:       h.ci.Turn.Username,
		Password:       h.ci.Turn.Credential,
		LoggerFactory:  &diagLoggerFactory{logFn: h.logFn},
	}
	tcpClient, err := turn.NewClient(tcpCfg)
	if err != nil {
		h.logFn("max-joiner: [turn-diag] TCP NewClient failed: %v", err)
		return
	}
	defer tcpClient.Close()

	if err := tcpClient.Listen(); err != nil {
		h.logFn("max-joiner: [turn-diag] TCP Listen failed: %v", err)
		return
	}

	h.logFn("max-joiner: [turn-diag] TCP Allocate...")
	tcpRelayConn, err := tcpClient.Allocate()
	if err != nil {
		h.logFn("max-joiner: [turn-diag] TCP Allocate FAILED: %v", err)
		return
	}
	defer tcpRelayConn.Close()
	h.logFn("max-joiner: [turn-diag] TCP relay addr: %s", tcpRelayConn.LocalAddr())

	for i := 0; i < 5; i++ {
		h.logFn("max-joiner: [turn-diag] TCP [%d] sending STUN via relay to %s", i+1, sfuAddr)
		n, err := tcpRelayConn.WriteTo(msg.Raw, sfuUDP)
		if err != nil {
			h.logFn("max-joiner: [turn-diag] TCP [%d] WriteTo FAILED: %v", i+1, err)
			continue
		}
		h.logFn("max-joiner: [turn-diag] TCP [%d] WriteTo OK, sent %d bytes", i+1, n)

		buf := make([]byte, 1500)
		if err := tcpRelayConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			h.logFn("max-joiner: [turn-diag] TCP [%d] SetReadDeadline failed: %v", i+1, err)
		}
		rn, from, rerr := tcpRelayConn.ReadFrom(buf)
		if rerr != nil {
			h.logFn("max-joiner: [turn-diag] TCP [%d] ReadFrom timeout/error: %v", i+1, rerr)
		} else {
			h.logFn("max-joiner: [turn-diag] TCP [%d] GOT RESPONSE! %d bytes from %s", i+1, rn, from)
			return
		}
	}
	h.logFn("max-joiner: [turn-diag] === TCP TURN also got NO RESPONSES ===")
}

// diagPacketConn wraps a PacketConn to log all WriteTo/ReadFrom calls and route
// all outgoing traffic to a fixed remote address (the TURN server).
type diagPacketConn struct {
	inner net.PacketConn
	raddr net.Addr
	logFn func(string, ...interface{})
}

func (d *diagPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := d.inner.ReadFrom(p)
	if err == nil && n > 0 && n >= 4 {
		d.logFn("max-joiner: [turn-diag-pkt] ReadFrom %d bytes from %s (first4: %02x%02x%02x%02x)", n, addr, p[0], p[1], p[2], p[3])
	}
	return n, addr, err
}

func (d *diagPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) >= 4 {
		d.logFn("max-joiner: [turn-diag-pkt] WriteTo %d bytes to %s (first4: %02x%02x%02x%02x)", len(p), d.raddr, p[0], p[1], p[2], p[3])
	}
	return d.inner.WriteTo(p, d.raddr)
}

func (d *diagPacketConn) Close() error                       { return d.inner.Close() }
func (d *diagPacketConn) LocalAddr() net.Addr                { return d.inner.LocalAddr() }
func (d *diagPacketConn) SetDeadline(t time.Time) error      { return d.inner.SetDeadline(t) }
func (d *diagPacketConn) SetReadDeadline(t time.Time) error  { return d.inner.SetReadDeadline(t) }
func (d *diagPacketConn) SetWriteDeadline(t time.Time) error { return d.inner.SetWriteDeadline(t) }

// diagLoggerFactory routes all pion log output through our logFn so it appears
// in the test log file instead of going to stderr.
type diagLoggerFactory struct {
	logFn func(string, ...interface{})
}

func (f *diagLoggerFactory) NewLogger(scope string) plog.LeveledLogger {
	return &diagLogger{scope: scope, logFn: f.logFn}
}

type diagLogger struct {
	scope string
	logFn func(string, ...interface{})
}

func (l *diagLogger) Trace(msg string)                          { l.logFn("[turn-diag-%s] TRACE: %s", l.scope, msg) }
func (l *diagLogger) Tracef(format string, args ...interface{}) { l.logFn("[turn-diag-%s] TRACE: "+format, append([]interface{}{l.scope}, args...)...) }
func (l *diagLogger) Debug(msg string)                          { l.logFn("[turn-diag-%s] DEBUG: %s", l.scope, msg) }
func (l *diagLogger) Debugf(format string, args ...interface{}) { l.logFn("[turn-diag-%s] DEBUG: "+format, append([]interface{}{l.scope}, args...)...) }
func (l *diagLogger) Info(msg string)                           { l.logFn("[turn-diag-%s] INFO: %s", l.scope, msg) }
func (l *diagLogger) Infof(format string, args ...interface{})  { l.logFn("[turn-diag-%s] INFO: "+format, append([]interface{}{l.scope}, args...)...) }
func (l *diagLogger) Warn(msg string)                           { l.logFn("[turn-diag-%s] WARN: %s", l.scope, msg) }
func (l *diagLogger) Warnf(format string, args ...interface{})  { l.logFn("[turn-diag-%s] WARN: "+format, append([]interface{}{l.scope}, args...)...) }
func (l *diagLogger) Error(msg string)                          { l.logFn("[turn-diag-%s] ERROR: %s", l.scope, msg) }
func (l *diagLogger) Errorf(format string, args ...interface{}) { l.logFn("[turn-diag-%s] ERROR: "+format, append([]interface{}{l.scope}, args...)...) }

func (h *MaxHeadlessJoiner) iceServers() []webrtc.ICEServer {
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
	return iceServers
}

// initPCSFU builds the PeerConnection for SFU (SERVER-topology) mode: the SFU
// is always the OFFERER (producer-updated), we answer, and the tunnel rides a
// VP8 media track (AddTracks/ReadTrackFn) — there is no DataChannel (an SFU
// cannot carry SCTP). Mirrors telemost_joiner.go's video mode.
func (h *MaxHeadlessJoiner) initPCSFU() {
	iceServers := h.iceServers()
	settingEngine := webrtc.SettingEngine{}
	settingEngine.DisableCloseByDTLS(true)
	settingEngine.SetICEMaxBindingRequests(50)
	// The SFU is ice-lite and offers a=setup:actpass. Pion's CreateAnswer
	// picks the DTLS SERVER role (a=setup:passive) whenever the remote is
	// ice-lite and we are not (peerconnection.go, RFC 8445 §6.1.1 heuristic),
	// while fixSFUAnswerSDP told the SFU a=setup:active. Both sides then sat
	// waiting for the other's ClientHello: ICE reached connected (verified
	// 2026-09-11 with the browser oracle) but the PeerConnection never left
	// "connecting" and the SFU's 20 s watchdog re-offered forever. Pin the
	// answering role to client so what we do matches what we say — and what
	// the real web client does (its answer is a=setup:active).
	settingEngine.SetAnsweringDTLSRole(webrtc.DTLSRoleClient)
	settingEngine.SetNetworkTypes([]webrtc.NetworkType{
		webrtc.NetworkTypeUDP4,
		webrtc.NetworkTypeTCP4,
	})
	lf := plog.NewDefaultLoggerFactory()
	lf.DefaultLogLevel = plog.LogLevelTrace
	settingEngine.LoggerFactory = lf
	if h.PCConfig != nil {
		h.PCConfig.ConfigureSettingEngine(&settingEngine)
	}
	icePolicy := webrtc.ICETransportPolicyRelay
	if h.params != nil && h.params.ICETransportPolicy == "all" {
		icePolicy = webrtc.ICETransportPolicyAll
	}
	pcCfg := webrtc.Configuration{
		ICEServers:         iceServers,
		ICETransportPolicy: icePolicy,
	}
	pc, err := webrtc.NewAPI(webrtc.WithSettingEngine(settingEngine)).NewPeerConnection(pcCfg)
	h.trPC("new", pcConfigArgs(pcCfg), nil, err)
	if err != nil {
		h.logFn("max-joiner: failed to create SFU PC: %v", err)
		return
	}
	h.pc = pc
	h.attachTranscriptStateHandlers(pc)
	h.startStatsLoop(pc)

	// Create the VP8 sample track object but do NOT add it to the PC yet.
	// handleProducerUpdated calls pc.AddTrack(sampleTrack) right before
	// SetRemoteDescription so pion's transceiver matching binds it to the
	// SFU's mid:3 (us->SFU video recvonly).
	sampleTrack, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8},
		"video", "tunnel-video",
	)
	if err != nil {
		h.logFn("max-joiner: failed to create VP8 sample track: %v", err)
		return
	}
	h.sampleTrack = sampleTrack

	// Silent Opus audio track for the SFU's audio-send m-line (mid:2). The web
	// client always binds BOTH a mic and a camera track before answering; if we
	// answer mid:2 with a=inactive (no track/ssrc) while the call session has an
	// active audio producer, the SFU media core rejects the answer layout and
	// re-offers. handleProducerUpdated AddTracks this before SetRemoteDescription
	// so pion matches it sendonly with a real local SSRC. We never push audio
	// frames (the tunnel rides video); the track only satisfies the negotiation.
	audioTrack, aerr := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus},
		"audio", "tunnel-audio",
	)
	if aerr != nil {
		h.logFn("max-joiner: failed to create Opus audio track: %v", aerr)
		return
	}
	h.sampleAudioTrack = audioTrack

	// SCTP data channels the SFU offers on mid:1 (UDP/DTLS/SCTP). The web
	// client's ServerTransport opens four (producerNotification, producerCommand,
	// producerScreenShare, consumerScreenShare); creating them here initializes
	// pion's SCTP association so mid:1 is answered as a real datachannel section
	// rather than a dead one — another layout the SFU media core rejects.
	for _, name := range []string{"producerNotification", "producerCommand", "producerScreenShare", "consumerScreenShare"} {
		dc, derr := pc.CreateDataChannel(name, nil)
		h.trPC("createDataChannel", map[string]any{"label": name, "options": nil}, nil, derr)
		if derr != nil {
			h.logFn("max-joiner: failed to create %s datachannel: %v", name, derr)
			continue
		}
		h.attachDCStateHandlers(dc)
	}

	pc.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		h.logFn("max-joiner: remote track: codec=%s ssrc=%d", track.Codec().MimeType, track.SSRC())
		go h.ReadTrackFn(track, func(frame []byte) {
			if h.vp8tunnel != nil {
				h.vp8tunnel.HandleFrame(frame)
			}
		}, h.logFn, "max-joiner")
	})

	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		h.trState("ice", state.String(), "")
		h.logFn("max-joiner: ICE state: %s", state.String())
	})
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c != nil {
			h.logFn("max-joiner: ICE candidate: %s %s %s:%d", c.Protocol, c.Typ, c.Address, c.Port)
		}
	})
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		h.trState("conn", state.String(), "")
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
				h.logFn("max-joiner: pushed vp8 config fps=%d batch=%d", vp8tun.FPS(), vp8tun.Batch())
			}
			if h.OnConnected != nil {
				h.OnConnected(vp8tun)
			}
		}
	})
	turnUser := ""
	if h.ci.Turn.Username != "" {
		turnUser = h.ci.Turn.Username[:min(6, len(h.ci.Turn.Username))] + "..."
	}
	h.logFn("max-joiner: SFU PC ready with %d ICE servers (turn-user=%q turn-urls=%v), waiting for producer offer",
		len(iceServers), turnUser, h.ci.Turn.URLs)
}

func (h *MaxHeadlessJoiner) initPC() {
	if h.params.MediaMode == "sfu" {
		h.initPCSFU()
		return
	}
	iceServers := h.iceServers()

	settingEngine := webrtc.SettingEngine{}
	settingEngine.DisableCloseByDTLS(true)
	settingEngine.DetachDataChannels()
	if h.PCConfig != nil {
		h.PCConfig.ConfigureSettingEngine(&settingEngine)
	}

	// Relay-only ICE. This is what the real client does in whitelist/restricted
	// mode: its SDK exposes forceRelayPolicy, which sets
	// iceTransportPolicy:"relay" (web bundle: `iceTransportPolicy: forceRelayPolicy
	// ? "relay" : "all"`). In DIRECT (peer-to-peer) topology that routes ALL media
	// through OK's own TURN servers instead of the peer's address — which is both
	// what a censor's allowlist permits (only MAX/OK IPs are reachable) and what
	// makes ICE work here: host/srflx pairs against the peer are exactly what the
	// TURN server refuses with "CreatePermission 403 Forbidden IP".
	icePolicy := webrtc.ICETransportPolicyRelay
	if h.params != nil && h.params.ICETransportPolicy == "all" {
		icePolicy = webrtc.ICETransportPolicyAll
	}
	h.logFn("max-joiner: ICE transport policy=%s", icePolicy)
	pcCfg := webrtc.Configuration{
		ICEServers:         iceServers,
		ICETransportPolicy: icePolicy,
	}
	pc, err := webrtc.NewAPI(webrtc.WithSettingEngine(settingEngine)).NewPeerConnection(pcCfg)
	h.trPC("new", pcConfigArgs(pcCfg), nil, err)
	if err != nil {
		h.logFn("max-joiner: failed to create PC: %v", err)
		return
	}
	h.pc = pc
	h.attachTranscriptStateHandlers(pc)
	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		h.trState("ice", state.String(), "")
	})
	h.startStatsLoop(pc)

	h.logFn("max-joiner: role=%s tunnelMode=%s", h.params.Role, h.params.TunnelMode)

	if h.params.Role == maxRoleOfferer {
		dc, err := pc.CreateDataChannel("tunnel", nil)
		h.trPC("createDataChannel", map[string]any{"label": "tunnel", "options": nil}, nil, err)
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
			// End-of-candidates. The real web client forwards an empty-candidate
			// sentinel {candidate:""} when local ICE gathering completes (gated by
			// its forwardEmptyIceCandidate flag). The *peer* ignores it — the
			// receiving side checks data.candidate.candidate is non-empty — so it
			// is meant for the SERVER: it is how the client tells OK-Calls "I'm
			// done gathering, you may trickle your own candidates now". Without it
			// the server withholds its trickled candidates from us, which is
			// exactly the offerer-receives-no-server-candidates asymmetry we hit.
			h.onLocalICEComplete()
			return
		}
		h.onLocalICECandidate(candidate)
	})
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		h.trState("conn", state.String(), "")
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
		h.trState("dc", "open", dc.Label())
		h.logFn("max-joiner: tunnel DC open")
		h.reconnectAttempt.Store(0)
		h.logFn("max-joiner: === DC TUNNEL CONNECTED ===")
		h.Status.EmitStatus(common.StatusTunnelConnected)
		if h.OnConnected != nil {
			h.OnConnected(tunnel.NewDCTunnel(dc, h.obf, common.RTPBufSize, h.logFn))
		}
	})
	dc.OnClose(func() {
		h.trState("dc", "close", dc.Label())
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

// emptyICECandidate is the end-of-candidates sentinel the real client sends to
// the server: transmit-data with data:{candidate:{candidate:""}}. The peer
// ignores it (empty inner .candidate), but OK-Calls uses it as the signal to
// begin trickling its own candidates back.
func emptyICECandidate() map[string]interface{} {
	return map[string]interface{}{"candidate": map[string]interface{}{"candidate": ""}}
}

// onLocalICEComplete fires when local ICE gathering finishes (nil candidate).
// It forwards the end-of-candidates sentinel to the server, buffering until the
// peer address is known so the marker always follows the real candidates.
func (h *MaxHeadlessJoiner) onLocalICEComplete() {
	h.peerMu.Lock()
	addr := h.peerAddr
	if addr == nil {
		h.pendingEmptyICE = true
		h.peerMu.Unlock()
		h.logFn("max-joiner: local ICE gathering complete (peer unknown, deferring end-of-candidates)")
		return
	}
	h.peerMu.Unlock()
	h.logFn("max-joiner: -> end-of-candidates marker")
	h.sendTransmitData(addr, emptyICECandidate())
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
		// Wait for the REAL peer's participantId (participant-joined /
		// registered-peer) before offering. The old ci.PeerID fallback sent the
		// offer + trickled candidates to the wrong participant, so the server
		// never associated them with the actual peer and never trickled its own
		// candidates back to us — the offerer-gets-no-server-candidates
		// asymmetry. Offer only once a real peer is known; a later trigger
		// (the notification) will call us again with a valid addr.
		h.logFn("max-joiner: offer deferred — real peer not learned yet")
		return
	}
	h.offerOnce.Do(func() {
		h.logFn("max-joiner: offering to peer participantId=%s type=%s deviceIdx=%d", addr.ParticipantID, addr.ParticipantType, addr.DeviceIdx)
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
	if h.params != nil && h.params.MediaMode == "sfu" {
		h.logFn("max-joiner: skipping direct offer in SFU mode (SFU will send producer-updated)")
		return
	}
	offer, err := h.pc.CreateOffer(nil)
	if err != nil {
		h.trPC("createOffer", nil, nil, err)
		h.logFn("max-joiner: create offer failed: %v", err)
		return
	}
	h.trPC("createOffer", nil, sdpArgs(offer), nil)
	if err := h.pc.SetLocalDescription(offer); err != nil {
		h.trPC("setLocalDescription", sdpArgs(offer), nil, err)
		h.logFn("max-joiner: set local description failed: %v", err)
		return
	}
	h.trPC("setLocalDescription", sdpArgs(offer), nil, nil)
	offer = h.gatheredLocalDescription(offer)
	// data:{sdp, animojiVersion}. The real client's sendSdp always attaches
	// animojiVersion (the vmoji protocol version, default 1) to every SDP and
	// sends no other extra field — in particular there is no "label" field.
	h.sendTransmitData(addr, map[string]interface{}{
		"sdp": map[string]interface{}{
			"type": "offer",
			"sdp":  offer.SDP,
		},
		"animojiVersion": 1,
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
	raw, err := json.Marshal(fields)
	if err != nil {
		h.logFn("max-joiner: ws marshal failed: %v", err)
		return
	}
	h.logFn("max-joiner: ws send raw JSON: %s", string(raw))
	// Write the exact bytes we transcribe (WriteJSON would append a newline).
	h.trWS("tx", string(raw))
	if err := h.ws.WriteMessage(websocket.TextMessage, raw); err != nil {
		h.logFn("max-joiner: ws write failed: %v", err)
	}
}

// sendRawText writes a bare (non-JSON) text frame under the write mutex.
// Used for the ws2 keepalive reply ("pong").
func (h *MaxHeadlessJoiner) sendRawText(text string) error {
	h.wsMu.Lock()
	defer h.wsMu.Unlock()
	if h.ws == nil {
		return errors.New("ws not connected")
	}
	h.trWS("tx", text)
	return h.ws.WriteMessage(websocket.TextMessage, []byte(text))
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
		h.trWS("rx", string(raw))
		h.handleMessage(raw)
	}
}

// handleMessage mirrors okcalls_peer.py Peer.reader/learn_peer exactly:
// learn the sender's participantId from EVERY notification (including
// transmitted-data — the answerer needs it to address the answer back to
// the offerer), then dispatch.
func (h *MaxHeadlessJoiner) handleMessage(raw []byte) {
	// ws2 keepalive: the server sends a bare text frame "ping" (not JSON) and
	// the web client answers with a bare text frame "pong" (MAX_WS2_REFERENCE.md
	// §6.1). Before this check the frame fell through the JSON decode below
	// and was silently dropped, so the server never got a pong from us.
	if string(raw) == "ping" {
		h.wsMu.Lock()
		first := !h.pongLogged
		h.pongLogged = true
		h.wsMu.Unlock()
		if err := h.sendRawText("pong"); err != nil {
			h.logFn("max-joiner: ws2 pong failed: %v", err)
		} else if first {
			h.logFn("max-joiner: ws2 ping -> pong (keepalive; further pings not logged)")
		}
		return
	}

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
		if seq, ok := m["sequence"]; ok {
			h.logFn("max-joiner: <- cmd response seq=%v result=%v error=%v (raw=%s)", seq, m["result"], m["error"], string(raw))
		} else {
			h.logFn("max-joiner: <- unknown msg (raw=%s)", string(raw))
		}
		return
	}

	h.learnPeer(m)

	switch notif {
	case "transmitted-data":
		// DIRECT p2p offer/answer/candidate relay. Not used in SFU mode.
		if data, ok := m["data"].(map[string]interface{}); ok {
			h.onTransmittedData(data)
		}
	case "producer-updated":
		// SFU's SDP offer for the producer/consumer negotiation.
		h.handleProducerUpdated(m)
	case "consumer-answered":
		// Confirms our allocate-consumer; nothing else to do.
		h.logFn("max-joiner: <- consumer-answered sessionId=%v", m["sessionId"])
	case "topology-changed":
		topo, _ := m["topology"].(string)
		h.logFn("max-joiner: <- topology-changed topology=%v", topo)
		// On a flip to SERVER (a 3rd participant joined), the DIRECT-era
		// allocate-consumer does not carry over — re-send it so the SFU offers.
		if h.params.MediaMode == "sfu" && topo == maxTopologyServer {
			h.sendAllocateConsumer()
		}
	case "participant-joined", "registered-peer":
		pid := m["participantId"]
		if pid == nil {
			if data, ok := m["data"].(map[string]interface{}); ok {
				pid = data["participantId"]
			}
		}
		h.logFn("max-joiner: <- %s participantId=%v", notif, pid)
		// DIRECT only: a peer joining triggers our p2p offer. SFU has no peer
		// offer (the SFU offers via producer-updated).
		if h.params.MediaMode != "sfu" {
			h.maybeSendOffer()
		}
	case "connection":
		h.logFn("max-joiner: <- connection (raw=%s)", string(raw))
		h.handleConnection(m)
	case "settings-update":
		h.logFn("max-joiner: <- %s", notif)
	default:
		h.logFn("max-joiner: <- notification %s (raw=%s)", notif, string(raw))
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
	emptyPending := h.pendingEmptyICE
	h.pendingEmptyICE = false
	h.peerMu.Unlock()

	for _, cand := range pending {
		h.sendTransmitData(addr, map[string]interface{}{"candidate": cand})
	}
	if emptyPending {
		h.logFn("max-joiner: -> end-of-candidates marker (flushed)")
		h.sendTransmitData(addr, emptyICECandidate())
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
		if err := json.Unmarshal(candidateJSON, &candidateInit); err == nil && candidateInit.Candidate != "" {
			// A non-empty inner .candidate distinguishes a real candidate from the
			// end-of-candidates sentinel {candidate:""}, which the real client
			// drops on receipt (the marker is for the server, not the peer).
			if h.OnRemoteCandidate != nil {
				h.OnRemoteCandidate(0, candidateInit.Candidate)
			}
			if h.remoteSet {
				h.logFn("max-joiner: <- server ICE candidate")
				h.trPC("addIceCandidate", candidateInit, nil, h.pc.AddICECandidate(candidateInit))
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
		remote := webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: sdpStr}
		h.trPC("setRemoteDescription", sdpArgs(remote), nil, h.pc.SetRemoteDescription(remote))
		h.remoteSet = true
		for _, candidate := range h.pendingICE {
			h.trPC("addIceCandidate", candidate, nil, h.pc.AddICECandidate(candidate))
		}
		h.pendingICE = nil

	case "offer":
		remote := webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: sdpStr}
		h.trPC("setRemoteDescription", sdpArgs(remote), nil, h.pc.SetRemoteDescription(remote))
		h.remoteSet = true
		for _, candidate := range h.pendingICE {
			h.trPC("addIceCandidate", candidate, nil, h.pc.AddICECandidate(candidate))
		}
		h.pendingICE = nil

		answer, err := h.pc.CreateAnswer(nil)
		if err != nil {
			h.trPC("createAnswer", nil, nil, err)
			h.logFn("max-joiner: create answer failed: %v", err)
			return
		}
		h.trPC("createAnswer", nil, sdpArgs(answer), nil)
		if err := h.pc.SetLocalDescription(answer); err != nil {
			h.trPC("setLocalDescription", sdpArgs(answer), nil, err)
			h.logFn("max-joiner: set local description failed: %v", err)
			return
		}
		h.trPC("setLocalDescription", sdpArgs(answer), nil, nil)
		answer = h.gatheredLocalDescription(answer)
		h.peerMu.Lock()
		addr := h.peerAddr
		h.peerMu.Unlock()
		if addr == nil {
			h.logFn("max-joiner: cannot send answer, peer not learned yet")
			return
		}
		h.sendTransmitData(addr, map[string]interface{}{
			"sdp": map[string]interface{}{
				"type": "answer",
				"sdp":  answer.SDP,
			},
			"animojiVersion": 1,
		})
		h.logFn("max-joiner: sent ANSWER [%s]", sdpUfragSummary(answer.SDP))
	}
}
