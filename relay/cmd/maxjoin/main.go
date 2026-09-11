// Command maxjoin is a two-host test harness for the MAX/OK-Calls data-tunnel
// joiner. It is NOT part of the shipped product — it exercises MaxHeadlessJoiner
// end to end so the WebRTC DataChannel can be validated across two hosts/egresses.
//
//	maxjoin -mode create -token-file A.json -peer-phone +B   > room.json
//	  (op76: create a room, print {joinLink, conversationId})
//	maxjoin -mode run -token-file A.json -role offerer -create -callee-phone +B [-secs 90]
//	  (offerer creates the room itself and offers; prints the joinLink/conv it made)
//	maxjoin -mode run -token-file B.json -role answerer -join-link <jl> -conv <uuid> [-secs 90]
//	maxjoin -mode callinfo -token-file B.json -join-link <jl> -conv <uuid> [-platform web]
//	  (control-plane join only: op166 CallInfo as JSON on stdout, for a browser
//	  page that opens the ws2 socket itself; the account token is never printed)
//
// A/B token files are {"token","device_id","phone","platform"?} JSON;
// platform is "android" (default, a master token) or "web" (a session derived
// with `maxverify -derive-phone`). -platform overrides the file. Both run peers
// derive the same obfuscator secret from the shared joinLink (or pass
// -tunnel-secret).
//
// -transcript <path> writes the JSONL diagnostic transcript (tools/maxref/
// TRANSCRIPT.md in letmeout) with -who as the participant label (default
// pion-<role>).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/pion/webrtc/v4"

	"github.com/alex-pirozhenko/whitelist-bypass/relay/maxproto"
	"github.com/alex-pirozhenko/whitelist-bypass/relay/pion"
	joiner "github.com/alex-pirozhenko/whitelist-bypass/relay/pion/headless-joiner-common"
	"github.com/alex-pirozhenko/whitelist-bypass/relay/tunnel"
)

type tokenFile struct {
	Token    string `json:"token"`
	DeviceID string `json:"device_id"`
	Phone    string `json:"phone"`
	Platform string `json:"platform"` // "android" (default) | "web"
}

// statusEmitter / pcConfigurer are trivial stubs of the joiner's deps.
type statusEmitter struct{}

func (statusEmitter) EmitStatus(s string)      { log.Printf("[status] %s", s) }
func (statusEmitter) EmitStatusError(s string) { log.Printf("[status-err] %s", s) }

type pcConfigurer struct{}

func (pcConfigurer) ConfigureSettingEngine(*webrtc.SettingEngine) {}

// resolve returns the first IP for host (prefer IPv4), pinning like the joiners do.
func resolve(host string) (string, error) {
	ips, err := net.DefaultResolver.LookupIPAddr(context.Background(), host)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			return ip.IP.String(), nil
		}
	}
	if len(ips) > 0 {
		return ips[0].IP.String(), nil
	}
	return "", fmt.Errorf("no addresses for %s", host)
}

func loadToken(path string) tokenFile {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read token file: %v", err)
	}
	var tf tokenFile
	if err := json.Unmarshal(b, &tf); err != nil {
		log.Fatalf("parse token file: %v", err)
	}
	return tf
}

// newControlClient builds the maxproto client for the token's platform: a WEB
// session must be used over a WEB-identified connection (maxproto.NewWeb).
func newControlClient(tf tokenFile) *maxproto.Client {
	if tf.Platform == "web" {
		return maxproto.NewWeb(tf.Token, tf.DeviceID)
	}
	return maxproto.New(tf.Token, tf.DeviceID)
}

// runOpts carries the -mode run / callinfo settings.
type runOpts struct {
	role, joinLink, conv      string
	create                    bool
	calleePhone, tunnelSecret string
	secs                      int
	icePolicy, mediaMode      string
	calleeUID                 int64
	transcriptPath, who       string
}

func main() {
	mode := flag.String("mode", "run", "create | run | callinfo")
	tokenPath := flag.String("token-file", "", "token JSON {token,device_id,phone,platform?}")
	platform := flag.String("platform", "", "session platform: android | web (overrides the token file's \"platform\")")
	peerPhone := flag.String("peer-phone", "", "create: callee phone for op76 (op46 resolve)")
	calleeUID := flag.Int64("callee-uid", 0, "create: callee uid to invite directly (skips op46; from the callee's own session)")
	role := flag.String("role", "answerer", "run: offerer | answerer")
	joinLink := flag.String("join-link", "", "run/answerer, callinfo: the room joinLink")
	conv := flag.String("conv", "", "run/answerer, callinfo: the conversationId")
	create := flag.Bool("create", false, "run/offerer: create the room via op76 itself")
	calleePhone := flag.String("callee-phone", "", "run/offerer -create: callee phone")
	tunnelSecret := flag.String("tunnel-secret", "", "optional shared base64 obfuscator secret")
	secs := flag.Int("secs", 90, "run: seconds to stay up")
	icePolicy := flag.String("ice-policy", "relay", "run: ICE transport policy (relay|all)")
	mediaMode := flag.String("media-mode", "direct", "run: media topology (direct|sfu)")
	transcriptPath := flag.String("transcript", "", "run: write the JSONL diagnostic transcript to this file")
	who := flag.String("who", "", "run: participant label for the transcript (default pion-<role>)")
	flag.Parse()

	if *tokenPath == "" {
		log.Fatal("-token-file is required")
	}
	tf := loadToken(*tokenPath)
	if *platform != "" {
		tf.Platform = *platform
	}
	if tf.Platform == "" {
		tf.Platform = "android"
	}
	if tf.Platform != "android" && tf.Platform != "web" {
		log.Fatalf("unknown platform %q (want android|web)", tf.Platform)
	}
	log.Printf("token file %s: phone=%s platform=%s", *tokenPath, tf.Phone, tf.Platform)

	opts := runOpts{
		role: *role, joinLink: *joinLink, conv: *conv, create: *create,
		calleePhone: *calleePhone, tunnelSecret: *tunnelSecret, secs: *secs,
		icePolicy: *icePolicy, mediaMode: *mediaMode, calleeUID: *calleeUID,
		transcriptPath: *transcriptPath, who: *who,
	}

	switch *mode {
	case "create":
		// peer-phone optional: empty => a creator-only room (the creator's own
		// devices can still join it). -callee-uid invites a specific account by
		// uid (obtained from that account's own session), no phone resolution.
		doCreate(tf, *peerPhone, *calleeUID)
	case "run":
		doRun(tf, opts)
	case "callinfo":
		if opts.joinLink == "" && !opts.create {
			log.Fatal("callinfo: -join-link is required (or -create with -callee-phone/-callee-uid)")
		}
		doCallInfo(tf, opts)
	default:
		log.Fatalf("unknown mode %q", *mode)
	}
}

// doCreate performs op76 and prints {joinLink, conversationId} as JSON.
func doCreate(tf tokenFile, peerPhone string, calleeUID int64) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	c := newControlClient(tf)
	if err := c.Connect(ctx, resolve); err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer c.Close()
	if _, err := c.SessionInit(ctx); err != nil {
		log.Fatalf("session init: %v", err)
	}
	if _, err := c.Login(ctx); err != nil {
		log.Fatalf("login: %v", err)
	}
	var callees []int64
	if calleeUID != 0 {
		callees = []int64{calleeUID}
	} else if peerPhone != "" {
		uid, err := c.ResolveUID(ctx, peerPhone)
		if err != nil {
			log.Fatalf("resolve peer: %v", err)
		}
		callees = []int64{uid}
	}
	// conversationId MUST be a UUID — the ws2 signaling server rejects other
	// formats with {"error":"invalid-request","message":"Invalid conversationId"}.
	// Empty callees => a creator-only room; the creator's own devices can still
	// op166-join it (only a DIFFERENT account is refused).
	convID := uuid.NewString()
	resp, err := c.VideoChatStart(ctx, callees, convID)
	if err != nil {
		log.Fatalf("op76: %v", err)
	}
	jl, _ := resp["joinLink"].(string)
	out, _ := json.MarshalIndent(map[string]string{"joinLink": jl, "conversationId": convID}, "", "  ")
	fmt.Println(string(out))
}

// authParams builds the joiner's JSON auth params from the token file + opts.
func authParams(tf tokenFile, o runOpts) string {
	params := joiner.MaxHeadlessAuthParams{
		Token:              tf.Token,
		DeviceID:           tf.DeviceID,
		Platform:           tf.Platform,
		JoinLink:           o.joinLink,
		ConversationID:     o.conv,
		Role:               o.role,
		ICETransportPolicy: o.icePolicy,
		TunnelMode:         "dc",
		TunnelSecret:       o.tunnelSecret,
		CreateRoom:         o.create,
		CalleePhone:        o.calleePhone,
		CalleeUID:          o.calleeUID,
		MediaMode:          o.mediaMode,
	}
	pj, _ := json.Marshal(params)
	return string(pj)
}

func newJoiner(logFn func(string, ...any)) *joiner.MaxHeadlessJoiner {
	return joiner.NewMaxHeadlessJoiner(
		logFn, joiner.ResolveFunc(resolve), statusEmitter{}, pcConfigurer{},
		pion.AddTunnelTracks,
		pion.ReadTrack,
	)
}

// doCallInfo performs the control-plane join only and prints the CallInfo a
// browser page needs to open ws2 itself. TURN credentials are short-lived call
// grants and are printed; the account token never is.
func doCallInfo(tf tokenFile, o runOpts) {
	logFn := func(f string, a ...any) { log.Printf("[callinfo] "+f, a...) }
	j := newJoiner(logFn)
	ci, jl, conv, err := j.CallInfoOnly(authParams(tf, o))
	if err != nil {
		log.Fatalf("callinfo: %v", err)
	}
	out := map[string]any{
		"platform":       tf.Platform,
		"phone":          tf.Phone,
		"joinLink":       jl,
		"conversationId": conv,
		"endpoint":       ci.Endpoint,
		"wtEndpoint":     ci.WtEndpoint,
		"turn":           ci.Turn,
		"stun":           map[string]any{"urls": ci.Stun.URLs},
		"id":             map[string]any{"internal": ci.ID.Internal, "external": ci.ID.External},
		"clientType":     ci.ClientType,
		"peerId":         ci.PeerID,
		"deviceIdx":      ci.DeviceIdx,
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		log.Fatalf("callinfo: marshal: %v", err)
	}
	fmt.Println(string(b))
}

// doRun constructs a MaxHeadlessJoiner and pumps test bytes over the tunnel.
func doRun(tf tokenFile, o runOpts) {
	role := o.role
	logFn := func(f string, a ...any) { log.Printf("[%s] "+f, append([]any{role}, a...)...) }

	j := newJoiner(logFn)

	if o.transcriptPath != "" {
		f, err := os.OpenFile(o.transcriptPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			log.Fatalf("open transcript: %v", err)
		}
		defer f.Close()
		who := o.who
		if who == "" {
			who = "pion-" + role
		}
		j.Transcript = joiner.NewJSONLTranscript(f, who)
		log.Printf("[%s] transcript -> %s (who=%s)", role, o.transcriptPath, who)
	}

	var recvCount atomic.Int64
	j.OnConnected = func(dt tunnel.DataTunnel) {
		logFn("*** TUNNEL CONNECTED — starting data pump ***")
		dt.SetOnData(func(b []byte) {
			recvCount.Add(1)
			logFn("<<< RECV %d bytes: %q", len(b), string(b))
		})
		go func() {
			for i := 0; i < 100; i++ {
				dt.SendData([]byte(fmt.Sprintf("%s-msg-%d", role, i)))
				time.Sleep(2 * time.Second)
			}
		}()
	}

	go j.RunWithParams(authParams(tf, o))

	time.Sleep(time.Duration(o.secs) * time.Second)
	j.Close()
	log.Printf("[%s] DONE — received %d messages", role, recvCount.Load())
	if recvCount.Load() > 0 {
		log.Printf("[%s] *** TRANSPORT WORKS — bytes flowed over the MAX call ***", role)
	}
}
