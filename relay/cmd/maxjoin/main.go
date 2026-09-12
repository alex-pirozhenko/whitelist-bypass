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
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
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
	role, joinLink, conv       string
	create                     bool
	calleePhone, tunnelSecret  string
	secs                       int
	icePolicy, mediaMode       string
	calleeUID                  int64
	transcriptPath, who        string
	vp8FPS, vp8Batch           int
	sfuWidth, sfuHeight        int
	bench                      bool
	benchSender                bool
	benchSize, benchIntervalMS int
	benchRateCtl               bool
	benchCSVPath               string
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
	vp8FPS := flag.Int("vp8-fps", 0, "run/sfu: VP8 tunnel nominal fps (0 = tunnel default)")
	vp8Batch := flag.Int("vp8-batch", 0, "run/sfu: VP8 tunnel samples per frame interval (0 = tunnel default)")
	sfuWidth := flag.Int("sfu-width", 1280, "run/sfu: requested SFU video width (default 1280)")
	sfuHeight := flag.Int("sfu-height", 720, "run/sfu: requested SFU video height (default 720)")
	transcriptPath := flag.String("transcript", "", "run: write the JSONL diagnostic transcript to this file")
	who := flag.String("who", "", "run: participant label for the transcript (default pion-<role>)")
	bench := flag.Bool("bench", false, "run: throughput benchmark mode")
	benchSender := flag.Bool("bench-sender", true, "run/bench: enable benchmark sender loop (set false for recv-only)")
	benchSize := flag.Int("bench-size", 800, "run/bench: payload bytes per frame (default 800)")
	benchIntervalMS := flag.Int("bench-interval-ms", 50, "run/bench: interval between sends in ms (default 50)")
	benchRateCtl := flag.Bool("bench-ratectl", true, "run/bench: drive the tunnel through the rate controller, so idle tiers and the AIMD frame size are exercised and reported (set false to measure the raw tunnel)")
	benchCSV := flag.String("bench-csv", "", "run/bench: write one CSV line per second to this path (t,sentFrames,sentBytes,keepalives,recvFrames,recvBytes,gaps,lostPkts,rttMs,lossPct,maxFrameBytes,state)")
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
		vp8FPS: *vp8FPS, vp8Batch: *vp8Batch,
		sfuWidth: *sfuWidth, sfuHeight: *sfuHeight,
		transcriptPath: *transcriptPath, who: *who,
		bench: *bench, benchSender: *benchSender, benchSize: *benchSize, benchIntervalMS: *benchIntervalMS,
		benchRateCtl: *benchRateCtl,
		benchCSVPath: *benchCSV,
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
		VP8FPS:             o.vp8FPS,
		VP8Batch:           o.vp8Batch,
		SFUVideoWidth:      o.sfuWidth,
		SFUVideoHeight:     o.sfuHeight,
		ForceVP8Read:       o.mediaMode == "sfu",
	}
	pj, _ := json.Marshal(params)
	return string(pj)
}

func newJoiner(logFn func(string, ...any), mediaMode string) *joiner.MaxHeadlessJoiner {
	j := joiner.NewMaxHeadlessJoiner(
		logFn, joiner.ResolveFunc(resolve), statusEmitter{}, pcConfigurer{},
		pion.AddTunnelTracks,
		pion.ReadTrack,
	)
	j.ForceReadTrackFn = pion.ReadTrackForceVP8
	return j
}

// doCallInfo performs the control-plane join only and prints the CallInfo a
// browser page needs to open ws2 itself. TURN credentials are short-lived call
// grants and are printed; the account token never is.
func doCallInfo(tf tokenFile, o runOpts) {
	logFn := func(f string, a ...any) { log.Printf("[callinfo] "+f, a...) }
	j := newJoiner(logFn, o.mediaMode)
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

	j := newJoiner(logFn, o.mediaMode)

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

	var csvFile *os.File
	if o.bench && o.benchCSVPath != "" {
		var err error
		csvFile, err = os.OpenFile(o.benchCSVPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			log.Fatalf("open bench csv: %v", err)
		}
		defer csvFile.Close()
		if _, err := csvFile.WriteString("t,sentFrames,sentBytes,keepalives,recvFrames,recvBytes,gaps,lostPkts,rttMs,lossPct,maxFrameBytes,state\n"); err != nil {
			log.Fatalf("write bench csv header: %v", err)
		}
	}

	var benchMu sync.Mutex
	var lastSeq uint32
	var haveLastSeq bool
	var gaps uint64
	var lostPkts uint64

	var recvCount atomic.Int64
	var recvBytes atomic.Int64
	var sendBytes atomic.Int64
	var firstRecv atomic.Int64
	var lastRecv atomic.Int64

	// rb is non-nil exactly when -bench -bench-ratectl routes traffic
	// through a real RelayBridge instead of straight at the DataTunnel (see
	// below). Every ratectl reading in this function (MaxFrameBytes/State/
	// LastStats) goes through rb, never through a bare *tunnel.RateController
	// -- that bare-RateController shortcut used to be exactly the bug this
	// fixes (see the comment at its construction below).
	var rb *tunnel.RelayBridge
	j.OnConnected = func(dt tunnel.DataTunnel) {
		logFn("*** TUNNEL CONNECTED — starting data pump ***")

		recvHandler := func(b []byte) {
			now := time.Now().UnixNano()
			firstRecv.CompareAndSwap(0, now)
			lastRecv.Store(now)
			cnt := recvCount.Add(1)
			tot := recvBytes.Add(int64(len(b)))

			if o.bench && len(b) >= 4 {
				seq := binary.BigEndian.Uint32(b[0:4])
				benchMu.Lock()
				if haveLastSeq {
					if seq != lastSeq+1 {
						gaps++
						lostPkts += uint64(seq - lastSeq)
					}
				}
				lastSeq = seq
				haveLastSeq = true
				benchMu.Unlock()
			}

			if !o.bench {
				logFn("<<< RECV %d bytes: %q", len(b), string(b))
			} else if cnt%20 == 0 || tot >= 500*1024 {
				el := time.Duration(now - firstRecv.Load()).Seconds()
				if el > 0 {
					rateKBps := (float64(tot) / 1024.0) / el
					rateMbps := (float64(tot) * 8.0) / (el * 1000.0 * 1000.0)
					logFn("<<< RECV #%d: total %d bytes (%.2f KB/s, %.2f Mbps)", cnt, tot, rateKBps, rateMbps)
				}
			}
		}

		// Benchmark traffic used to go straight at the raw tunnel with a bare
		// *tunnel.RateController constructed on the side (NewRateController(dt,
		// ...)). That controller's own statsPingLoop DOES send real
		// MsgPing/MsgStats frames onto dt -- but nothing on either end ever
		// decodes them: dt.SetOnData was bound directly to bench payload
		// parsing (checking b[0:4] as a raw sequence number), the exact
		// dispatch RelayBridge.handleTunnelData normally provides. So the
		// controller's own ping/stats frames arrived at the peer and were
		// silently misread as bench payloads (or vice versa), AIMD never saw
		// a peer's real loss/RTT, and the rtt column stayed zero forever.
		// Routing bench traffic through an actual RelayBridge (via the
		// reserved benchConnID path -- see SendBenchData/SetOnBenchData) is
		// the fix: it's the same control-message dispatch a live SOCKS
		// connection gets, just carrying synthetic payload instead of proxied
		// bytes, so MsgStats/MsgPing genuinely round-trip and AIMD reacts to
		// the peer's real measurements.
		if o.bench && o.benchRateCtl {
			rb = tunnel.NewRelayBridge(dt, "bench", 32*1024, logFn, true)
			rb.SetOnBenchData(recvHandler)
			logFn("bench: rate controller attached via RelayBridge (tiers, AIMD and real peer stats active)")
		} else {
			dt.SetOnData(recvHandler)
		}

		if rb != nil {
			// Independent of -bench-csv: without this, a run with no CSV
			// path gets zero visibility into what the controller is doing
			// until the final summary line, which is exactly the number
			// that does not matter for an idle/congestion question.
			go func() {
				ticker := time.NewTicker(5 * time.Second)
				defer ticker.Stop()
				for range ticker.C {
					st := rb.LastStats()
					logFn("bench: ratectl state=%s maxFrameBytes=%d lastLossPct=%.2f lastRTT=%s",
						rb.State(), rb.MaxFrameBytes(), st.LossPercent, st.RTT)
				}
			}()
		}

		if csvFile != nil {
			go func() {
				tSec := 0
				ticker := time.NewTicker(time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						var sentFrames, sentBytes, keepalives, recvFrames, recvBytes uint64
						if cs, ok := dt.(interface{ Counters() tunnel.Counters }); ok {
							c := cs.Counters()
							sentFrames = c.SentFrames
							sentBytes = c.SentBytes
							keepalives = c.Keepalives
							recvFrames = c.RecvFrames
							recvBytes = c.RecvBytes
						}

						benchMu.Lock()
						g := gaps
						lp := lostPkts
						benchMu.Unlock()

						rttMs := 0
						lossPct := 0.0
						maxFrameBytes := 0
						state := "raw"
						if rb != nil {
							maxFrameBytes = rb.MaxFrameBytes()
							state = rb.State().String()
							st := rb.LastStats()
							rttMs = int(st.RTT / time.Millisecond)
							lossPct = st.LossPercent
						}

						row := fmt.Sprintf("%d,%d,%d,%d,%d,%d,%d,%d,%d,%.2f,%d,%s\n",
							tSec, sentFrames, sentBytes, keepalives, recvFrames, recvBytes, g, lp, rttMs, lossPct, maxFrameBytes, state)
						if _, err := csvFile.WriteString(row); err != nil {
							logFn("write csv row error: %v", err)
						}
						tSec++
					}
				}
			}()
		}
		go func() {
			if o.bench && o.benchSender {
				chunkSize := o.benchSize
				if chunkSize <= 0 {
					chunkSize = 800
				}
				interval := time.Duration(o.benchIntervalMS) * time.Millisecond
				if interval < 0 {
					interval = 50 * time.Millisecond
				} else if interval == 0 {
					interval = 2 * time.Millisecond
				}
				buf := make([]byte, chunkSize)
				for i := range buf {
					buf[i] = byte(i & 0xff)
				}
				logFn(">>> STARTING BENCHMARK chunk=%d bytes interval=%v", chunkSize, interval)
				seq := 0
				ticker := time.NewTicker(interval)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						binary.BigEndian.PutUint32(buf[0:4], uint32(seq))
						seq++
						if rb != nil {
							rb.SendBenchData(buf)
						} else {
							dt.SendData(buf)
						}
						sendBytes.Add(int64(chunkSize))
					}
				}
			} else if o.bench {
				// Receive-only really must mean silent. This used to fall through
				// to the chat loop below, which sends every two seconds -- just
				// inside the three-second active-to-drain threshold, so the tunnel
				// never went idle and an idle measurement could not be taken at
				// all. The tier sat at active for a full minute of "idle" before
				// this was noticed.
				logFn("bench: receive-only, sending nothing")
			} else {
				for i := 0; i < 100; i++ {
					msg := fmt.Sprintf("%s-msg-%d", role, i)
					dt.SendData([]byte(msg))
					sendBytes.Add(int64(len(msg)))
					logFn(">>> SEND %d bytes: %q", len(msg), msg)
					time.Sleep(2 * time.Second)
				}
			}
		}()
	}

	go j.RunWithParams(authParams(tf, o))

	time.Sleep(time.Duration(o.secs) * time.Second)
	j.Close()
	rc := recvCount.Load()
	rBytes := recvBytes.Load()
	sb := sendBytes.Load()
	log.Printf("[%s] DONE — sent %d bytes, received %d msgs (%d bytes)", role, sb, rc, rBytes)
	if rc > 0 {
		log.Printf("[%s] *** TRANSPORT WORKS — bytes flowed over the MAX call ***", role)
		if o.bench && firstRecv.Load() > 0 && lastRecv.Load() > firstRecv.Load() {
			dur := time.Duration(lastRecv.Load() - firstRecv.Load()).Seconds()
			rateKBps := (float64(rBytes) / 1024.0) / dur
			rateMbps := (float64(rBytes) * 8.0) / (dur * 1000.0 * 1000.0)
			log.Printf("[%s] *** THROUGHPUT BENCHMARK: %.2f KB/s (%.2f Mbps) over %.2f seconds ***",
				role, rateKBps, rateMbps, dur)
		}
	}
}
