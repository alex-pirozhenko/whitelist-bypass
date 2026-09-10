// Command maxjoin is a two-host test harness for the MAX/OK-Calls data-tunnel
// joiner. It is NOT part of the shipped product — it exercises MaxHeadlessJoiner
// end to end so the WebRTC DataChannel can be validated across two hosts/egresses.
//
//	maxjoin -mode create -token-file A.json -peer-phone +B   > room.json
//	  (op76: create a room, print {joinLink, conversationId})
//	maxjoin -mode run -token-file A.json -role offerer -create -callee-phone +B [-secs 90]
//	  (offerer creates the room itself and offers; prints the joinLink/conv it made)
//	maxjoin -mode run -token-file B.json -role answerer -join-link <jl> -conv <uuid> [-secs 90]
//
// A/B token files are {"token","device_id","phone"} JSON. Both run peers derive
// the same obfuscator secret from the shared joinLink (or pass -tunnel-secret).
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
	joiner "github.com/alex-pirozhenko/whitelist-bypass/relay/pion/headless-joiner-common"
	"github.com/alex-pirozhenko/whitelist-bypass/relay/tunnel"
)

type tokenFile struct {
	Token    string `json:"token"`
	DeviceID string `json:"device_id"`
	Phone    string `json:"phone"`
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

func main() {
	mode := flag.String("mode", "run", "create | run")
	tokenPath := flag.String("token-file", "", "token JSON {token,device_id,phone}")
	peerPhone := flag.String("peer-phone", "", "create: callee phone for op76")
	role := flag.String("role", "answerer", "run: offerer | answerer")
	joinLink := flag.String("join-link", "", "run/answerer: the room joinLink")
	conv := flag.String("conv", "", "run/answerer: the conversationId")
	create := flag.Bool("create", false, "run/offerer: create the room via op76 itself")
	calleePhone := flag.String("callee-phone", "", "run/offerer -create: callee phone")
	tunnelSecret := flag.String("tunnel-secret", "", "optional shared base64 obfuscator secret")
	secs := flag.Int("secs", 90, "run: seconds to stay up")
	flag.Parse()

	if *tokenPath == "" {
		log.Fatal("-token-file is required")
	}
	tf := loadToken(*tokenPath)

	switch *mode {
	case "create":
		if *peerPhone == "" {
			log.Fatal("-peer-phone is required in create mode")
		}
		doCreate(tf, *peerPhone)
	case "run":
		doRun(tf, *role, *joinLink, *conv, *create, *calleePhone, *tunnelSecret, *secs)
	default:
		log.Fatalf("unknown mode %q", *mode)
	}
}

// doCreate performs op76 and prints {joinLink, conversationId} as JSON.
func doCreate(tf tokenFile, peerPhone string) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	c := maxproto.New(tf.Token, tf.DeviceID)
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
	uid, err := c.ResolveUID(ctx, peerPhone)
	if err != nil {
		log.Fatalf("resolve peer: %v", err)
	}
	// conversationId MUST be a UUID — the ws2 signaling server rejects other
	// formats with {"error":"invalid-request","message":"Invalid conversationId"}.
	convID := uuid.NewString()
	resp, err := c.VideoChatStart(ctx, []int64{uid}, convID)
	if err != nil {
		log.Fatalf("op76: %v", err)
	}
	jl, _ := resp["joinLink"].(string)
	out, _ := json.MarshalIndent(map[string]string{"joinLink": jl, "conversationId": convID}, "", "  ")
	fmt.Println(string(out))
}

// doRun constructs a MaxHeadlessJoiner and pumps test bytes over the tunnel.
func doRun(tf tokenFile, role, joinLink, conv string, create bool, calleePhone, tunnelSecret string, secs int) {
	logFn := func(f string, a ...any) { log.Printf("[%s] "+f, append([]any{role}, a...)...) }

	j := joiner.NewMaxHeadlessJoiner(
		logFn, joiner.ResolveFunc(resolve), statusEmitter{}, pcConfigurer{},
		func(*webrtc.PeerConnection, func(string, ...any), string) *webrtc.TrackLocalStaticSample { return nil },
		func(*webrtc.TrackRemote, func([]byte), func(string, ...any), string) {},
	)

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

	params := joiner.MaxHeadlessAuthParams{
		Token:          tf.Token,
		DeviceID:       tf.DeviceID,
		JoinLink:       joinLink,
		ConversationID: conv,
		Role:           role,
		TunnelMode:     "dc",
		TunnelSecret:   tunnelSecret,
		CreateRoom:     create,
		CalleePhone:    calleePhone,
	}
	pj, _ := json.Marshal(params)

	go j.RunWithParams(string(pj))

	time.Sleep(time.Duration(secs) * time.Second)
	j.Close()
	log.Printf("[%s] DONE — received %d messages", role, recvCount.Load())
	if recvCount.Load() > 0 {
		log.Printf("[%s] *** TRANSPORT WORKS — bytes flowed over the MAX call ***", role)
	}
}
