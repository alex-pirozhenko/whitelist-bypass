package joiner

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

func tmServerHelloRaw(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]interface{}{
		"uid":         "",
		"serverHello": tmServerHelloFixture(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func tmFastJoiner(t *testing.T) *TelemostHeadlessJoiner {
	t.Helper()
	f := newFakeICEResolver()
	f.answer[tmFastICEHost] = tmFastICEIP
	f.answer[tmStallICEHost] = tmStallICEIP
	j := newTelemostTestJoiner(f.resolve)
	t.Cleanup(j.Close)
	return j
}

// TestTelemostSecondServerHelloClosesPreviousPCs is the regression test for
// the PeerConnection leak: a second serverHello on the same session must not
// leave the first sub/pub pair open. Dropping the pointer is not enough --
// only Close() tears down the ICE agent, DTLS transport and TURN allocation,
// and those are what accumulated as ~+125 goroutines/h on the exit.
func TestTelemostSecondServerHelloClosesPreviousPCs(t *testing.T) {
	j := tmFastJoiner(t)
	raw := tmServerHelloRaw(t)

	j.handleMessage(raw)
	firstSub, firstPub := j.subPC, j.pubPC
	if firstSub == nil || firstPub == nil {
		t.Fatalf("first serverHello created no PCs: sub=%v pub=%v", firstSub, firstPub)
	}

	j.handleMessage(raw)
	secondSub, secondPub := j.subPC, j.pubPC
	if secondSub == nil || secondPub == nil {
		t.Fatalf("second serverHello created no PCs: sub=%v pub=%v", secondSub, secondPub)
	}
	if secondSub == firstSub || secondPub == firstPub {
		t.Fatalf("second serverHello reused the old PCs: sub same=%v pub same=%v",
			secondSub == firstSub, secondPub == firstPub)
	}

	if got := firstSub.ConnectionState(); got != webrtc.PeerConnectionStateClosed {
		t.Fatalf("orphaned sub PC state = %s, want closed", got)
	}
	if got := firstPub.ConnectionState(); got != webrtc.PeerConnectionStateClosed {
		t.Fatalf("orphaned pub PC state = %s, want closed", got)
	}
	if got := secondSub.ConnectionState(); got == webrtc.PeerConnectionStateClosed {
		t.Fatalf("current sub PC was closed too")
	}
	if got := secondPub.ConnectionState(); got == webrtc.PeerConnectionStateClosed {
		t.Fatalf("current pub PC was closed too")
	}
}

// TestTelemostRepeatedServerHelloLeavesOnePairOpen extends the above across
// several re-inits: at most one live pair may exist at any time.
func TestTelemostRepeatedServerHelloLeavesOnePairOpen(t *testing.T) {
	j := tmFastJoiner(t)
	raw := tmServerHelloRaw(t)

	var seen []*webrtc.PeerConnection
	for i := 0; i < 5; i++ {
		j.handleMessage(raw)
		seen = append(seen, j.subPC, j.pubPC)
	}

	live := 0
	for _, pc := range seen {
		if pc != nil && pc.ConnectionState() != webrtc.PeerConnectionStateClosed {
			live++
		}
	}
	if live != 2 {
		t.Fatalf("%d PeerConnections still open after 5 re-inits, want exactly 2 (the current pair)", live)
	}
}

// TestTelemostInitPCAfterCloseCreatesNothing proves a serverHello that lands
// after the joiner has been abandoned builds no PeerConnections at all --
// exactly the shape of the 2026-09-18 capture, where the pair was created
// 20.1s after serverHello into a session the ladder had already given up on
// and both PCs went straight to "closed".
func TestTelemostInitPCAfterCloseCreatesNothing(t *testing.T) {
	j := tmFastJoiner(t)
	raw := tmServerHelloRaw(t)

	j.Close()
	j.handleMessage(raw)

	if j.subPC != nil || j.pubPC != nil {
		t.Fatalf("PCs created for a closed joiner: sub=%v pub=%v", j.subPC, j.pubPC)
	}
}

// TestTelemostClosePCPairIsIdempotent proves Close() may be called twice (the
// reconnect loop and the caller both do) without panicking or double-closing.
func TestTelemostClosePCPairIsIdempotent(t *testing.T) {
	j := tmFastJoiner(t)
	j.handleMessage(tmServerHelloRaw(t))

	done := make(chan struct{})
	go func() {
		j.Close()
		j.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close() did not return")
	}
	if j.subPC != nil || j.pubPC != nil {
		t.Fatalf("Close left PC pointers set: sub=%v pub=%v", j.subPC, j.pubPC)
	}
}
