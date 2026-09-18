package joiner

import (
	"testing"

	"github.com/alex-pirozhenko/whitelist-bypass/relay/common"
	"github.com/alex-pirozhenko/whitelist-bypass/relay/maxproto"
)

// recordingStatusEmitter captures every status a joiner emits, in order.
type recordingStatusEmitter struct {
	statuses []string
	errors   []string
}

func (r *recordingStatusEmitter) EmitStatus(status string) {
	r.statuses = append(r.statuses, status)
}

func (r *recordingStatusEmitter) EmitStatusError(msg string) {
	r.errors = append(r.errors, msg)
}

// TestHandleConnectionEmitsStatusJoined pins the signal letmeout's exitd
// relies on to tell "the MAX exit is in the room, waiting for a device" apart
// from "the MAX join failed".
//
// In DIRECT topology the joiner's PeerConnection only reaches Connected once a
// real peer answers, so StatusTunnelConnected never fires in an empty room and
// the joiner is silent after StatusConnecting -- exactly what a failed join
// looks like from the outside. handleConnection is the point where that
// ambiguity is resolved: op166 was accepted, ws2 is up, the server's
// "connection" notification has arrived with this session's TURN grant and the
// PeerConnection is built.
func TestHandleConnectionEmitsStatusJoined(t *testing.T) {
	rec := &recordingStatusEmitter{}
	h := NewMaxHeadlessJoiner(func(string, ...any) {}, stubMaxResolve, rec, stubMaxPCConfigurer{}, stubMaxAddTracks, stubMaxReadTrack)
	params := &MaxHeadlessAuthParams{Platform: "android", Role: maxRoleAnswerer, ICETransportPolicy: "all"}
	params.applyDefaults()
	h.params = params
	h.ci = &maxproto.CallInfo{Endpoint: "wss://stub.invalid/ws"}
	h.selfUID = "1"
	defer h.Close()

	h.handleConnection(map[string]interface{}{
		"conversation": map[string]interface{}{"topology": "DIRECT", "state": "ACTIVE"},
		"conversationParams": map[string]interface{}{
			"turn": map[string]interface{}{
				"urls":       []interface{}{"turn:127.0.0.1:3478?transport=udp"},
				"username":   "stub",
				"credential": "stub",
			},
		},
	})

	if h.pc == nil {
		t.Fatal("handleConnection did not build a PeerConnection")
	}
	if got := countStatus(rec.statuses, common.StatusJoined); got != 1 {
		t.Fatalf("StatusJoined emitted %d times, want exactly 1 (got %v)", got, rec.statuses)
	}
	if got := countStatus(rec.statuses, common.StatusTunnelConnected); got != 0 {
		t.Fatalf("StatusTunnelConnected emitted %d times with no peer present, want 0 (got %v)", got, rec.statuses)
	}
	if len(rec.errors) != 0 {
		t.Fatalf("unexpected status errors: %v", rec.errors)
	}

	// A repeated "connection" notification must not re-emit: it is guarded by
	// the same h.pc == nil check initPC is.
	h.handleConnection(map[string]interface{}{
		"conversation": map[string]interface{}{"topology": "DIRECT"},
	})
	if got := countStatus(rec.statuses, common.StatusJoined); got != 1 {
		t.Fatalf("StatusJoined re-emitted on a repeated connection notification: %v", rec.statuses)
	}
}

// TestStatusJoinedIsDistinct guards against the new constant colliding with an
// existing one -- consumers switch on these strings, and a duplicate value
// would silently alias two states.
func TestStatusJoinedIsDistinct(t *testing.T) {
	all := []string{
		common.StatusReady, common.StatusConnecting, common.StatusReconnecting,
		common.StatusTunnelConnected, common.StatusTunnelLost, common.StatusError,
		common.StatusJoined,
	}
	seen := map[string]bool{}
	for _, s := range all {
		if s == "" {
			t.Fatal("empty status constant")
		}
		if seen[s] {
			t.Fatalf("duplicate status constant value %q", s)
		}
		seen[s] = true
	}
	if common.StatusJoined != "JOINED" {
		t.Fatalf("StatusJoined = %q, want JOINED", common.StatusJoined)
	}
}

func countStatus(got []string, want string) int {
	n := 0
	for _, s := range got {
		if s == want {
			n++
		}
	}
	return n
}
