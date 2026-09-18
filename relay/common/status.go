package common

import "fmt"

const (
	StatusReady           = "READY"
	StatusConnecting      = "CONNECTING"
	StatusReconnecting    = "RECONNECTING"
	StatusTunnelConnected = "TUNNEL_CONNECTED"
	StatusTunnelLost      = "TUNNEL_LOST"
	StatusError           = "ERROR"

	// StatusJoined sits between StatusConnecting and StatusTunnelConnected:
	// the joiner's SIGNALLING join has been acknowledged by the provider
	// (the joiner is a participant in the room/conversation and its
	// PeerConnection is built and gathering), but no remote peer has
	// answered yet, so the PeerConnection has not reached
	// webrtc.PeerConnectionStateConnected and StatusTunnelConnected has NOT
	// been emitted.
	//
	// It exists because that gap is not the same length for every provider.
	// The Telemost joiner publishes to an SFU, so its pub PC connects with
	// nobody else in the room and StatusTunnelConnected follows within
	// seconds. The MAX joiner in DIRECT topology has no SFU to connect to:
	// its PC only reaches Connected once a real device peer sends an
	// answer, so a headless MAX joiner sitting in an empty room emits
	// StatusConnecting and then nothing at all, indefinitely — which is
	// indistinguishable, to a supervisor, from a join that failed outright.
	// StatusJoined is that missing "I am in the room, waiting for someone"
	// signal.
	//
	// Consumers that map this vocabulary onto their own state machine
	// should treat it like StatusConnecting (it is NOT a connected tunnel);
	// supervisors that time out a join should treat it as progress.
	StatusJoined = "JOINED"
)

func EmitStatus(status string) {
	fmt.Printf("STATUS:%s\n", status)
}

func EmitStatusError(msg string) {
	fmt.Printf("STATUS:%s:%s\n", StatusError, msg)
}
