package joiner

import (
	"testing"

	"github.com/alex-pirozhenko/whitelist-bypass/relay/tunnel"
)

func TestMaxReliableActivatesKCP(t *testing.T) {
	h := NewMaxHeadlessJoiner(func(string, ...any) {}, stubMaxResolve, stubMaxStatusEmitter{}, stubMaxPCConfigurer{}, stubMaxAddTracks, stubMaxReadTrack)
	h.params = &MaxHeadlessAuthParams{Reliable: true}
	h.configAck.mark()

	secret := []byte("pump-secret-key-12345")
	obf, err := tunnel.NewTunnelObfuscator(secret)
	if err != nil {
		t.Fatalf("failed to create obfuscator: %v", err)
	}
	vp8 := tunnel.NewVP8DataTunnelWithQueue(nil, obf, func(string, ...any) {}, 64)

	var captured tunnel.DataTunnel
	h.OnConnected = func(dt tunnel.DataTunnel) {
		captured = dt
	}

	h.activateTunnel(vp8)

	if h.kcptun == nil {
		t.Fatal("expected h.kcptun != nil")
	}
	defer h.Close()

	wrapper, ok := captured.(*sfuTunnelWrapper)
	if !ok {
		t.Fatalf("expected captured tunnel to be *sfuTunnelWrapper, got %T", captured)
	}
	if wrapper.DataTunnel != h.kcptun {
		t.Fatalf("expected wrapper embedded DataTunnel to be h.kcptun, got %T", wrapper.DataTunnel)
	}
}

func TestMaxReliableAutoDetectsPeerFraming(t *testing.T) {
	h := NewMaxHeadlessJoiner(func(string, ...any) {}, stubMaxResolve, stubMaxStatusEmitter{}, stubMaxPCConfigurer{}, stubMaxAddTracks, stubMaxReadTrack)
	h.params = &MaxHeadlessAuthParams{ReliableAuto: true}
	h.configAck.mark()

	secret := []byte("pump-secret-key-12345")
	obf, err := tunnel.NewTunnelObfuscator(secret)
	if err != nil {
		t.Fatalf("failed to create obfuscator: %v", err)
	}
	vp8 := tunnel.NewVP8DataTunnelWithQueue(nil, obf, func(string, ...any) {}, 64)

	var got []tunnel.DataTunnel
	h.OnConnected = func(dt tunnel.DataTunnel) {
		got = append(got, dt)
	}

	h.activateTunnel(vp8)

	// Feed the vp8 tunnel's OnData a raw relay frame -> OnConnected fired once with a wrapper over the raw vp8 tunnel and h.kcptun == nil
	raw := tunnel.EncodeFrame(1, tunnel.MsgPing, make([]byte, 8))
	vp8.OnData(raw)

	if len(got) != 1 {
		t.Fatalf("expected 1 connection event, got %d", len(got))
	}
	w1, ok := got[0].(*sfuTunnelWrapper)
	if !ok {
		t.Fatalf("expected *sfuTunnelWrapper, got %T", got[0])
	}
	if w1.DataTunnel != vp8 {
		t.Fatalf("expected wrapper over raw vp8 tunnel, got %T", w1.DataTunnel)
	}
	if h.kcptun != nil {
		t.Fatalf("expected h.kcptun == nil, got %v", h.kcptun)
	}

	// Simulate a peer restart (vp8.OnPeerRestart()) and feed a KCP-looking payload -> OnConnected fired again with a wrapper over a KCP tunnel and h.kcptun != nil
	vp8.OnPeerRestart()
	kcpPayload := []byte{0x00, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44}
	vp8.OnData(kcpPayload)

	if len(got) != 2 {
		t.Fatalf("expected 2 connection events, got %d", len(got))
	}
	w2, ok := got[1].(*sfuTunnelWrapper)
	if !ok {
		t.Fatalf("expected *sfuTunnelWrapper, got %T", got[1])
	}
	if h.kcptun == nil {
		t.Fatalf("expected h.kcptun != nil")
	}
	if w2.DataTunnel != h.kcptun {
		t.Fatalf("expected wrapper over KCP tunnel (h.kcptun), got %T", w2.DataTunnel)
	}
	defer h.Close()
}

func TestMaxRawDefaultUnchanged(t *testing.T) {
	h := NewMaxHeadlessJoiner(func(string, ...any) {}, stubMaxResolve, stubMaxStatusEmitter{}, stubMaxPCConfigurer{}, stubMaxAddTracks, stubMaxReadTrack)
	h.params = &MaxHeadlessAuthParams{}
	h.configAck.mark()

	secret := []byte("pump-secret-key-12345")
	obf, err := tunnel.NewTunnelObfuscator(secret)
	if err != nil {
		t.Fatalf("failed to create obfuscator: %v", err)
	}
	vp8 := tunnel.NewVP8DataTunnelWithQueue(nil, obf, func(string, ...any) {}, 64)

	var captured tunnel.DataTunnel
	h.OnConnected = func(dt tunnel.DataTunnel) {
		captured = dt
	}

	h.activateTunnel(vp8)

	if h.kcptun != nil {
		t.Fatalf("expected h.kcptun == nil, got %v", h.kcptun)
	}
	defer h.Close()

	wrapper, ok := captured.(*sfuTunnelWrapper)
	if !ok {
		t.Fatalf("expected captured tunnel to be *sfuTunnelWrapper, got %T", captured)
	}
	if wrapper.DataTunnel != vp8 {
		t.Fatalf("expected wrapper over raw vp8 tunnel, got %T", wrapper.DataTunnel)
	}
}
