package tunnel

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alex-pirozhenko/whitelist-bypass/relay/common"
	"github.com/pion/webrtc/v4"
)

type peerSignaling struct {
	pc         *webrtc.PeerConnection
	remoteSet  bool
	pendingICE []webrtc.ICECandidateInit
	mu         sync.Mutex
	t          *testing.T
}

func (s *peerSignaling) handleRemoteCandidate(init webrtc.ICECandidateInit) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.remoteSet {
		if err := s.pc.AddICECandidate(init); err != nil {
			s.t.Logf("AddICECandidate failed: %v", err)
		}
	} else {
		s.pendingICE = append(s.pendingICE, init)
	}
}

func (s *peerSignaling) markRemoteSet() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.remoteSet = true
	for _, cand := range s.pendingICE {
		if err := s.pc.AddICECandidate(cand); err != nil {
			s.t.Logf("AddICECandidate (flushed) failed: %v", err)
		}
	}
	s.pendingICE = nil
}

func TestVKOfferLoopback(t *testing.T) {
	var logClosed atomic.Bool
	t.Cleanup(func() {
		logClosed.Store(true)
	})
	logFn := func(format string, args ...any) {
		if logClosed.Load() {
			return
		}
		t.Logf(format, args...)
	}

	// 1. PeerConnections Setup
	buildPC := func() (*webrtc.PeerConnection, error) {
		se := webrtc.SettingEngine{}
		se.DetachDataChannels()
		se.DisableCloseByDTLS(true)
		se.SetIncludeLoopbackCandidate(true)
		se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})

		api := webrtc.NewAPI(webrtc.WithSettingEngine(se))
		return api.NewPeerConnection(webrtc.Configuration{})
	}

	pcClient, err := buildPC()
	if err != nil {
		t.Fatalf("failed to create client PC: %v", err)
	}
	pcExit, err := buildPC()
	if err != nil {
		pcClient.Close()
		t.Fatalf("failed to create exit PC: %v", err)
	}

	// 2. Negotiated DataChannel setup
	negotiated := true
	dcID := uint16(2)
	dcClient, err := pcClient.CreateDataChannel("tunnel", &webrtc.DataChannelInit{
		Negotiated: &negotiated,
		ID:         &dcID,
	})
	if err != nil {
		pcClient.Close()
		pcExit.Close()
		t.Fatalf("failed to create client DC: %v", err)
	}

	dcExit, err := pcExit.CreateDataChannel("tunnel", &webrtc.DataChannelInit{
		Negotiated: &negotiated,
		ID:         &dcID,
	})
	if err != nil {
		pcClient.Close()
		pcExit.Close()
		t.Fatalf("failed to create exit DC: %v", err)
	}

	clientDCOpen := make(chan struct{})
	exitDCOpen := make(chan struct{})

	dcClient.OnOpen(func() {
		logFn("Client DataChannel opened")
		close(clientDCOpen)
	})

	dcExit.OnOpen(func() {
		logFn("Exit DataChannel opened")
		close(exitDCOpen)
	})

	clientConnected := make(chan struct{})
	exitConnected := make(chan struct{})

	pcClient.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		logFn("Client PC state: %s", state.String())
		if state == webrtc.PeerConnectionStateConnected {
			close(clientConnected)
		}
	})

	pcExit.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		logFn("Exit PC state: %s", state.String())
		if state == webrtc.PeerConnectionStateConnected {
			close(exitConnected)
		}
	})

	// 3. Signaling with channels
	clientSig := &peerSignaling{pc: pcClient, t: t}
	exitSig := &peerSignaling{pc: pcExit, t: t}

	pcClient.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			return
		}
		exitSig.handleRemoteCandidate(candidate.ToJSON())
	})

	pcExit.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			return
		}
		clientSig.handleRemoteCandidate(candidate.ToJSON())
	})

	offerChan := make(chan webrtc.SessionDescription, 1)
	answerChan := make(chan webrtc.SessionDescription, 1)
	errChan := make(chan error, 10)

	// Offerer (Client)
	go func() {
		offer, err := pcClient.CreateOffer(nil)
		if err != nil {
			errChan <- fmt.Errorf("client create offer: %w", err)
			return
		}
		if err := pcClient.SetLocalDescription(offer); err != nil {
			errChan <- fmt.Errorf("client set local description: %w", err)
			return
		}
		offerChan <- offer

		select {
		case answer := <-answerChan:
			if err := pcClient.SetRemoteDescription(answer); err != nil {
				errChan <- fmt.Errorf("client set remote description: %w", err)
				return
			}
			clientSig.markRemoteSet()
		case <-time.After(10 * time.Second):
			errChan <- fmt.Errorf("client timeout waiting for answer")
		}
	}()

	// Answerer (Exit)
	go func() {
		select {
		case offer := <-offerChan:
			if err := pcExit.SetRemoteDescription(offer); err != nil {
				errChan <- fmt.Errorf("exit set remote description: %w", err)
				return
			}
			exitSig.markRemoteSet()
		case <-time.After(10 * time.Second):
			errChan <- fmt.Errorf("exit timeout waiting for offer")
			return
		}

		answer, err := pcExit.CreateAnswer(nil)
		if err != nil {
			errChan <- fmt.Errorf("exit create answer: %w", err)
			return
		}
		if err := pcExit.SetLocalDescription(answer); err != nil {
			errChan <- fmt.Errorf("exit set local description: %w", err)
			return
		}
		answerChan <- answer
	}()

	// Wait for WebRTC connection and DataChannel OnOpen events
	timeout := time.After(10 * time.Second)
	select {
	case <-clientDCOpen:
	case <-timeout:
		t.Fatal("Client DataChannel failed to open in 10s")
	case err := <-errChan:
		t.Fatalf("Signaling error: %v", err)
	}

	select {
	case <-exitDCOpen:
	case <-timeout:
		t.Fatal("Exit DataChannel failed to open in 10s")
	case err := <-errChan:
		t.Fatalf("Signaling error: %v", err)
	}

	select {
	case <-clientConnected:
	case <-timeout:
		t.Fatal("Client PC failed to reach Connected state in 10s")
	case err := <-errChan:
		t.Fatalf("Signaling error: %v", err)
	}

	select {
	case <-exitConnected:
	case <-timeout:
		t.Fatal("Exit PC failed to reach Connected state in 10s")
	case err := <-errChan:
		t.Fatalf("Signaling error: %v", err)
	}

	// 4. Wrap with DCTunnels
	exitTunnel := NewDCTunnel(dcExit, nil, common.RTPBufSize, logFn)
	clientTunnel := NewDCTunnel(dcClient, nil, common.RTPBufSize, logFn)

	// 5. RelayBridges
	exitBridge := NewRelayBridge(exitTunnel, "creator", common.RTPBufSize, logFn)
	clientBridge := NewRelayBridge(clientTunnel, "joiner", common.RTPBufSize, logFn)
	clientBridge.MarkReady()

	t.Cleanup(func() {
		logClosed.Store(true)
		if exitBridge != nil {
			exitBridge.Close()
		}
		if clientBridge != nil {
			clientBridge.Close()
		}
		pcClient.Close()
		pcExit.Close()
	})

	// 6. Private-destination guard
	oldAllow := common.AllowPrivateDst
	common.AllowPrivateDst = true
	t.Cleanup(func() {
		common.AllowPrivateDst = oldAllow
	})

	// 7. SOCKS listener
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen on probe: %v", err)
	}
	socksAddr := probe.Addr().String()
	probe.Close()

	socksListenErr := make(chan error, 1)
	go func() {
		if err := clientBridge.ListenSOCKS(socksAddr); err != nil {
			socksListenErr <- err
		}
	}()

	// Wait/dial loop to ensure the SOCKS port is listening
	var socksConn net.Conn
	for i := 0; i < 50; i++ {
		select {
		case err := <-socksListenErr:
			t.Fatalf("ListenSOCKS failed: %v", err)
		default:
		}
		socksConn, err = net.DialTimeout("tcp", socksAddr, 50*time.Millisecond)
		if err == nil {
			socksConn.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("SOCKS port never became active: %v", err)
	}

	// 8. httptest server + real bytes
	expectedBody := bytes.Repeat([]byte("A"), 4096)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(expectedBody)
	}))
	defer ts.Close()

	socksUpstream := &common.Socks5Upstream{Addr: socksAddr}
	conn, err := socksUpstream.DialTCP(ts.Listener.Addr().String(), 10*time.Second)
	if err != nil {
		t.Fatalf("SOCKS dial to %s failed: %v", ts.Listener.Addr().String(), err)
	}
	defer conn.Close()

	reqStr := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", ts.Listener.Addr().String())
	nSent, err := conn.Write([]byte(reqStr))
	if err != nil {
		t.Fatalf("Write request failed: %v", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("Read response failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Read body failed: %v", err)
	}

	if !bytes.Equal(body, expectedBody) {
		t.Fatalf("Response body mismatch, expected %d bytes, got %d bytes", len(expectedBody), len(body))
	}

	t.Logf("Success! Bytes sent (request size): %d, Bytes received (body size): %d", nSent, len(body))
}
