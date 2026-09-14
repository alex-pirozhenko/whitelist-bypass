package tunnel

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"

	"github.com/alex-pirozhenko/whitelist-bypass/relay/common"
)

const (
	kcpConvBase           = 0x77627374
	kcpUpdateInterval     = 10 * time.Millisecond
	kcpIdleUpdateInterval = 500 * time.Millisecond
	kcpIdleAfterTicks     = 50
	// One KCP segment must ride in a single RTP packet so a dropped packet
	// loses only its own frame, not a two-packet frame that readVP8Track
	// would discard whole. 1200 RTP budget - 1 VP8 descriptor - interframe
	// header - 24 XChaCha20 nonce - 16 Poly1305 tag - 1 channel tag.
	kcpSegmentMTU     = 1200 - 1 - interframeHdrLen - 24 - 16 - 1 - kcpUnitLenBytes
	kcpReceiveBufSize = 128 * 1024
	kcpStatsEvery     = 500

	kcpWindowFloor      = 64
	kcpWindowCeiling    = 4096
	kcpCarrierRTT       = 1 * time.Second
	kcpWaitSndFactor    = 2
	kcpBackpressurePoll = 2 * time.Millisecond

	kcpChannelReliable byte = 0x00
	kcpChannelRaw      byte = 0x01

	// kcpUnitLenBytes is the big-endian length that follows the channel tag of
	// a reliable unit. Units must be self-delimiting: once a RateController
	// sets MaxFrameBytes on the carrier, VP8DataTunnel's writer coalesces
	// several queued units into ONE carrier frame, and the receiver gets them
	// glued together. A raw unit carries a relay frame, which delimits itself
	// (4-byte length prefix); a KCP segment does not, and kcp-go stops parsing
	// at the first foreign byte -- so before this prefix every glued segment
	// after the first was lost, ACKs included, and the reliable stream stalled
	// (letmeout, 2026-09-14: KCP mode moved nothing while the raw lane worked).
	kcpUnitLenBytes = 2

	KCPCarrierQueueDepth = kcpWaitSndFactor * kcpWindowCeiling

	// The send window tracks what the carrier actually drains (adaptWindow):
	// it starts at kcpWindowStart, grows by kcpWindowRTTFactor per second
	// while the carrier keeps up (an implicit slow start -- with W in
	// flight the carrier can only ship W per RTT, so the measured rate
	// tracks the window until the carrier saturates), shrinks when the
	// output queue backs up, and rests at kcpWindowStart when idle. The
	// theoretical ticks x segments-per-tick value is only the CAP: on
	// 2026-09-14 the exit's carrier shipped ~220 frames/s where the formula
	// assumed 720, the window sat at 2x the real bandwidth-delay product,
	// every RTO was spurious, and the output queue never drained.
	kcpWindowStart      = 512
	kcpWindowRTTFactor  = 1.25
	kcpAdaptEveryTicks  = 100 // 1 s at the fast update cadence
	kcpBacklogShrinkNum = 4
	kcpBacklogShrinkDen = 5
)

func computeKCPWindowFor(fps, batch, maxFrameBytes int) int {
	ticks := fps * batch
	if ticks < 1 {
		ticks = defaultVP8FPS * defaultVP8Batch
	}
	segsPerTick := 1
	if maxFrameBytes > 0 {
		segsPerTick = (maxFrameBytes + kcpSegmentMTU - 1) / kcpSegmentMTU
		if segsPerTick < 1 {
			segsPerTick = 1
		}
	}
	w := float64(ticks*segsPerTick) * kcpCarrierRTT.Seconds()
	window := int(w)
	if window < kcpWindowFloor {
		return kcpWindowFloor
	}
	if window > kcpWindowCeiling {
		return kcpWindowCeiling
	}
	return window
}

func computeKCPWindow(fps, batch int) int {
	return computeKCPWindowFor(fps, batch, 0)
}

var kcpWndSize = func(k *kcp.KCP, snd, rcv int) {
	k.WndSize(snd, rcv)
}

type trackKCPSession struct {
	conv    uint32
	vp8     *VP8DataTunnel
	parent  *MultiTrackKCPTunnel
	kcpMu   sync.Mutex
	kcp     *kcp.KCP
	recvBuf []byte
	outQ    chan []byte
	stopCh  chan struct{}
}

func newTrackKCPSession(parent *MultiTrackKCPTunnel, vp8 *VP8DataTunnel, conv uint32, window int) *trackKCPSession {
	session := &trackKCPSession{
		conv:    conv,
		vp8:     vp8,
		parent:  parent,
		recvBuf: make([]byte, kcpReceiveBufSize),
		outQ:    make(chan []byte, KCPCarrierQueueDepth),
		stopCh:  make(chan struct{}),
	}
	session.kcp = kcp.NewKCP(conv, func(buf []byte, size int) {
		if size <= 0 {
			return
		}
		segment := make([]byte, size+1+kcpUnitLenBytes)
		segment[0] = kcpChannelReliable
		binary.BigEndian.PutUint16(segment[1:3], uint16(size))
		copy(segment[1+kcpUnitLenBytes:], buf[:size])
		parent.outputSegments.Add(1)
		select {
		case session.outQ <- segment:
		default:
			parent.droppedSegments.Add(1)
		}
	})
	// nodelay, 10 ms interval, fast resend after 2 dup-acks, KCP's own
	// congestion control OFF: it halves and resets cwnd on every loss burst,
	// and the SFU drops whole frames (many segments at once), so it settled
	// at ~1 segment per second-long RTT (2026-09-14: 735 KB in 120 s). The
	// send window is governed by adaptWindow instead.
	session.kcp.NoDelay(1, 10, 2, 1)
	kcpWndSize(session.kcp, window, kcpWindowCeiling)
	session.kcp.SetMtu(kcpSegmentMTU)
	go session.pump()
	return session
}

func (s *trackKCPSession) pump() {
	for {
		select {
		case <-s.parent.stopCh:
			return
		case <-s.stopCh:
			return
		case seg, ok := <-s.outQ:
			if !ok {
				return
			}
			s.vp8.SendData(seg)
		}
	}
}

func (s *trackKCPSession) stop() {
	close(s.stopCh)
}

func (s *trackKCPSession) setWindow(window int) {
	s.kcpMu.Lock()
	kcpWndSize(s.kcp, window, kcpWindowCeiling)
	s.kcpMu.Unlock()
}

func (s *trackKCPSession) send(frame []byte) {
	s.kcpMu.Lock()
	s.kcp.Send(frame)
	s.kcp.Update()
	s.kcpMu.Unlock()
}

func (s *trackKCPSession) input(segment []byte) [][]byte {
	s.kcpMu.Lock()
	s.kcp.Input(segment, kcp.IKCP_PACKET_REGULAR, true)
	var messages [][]byte
	for {
		size := s.kcp.PeekSize()
		if size <= 0 {
			break
		}
		if size > len(s.recvBuf) {
			s.recvBuf = make([]byte, size)
		}
		n := s.kcp.Recv(s.recvBuf)
		if n <= 0 {
			break
		}
		message := make([]byte, n)
		copy(message, s.recvBuf[:n])
		messages = append(messages, message)
	}
	s.kcpMu.Unlock()
	return messages
}

func (s *trackKCPSession) update() {
	s.kcpMu.Lock()
	s.kcp.Update()
	s.kcpMu.Unlock()
}

func (s *trackKCPSession) waitSnd() int {
	s.kcpMu.Lock()
	pending := s.kcp.WaitSnd()
	s.kcpMu.Unlock()
	return pending
}

type MultiTrackKCPTunnel struct {
	mt    *MultiTrackTunnel
	logFn func(string, ...any)

	mu        sync.Mutex
	lastMaxFB int

	lastSentBytes uint64
	lastAdaptAt   time.Time
	sessions      []*trackKCPSession
	convMap       map[uint32]*trackKCPSession
	connPin       map[uint32]int
	onData        func([]byte)
	onClose       func()

	stopCh   chan struct{}
	stopOnce sync.Once
	nudge    chan struct{}

	currentWindow atomic.Int32

	sentMessages      atomic.Uint64
	deliveredMessages atomic.Uint64
	outputSegments    atomic.Uint64
	inputSegments     atomic.Uint64
	rawSent           atomic.Uint64
	rawReceived       atomic.Uint64
	droppedSegments   atomic.Uint64
}

func NewMultiTrackKCPTunnel(mt *MultiTrackTunnel, logFn func(string, ...any)) *MultiTrackKCPTunnel {
	t := &MultiTrackKCPTunnel{
		mt:      mt,
		logFn:   logFn,
		convMap: make(map[uint32]*trackKCPSession),
		connPin: make(map[uint32]int),
		stopCh:  make(chan struct{}),
		nudge:   make(chan struct{}, 1),
	}
	subs := mt.SubTunnels()
	window := kcpWindowFloor
	if len(subs) > 0 {
		window = minInt(computeKCPWindow(subs[0].FPS(), subs[0].Batch()), kcpWindowStart)
	}
	t.currentWindow.Store(int32(window))
	t.lastAdaptAt = time.Now()
	for i, sub := range subs {
		conv := uint32(kcpConvBase + i)
		session := newTrackKCPSession(t, sub, conv, window)
		t.sessions = append(t.sessions, session)
		t.convMap[conv] = session
	}
	if logFn != nil {
		logFn("kcptunnel: init tracks=%d window=%d queue=%d", len(subs), window, KCPCarrierQueueDepth)
	}
	mt.SetOnData(t.handleDecodedSegment)
	mt.SetOnClose(t.handleInnerClose)
	go t.updateLoop()
	return t
}

func (t *MultiTrackKCPTunnel) SendData(frame []byte) {
	if len(frame) < 9 {
		return
	}
	connID := binary.BigEndian.Uint32(frame[4:8])
	msgType := frame[8]

	if msgType == MsgUDP || msgType == MsgUDPReply {
		t.sendRaw(connID, frame)
		return
	}
	t.wake()

	t.mu.Lock()
	if len(t.sessions) == 0 {
		t.mu.Unlock()
		return
	}
	index, pinned := t.connPin[connID]
	if !pinned || index >= len(t.sessions) {
		index = int(connID % uint32(len(t.sessions)))
		t.connPin[connID] = index
	}
	session := t.sessions[index]
	t.mu.Unlock()

	if msgType == MsgData {
		sndCap := int(t.currentWindow.Load()) * kcpWaitSndFactor
		for session.waitSnd() >= sndCap {
			select {
			case <-t.stopCh:
				return
			case <-time.After(kcpBackpressurePoll):
			}
		}
	}

	t.sentMessages.Add(1)
	session.send(frame)

	if msgType == MsgClose {
		t.mu.Lock()
		delete(t.connPin, connID)
		t.mu.Unlock()
	}
}

func (t *MultiTrackKCPTunnel) sendRaw(connID uint32, frame []byte) {
	t.mu.Lock()
	if len(t.sessions) == 0 {
		t.mu.Unlock()
		return
	}
	index := int(connID % uint32(len(t.sessions)))
	session := t.sessions[index]
	t.mu.Unlock()

	segment := make([]byte, len(frame)+1)
	segment[0] = kcpChannelRaw
	copy(segment[1:], frame)
	t.rawSent.Add(1)
	session.vp8.TrySendData(segment)
}

func (t *MultiTrackKCPTunnel) InjectSegment(payload []byte) {
	t.handleDecodedSegment(payload)
}

func (t *MultiTrackKCPTunnel) handleDecodedSegment(payload []byte) {
	// One carrier frame may hold several units (see kcpUnitLenBytes); walk them.
	for len(payload) > 0 {
		channel := payload[0]
		switch channel {
		case kcpChannelRaw:
			// A raw unit is one relay frame: 4-byte big-endian length + body.
			if len(payload) < 5 {
				return
			}
			n := int(binary.BigEndian.Uint32(payload[1:5])) + 4
			if n < 4 || 1+n > len(payload) {
				return
			}
			body := payload[1 : 1+n]
			payload = payload[1+n:]
			t.mu.Lock()
			callback := t.onData
			t.mu.Unlock()
			if callback != nil {
				t.rawReceived.Add(1)
				callback(body)
			}
		case kcpChannelReliable:
			if len(payload) < 1+kcpUnitLenBytes {
				return
			}
			n := int(binary.BigEndian.Uint16(payload[1 : 1+kcpUnitLenBytes]))
			if n < 4 || 1+kcpUnitLenBytes+n > len(payload) {
				return
			}
			body := payload[1+kcpUnitLenBytes : 1+kcpUnitLenBytes+n]
			payload = payload[1+kcpUnitLenBytes+n:]
			conv := binary.LittleEndian.Uint32(body[0:4])
			t.mu.Lock()
			session := t.convMap[conv]
			callback := t.onData
			t.mu.Unlock()
			if session == nil {
				continue
			}
			t.inputSegments.Add(1)
			t.wake()
			messages := session.input(body)
			if callback == nil {
				continue
			}
			for _, message := range messages {
				t.deliveredMessages.Add(1)
				callback(message)
			}
		default:
			return
		}
	}
}

func (t *MultiTrackKCPTunnel) SetOnData(fn func([]byte)) {
	t.mu.Lock()
	t.onData = fn
	t.mu.Unlock()
}

func (t *MultiTrackKCPTunnel) SetOnClose(fn func()) {
	t.mu.Lock()
	t.onClose = fn
	t.mu.Unlock()
}

func (t *MultiTrackKCPTunnel) SetProfile(p Profile) {
	t.mt.SetProfile(p)
	if p.MaxFrameBytes > 0 {
		t.mu.Lock()
		t.lastMaxFB = p.MaxFrameBytes
		t.mu.Unlock()
	}
	t.mu.Lock()
	lastMaxFB := t.lastMaxFB
	t.mu.Unlock()

	fps, batch := t.FPS(), t.Batch()
	t.fitWindow(computeKCPWindowFor(fps, batch, lastMaxFB))
}

// fitWindow keeps the live window inside [min(start, cap), cap] for a new cap:
// a profile with room lifts a window that never left the floor up to the
// start value, and a smaller cap clamps it.
func (t *MultiTrackKCPTunnel) fitWindow(capW int) {
	target := int(t.currentWindow.Load())
	if lo := minInt(kcpWindowStart, capW); target < lo {
		target = lo
	} else if target > capW {
		target = capW
	}
	t.applyWindow(target) // always: the receive window is re-pinned to the ceiling on every profile
}

// capWindow is the ceiling adaptWindow may grow to for the current profile.
func (t *MultiTrackKCPTunnel) capWindow() int {
	t.mu.Lock()
	lastMaxFB := t.lastMaxFB
	t.mu.Unlock()
	return computeKCPWindowFor(t.FPS(), t.Batch(), lastMaxFB)
}

// outQBacklog is how many produced segments are still waiting for the carrier.
func (t *MultiTrackKCPTunnel) outQBacklog() int {
	t.mu.Lock()
	sessions := make([]*trackKCPSession, len(t.sessions))
	copy(sessions, t.sessions)
	t.mu.Unlock()
	n := 0
	for _, s := range sessions {
		n += len(s.outQ)
	}
	return n
}

// nextWindow is adaptWindow's decision, kept pure for tests: cur is the
// window now, capW the profile cap, segsPerSec the carrier's measured drain,
// backlog the segments waiting for the carrier.
func nextWindow(cur, capW int, segsPerSec float64, backlog int) int {
	var target int
	switch {
	case segsPerSec < float64(kcpWindowFloor):
		// idle or a trickle: rest where the next burst starts sensibly
		target = minInt(cur, kcpWindowStart)
	case backlog > cur/2:
		// the carrier is not keeping up with what we already committed
		target = cur * kcpBacklogShrinkNum / kcpBacklogShrinkDen
	default:
		target = int(segsPerSec * kcpWindowRTTFactor)
	}
	if target < kcpWindowFloor {
		target = kcpWindowFloor
	}
	if target > capW {
		target = capW
	}
	return target
}

func (t *MultiTrackKCPTunnel) adaptWindow() {
	now := time.Now()
	c := t.mt.Counters()
	dt := now.Sub(t.lastAdaptAt).Seconds()
	dB := c.SentBytes - t.lastSentBytes
	t.lastSentBytes = c.SentBytes
	t.lastAdaptAt = now
	if dt <= 0 {
		return
	}
	cur := int(t.currentWindow.Load())
	target := nextWindow(cur, t.capWindow(), float64(dB)/dt/float64(kcpSegmentMTU), t.outQBacklog())
	if target != cur {
		t.applyWindow(target)
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (t *MultiTrackKCPTunnel) Counters() Counters {
	return t.mt.Counters()
}

func (t *MultiTrackKCPTunnel) FPS() int {
	subs := t.mt.SubTunnels()
	if len(subs) > 0 {
		return subs[0].FPS()
	}
	return defaultVP8FPS
}

func (t *MultiTrackKCPTunnel) Batch() int {
	subs := t.mt.SubTunnels()
	if len(subs) > 0 {
		return subs[0].Batch()
	}
	return defaultVP8Batch
}

func (t *MultiTrackKCPTunnel) Reconfigure(fps, batch int) {
	t.mt.Reconfigure(fps, batch)
	t.mu.Lock()
	lastMaxFB := t.lastMaxFB
	t.mu.Unlock()
	capW := computeKCPWindowFor(fps, batch, lastMaxFB)
	t.fitWindow(capW)
	if t.logFn != nil {
		t.logFn("kcptunnel: reconfigure fps=%d batch=%d -> window cap=%d (now %d)", fps, batch, capW, t.currentWindow.Load())
	}
}

func (t *MultiTrackKCPTunnel) SendControl(frame []byte) bool {
	t.mu.Lock()
	if len(t.sessions) == 0 {
		t.mu.Unlock()
		return false
	}
	session0 := t.sessions[0]
	t.mu.Unlock()

	segment := make([]byte, len(frame)+1)
	segment[0] = kcpChannelRaw
	copy(segment[1:], frame)

	return session0.vp8.SendControl(segment)
}

func (t *MultiTrackKCPTunnel) CtlQueueLen() int {
	t.mu.Lock()
	if len(t.sessions) == 0 {
		t.mu.Unlock()
		return 0
	}
	session0 := t.sessions[0]
	t.mu.Unlock()

	return session0.vp8.CtlQueueLen()
}

func (t *MultiTrackKCPTunnel) QueueLen() int {
	t.mu.Lock()
	sessions := make([]*trackKCPSession, len(t.sessions))
	copy(sessions, t.sessions)
	t.mu.Unlock()

	total := 0
	for _, session := range sessions {
		total += session.waitSnd() + len(session.outQ)
	}
	return total
}

func (t *MultiTrackKCPTunnel) TrySendData(frame []byte) bool {
	if len(frame) < 9 {
		return false
	}
	connID := binary.BigEndian.Uint32(frame[4:8])
	msgType := frame[8]

	if msgType == MsgUDP || msgType == MsgUDPReply {
		t.sendRaw(connID, frame)
		return true
	}
	t.wake()

	t.mu.Lock()
	if len(t.sessions) == 0 {
		t.mu.Unlock()
		return false
	}
	index, pinned := t.connPin[connID]
	if !pinned || index >= len(t.sessions) {
		index = int(connID % uint32(len(t.sessions)))
		t.connPin[connID] = index
	}
	session := t.sessions[index]
	t.mu.Unlock()

	if msgType == MsgData {
		sndCap := int(t.currentWindow.Load()) * kcpWaitSndFactor
		if session.waitSnd() >= sndCap {
			return false
		}
	}

	t.sentMessages.Add(1)
	session.send(frame)

	if msgType == MsgClose {
		t.mu.Lock()
		delete(t.connPin, connID)
		t.mu.Unlock()
	}
	return true
}

func (t *MultiTrackKCPTunnel) applyWindow(window int) {
	t.currentWindow.Store(int32(window))
	t.mu.Lock()
	sessions := make([]*trackKCPSession, len(t.sessions))
	copy(sessions, t.sessions)
	t.mu.Unlock()
	for _, session := range sessions {
		session.setWindow(window)
	}
}

func (t *MultiTrackKCPTunnel) AddSession(sub *VP8DataTunnel) {
	window := int(t.currentWindow.Load())
	t.mu.Lock()
	conv := uint32(kcpConvBase + len(t.sessions))
	session := newTrackKCPSession(t, sub, conv, window)
	t.sessions = append(t.sessions, session)
	t.convMap[conv] = session
	t.mu.Unlock()
}

func (t *MultiTrackKCPTunnel) RemoveLastSession() {
	t.mu.Lock()
	if len(t.sessions) <= 1 {
		t.mu.Unlock()
		return
	}
	last := t.sessions[len(t.sessions)-1]
	t.sessions = t.sessions[:len(t.sessions)-1]
	delete(t.convMap, last.conv)
	t.mu.Unlock()

	last.stop()
}

func (t *MultiTrackKCPTunnel) Stop() {
	t.stopOnce.Do(func() { close(t.stopCh) })
	t.mt.Stop()
}

func (t *MultiTrackKCPTunnel) StopLayer() {
	t.stopOnce.Do(func() { close(t.stopCh) })
}

func (t *MultiTrackKCPTunnel) handleInnerClose() {
	t.stopOnce.Do(func() { close(t.stopCh) })
	t.mu.Lock()
	callback := t.onClose
	t.mu.Unlock()
	if callback != nil {
		callback()
	}
}

func (t *MultiTrackKCPTunnel) wake() {
	select {
	case t.nudge <- struct{}{}:
	default:
	}
}

func (t *MultiTrackKCPTunnel) updateLoop() {
	ticker := time.NewTicker(kcpUpdateInterval)
	defer ticker.Stop()
	ticks := 0
	idleTicks := 0
	fast := true
	for {
		select {
		case <-t.stopCh:
			return
		case <-t.nudge:
			if !fast {
				fast = true
				idleTicks = 0
				ticker.Reset(kcpUpdateInterval)
			}
		case <-ticker.C:
			t.mu.Lock()
			sessions := make([]*trackKCPSession, len(t.sessions))
			copy(sessions, t.sessions)
			t.mu.Unlock()
			pending := 0
			for _, session := range sessions {
				session.update()
				pending += session.waitSnd()
			}
			if pending > 0 {
				idleTicks = 0
				if !fast {
					fast = true
					ticker.Reset(kcpUpdateInterval)
				}
			} else if fast {
				idleTicks++
				if idleTicks >= kcpIdleAfterTicks {
					fast = false
					idleTicks = 0
					ticker.Reset(kcpIdleUpdateInterval)
				}
			}
			ticks++
			if ticks%kcpAdaptEveryTicks == 0 {
				t.adaptWindow()
			}
			if common.Debug && ticks%kcpStatsEvery == 0 && t.logFn != nil {
				t.logFn("kcptunnel: sessions=%d window=%d sent=%d delivered=%d out_segs=%d in_segs=%d raw_out=%d raw_in=%d dropped=%d",
					len(sessions), t.currentWindow.Load(), t.sentMessages.Load(), t.deliveredMessages.Load(),
					t.outputSegments.Load(), t.inputSegments.Load(),
					t.rawSent.Load(), t.rawReceived.Load(), t.droppedSegments.Load())
				snmp := kcp.DefaultSnmp.Copy()
				t.logFn("kcptunnel: kcp_out=%d kcp_in=%d retrans=%d fastretrans=%d lost=%d repeat=%d",
					snmp.OutSegs, snmp.InSegs, snmp.RetransSegs, snmp.FastRetransSegs, snmp.LostSegs, snmp.RepeatSegs)
			}
		}
	}
}
