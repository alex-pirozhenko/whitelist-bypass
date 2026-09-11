package tunnel

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"

	"github.com/alex-pirozhenko/whitelist-bypass/relay/common"
)

const (
	defaultVP8FPS       = 20
	defaultVP8Batch     = 1
	keepaliveIdlePeriod = 100 * time.Millisecond
	keepaliveIdleMin    = 50 * time.Millisecond
	keepaliveIdleMax    = 150 * time.Millisecond
	keepalivePadMax     = 64
	sendQueueDepth      = 128

	paceBatchFloorPercent = 80
	paceDriftMin          = 5 * time.Second
	paceDriftMax          = 20 * time.Second

	idleSpinTicks       = 40
	defaultKeyframeRate = 40 // Every 40 frames (~2s at 20fps), emit a keyframe
)

type VP8Packetizer struct {
	mu             sync.Mutex
	sequenceNumber uint16
	timestamp      uint32
	pictureID      uint16
	tl0picidx      uint8
	tid            uint8
}

func NewVP8Packetizer() *VP8Packetizer {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		b[0] = 0x12
		b[1] = 0x34
		b[2] = 0x56
		b[3] = 0x78
	}
	return &VP8Packetizer{
		sequenceNumber: binary.BigEndian.Uint16(b[0:2]),
		timestamp:      binary.BigEndian.Uint32(b[0:4]),
		pictureID:      1,
		tl0picidx:      1,
		tid:            0,
	}
}

func (p *VP8Packetizer) Packetize(frame []byte, isKeyframe bool, tsDelta uint32, mtu int) []*rtp.Packet {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.timestamp += tsDelta
	p.pictureID = (p.pictureID + 1) & 0x7fff
	if p.pictureID == 0 {
		p.pictureID = 1
	}
	if isKeyframe {
		p.tl0picidx++
	}

	buildDescriptor := func(startOfPartition bool) []byte {
		b0 := byte(0x80) // X=1
		if startOfPartition {
			b0 |= 0x10 // S=1
		}
		b1 := byte(0xe0) // I=1, L=1, T=1
		desc := make([]byte, 0, 6)
		desc = append(desc, b0, b1)
		if p.pictureID <= 0x7f {
			desc = append(desc, byte(p.pictureID))
		} else {
			desc = append(desc, 0x80|byte(p.pictureID>>8), byte(p.pictureID&0xff))
		}
		desc = append(desc, p.tl0picidx)
		desc = append(desc, 0x20) // TID=0, Y=1
		return desc
	}

	if mtu <= 0 {
		mtu = 1200
	}

	var packets []*rtp.Packet
	rem := frame
	first := true
	for len(rem) > 0 {
		desc := buildDescriptor(first)
		first = false
		maxChunk := mtu - len(desc)
		if maxChunk > len(rem) {
			maxChunk = len(rem)
		}
		chunk := rem[:maxChunk]
		rem = rem[maxChunk:]

		payload := make([]byte, len(desc)+len(chunk))
		copy(payload, desc)
		copy(payload[len(desc):], chunk)

		p.sequenceNumber++
		pkt := &rtp.Packet{
			Header: rtp.Header{
				Version:        2,
				Padding:        false,
				Extension:      false,
				Marker:         len(rem) == 0,
				PayloadType:    100,
				SequenceNumber: p.sequenceNumber,
				Timestamp:      p.timestamp,
			},
			Payload: payload,
		}
		packets = append(packets, pkt)
	}
	return packets
}

type VP8DataTunnel struct {
	track          *webrtc.TrackLocalStaticSample
	trackRTP       *webrtc.TrackLocalStaticRTP
	packetizer     *VP8Packetizer
	needKeyframe   atomic.Bool
	keyframePeriod int
	logFn          func(string, ...any)
	obf            *TunnelObfuscator
	stopCh         chan struct{}
	sendQueue      chan []byte
	cfgChan        chan struct{}

	stopOnce sync.Once
	running  atomic.Bool

	cfgMu           sync.Mutex
	fps             int
	batch           int
	keepaliveMin    time.Duration
	keepaliveMax    time.Duration
	keepalivePadMax int

	sentFrames      atomic.Uint64
	recvFrames      atomic.Uint64
	keepaliveFrames atomic.Uint64

	OnData        func([]byte)
	OnClose       func()
	OnPeerRestart func()

	WriteFrame func([]byte) error
}

func (t *VP8DataTunnel) SetOnData(fn func([]byte))  { t.OnData = fn }
func (t *VP8DataTunnel) SetOnClose(fn func())       { t.OnClose = fn }
func (t *VP8DataTunnel) SetOnPeerRestart(fn func()) { t.OnPeerRestart = fn }

func (t *VP8DataTunnel) RequestKeyframe() {
	t.needKeyframe.Store(true)
}

func NewVP8DataTunnel(track *webrtc.TrackLocalStaticSample, obf *TunnelObfuscator, logFn func(string, ...any)) *VP8DataTunnel {
	return NewVP8DataTunnelWithQueue(track, obf, logFn, sendQueueDepth)
}

func NewVP8DataTunnelRTP(track *webrtc.TrackLocalStaticRTP, obf *TunnelObfuscator, logFn func(string, ...any)) *VP8DataTunnel {
	tun := NewVP8DataTunnelWithQueue(nil, obf, logFn, sendQueueDepth)
	tun.trackRTP = track
	tun.packetizer = NewVP8Packetizer()
	return tun
}

func NewVP8DataTunnelWithQueue(track *webrtc.TrackLocalStaticSample, obf *TunnelObfuscator, logFn func(string, ...any), queueDepth int) *VP8DataTunnel {
	if queueDepth < sendQueueDepth {
		queueDepth = sendQueueDepth
	}
	tun := &VP8DataTunnel{
		track:           track,
		packetizer:      NewVP8Packetizer(),
		obf:             obf,
		logFn:           logFn,
		stopCh:          make(chan struct{}),
		sendQueue:       make(chan []byte, queueDepth),
		cfgChan:         make(chan struct{}, 1),
		fps:             defaultVP8FPS,
		batch:           defaultVP8Batch,
		keepaliveMin:    keepaliveIdleMin,
		keepaliveMax:    keepaliveIdleMax,
		keepalivePadMax: keepalivePadMax,
		keyframePeriod:  defaultKeyframeRate,
	}
	tun.needKeyframe.Store(true) // Start with a keyframe
	return tun
}

func (t *VP8DataTunnel) nextKeepalive(sampleInterval time.Duration) (ticks, padLen int) {
	t.cfgMu.Lock()
	minPeriod, maxPeriod, padMax := t.keepaliveMin, t.keepaliveMax, t.keepalivePadMax
	t.cfgMu.Unlock()
	ticks = int(common.DurationInRange(minPeriod, maxPeriod) / sampleInterval)
	if ticks < 1 {
		ticks = 1
	}
	return ticks, common.IntInRange(0, padMax)
}

func (t *VP8DataTunnel) Reconfigure(fps, batch int) {
	if fps <= 0 && batch <= 0 {
		return
	}
	t.cfgMu.Lock()
	changed := false
	if fps > 0 && t.fps != fps {
		t.fps = fps
		changed = true
	}
	if batch > 0 && t.batch != batch {
		t.batch = batch
		changed = true
	}
	newFPS, newBatch := t.fps, t.batch
	t.cfgMu.Unlock()
	if !changed {
		return
	}
	t.logFn("vp8tunnel: reconfigure fps=%d batch=%d", newFPS, newBatch)
	select {
	case t.cfgChan <- struct{}{}:
	default:
	}
}

func (t *VP8DataTunnel) FPS() int {
	t.cfgMu.Lock()
	defer t.cfgMu.Unlock()
	return t.fps
}

func (t *VP8DataTunnel) Batch() int {
	t.cfgMu.Lock()
	defer t.cfgMu.Unlock()
	return t.batch
}

func (t *VP8DataTunnel) SendData(data []byte) {
	if len(data) == 0 {
		return
	}
	select {
	case t.sendQueue <- data:
	case <-t.stopCh:
	}
}

func (t *VP8DataTunnel) TrySendData(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	select {
	case t.sendQueue <- data:
		return true
	case <-t.stopCh:
		return false
	default:
		return false
	}
}

func (t *VP8DataTunnel) Start(fps, batch int) {
	t.cfgMu.Lock()
	if fps > 0 {
		t.fps = fps
	}
	if batch > 0 {
		t.batch = batch
	}
	t.cfgMu.Unlock()
	if !t.running.CompareAndSwap(false, true) {
		return
	}
	go t.writerLoop()
}

func (t *VP8DataTunnel) Stop() {
	if !t.running.CompareAndSwap(true, false) {
		return
	}
	t.stopOnce.Do(func() { close(t.stopCh) })
	if t.OnClose != nil {
		t.OnClose()
	}
}

func (t *VP8DataTunnel) currentRate() (fps, batch int) {
	t.cfgMu.Lock()
	defer t.cfgMu.Unlock()
	return t.fps, t.batch
}

func sampleIntervalFor(fps, batch int) time.Duration {
	if fps < 1 {
		fps = 1
	}
	frameInterval := time.Second / time.Duration(fps)
	interval := frameInterval
	if batch > 1 {
		interval = frameInterval / time.Duration(batch)
	}
	if interval <= 0 {
		interval = time.Millisecond
	}
	return interval
}

func pacedBatchFor(batch int) int {
	if batch <= 1 {
		return batch
	}
	floor := batch * paceBatchFloorPercent / 100
	if floor < 1 {
		floor = 1
	}
	return common.IntInRange(floor, batch)
}

func (t *VP8DataTunnel) writerLoop() {
	for {
		fps, batch := t.currentRate()
		pacedBatch := pacedBatchFor(batch)
		sampleInterval := sampleIntervalFor(fps, pacedBatch)
		t.logFn("vp8tunnel: writer (re)started fps=%d batch=%d pacedBatch=%d sampleInterval=%s",
			fps, batch, pacedBatch, sampleInterval)

		ticker := time.NewTicker(sampleInterval)
		reconfigure := false

		emit := func(sample []byte, isKeyframe bool, isKeepalive bool) {
			if sample == nil {
				return
			}
			if t.WriteFrame != nil {
				if err := t.WriteFrame(sample); err != nil {
					if common.Debug {
						t.logFn("vp8tunnel: WriteFrame error: %v", err)
					}
					return
				}
			} else if t.trackRTP != nil {
				tsDelta := uint32(sampleInterval.Seconds() * 90000)
				if tsDelta == 0 {
					tsDelta = 4500
				}
				pkts := t.packetizer.Packetize(sample, isKeyframe, tsDelta, 1200)
				for _, pkt := range pkts {
					if err := t.trackRTP.WriteRTP(pkt); err != nil {
						if common.Debug {
							t.logFn("vp8tunnel: WriteRTP error: %v", err)
						}
						return
					}
				}
			} else if t.track != nil {
				if err := t.track.WriteSample(media.Sample{Data: sample, Duration: sampleInterval}); err != nil {
					if common.Debug {
						t.logFn("vp8tunnel: WriteSample error: %v", err)
					}
					return
				}
			}
			n := t.sentFrames.Add(1)
			if isKeepalive {
				t.keepaliveFrames.Add(1)
			}
			if common.Debug && (n <= 5 || n%500 == 0) {
				keepalives := t.keepaliveFrames.Load()
				t.logFn("vp8tunnel: sent frame #%d kf=%v size=%d data=%d keepalive=%d", n, isKeyframe, len(sample), n-keepalives, keepalives)
			}
		}

		sendFrame := func(data []byte) {
			isKf := t.needKeyframe.Swap(false) || (t.sentFrames.Load()%uint64(t.keyframePeriod) == 0)
			var s []byte
			if isKf {
				s = t.obf.EncodeDataKeyframe(data)
			} else {
				s = t.obf.EncodeData(data)
			}
			emit(s, isKf, false)
		}

		sendKeepalive := func() {
			isKf := t.needKeyframe.Swap(false) || (t.sentFrames.Load()%uint64(t.keyframePeriod) == 0)
			var s []byte
			if isKf {
				s = t.obf.EncodeKeepalive(16)
			} else {
				s = t.obf.EncodeKeepaliveInterframe(16)
			}
			emit(s, isKf, true)
		}

		for !reconfigure {
			select {
			case <-t.stopCh:
				ticker.Stop()
				return
			case <-t.cfgChan:
				reconfigure = true
			case <-ticker.C:
				select {
				case data := <-t.sendQueue:
					sendFrame(data)
				default:
					sendKeepalive()
				}
			}
		}
		ticker.Stop()
	}
}

func (t *VP8DataTunnel) HandleFrame(frame []byte) {
	res := t.obf.Decode(frame)
	if !res.HasFrame {
		return
	}
	if res.SelfEcho {
		return
	}
	if res.PeerRestart {
		t.logFn("vp8tunnel: peer restart detected, new epoch=0x%08x", res.PeerEpoch)
		if t.OnPeerRestart != nil {
			t.OnPeerRestart()
		}
	}
	if res.Keepalive || len(res.Payload) == 0 {
		return
	}
	n := t.recvFrames.Add(1)
	if common.Debug && (n <= 5 || n%500 == 0) {
		t.logFn("vp8tunnel: recv frame #%d size=%d", n, len(res.Payload))
	}
	if t.OnData != nil {
		t.OnData(res.Payload)
	}
}
