package tunnel

import "encoding/binary"

const (
	MsgConnect    byte = 0x01
	MsgConnectOK  byte = 0x02
	MsgConnectErr byte = 0x03
	MsgData       byte = 0x04
	MsgClose      byte = 0x05
	MsgUDP        byte = 0x06
	MsgUDPReply   byte = 0x07
	MsgConfig     byte = 0x08
	MsgConfigAck  byte = 0x09
	MsgStats      byte = 0x0A
	MsgPing       byte = 0x0B
)

const ControlConnID uint32 = 0

type DataTunnel interface {
	SendData(data []byte)
	SetOnData(fn func([]byte))
	SetOnClose(fn func())
	Reconfigure(fps, batch int)
}

// EncodeVP8Config builds a MsgConfig payload. maxFrameBytes and
// idleKeepaliveMs are optional trailing fields (a later step's rate
// controller uses them); pass 0 for both if you only need
// fps/batch/trackCount, exactly like every call site in this codebase does
// today. flags is reserved for future per-message bits (also unused by any
// caller yet) — always encoded as a single trailing byte so a decoder that
// doesn't know about it yet can still safely ignore the payload tail.
func EncodeVP8Config(fps, batch, trackCount, maxFrameBytes, idleKeepaliveMs int, flags uint8) []byte {
	if fps < 1 {
		fps = 1
	}
	if batch < 1 {
		batch = 1
	}
	if trackCount < 1 {
		trackCount = 1
	}
	clamp16 := func(v int) uint16 {
		if v < 0 {
			return 0
		}
		if v > 0xFFFF {
			return 0xFFFF
		}
		return uint16(v)
	}
	var payload [11]byte
	binary.BigEndian.PutUint16(payload[0:2], clamp16(fps))
	binary.BigEndian.PutUint16(payload[2:4], clamp16(batch))
	binary.BigEndian.PutUint16(payload[4:6], clamp16(trackCount))
	binary.BigEndian.PutUint16(payload[6:8], clamp16(maxFrameBytes))
	binary.BigEndian.PutUint16(payload[8:10], clamp16(idleKeepaliveMs))
	payload[10] = flags
	return EncodeFrame(ControlConnID, MsgConfig, payload[:])
}

// DecodeVP8Config is the inverse. A short payload (from an OLDER peer that
// doesn't know about the trailing fields, or a caller that never set them)
// is tolerated exactly like today: fields past what's present default to 0
// (trackCount defaults to 1, matching existing behavior — everything added
// in this step defaults to 0, meaning "not set / use tunnel default").
func DecodeVP8Config(payload []byte) (fps, batch, trackCount, maxFrameBytes, idleKeepaliveMs int, flags uint8, ok bool) {
	if len(payload) < 4 {
		return 0, 0, 0, 0, 0, 0, false
	}
	fps = int(binary.BigEndian.Uint16(payload[0:2]))
	batch = int(binary.BigEndian.Uint16(payload[2:4]))
	trackCount = 1
	if len(payload) >= 6 {
		trackCount = int(binary.BigEndian.Uint16(payload[4:6]))
	}
	if len(payload) >= 8 {
		maxFrameBytes = int(binary.BigEndian.Uint16(payload[6:8]))
	}
	if len(payload) >= 10 {
		idleKeepaliveMs = int(binary.BigEndian.Uint16(payload[8:10]))
	}
	if len(payload) >= 11 {
		flags = payload[10]
	}
	return fps, batch, trackCount, maxFrameBytes, idleKeepaliveMs, flags, true
}

func EncodeFrame(connID uint32, msgType byte, payload []byte) []byte {
	buf := make([]byte, 4+5+len(payload))
	binary.BigEndian.PutUint32(buf[0:4], uint32(5+len(payload)))
	binary.BigEndian.PutUint32(buf[4:8], connID)
	buf[8] = msgType
	copy(buf[9:], payload)
	return buf
}

func LooksLikeRelayFrame(payload []byte) bool {
	if len(payload) < 9 {
		return false
	}
	frameLen := binary.BigEndian.Uint32(payload[0:4])
	return frameLen >= 5 && int(frameLen)+4 <= len(payload)
}

func DecodeFrames(data []byte, cb func(connID uint32, msgType byte, payload []byte)) {
	for len(data) >= 4 {
		frameLen := int(binary.BigEndian.Uint32(data[0:4]))
		if frameLen < 5 || 4+frameLen > len(data) {
			return
		}
		connID := binary.BigEndian.Uint32(data[4:8])
		msgType := data[8]
		payload := data[9 : 4+frameLen]
		cb(connID, msgType, payload)
		data = data[4+frameLen:]
	}
}
