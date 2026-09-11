package tunnel

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// vp8Keyframe is a valid, complete 320x240 VP8 keyframe (160 bytes) produced
// by libvpx. It contains:
// - 3-byte uncompressed header (frame tag, keyframe, version 0, show_frame=1, first_part_size=145)
// - 3-byte start code (0x9d, 0x01, 0x2a)
// - 4-byte dimensions (320x240, 14-bit with 2 scale bits)
// - 150 bytes partition 0 boolean entropy-coded macroblocks covering all 300 macroblocks of 320x240
// Trailing bytes (epoch, nonce, ciphertext) appended after this complete frame
// are ignored by VP8 parsers/decoders since all macroblocks are already decoded.
var vp8Keyframe = []byte{
	0x30, 0x12, 0x00, 0x9d, 0x01, 0x2a, 0x40, 0x01,
	0xf0, 0x00, 0x00, 0x47, 0x08, 0x85, 0x85, 0x88,
	0x85, 0x84, 0x88, 0x02, 0x02, 0x00, 0x06, 0x16,
	0x04, 0xf7, 0x06, 0x81, 0x64, 0x9f, 0x6b, 0xdb,
	0x9b, 0x27, 0x38, 0x7b, 0x27, 0x38, 0x7b, 0x27,
	0x38, 0x7b, 0x27, 0x38, 0x7b, 0x27, 0x38, 0x7b,
	0x27, 0x38, 0x7b, 0x27, 0x38, 0x7b, 0x27, 0x38,
	0x7b, 0x27, 0x38, 0x7b, 0x27, 0x38, 0x7b, 0x27,
	0x38, 0x7b, 0x27, 0x38, 0x7b, 0x27, 0x38, 0x7b,
	0x27, 0x38, 0x7b, 0x27, 0x38, 0x7b, 0x27, 0x38,
	0x7b, 0x27, 0x38, 0x7b, 0x27, 0x38, 0x7b, 0x27,
	0x38, 0x7b, 0x27, 0x38, 0x7b, 0x27, 0x38, 0x7b,
	0x27, 0x38, 0x7b, 0x27, 0x38, 0x7b, 0x27, 0x38,
	0x7b, 0x27, 0x38, 0x7b, 0x27, 0x38, 0x7b, 0x27,
	0x38, 0x7b, 0x27, 0x38, 0x7b, 0x27, 0x38, 0x7b,
	0x27, 0x38, 0x7b, 0x27, 0x38, 0x7b, 0x27, 0x38,
	0x7b, 0x27, 0x38, 0x7b, 0x27, 0x38, 0x7b, 0x27,
	0x38, 0x7b, 0x27, 0x38, 0x7b, 0x27, 0x38, 0x7b,
	0x27, 0x38, 0x7b, 0x27, 0x38, 0x7b, 0x27, 0x38,
	0x7a, 0xf4, 0x00, 0xfe, 0xff, 0xab, 0x50, 0x80,
}

// vp8Interframe is a valid, complete 320x240 VP8 interframe (26 bytes) produced
// by libvpx. It encodes an all-skip / zero-motion update across all 300 macroblocks.
var vp8Interframe = []byte{
	0xd1, 0x02, 0x00, 0x05, 0x10, 0xac, 0x00, 0x18,
	0x00, 0x18, 0x58, 0x2f, 0xf4, 0x00, 0x08, 0x80,
	0x04, 0x33, 0x5f, 0xad, 0x72, 0x4f, 0x9c, 0x73,
	0x00, 0x00,
}

var vp8Keepalive = vp8Keyframe

const (
	vp8KeyframeLen   = 160
	vp8InterframeLen = 26
	epochFieldLen    = 4
	keyframeHdrLen   = vp8KeyframeLen + epochFieldLen
	interframeHdrLen = vp8InterframeLen + epochFieldLen

	vp8KeepaliveLen = vp8KeyframeLen
	keepaliveHdrLen = keyframeHdrLen
)

var ErrEmptySecret = errors.New("tunnel: obfuscator requires a non-empty secret")

type DecodeResult struct {
	HasFrame    bool
	Keepalive   bool
	SelfEcho    bool
	PeerRestart bool
	Payload     []byte
	PeerEpoch   uint32
}

type TunnelObfuscator struct {
	aead       cipher.AEAD
	localEpoch uint32

	mu        sync.Mutex
	peerEpoch uint32
	hasPeer   bool
}

func DeriveSecretFromJoinLink(joinLink string) []byte {
	token := extractJoinToken(joinLink)
	if token == "" {
		return nil
	}
	return []byte(token)
}

func extractJoinToken(joinLink string) string {
	s := strings.TrimSpace(joinLink)
	s = strings.TrimRight(s, "/")
	if i := strings.IndexByte(s, '?'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		s = s[i+1:]
	}
	return s
}

func NewTunnelObfuscator(secret []byte) (*TunnelObfuscator, error) {
	if len(secret) == 0 {
		return nil, ErrEmptySecret
	}
	keyHash := sha256.Sum256(secret)
	aead, err := chacha20poly1305.NewX(keyHash[:])
	if err != nil {
		return nil, err
	}
	var epochBytes [4]byte
	if _, err := rand.Read(epochBytes[:]); err != nil {
		return nil, err
	}
	epoch := binary.BigEndian.Uint32(epochBytes[:])
	if epoch == 0 {
		epoch = 1
	}
	return &TunnelObfuscator{aead: aead, localEpoch: epoch}, nil
}

func (o *TunnelObfuscator) LocalEpoch() uint32 { return o.localEpoch }

func (o *TunnelObfuscator) keyframeHeader() []byte {
	hdr := make([]byte, keyframeHdrLen)
	copy(hdr, vp8Keyframe)
	binary.BigEndian.PutUint32(hdr[vp8KeyframeLen:], o.localEpoch)
	return hdr
}

func (o *TunnelObfuscator) keepaliveHeader() []byte {
	return o.keyframeHeader()
}

func (o *TunnelObfuscator) dataHeader() []byte {
	hdr := make([]byte, interframeHdrLen)
	copy(hdr, vp8Interframe)
	binary.BigEndian.PutUint32(hdr[vp8InterframeLen:], o.localEpoch)
	return hdr
}

func (o *TunnelObfuscator) EncodeKeepalive(padLen int) []byte {
	hdr := o.keepaliveHeader()
	if padLen <= 0 {
		return hdr
	}
	out := make([]byte, keyframeHdrLen+padLen)
	copy(out, hdr)
	if _, err := rand.Read(out[keyframeHdrLen:]); err != nil {
		return hdr
	}
	return out
}

func (o *TunnelObfuscator) EncodeKeepaliveInterframe(padLen int) []byte {
	hdr := o.dataHeader()
	if padLen <= 0 {
		return hdr
	}
	out := make([]byte, interframeHdrLen+padLen)
	copy(out, hdr)
	if _, err := rand.Read(out[interframeHdrLen:]); err != nil {
		return hdr
	}
	return out
}

func (o *TunnelObfuscator) EncodeData(payload []byte) []byte {
	return o.encodeDataWithHeader(o.dataHeader(), payload)
}

func (o *TunnelObfuscator) EncodeDataKeyframe(payload []byte) []byte {
	return o.encodeDataWithHeader(o.keyframeHeader(), payload)
}

func (o *TunnelObfuscator) encodeDataWithHeader(hdr []byte, payload []byte) []byte {
	nonce := make([]byte, o.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil
	}
	out := make([]byte, 0, len(hdr)+len(nonce)+len(payload)+o.aead.Overhead())
	out = append(out, hdr...)
	out = append(out, nonce...)
	out = o.aead.Seal(out, nonce, payload, nil)
	return out
}

func (o *TunnelObfuscator) EncryptPayload(plaintext []byte) []byte {
	if o == nil {
		return plaintext
	}
	nonce := make([]byte, o.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil
	}
	out := make([]byte, 0, len(nonce)+len(plaintext)+o.aead.Overhead())
	out = append(out, nonce...)
	return o.aead.Seal(out, nonce, plaintext, nil)
}

func (o *TunnelObfuscator) DecryptPayload(data []byte) ([]byte, bool) {
	if o == nil {
		return data, true
	}
	nonceSize := o.aead.NonceSize()
	if len(data) < nonceSize+o.aead.Overhead() {
		return nil, false
	}
	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]
	plaintext, err := o.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, false
	}
	return plaintext, true
}

func (o *TunnelObfuscator) Decode(frame []byte) DecodeResult {
	if len(frame) < 1 {
		return DecodeResult{}
	}
	var hdrLen, epochOff int
	isKeyframe := false
	switch frame[0] {
	case vp8Keyframe[0]:
		hdrLen = keyframeHdrLen
		epochOff = vp8KeyframeLen
		isKeyframe = true
	case vp8Interframe[0]:
		hdrLen = interframeHdrLen
		epochOff = vp8InterframeLen
	default:
		return DecodeResult{}
	}
	if len(frame) < hdrLen {
		return DecodeResult{}
	}
	peerEpoch := binary.BigEndian.Uint32(frame[epochOff : epochOff+epochFieldLen])
	if peerEpoch == o.localEpoch {
		return DecodeResult{HasFrame: true, SelfEcho: true, PeerEpoch: peerEpoch}
	}

	res := DecodeResult{HasFrame: true, PeerEpoch: peerEpoch}
	o.mu.Lock()
	if !o.hasPeer {
		o.peerEpoch = peerEpoch
		o.hasPeer = true
	} else if o.peerEpoch != peerEpoch {
		o.peerEpoch = peerEpoch
		res.PeerRestart = true
	}
	o.mu.Unlock()

	body := frame[hdrLen:]
	nonceSize := o.aead.NonceSize()
	if len(body) < nonceSize+o.aead.Overhead() {
		res.Keepalive = true
		return res
	}
	nonce := body[:nonceSize]
	ciphertext := body[nonceSize:]
	plaintext, err := o.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		if isKeyframe {
			res.Keepalive = true
			return res
		}
		return DecodeResult{}
	}
	res.Payload = plaintext
	return res
}
