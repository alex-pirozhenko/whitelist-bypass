package joiner

// OK-Calls SFU data-channel control protocol (web.max.ru bundle port).
//
// Two SCTP data channels the client opens on the SFU PeerConnection carry the
// on-demand video control plane:
//
//   - producerCommand      client -> SFU binary commands (UPDATE_DISPLAY_LAYOUT
//                          etc.), SFU -> client binary command responses.
//   - producerNotification SFU -> client binary notifications (participant
//                          registry, slot assignments, activity, ...).
//
// Both use a hand-rolled msgpack encoding (the bundle's `_S`/`yS` byte
// buffers and the `F_`/`N_`/`P_`/`z_`/`R_`/`V_`/`H_`/`M_` codecs). The codec
// is re-implemented here rather than via vmihailenco/msgpack because the
// bundle's integer encoder (`F_.enc`) always uses the SIGNED tag family
// (0xd1 int16 for 320, where a canonical encoder emits 0xcd uint16) and the
// tests below must reproduce the browser's captured bytes exactly.
//
// See MAX_SFU_DATACHANNEL.md next to this file for the wire format with
// bundle cites and the captured frames decoded field by field.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// ---------------------------------------------------------------------------
// msgpack subset (bundle.min.js offsets 290576-296560)
// ---------------------------------------------------------------------------

// mpWriter mirrors `_S()` (slice.pretty.js:2116-2181): a growable big-endian
// byte buffer the typed codecs append to.
type mpWriter struct{ b []byte }

// putInt is `F_.enc` (bundle.min.js @293194): signed tag family only.
func (w *mpWriter) putInt(v int64) {
	switch {
	case v >= 0 && v <= 127:
		w.b = append(w.b, byte(v)) // positive fixint (c_)
	case v < 0 && v > -32:
		w.b = append(w.b, byte(0xe0|(v&0x1f))) // negative fixint (d_)
	case v >= -128 && v <= 127:
		w.b = append(w.b, 0xd0, byte(v))
	case v >= math.MinInt16 && v <= math.MaxInt16:
		w.b = append(w.b, 0xd1)
		w.b = binary.BigEndian.AppendUint16(w.b, uint16(int16(v)))
	case v >= math.MinInt32 && v <= math.MaxInt32:
		w.b = append(w.b, 0xd2)
		w.b = binary.BigEndian.AppendUint32(w.b, uint32(int32(v)))
	default:
		w.b = append(w.b, 0xd3)
		w.b = binary.BigEndian.AppendUint64(w.b, uint64(v))
	}
}

// putNil is `N_.enc` (@292970).
func (w *mpWriter) putNil() { w.b = append(w.b, 0xc0) }

// putBool is `P_.enc` (@293057).
func (w *mpWriter) putBool(v bool) {
	if v {
		w.b = append(w.b, 0xc3)
	} else {
		w.b = append(w.b, 0xc2)
	}
}

// putLenPrefixed is `w_` (@291792): 1/2/4-byte length after base, base+1, base+2.
func (w *mpWriter) putLenPrefixed(base byte, p []byte) {
	n := len(p)
	switch {
	case n <= 0xff:
		w.b = append(w.b, base, byte(n))
	case n <= 0xffff:
		w.b = append(w.b, base+1)
		w.b = binary.BigEndian.AppendUint16(w.b, uint16(n))
	default:
		w.b = append(w.b, base+2)
		w.b = binary.BigEndian.AppendUint32(w.b, uint32(n))
	}
	w.b = append(w.b, p...)
}

// putStr is `z_.enc` (@294264): fixstr below 32 bytes, else str8/16/32 (0xd9..).
func (w *mpWriter) putStr(s string) {
	if len(s) < 32 {
		w.b = append(w.b, byte(0xa0|len(s)))
		w.b = append(w.b, s...)
		return
	}
	w.putLenPrefixed(0xd9, []byte(s))
}

// putBin is `R_.enc` (@294230): bin8/16/32 (0xc4..).
func (w *mpWriter) putBin(p []byte) { w.putLenPrefixed(0xc4, p) }

// putArrayHeader is `E_` (@292252): fixarray below 16, else array16/32.
func (w *mpWriter) putArrayHeader(n int) {
	switch {
	case n < 16:
		w.b = append(w.b, byte(0x90|n))
	case n <= 0xffff:
		w.b = append(w.b, 0xdc)
		w.b = binary.BigEndian.AppendUint16(w.b, uint16(n))
	default:
		w.b = append(w.b, 0xdd)
		w.b = binary.BigEndian.AppendUint32(w.b, uint32(n))
	}
}

// mpReader mirrors `yS()`/`C_()` (slice.pretty.js:2182-2236): a cursor over a
// big-endian byte slice.
type mpReader struct {
	b   []byte
	pos int
}

var errMPShort = errors.New("msgpack: truncated input")

func (r *mpReader) need(n int) error {
	if r.pos+n > len(r.b) {
		return errMPShort
	}
	return nil
}

func (r *mpReader) peek() (byte, error) {
	if err := r.need(1); err != nil {
		return 0, err
	}
	return r.b[r.pos], nil
}

func (r *mpReader) u8() (byte, error) {
	if err := r.need(1); err != nil {
		return 0, err
	}
	v := r.b[r.pos]
	r.pos++
	return v, nil
}

func (r *mpReader) u16() (uint16, error) {
	if err := r.need(2); err != nil {
		return 0, err
	}
	v := binary.BigEndian.Uint16(r.b[r.pos:])
	r.pos += 2
	return v, nil
}

func (r *mpReader) u32() (uint32, error) {
	if err := r.need(4); err != nil {
		return 0, err
	}
	v := binary.BigEndian.Uint32(r.b[r.pos:])
	r.pos += 4
	return v, nil
}

func (r *mpReader) u64() (uint64, error) {
	if err := r.need(8); err != nil {
		return 0, err
	}
	v := binary.BigEndian.Uint64(r.b[r.pos:])
	r.pos += 8
	return v, nil
}

func (r *mpReader) bytes(n int) ([]byte, error) {
	if err := r.need(n); err != nil {
		return nil, err
	}
	v := r.b[r.pos : r.pos+n]
	r.pos += n
	return v, nil
}

func (r *mpReader) done() bool { return r.pos >= len(r.b) }

// readInt is `F_.dec` (@293194): fixints, nil (-> 0), d0-d3 signed, cc-cf unsigned.
func (r *mpReader) readInt() (int64, error) {
	t, err := r.u8()
	if err != nil {
		return 0, err
	}
	switch {
	case t&0x80 == 0: // positive fixint (l_/u_)
		return int64(t & 0x7f), nil
	case t&0xe0 == 0xe0: // negative fixint (f_/p_)
		return int64(t) - 256, nil
	}
	switch t {
	case 0xc0:
		return 0, nil
	case 0xd0:
		v, err := r.u8()
		return int64(int8(v)), err
	case 0xd1:
		v, err := r.u16()
		return int64(int16(v)), err
	case 0xd2:
		v, err := r.u32()
		return int64(int32(v)), err
	case 0xd3:
		v, err := r.u64()
		return int64(v), err
	case 0xcc:
		v, err := r.u8()
		return int64(v), err
	case 0xcd:
		v, err := r.u16()
		return int64(v), err
	case 0xce:
		v, err := r.u32()
		return int64(v), err
	case 0xcf:
		v, err := r.u64()
		return int64(v), err
	}
	return 0, fmt.Errorf("msgpack: unexpected tag 0x%02x (int expected)", t)
}

// readBytesOrStr is `T_` (@292013): nil -> empty, bin8/16/32, str8/16/32, fixstr.
func (r *mpReader) readBytesOrStr() ([]byte, error) {
	t, err := r.u8()
	if err != nil {
		return nil, err
	}
	var n int
	switch t {
	case 0xc0:
		n = 0
	case 0xc4, 0xd9:
		v, err := r.u8()
		if err != nil {
			return nil, err
		}
		n = int(v)
	case 0xc5, 0xda:
		v, err := r.u16()
		if err != nil {
			return nil, err
		}
		n = int(v)
	case 0xc6, 0xdb:
		v, err := r.u32()
		if err != nil {
			return nil, err
		}
		n = int(v)
	default:
		if t&0xe0 != 0xa0 {
			return nil, fmt.Errorf("msgpack: unexpected tag 0x%02x (bytes or string expected)", t)
		}
		n = int(t & 0x1f)
	}
	return r.bytes(n)
}

// readArrayHeader is `D_` (@292302).
func (r *mpReader) readArrayHeader() (int, error) {
	t, err := r.u8()
	if err != nil {
		return 0, err
	}
	switch {
	case t&0xf0 == 0x90:
		return int(t & 0x0f), nil
	case t == 0xc0:
		return 0, nil
	case t == 0xdc:
		v, err := r.u16()
		return int(v), err
	case t == 0xdd:
		v, err := r.u32()
		return int(v), err
	}
	return 0, fmt.Errorf("msgpack: unexpected tag 0x%02x (array expected)", t)
}

// readMapHeader is `k_` (@292493).
func (r *mpReader) readMapHeader() (int, error) {
	t, err := r.u8()
	if err != nil {
		return 0, err
	}
	switch {
	case t&0xf0 == 0x80:
		return int(t & 0x0f), nil
	case t == 0xc0:
		return 0, nil
	case t == 0xde:
		v, err := r.u16()
		return int(v), err
	case t == 0xdf:
		v, err := r.u32()
		return int(v), err
	}
	return 0, fmt.Errorf("msgpack: unexpected tag 0x%02x (map expected)", t)
}

// mpMap is a decoded msgpack map. Keys are int64 or string (the only key types
// the SFU emits); JS folds both into object-key strings, so consumers use
// mapInt/mapStr to look up either spelling.
type mpMap struct {
	keys []any
	vals map[any]any
}

func (m *mpMap) get(k any) (any, bool) {
	v, ok := m.vals[k]
	return v, ok
}

// readAny is `M_.dec` via the `J_` tag dispatch (@296036): the generic decoder
// the notification decoder (`Y_`, @296527) runs over a message body.
func (r *mpReader) readAny() (any, error) {
	t, err := r.peek()
	if err != nil {
		return nil, err
	}
	switch {
	case t == 0xc0:
		r.pos++
		return nil, nil
	case t == 0xc2 || t == 0xc3:
		r.pos++
		return t == 0xc3, nil
	case t&0x80 == 0 || t&0xe0 == 0xe0, t >= 0xcc && t <= 0xcf, t >= 0xd0 && t <= 0xd3:
		return r.readInt()
	case t == 0xca:
		r.pos++
		v, err := r.u32()
		return float64(math.Float32frombits(v)), err
	case t == 0xcb:
		r.pos++
		v, err := r.u64()
		return math.Float64frombits(v), err
	case t >= 0xc4 && t <= 0xc6:
		p, err := r.readBytesOrStr()
		if err != nil {
			return nil, err
		}
		return append([]byte(nil), p...), nil
	case t&0xe0 == 0xa0, t >= 0xd9 && t <= 0xdb:
		p, err := r.readBytesOrStr()
		if err != nil {
			return nil, err
		}
		return string(p), nil
	case t&0xf0 == 0x90, t == 0xdc || t == 0xdd:
		n, err := r.readArrayHeader()
		if err != nil {
			return nil, err
		}
		out := make([]any, 0, n)
		for i := 0; i < n; i++ {
			v, err := r.readAny()
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case t&0xf0 == 0x80, t == 0xde || t == 0xdf:
		n, err := r.readMapHeader()
		if err != nil {
			return nil, err
		}
		m := &mpMap{vals: make(map[any]any, n)}
		for i := 0; i < n; i++ {
			k, err := r.readAny()
			if err != nil {
				return nil, err
			}
			v, err := r.readAny()
			if err != nil {
				return nil, err
			}
			switch k.(type) {
			case int64, string:
			default:
				return nil, fmt.Errorf("msgpack: unsupported map key %T", k)
			}
			if _, dup := m.vals[k]; !dup {
				m.keys = append(m.keys, k)
			}
			m.vals[k] = v
		}
		return m, nil
	}
	return nil, fmt.Errorf("msgpack: unsupported tag 0x%02x", t)
}

// asInt converts a decoded scalar the way JS `Number()` would for our purposes.
func asInt(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case float64:
		return int64(x), true
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

// keyInt reads a map key that JS would have `Number()`-ed: int keys as-is,
// numeric strings parsed.
func keyInt(k any) (int64, bool) {
	switch x := k.(type) {
	case int64:
		return x, true
	case string:
		n, err := strconv.ParseInt(x, 10, 64)
		return n, err == nil
	}
	return 0, false
}

// ---------------------------------------------------------------------------
// Stream descriptions ("u<id>[:d<idx>][:s<MEDIA>][:m<name>]")
// ---------------------------------------------------------------------------

// SFU media types (`dS`, slice.pretty.js:2066-2075).
const (
	SFUMediaCamera    = "CAMERA"
	SFUMediaScreen    = "SCREEN"
	SFUMediaStream    = "STREAM"
	SFUMediaMovie     = "MOVIE"
	SFUMediaAnimoji   = "ANIMOJI"
	SFUMediaSharedURL = "SHARED_URL"
)

var sfuMediaTypes = map[string]bool{
	SFUMediaCamera: true, SFUMediaScreen: true, SFUMediaStream: true,
	SFUMediaMovie: true, SFUMediaAnimoji: true, SFUMediaSharedURL: true,
}

// SFUStreamDesc identifies one participant media source: the composite
// participant id (`Z.composeParticipantId`, slice.pretty.js:270-292:
// "u"/"g" + numeric id, ":d<deviceIdx>" when non-zero), an optional media
// type and an optional stream name.
type SFUStreamDesc struct {
	ParticipantID string // composite: "u1125900244908947" (with ":d<n>" folded in by String())
	DeviceIdx     int
	MediaType     string // "" = participant-level (no media type)
	StreamName    string
}

// String is `mS` (slice.pretty.js:2079-2085): participantId + ":s"+mediaType + ":m"+streamName.
func (d SFUStreamDesc) String() string {
	var sb strings.Builder
	sb.WriteString(d.ParticipantID)
	if d.DeviceIdx != 0 && !strings.Contains(d.ParticipantID, ":d") {
		sb.WriteString(":d")
		sb.WriteString(strconv.Itoa(d.DeviceIdx))
	}
	if d.MediaType != "" {
		sb.WriteString(":s")
		sb.WriteString(d.MediaType)
	}
	if d.StreamName != "" {
		sb.WriteString(":m")
		sb.WriteString(d.StreamName)
	}
	return sb.String()
}

// sfuCompositeUserID is `Z.composeUserId` for USER ids: "u" + id, unless the
// value is already composite.
func sfuCompositeUserID(id string) string {
	if strings.HasPrefix(id, "u") || strings.HasPrefix(id, "g") {
		return id
	}
	return "u" + id
}

// parseSFUStreamDesc is `hS` (slice.pretty.js:2086-2113): splits on ":" and
// reads the s/m/d parameters; unknown media types decode as "" (gS -> null).
func parseSFUStreamDesc(s string) (SFUStreamDesc, error) {
	parts := strings.Split(s, ":")
	if parts[0] == "" {
		return SFUStreamDesc{}, fmt.Errorf("illegal stream description %q", s)
	}
	d := SFUStreamDesc{ParticipantID: parts[0]}
	for _, p := range parts[1:] {
		if p == "" {
			return d, fmt.Errorf("empty parameter in stream description %q", s)
		}
		switch p[0] {
		case 's':
			if sfuMediaTypes[p[1:]] {
				d.MediaType = p[1:]
			}
		case 'm':
			d.StreamName = p[1:]
		case 'd':
			n, err := strconv.Atoi(p[1:])
			if err != nil {
				return d, fmt.Errorf("bad device idx in %q: %w", s, err)
			}
			d.DeviceIdx = n
		default:
			return d, fmt.Errorf("unexpected parameter type %q in stream description %q", p[:1], s)
		}
	}
	return d, nil
}

// ---------------------------------------------------------------------------
// producerCommand: client -> SFU commands (FS class, slice.pretty.js:2249-2378)
// ---------------------------------------------------------------------------

// Command type ids (slice.pretty.js:2237-2248: bS..DS).
const (
	sfuCmdUpdateDisplayLayout      = 0 // bS
	sfuCmdReportPerfStat           = 1 // xS
	sfuCmdReportSharingStat        = 2 // SS
	sfuCmdRequestASR               = 3 // CS
	sfuCmdReportNetworkStat        = 4 // wS
	sfuCmdEnableVideoSuspend       = 5 // TS
	sfuCmdEnableVideoSuspendSugest = 6 // ES
	sfuCmdChangeSimulcast          = 7 // DS

	sfuCmdVersion = 0 // jS: protocol version field, always 0
	sfuCmdErrOK   = 0 // MS: response error code "ok"

	sfuLayoutNormal     = 0 // OS: regular layout entry
	sfuLayoutStopStream = 1 // kS: {stopStream:true}
	sfuLayoutKeyFrame   = 2 // AS: {keyFrameRequested:true}

	sfuFitCover   = 0 // NS: fit "cv"
	sfuFitContain = 1 // PS: fit "cn"
)

// SFULayoutRequest is one entry of the UPDATE_DISPLAY_LAYOUT map: the stream
// we want and how big we display it. Zero Width/Height encode as nil (no size);
// Fit "" encodes as nil.
type SFULayoutRequest struct {
	Stream    SFUStreamDesc
	Stop      bool // stopStream
	KeyFrame  bool // keyFrameRequested
	Priority  *int
	Width     int
	Height    int
	Fit       string // "cv" (cover) | "cn" (contain) | ""
	CompactID *int   // registry compact id, when known (writeStreamDesc prefers it)
}

// encodeUpdateDisplayLayout is `FS.serializeUpdateDisplayLayout` +
// `writeLayout` + `writeStreamDesc` (slice.pretty.js:2258-2300):
//
//	int(0) int(0) int(seq) nil array[ bin(layout)... ] nil
//	layout = streamDesc(int compactId | str) int(kind) [nil|int priority] [int w int h | nil nil] [int fit | nil]
func encodeUpdateDisplayLayout(seq int, layouts []SFULayoutRequest) []byte {
	w := &mpWriter{}
	w.putInt(sfuCmdUpdateDisplayLayout)
	w.putInt(sfuCmdVersion)
	w.putInt(int64(seq))
	w.putNil()
	w.putArrayHeader(len(layouts))
	for _, l := range layouts {
		w.putBin(encodeSFULayout(l))
	}
	w.putNil()
	return w.b
}

func encodeSFULayout(l SFULayoutRequest) []byte {
	w := &mpWriter{}
	if l.CompactID != nil {
		w.putInt(int64(*l.CompactID))
	} else {
		w.putStr(l.Stream.String())
	}
	switch {
	case l.Stop:
		w.putInt(sfuLayoutStopStream)
	case l.KeyFrame:
		w.putInt(sfuLayoutKeyFrame)
	default:
		w.putInt(sfuLayoutNormal)
		if l.Priority == nil {
			w.putNil()
		} else {
			w.putInt(int64(*l.Priority))
		}
		if l.Width > 0 && l.Height > 0 {
			w.putInt(int64(l.Width))
			w.putInt(int64(l.Height))
		} else {
			w.putNil()
			w.putNil()
		}
		switch l.Fit {
		case "cv":
			w.putInt(sfuFitCover)
		case "cn":
			w.putInt(sfuFitContain)
		default:
			w.putNil()
		}
	}
	return w.b
}

// SFUCommandResponse is a decoded producerCommand reply
// (`FS.deserializeCommandResponse`, slice.pretty.js:2379-2417).
type SFUCommandResponse struct {
	CommandType int
	Version     int
	ErrorCode   int
	Sequence    int
	// UPDATE_DISPLAY_LAYOUT: per-stream error codes (key = compact id resolved
	// through the registry when possible, else the raw int/string key).
	ErrorCodeByStream map[string]int
	// REPORT_PERF_STAT: server-estimated performance index.
	EstimatedPerformanceIndex int
}

func (r SFUCommandResponse) String() string {
	switch r.CommandType {
	case sfuCmdUpdateDisplayLayout:
		return fmt.Sprintf("update-display-layout seq=%d err=%d perStream=%v", r.Sequence, r.ErrorCode, r.ErrorCodeByStream)
	case sfuCmdReportPerfStat:
		return fmt.Sprintf("report-perf-stat seq=%d err=%d epi=%d", r.Sequence, r.ErrorCode, r.EstimatedPerformanceIndex)
	}
	return fmt.Sprintf("command-type=%d version=%d err=%d", r.CommandType, r.Version, r.ErrorCode)
}

// decodeSFUCommandResponse parses `int(type) int(version) int(errorCode) ...`.
// reg may be nil; it resolves int stream keys to descriptions.
func decodeSFUCommandResponse(b []byte, reg *sfuStreamRegistry) (SFUCommandResponse, error) {
	r := &mpReader{b: b}
	var out SFUCommandResponse
	var err error
	var v int64
	if v, err = r.readInt(); err != nil {
		return out, err
	}
	out.CommandType = int(v)
	if v, err = r.readInt(); err != nil {
		return out, err
	}
	out.Version = int(v)
	if out.Version != sfuCmdVersion {
		return out, fmt.Errorf("unsupported command response version %d for type %d", out.Version, out.CommandType)
	}
	if v, err = r.readInt(); err != nil {
		return out, err
	}
	out.ErrorCode = int(v)
	if out.ErrorCode != sfuCmdErrOK {
		// The bundle stops here ("Error code: N received for command type").
		return out, nil
	}
	switch out.CommandType {
	case sfuCmdUpdateDisplayLayout:
		if v, err = r.readInt(); err != nil {
			return out, err
		}
		out.Sequence = int(v)
		n, err := r.readArrayHeader()
		if err != nil {
			return out, err
		}
		out.ErrorCodeByStream = map[string]int{}
		for i := 0; i < n; i++ {
			entry, err := r.readBytesOrStr()
			if err != nil {
				return out, err
			}
			er := &mpReader{b: entry}
			key, err := er.readAny()
			if err != nil {
				return out, err
			}
			code, err := er.readInt()
			if err != nil {
				return out, err
			}
			var ks string
			switch k := key.(type) {
			case string:
				ks = k
			case int64:
				ks = strconv.FormatInt(k, 10)
				if reg != nil {
					if d, ok := reg.desc(int(k)); ok {
						ks = d.String()
					}
				}
			default:
				ks = fmt.Sprint(key)
			}
			out.ErrorCodeByStream[ks] = int(code)
		}
	case sfuCmdReportPerfStat:
		if v, err = r.readInt(); err != nil {
			return out, err
		}
		out.Sequence = int(v)
		if v, err = r.readInt(); err != nil {
			return out, err
		}
		out.EstimatedPerformanceIndex = int(v)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// producerNotification: SFU -> client (VC class, slice.pretty.js:4155-4310)
// ---------------------------------------------------------------------------

// Notification type byte (first byte of every producerNotification frame).
const (
	sfuNotifRegistry          = 1 // compactId <-> stream description map
	sfuNotifAudioActivity     = 2
	sfuNotifSpeakerChanged    = 3
	sfuNotifStalledActivity   = 4
	sfuNotifVideoQuality      = 5
	sfuNotifNetworkStatus     = 6
	sfuNotifSourcesUpdate     = 7 // slot (pat-N) <-> stream assignment
	sfuNotifMovieUpdate       = 8
	sfuNotifVideoSuspendSugst = 9
)

var sfuNotifNames = map[int]string{
	sfuNotifRegistry:          "registry",
	sfuNotifAudioActivity:     "audio-activity",
	sfuNotifSpeakerChanged:    "speaker-changed",
	sfuNotifStalledActivity:   "stalled-activity",
	sfuNotifVideoQuality:      "video-quality-update",
	sfuNotifNetworkStatus:     "network-status",
	sfuNotifSourcesUpdate:     "participant-sources-update",
	sfuNotifMovieUpdate:       "movie-update-notification",
	sfuNotifVideoSuspendSugst: "video-suspend-suggest",
}

// sfuPATPrefix is `IC.PARTICIPANT_AGNOSTIC_TRACK_PREFIX` (slice.pretty.js:4076).
const sfuPATPrefix = "pat"

// sfuStreamRegistry is the `VC` participant-id registry: the SFU assigns a
// small "compact id" to every stream description it will refer to in later
// notifications (type 1 message), and both sides may use the compact id
// instead of the string in commands/responses.
type sfuStreamRegistry struct {
	mu        sync.Mutex
	byCompact map[int]SFUStreamDesc
	byDesc    map[string]int
}

func newSFUStreamRegistry() *sfuStreamRegistry {
	return &sfuStreamRegistry{byCompact: map[int]SFUStreamDesc{}, byDesc: map[string]int{}}
}

func (r *sfuStreamRegistry) set(desc string, id int) error {
	d, err := parseSFUStreamDesc(desc)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.byCompact[id] = d
	r.byDesc[desc] = id
	r.mu.Unlock()
	return nil
}

func (r *sfuStreamRegistry) desc(id int) (SFUStreamDesc, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.byCompact[id]
	return d, ok
}

func (r *sfuStreamRegistry) compactID(desc string) (int, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.byDesc[desc]
	return id, ok
}

// SFUSourceUpdate is one entry of a participant-sources-update (type 7):
// consumer slot `pat-<Slot>` now carries Stream (nil = slot released).
type SFUSourceUpdate struct {
	Slot            int
	StreamID        string // "pat-N" == the offer's a=msid stream id / "video-pat-N" ssrc label minus "video-"
	CompactID       *int
	Stream          *SFUStreamDesc // resolved via registry; nil when unknown or slot released
	RTPTimestamp    *uint32        // when set, the switch happens at this RTP timestamp
	SequenceNumber  int            // the command sequence this allocation answers
	FastScreenShare bool
	Suspend         *bool
}

// SFUNotification is a decoded producerNotification frame.
type SFUNotification struct {
	Type int
	Name string
	Raw  any // generic-decoded body (for logging unknown shapes)

	Registry     map[string]int    // type 1
	CompactIDs   []int             // types 2, 4 (and 3 as a single element)
	Participants []SFUStreamDesc   // types 2, 3, 4 resolved through the registry
	VideoQuality *SFUVideoQuality  // type 5
	Network      map[int]float64   // type 6: compactId -> 0..1
	Sources      []SFUSourceUpdate // type 7
	Bandwidth    int64             // type 9
	Movies       []map[string]any  // type 8 (rarely relevant; kept generic)
}

// describeSFUSlots renders a slot map sorted by slot index for logging.
func describeSFUSlots(slots map[string]*sfuSlot) string {
	ids := make([]string, 0, len(slots))
	for id := range slots {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, _ := strconv.Atoi(strings.TrimPrefix(ids[i], sfuPATPrefix+"-"))
		b, _ := strconv.Atoi(strings.TrimPrefix(ids[j], sfuPATPrefix+"-"))
		return a < b
	})
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		s := slots[id]
		parts = append(parts, fmt.Sprintf("%s:mid=%s ssrcs=%v", id, s.Mid, s.SSRCs))
	}
	return strings.Join(parts, " ")
}

// jsonIDString renders a JSON-decoded participant id (json.Number, float64,
// int or string) as the plain decimal string the SFU registry uses.
func jsonIDString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', 0, 64)
	case fmt.Stringer:
		return x.String()
	}
	return fmt.Sprint(v)
}

// SFUVideoQuality is the type-5 payload.
type SFUVideoQuality struct {
	MaxBitrate   int64
	MaxDimension int64
	MediaType    string // CAMERA/SCREEN/""
}

func (n SFUNotification) String() string {
	switch n.Type {
	case sfuNotifRegistry:
		return fmt.Sprintf("%s %v", n.Name, n.Registry)
	case sfuNotifAudioActivity, sfuNotifStalledActivity, sfuNotifSpeakerChanged:
		return fmt.Sprintf("%s ids=%v participants=%v", n.Name, n.CompactIDs, n.Participants)
	case sfuNotifVideoQuality:
		return fmt.Sprintf("%s %+v", n.Name, *n.VideoQuality)
	case sfuNotifNetworkStatus:
		return fmt.Sprintf("%s %v", n.Name, n.Network)
	case sfuNotifSourcesUpdate:
		parts := make([]string, 0, len(n.Sources))
		for _, s := range n.Sources {
			who := "(released)"
			if s.Stream != nil {
				who = s.Stream.String()
			} else if s.CompactID != nil {
				who = fmt.Sprintf("compact#%d", *s.CompactID)
			}
			ts := "now"
			if s.RTPTimestamp != nil {
				ts = fmt.Sprintf("rtp=%d", *s.RTPTimestamp)
			}
			parts = append(parts, fmt.Sprintf("%s<-%s seq=%d %s fss=%v", s.StreamID, who, s.SequenceNumber, ts, s.FastScreenShare))
		}
		return fmt.Sprintf("%s [%s]", n.Name, strings.Join(parts, "; "))
	case sfuNotifVideoSuspendSugst:
		return fmt.Sprintf("%s bandwidth=%d", n.Name, n.Bandwidth)
	}
	return fmt.Sprintf("%s(type=%d) %v", n.Name, n.Type, n.Raw)
}

// decodeSFUNotification is `VC.handleMessage` (slice.pretty.js:4168-4262): the
// first byte selects the type, the rest is one generic msgpack value. Type 1
// updates reg (when non-nil); other types resolve compact ids through it.
func decodeSFUNotification(b []byte, reg *sfuStreamRegistry) (SFUNotification, error) {
	if len(b) == 0 {
		return SFUNotification{}, errors.New("empty producerNotification frame")
	}
	n := SFUNotification{Type: int(b[0])}
	n.Name = sfuNotifNames[n.Type]
	if n.Name == "" {
		n.Name = "unsupported"
	}
	r := &mpReader{b: b[1:]}
	body, err := r.readAny()
	if err != nil {
		return n, err
	}
	n.Raw = body
	resolve := func(id int64) *SFUStreamDesc {
		if reg == nil {
			return nil
		}
		if d, ok := reg.desc(int(id)); ok {
			return &d
		}
		return nil
	}
	switch n.Type {
	case sfuNotifRegistry:
		m, ok := body.(*mpMap)
		if !ok {
			return n, fmt.Errorf("registry: want map, got %T", body)
		}
		n.Registry = map[string]int{}
		for _, k := range m.keys {
			ks, ok := k.(string)
			if !ok {
				return n, fmt.Errorf("registry: non-string key %v", k)
			}
			id, ok := asInt(m.vals[k])
			if !ok {
				return n, fmt.Errorf("registry: non-int compact id for %q", ks)
			}
			n.Registry[ks] = int(id)
			if reg != nil {
				if err := reg.set(ks, int(id)); err != nil {
					return n, err
				}
			}
		}
	case sfuNotifAudioActivity, sfuNotifStalledActivity:
		arr, ok := body.([]any)
		if !ok {
			return n, fmt.Errorf("%s: want array, got %T", n.Name, body)
		}
		for _, v := range arr {
			id, ok := asInt(v)
			if !ok {
				continue
			}
			n.CompactIDs = append(n.CompactIDs, int(id))
			if d := resolve(id); d != nil {
				n.Participants = append(n.Participants, *d)
			}
		}
	case sfuNotifSpeakerChanged:
		id, ok := asInt(body)
		if !ok {
			return n, fmt.Errorf("speaker-changed: want int, got %T", body)
		}
		n.CompactIDs = []int{int(id)}
		if d := resolve(id); d != nil {
			n.Participants = []SFUStreamDesc{*d}
		}
	case sfuNotifVideoQuality:
		arr, ok := body.([]any)
		if !ok || len(arr) < 3 {
			return n, fmt.Errorf("video-quality-update: want [bitrate,dimension,mediaType], got %v", body)
		}
		q := &SFUVideoQuality{}
		q.MaxBitrate, _ = asInt(arr[0])
		q.MaxDimension, _ = asInt(arr[1])
		if mt, ok := asInt(arr[2]); ok && arr[2] != nil {
			switch mt {
			case 0:
				q.MediaType = SFUMediaCamera
			case 1:
				q.MediaType = SFUMediaScreen
			default:
				return n, fmt.Errorf("video-quality-update: unsupported media type %d", mt)
			}
		}
		n.VideoQuality = q
	case sfuNotifNetworkStatus:
		m, ok := body.(*mpMap)
		if !ok {
			return n, fmt.Errorf("network-status: want map, got %T", body)
		}
		n.Network = map[int]float64{}
		for _, k := range m.keys {
			id, ok := keyInt(k)
			if !ok {
				continue
			}
			v, ok := asInt(m.vals[k])
			if !ok {
				continue
			}
			n.Network[int(id)] = float64(v) / 100
		}
	case sfuNotifSourcesUpdate:
		m, ok := body.(*mpMap)
		if !ok {
			return n, fmt.Errorf("participant-sources-update: want map, got %T", body)
		}
		for _, k := range m.keys {
			slot, ok := keyInt(k)
			if !ok {
				return n, fmt.Errorf("participant-sources-update: non-int slot key %v", k)
			}
			tuple, ok := m.vals[k].([]any)
			if !ok || len(tuple) < 3 {
				return n, fmt.Errorf("participant-sources-update: slot %d: want [compactId,rtpTs,seq,fss,suspend], got %v", slot, m.vals[k])
			}
			su := SFUSourceUpdate{Slot: int(slot), StreamID: fmt.Sprintf("%s-%d", sfuPATPrefix, slot)}
			if tuple[0] != nil {
				id, ok := asInt(tuple[0])
				if !ok {
					return n, fmt.Errorf("participant-sources-update: slot %d: bad compact id %v", slot, tuple[0])
				}
				cid := int(id)
				su.CompactID = &cid
				su.Stream = resolve(id)
			}
			if tuple[1] != nil {
				if ts, ok := asInt(tuple[1]); ok {
					u := uint32(ts) // JS: i >>> 0
					su.RTPTimestamp = &u
				}
			}
			if tuple[2] == nil {
				return n, fmt.Errorf("participant-sources-update: slot %d: null sequenceNumber", slot)
			}
			seq, _ := asInt(tuple[2])
			su.SequenceNumber = int(seq)
			if len(tuple) > 3 {
				if bv, ok := tuple[3].(bool); ok {
					su.FastScreenShare = bv
				} else if iv, ok := asInt(tuple[3]); ok {
					su.FastScreenShare = iv != 0
				}
			}
			if len(tuple) > 4 && tuple[4] != nil {
				var s bool
				if bv, ok := tuple[4].(bool); ok {
					s = bv
				} else if iv, ok := asInt(tuple[4]); ok {
					s = iv != 0
				}
				su.Suspend = &s
			}
			n.Sources = append(n.Sources, su)
		}
	case sfuNotifMovieUpdate:
		arr, _ := body.([]any)
		for _, e := range arr {
			t, ok := e.([]any)
			if !ok || len(t) < 7 {
				continue
			}
			row := map[string]any{"gain": t[1], "pause": t[2], "offset": t[3], "mute": t[4], "liveStatus": t[5], "startTimeMs": t[6]}
			if id, ok := asInt(t[0]); ok {
				row["compactId"] = id
				if d := resolve(id); d != nil {
					row["participant"] = d.String()
				}
			}
			n.Movies = append(n.Movies, row)
		}
	case sfuNotifVideoSuspendSugst:
		n.Bandwidth, _ = asInt(body)
	}
	if !r.done() {
		return n, fmt.Errorf("%s: %d trailing bytes", n.Name, len(r.b)-r.pos)
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// Consumer slots from the SFU offer SDP
// ---------------------------------------------------------------------------

// sfuSlot is one pre-allocated consumer video slot in the SFU's offer: the
// m-line mid whose a=msid stream id is "pat-N" and the SSRCs labelled
// "video-pat-N" (primary + RTX).
type sfuSlot struct {
	StreamID string // "pat-N"
	Mid      string
	SSRCs    []uint32
}

var (
	sfuMidRe   = regexp.MustCompile(`^a=mid:(\S+)`)
	sfuMsidRe  = regexp.MustCompile(`^a=msid:(` + sfuPATPrefix + `-\d+)\s`)
	sfuSSRCRe  = regexp.MustCompile(`^a=ssrc:(\d+) label:video-(` + sfuPATPrefix + `-\d+)`)
	sfuMediaRe = regexp.MustCompile(`^m=`)
)

// parseSFUSlotMap walks an SFU offer and returns pat-N -> {mid, ssrcs}. The
// browser's `_updateSSRCMap` (slice.pretty.js:6784-6789) keeps ssrc -> label;
// we additionally keep the mid so OnTrack (which reports mid/ssrc/streamId)
// can be correlated with participant-sources-update (which reports pat-N).
func parseSFUSlotMap(sdp string) map[string]*sfuSlot {
	out := map[string]*sfuSlot{}
	get := func(id string) *sfuSlot {
		s := out[id]
		if s == nil {
			s = &sfuSlot{StreamID: id}
			out[id] = s
		}
		return s
	}
	mid := ""
	for _, line := range strings.Split(sdp, "\n") {
		line = strings.TrimRight(line, "\r")
		if sfuMediaRe.MatchString(line) {
			mid = ""
			continue
		}
		if m := sfuMidRe.FindStringSubmatch(line); m != nil {
			mid = m[1]
			continue
		}
		if m := sfuMsidRe.FindStringSubmatch(line); m != nil {
			get(m[1]).Mid = mid
			continue
		}
		if m := sfuSSRCRe.FindStringSubmatch(line); m != nil {
			s := get(m[2])
			if s.Mid == "" {
				s.Mid = mid
			}
			ssrc, _ := strconv.ParseUint(m[1], 10, 32)
			dup := false
			for _, e := range s.SSRCs {
				if e == uint32(ssrc) {
					dup = true
				}
			}
			if !dup {
				s.SSRCs = append(s.SSRCs, uint32(ssrc))
			}
		}
	}
	return out
}

// sfuSlotForSSRC finds the slot whose SSRC list contains ssrc.
func sfuSlotForSSRC(slots map[string]*sfuSlot, ssrc uint32) *sfuSlot {
	ids := make([]string, 0, len(slots))
	for id := range slots {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		for _, s := range slots[id].SSRCs {
			if s == ssrc {
				return slots[id]
			}
		}
	}
	return nil
}
