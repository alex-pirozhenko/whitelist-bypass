package joiner

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// Frames captured from the real web.max.ru client on 2026-09-11
// (/tmp/golden/D3.jsonl, kind:"dc"). See MAX_SFU_DATACHANNEL.md.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const (
	capPeerDesc = "u1125900244908947:sCAMERA"
	capSelfDesc = "u1125900244960634"
)

func capCmdTx(t *testing.T) []byte {
	return append(append(mustHex(t, "00 00 04 c0 91 c4 23 b9"), []byte(capPeerDesc)...), mustHex(t, "00 c0 d1 01 40 d1 00 f0 00 c0")...)
}

func TestEncodeUpdateDisplayLayoutMatchesCapture(t *testing.T) {
	want := capCmdTx(t)
	if len(want) != 43 {
		t.Fatalf("capture length = %d, want 43", len(want))
	}
	req := SFULayoutRequest{
		Stream: SFUStreamDesc{ParticipantID: "u1125900244908947", MediaType: SFUMediaCamera},
		Width:  320, Height: 240, Fit: "cv",
	}
	got := encodeUpdateDisplayLayout(4, []SFULayoutRequest{req})
	if !bytes.Equal(got, want) {
		t.Fatalf("encode mismatch\n got=%x\nwant=%x", got, want)
	}
	// Raw numeric id is composed the way Z.composeUserId does ("u" + id).
	req.Stream.ParticipantID = sfuCompositeUserID("1125900244908947")
	if got := encodeUpdateDisplayLayout(4, []SFULayoutRequest{req}); !bytes.Equal(got, want) {
		t.Fatalf("composite-id encode mismatch\n got=%x\nwant=%x", got, want)
	}
}

func TestEncodeUpdateDisplayLayoutCompactIDAndVariants(t *testing.T) {
	id := 1
	req := SFULayoutRequest{
		Stream: SFUStreamDesc{ParticipantID: "u1125900244908947", MediaType: SFUMediaCamera},
		Width:  320, Height: 240, Fit: "cv",
		CompactID: &id,
	}
	// writeStreamDesc uses the registry compact id when known: inner = 01 00 c0 d1 0140 d1 00f0 00 (10 bytes).
	want := mustHex(t, "00 00 05 c0 91 c4 0a 01 00 c0 d1 01 40 d1 00 f0 00 c0")
	if got := encodeUpdateDisplayLayout(5, []SFULayoutRequest{req}); !bytes.Equal(got, want) {
		t.Fatalf("compact-id encode\n got=%x\nwant=%x", got, want)
	}
	// stopStream: streamDesc + int(1), nothing else.
	stop := SFULayoutRequest{Stream: SFUStreamDesc{ParticipantID: "u5", MediaType: SFUMediaCamera}, Stop: true}
	want = append(append(mustHex(t, "00 00 06 c0 91 c4 0c aa"), []byte("u5:sCAMERA")...), mustHex(t, "01 c0")...)
	if got := encodeUpdateDisplayLayout(6, []SFULayoutRequest{stop}); !bytes.Equal(got, want) {
		t.Fatalf("stopStream encode\n got=%x\nwant=%x", got, want)
	}
	// keyFrameRequested: int(2). No size: nil nil. No fit: nil. Priority set.
	pr := 3
	kf := SFULayoutRequest{Stream: SFUStreamDesc{ParticipantID: "u5"}, KeyFrame: true}
	if got := encodeSFULayout(kf); !bytes.Equal(got, append([]byte{0xa2, 'u', '5'}, 0x02)) {
		t.Fatalf("keyframe layout = %x", got)
	}
	nosize := SFULayoutRequest{Stream: SFUStreamDesc{ParticipantID: "u5"}, Priority: &pr}
	if got := encodeSFULayout(nosize); !bytes.Equal(got, mustHex(t, "a2 75 35 00 03 c0 c0 c0")) {
		t.Fatalf("no-size layout = %x", got)
	}
	// Two layouts keep order; contain fit = 1.
	two := []SFULayoutRequest{
		{Stream: SFUStreamDesc{ParticipantID: "u5", MediaType: SFUMediaCamera}, Width: 1, Height: 2, Fit: "cn"},
		{Stream: SFUStreamDesc{ParticipantID: "u6", MediaType: SFUMediaScreen}, Width: 1, Height: 2},
	}
	got := encodeUpdateDisplayLayout(7, two)
	if got[4] != 0x92 || !bytes.Contains(got, append([]byte("u5:sCAMERA"), 0x00, 0xc0, 0x01, 0x02, 0x01)) ||
		!bytes.Contains(got, append([]byte("u6:sSCREEN"), 0x00, 0xc0, 0x01, 0x02, 0xc0)) {
		t.Fatalf("two-layout encode = %x", got)
	}
}

func TestDecodeCommandResponseMatchesCapture(t *testing.T) {
	// SFU reply to the seq=4 request: type 0, version 0, err 0, seq 4, [] errors.
	resp, err := decodeSFUCommandResponse(mustHex(t, "00 00 00 04 90"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.CommandType != sfuCmdUpdateDisplayLayout || resp.Version != 0 || resp.ErrorCode != 0 || resp.Sequence != 4 || len(resp.ErrorCodeByStream) != 0 {
		t.Fatalf("resp = %+v", resp)
	}
	// Per-stream error entries: bin(str key + code) and bin(int key + code), int key resolved via registry.
	reg := newSFUStreamRegistry()
	if err := reg.set(capPeerDesc, 1); err != nil {
		t.Fatal(err)
	}
	frame := append(mustHex(t, "00 00 00 09 92 c4 0c aa"), []byte("u5:sCAMERA")...)
	frame = append(frame, 0x07)                   // code 7 for u5:sCAMERA
	frame = append(frame, 0xc4, 0x02, 0x01, 0x02) // compact 1 -> code 2
	resp, err = decodeSFUCommandResponse(frame, reg)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Sequence != 9 || resp.ErrorCodeByStream["u5:sCAMERA"] != 7 || resp.ErrorCodeByStream[capPeerDesc] != 2 {
		t.Fatalf("resp = %+v", resp)
	}
	// Non-zero error code short-circuits.
	resp, err = decodeSFUCommandResponse(mustHex(t, "00 00 03"), nil)
	if err != nil || resp.ErrorCode != 3 {
		t.Fatalf("err resp = %+v, %v", resp, err)
	}
	// perf-stat response.
	resp, err = decodeSFUCommandResponse(mustHex(t, "01 00 00 0b 02"), nil)
	if err != nil || resp.CommandType != sfuCmdReportPerfStat || resp.Sequence != 11 || resp.EstimatedPerformanceIndex != 2 {
		t.Fatalf("perf resp = %+v, %v", resp, err)
	}
	if _, err := decodeSFUCommandResponse(mustHex(t, "00 01 00"), nil); err == nil {
		t.Fatal("version 1 must be rejected")
	}
}

func TestDecodeNotificationsMatchCapture(t *testing.T) {
	reg := newSFUStreamRegistry()

	// 01 81 b1 "u1125900244960634" 00 — own participant registered as compact id 0.
	n, err := decodeSFUNotification(append(append(mustHex(t, "01 81 b1"), []byte(capSelfDesc)...), 0x00), reg)
	if err != nil {
		t.Fatal(err)
	}
	if n.Type != sfuNotifRegistry || n.Registry[capSelfDesc] != 0 || len(n.Registry) != 1 {
		t.Fatalf("registry notif = %+v", n)
	}
	if d, ok := reg.desc(0); !ok || d.ParticipantID != capSelfDesc || d.MediaType != "" {
		t.Fatalf("registry desc(0) = %+v ok=%v", d, ok)
	}

	// 06 81 00 3c — network status compact 0 -> 60/100.
	n, err = decodeSFUNotification(mustHex(t, "06 81 00 3c"), reg)
	if err != nil || n.Type != sfuNotifNetworkStatus || n.Network[0] != 0.6 {
		t.Fatalf("network notif = %+v err=%v", n, err)
	}

	// 04 90 — stalled activity, nobody.
	n, err = decodeSFUNotification(mustHex(t, "04 90"), reg)
	if err != nil || n.Type != sfuNotifStalledActivity || len(n.CompactIDs) != 0 {
		t.Fatalf("stalled notif = %+v err=%v", n, err)
	}

	// 01 81 b9 "u1125900244908947:sCAMERA" 01 — peer CAMERA registered as compact id 1.
	n, err = decodeSFUNotification(append(append(mustHex(t, "01 81 b9"), []byte(capPeerDesc)...), 0x01), reg)
	if err != nil || n.Registry[capPeerDesc] != 1 {
		t.Fatalf("peer registry notif = %+v err=%v", n, err)
	}
	if id, ok := reg.compactID(capPeerDesc); !ok || id != 1 {
		t.Fatalf("compactID(%q) = %d ok=%v", capPeerDesc, id, ok)
	}

	// 07 81 00 95 01 c0 04 c0 c0 — slot pat-0 <- compact 1, no rtp ts, seq 4, fss false, suspend undefined.
	n, err = decodeSFUNotification(mustHex(t, "07 81 00 95 01 c0 04 c0 c0"), reg)
	if err != nil {
		t.Fatal(err)
	}
	if n.Type != sfuNotifSourcesUpdate || len(n.Sources) != 1 {
		t.Fatalf("sources notif = %+v", n)
	}
	s := n.Sources[0]
	if s.Slot != 0 || s.StreamID != "pat-0" || s.CompactID == nil || *s.CompactID != 1 || s.RTPTimestamp != nil ||
		s.SequenceNumber != 4 || s.FastScreenShare || s.Suspend != nil {
		t.Fatalf("source update = %+v", s)
	}
	if s.Stream == nil || s.Stream.ParticipantID != "u1125900244908947" || s.Stream.MediaType != SFUMediaCamera {
		t.Fatalf("source stream = %+v", s.Stream)
	}
	if !strings.Contains(n.String(), "pat-0<-u1125900244908947:sCAMERA seq=4") {
		t.Fatalf("String() = %q", n.String())
	}

	// Slot release: [nil, nil, 5, nil, nil]; rtp timestamp + suspend present on another.
	n, err = decodeSFUNotification(mustHex(t, "07 82 00 95 c0 c0 05 c0 c0 01 95 01 ce 80 00 00 01 06 c3 c2"), reg)
	if err != nil || len(n.Sources) != 2 {
		t.Fatalf("release notif = %+v err=%v", n, err)
	}
	if n.Sources[0].Stream != nil || n.Sources[0].CompactID != nil || n.Sources[0].SequenceNumber != 5 {
		t.Fatalf("released slot = %+v", n.Sources[0])
	}
	if s := n.Sources[1]; s.Slot != 1 || s.RTPTimestamp == nil || *s.RTPTimestamp != 0x80000001 || !s.FastScreenShare || s.Suspend == nil || *s.Suspend {
		t.Fatalf("slot 1 = %+v", s)
	}
	// Null sequenceNumber is an error (bundle: "unexpected null sequenceNumber").
	if _, err := decodeSFUNotification(mustHex(t, "07 81 00 95 01 c0 c0 c0 c0"), reg); err == nil {
		t.Fatal("null sequenceNumber must error")
	}

	// Other types: audio activity [0,1], speaker 1, video quality [1200, 640, 0], suspend suggest 300.
	n, err = decodeSFUNotification(mustHex(t, "02 92 00 01"), reg)
	if err != nil || len(n.Participants) != 2 || n.Participants[1].MediaType != SFUMediaCamera {
		t.Fatalf("audio activity = %+v err=%v", n, err)
	}
	n, err = decodeSFUNotification(mustHex(t, "03 01"), reg)
	if err != nil || len(n.Participants) != 1 || n.Participants[0].ParticipantID != "u1125900244908947" {
		t.Fatalf("speaker = %+v err=%v", n, err)
	}
	n, err = decodeSFUNotification(mustHex(t, "05 93 d1 04 b0 d1 02 80 00"), reg)
	if err != nil || n.VideoQuality == nil || n.VideoQuality.MaxBitrate != 1200 || n.VideoQuality.MaxDimension != 640 || n.VideoQuality.MediaType != SFUMediaCamera {
		t.Fatalf("video quality = %+v err=%v", n, err)
	}
	n, err = decodeSFUNotification(mustHex(t, "09 d1 01 2c"), reg)
	if err != nil || n.Bandwidth != 300 {
		t.Fatalf("suspend suggest = %+v err=%v", n, err)
	}
	if _, err := decodeSFUNotification(mustHex(t, "01 81 a1 78 00 ff"), reg); err == nil {
		t.Fatal("trailing bytes must error")
	}
	if _, err := decodeSFUNotification(nil, reg); err == nil {
		t.Fatal("empty frame must error")
	}
}

func TestMsgpackIntEncodingMatchesBundleF(t *testing.T) {
	cases := []struct {
		v    int64
		want string
	}{
		{0, "00"}, {127, "7f"}, {-1, "ff"}, {-31, "e1"}, {-32, "d0e0"}, {-128, "d080"},
		{128, "d10080"}, {320, "d10140"}, {32767, "d17fff"}, {32768, "d200008000"},
		{-40000, "d2ffff63c0"}, {1 << 31, "d30000000080000000"},
	}
	for _, c := range cases {
		w := &mpWriter{}
		w.putInt(c.v)
		if got := hex.EncodeToString(w.b); got != c.want {
			t.Errorf("putInt(%d) = %s, want %s", c.v, got, c.want)
		}
		r := &mpReader{b: w.b}
		if got, err := r.readInt(); err != nil || got != c.v {
			t.Errorf("readInt(%s) = %d, %v", c.want, got, err)
		}
	}
	// F_.dec also accepts the unsigned family and nil (-> 0).
	for s, want := range map[string]int64{"cc80": 128, "cd0140": 320, "ce00010000": 65536, "c0": 0} {
		r := &mpReader{b: mustHex(t, s)}
		if got, err := r.readInt(); err != nil || got != want {
			t.Errorf("readInt(%s) = %d, %v; want %d", s, got, err, want)
		}
	}
	// Strings: fixstr < 32, str8 otherwise (0xd9).
	w := &mpWriter{}
	w.putStr(strings.Repeat("a", 32))
	if w.b[0] != 0xd9 || w.b[1] != 32 {
		t.Errorf("str8 header = %x", w.b[:2])
	}
	w = &mpWriter{}
	w.putArrayHeader(16)
	if !bytes.Equal(w.b, []byte{0xdc, 0, 16}) {
		t.Errorf("array16 header = %x", w.b)
	}
}

func TestStreamDescRoundTrip(t *testing.T) {
	for _, s := range []string{"u1125900244908947:sCAMERA", "u1125900244960634", "g42:sSCREEN", "u7:d2:sSTREAM:mlive1"} {
		d, err := parseSFUStreamDesc(s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		if got := d.String(); got != s {
			t.Errorf("round trip %q -> %+v -> %q", s, d, got)
		}
	}
	d, err := parseSFUStreamDesc("u7:sBOGUS")
	if err != nil || d.MediaType != "" {
		t.Errorf("unknown media type must decode as empty: %+v %v", d, err)
	}
	if _, err := parseSFUStreamDesc("u7:x1"); err == nil {
		t.Error("unknown parameter must error")
	}
	if _, err := parseSFUStreamDesc(":sCAMERA"); err == nil {
		t.Error("empty participant must error")
	}
	if got := sfuCompositeUserID("u1"); got != "u1" {
		t.Errorf("already composite: %q", got)
	}
	if got := (SFUStreamDesc{ParticipantID: "u1", DeviceIdx: 3, MediaType: SFUMediaCamera}).String(); got != "u1:d3:sCAMERA" {
		t.Errorf("device idx: %q", got)
	}
}

func TestParseSFUSlotMap(t *testing.T) {
	// Excerpt of the captured SFU offer (D3.jsonl, t=65582).
	sdp := strings.Join([]string{
		"v=0", "a=ice-lite",
		"m=audio 9 UDP/TLS/RTP/SAVPF 111", "a=mid:0", "a=ssrc:3611711213 label:audio-mix",
		"m=application 9 UDP/DTLS/SCTP webrtc-datachannel", "a=mid:1",
		"m=video 9 UDP/TLS/RTP/SAVPF 100", "a=mid:3", "a=recvonly", "a=msid:pat-256 video-pat-256",
		"m=video 9 UDP/TLS/RTP/SAVPF 102", "a=mid:5", "a=sendonly", "a=msid:pat-0 video-pat-0",
		"a=ssrc-group:FID 3611711214 3611711215",
		"a=ssrc:3611711214 cname:x", "a=ssrc:3611711214 mslabel:pat-0", "a=ssrc:3611711214 label:video-pat-0",
		"a=ssrc:3611711215 mslabel:pat-0", "a=ssrc:3611711215 label:video-pat-0",
		"m=video 9 UDP/TLS/RTP/SAVPF 102", "a=mid:6", "a=ssrc:3611711216 label:video-pat-1", "a=ssrc:3611711217 label:video-pat-1",
	}, "\r\n") + "\r\n"
	slots := parseSFUSlotMap(sdp)
	if len(slots) != 3 {
		t.Fatalf("slots = %v", describeSFUSlots(slots))
	}
	if s := slots["pat-0"]; s == nil || s.Mid != "5" || len(s.SSRCs) != 2 || s.SSRCs[0] != 3611711214 || s.SSRCs[1] != 3611711215 {
		t.Fatalf("pat-0 = %+v", s)
	}
	if s := slots["pat-1"]; s == nil || s.Mid != "6" || len(s.SSRCs) != 2 {
		t.Fatalf("pat-1 = %+v", s)
	}
	if s := slots["pat-256"]; s == nil || s.Mid != "3" || len(s.SSRCs) != 0 {
		t.Fatalf("pat-256 (our producer slot) = %+v", s)
	}
	if got := sfuSlotForSSRC(slots, 3611711215); got == nil || got.StreamID != "pat-0" {
		t.Fatalf("slot for rtx ssrc = %+v", got)
	}
	if got := sfuSlotForSSRC(slots, 1); got != nil {
		t.Fatalf("unknown ssrc = %+v", got)
	}
	if got := describeSFUSlots(slots); !strings.HasPrefix(got, "pat-0:mid=5 ssrcs=[3611711214 3611711215] pat-1:") {
		t.Fatalf("describe = %q", got)
	}
}

func TestJSONIDString(t *testing.T) {
	if got := jsonIDString(float64(1125900244908947)); got != "1125900244908947" {
		t.Errorf("float64 id = %q", got)
	}
	if got := jsonIDString("u1"); got != "u1" {
		t.Errorf("string id = %q", got)
	}
	if got := jsonIDString(nil); got != "" {
		t.Errorf("nil id = %q", got)
	}
}
