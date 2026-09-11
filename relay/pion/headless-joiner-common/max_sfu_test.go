package joiner

import "testing"

func TestExtractSSRCs(t *testing.T) {
	sdp := "v=0\r\n" +
		"a=ssrc:11111 cname:abc\r\n" +
		"a=ssrc:11111 msid:x y\r\n" + // duplicate id -> once
		"a=ssrc:22222 cname:def\r\n" +
		"a=ssrc:\r\n" + // empty -> skipped
		"m=video 9 UDP/TLS/RTP/SAVPF 98\r\n"
	got := extractSSRCs(sdp)
	if len(got) != 2 || got[0] != "11111" || got[1] != "22222" {
		t.Fatalf("extractSSRCs = %v, want [11111 22222]", got)
	}
	if len(extractSSRCs("m=video 9 UDP 98\r\n")) != 0 {
		t.Error("expected no ssrcs when none present")
	}
}

func TestParseSFUDescription(t *testing.T) {
	// raw string -> offer
	if d, ok := parseSFUDescription("v=0\r\n"); !ok || d.SDP != "v=0\r\n" || d.Type.String() != "offer" {
		t.Errorf("string case: %+v ok=%v", d, ok)
	}
	// {type,sdp} object
	if d, ok := parseSFUDescription(map[string]interface{}{"type": "offer", "sdp": "v=0\r\n"}); !ok || d.SDP != "v=0\r\n" {
		t.Errorf("object case: %+v ok=%v", d, ok)
	}
	// empty / wrong type -> not ok
	if _, ok := parseSFUDescription(""); ok {
		t.Error("empty string should be not-ok")
	}
	if _, ok := parseSFUDescription(map[string]interface{}{"sdp": ""}); ok {
		t.Error("empty sdp should be not-ok")
	}
	if _, ok := parseSFUDescription(42); ok {
		t.Error("non-string/map should be not-ok")
	}
}

func TestSFUCapabilitiesShape(t *testing.T) {
	h := &MaxHeadlessJoiner{}
	c := h.sfuCapabilities()
	// The server rejects the hex bitmask; it wants this structured object with
	// exactly one advertised video track and unifiedPlan.
	if c["videoTracksCount"] != 1 {
		t.Errorf("videoTracksCount = %v, want 1", c["videoTracksCount"])
	}
	if c["unifiedPlan"] != true {
		t.Errorf("unifiedPlan = %v, want true", c["unifiedPlan"])
	}
	for _, k := range []string{"estimatedPerformanceIndex", "audioMix", "onDemandTracks", "singleSession", "red"} {
		if _, ok := c[k]; !ok {
			t.Errorf("capabilities missing required key %q", k)
		}
	}
}
