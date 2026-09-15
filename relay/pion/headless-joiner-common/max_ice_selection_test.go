package joiner

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

// relayAcceptanceMinWaitOf reads back the (unexported) relay acceptance wait a
// SettingEngine carries. reflect can read unexported fields as long as we never
// ask for Interface()/Set. Returns ok=false when the field cannot be found,
// e.g. after a pion/webrtc bump renames it — the caller then skips rather than
// failing on an unrelated dependency change.
func relayAcceptanceMinWaitOf(se *webrtc.SettingEngine) (d time.Duration, set, ok bool) {
	timeout := reflect.ValueOf(se).Elem().FieldByName("timeout")
	if !timeout.IsValid() || timeout.Kind() != reflect.Struct {
		return 0, false, false
	}
	f := timeout.FieldByName("ICERelayAcceptanceMinWait")
	if !f.IsValid() || f.Kind() != reflect.Ptr {
		return 0, false, false
	}
	if f.IsNil() {
		return 0, false, true
	}
	return time.Duration(f.Elem().Int()), true, true
}

// maxBindingRequestsOf is the binding-request-budget counterpart of
// relayAcceptanceMinWaitOf. Same reflect caveats.
func maxBindingRequestsOf(se *webrtc.SettingEngine) (n uint16, set, ok bool) {
	f := reflect.ValueOf(se).Elem().FieldByName("iceMaxBindingRequests")
	if !f.IsValid() || f.Kind() != reflect.Ptr {
		return 0, false, false
	}
	if f.IsNil() {
		return 0, false, true
	}
	return uint16(f.Elem().Uint()), true, true
}

// TestApplyDirectICESelectionTuning pins what the DIRECT path puts on the
// SettingEngine — and, just as importantly, what it must NOT put there.
//
// The relay acceptance wait must stay unset. Fork PR #24 set it to 7 s on a
// theory that measurement disproved (see applyDirectICESelectionTuning's
// comment); with the fork's aggressive nomination it never influenced
// selection, and leaving a large value behind would only stall the
// regular-nomination fallback paths. The relay bias now lives in the vendored
// pion fork (relayHeadStartGrace), which is also where the relay-only
// carve-out is enforced.
func TestApplyDirectICESelectionTuning(t *testing.T) {
	t.Run("sets the binding-request budget", func(t *testing.T) {
		se := &webrtc.SettingEngine{}
		if !applyDirectICESelectionTuning(se) {
			t.Fatal("expected tuning to be applied")
		}
		got, set, ok := maxBindingRequestsOf(se)
		if !ok {
			t.Skip("SettingEngine.iceMaxBindingRequests not introspectable in this pion/webrtc version")
		}
		if !set {
			t.Fatal("max binding requests was not set on the SettingEngine")
		}
		if got != maxDirectICEMaxBindingRequests {
			t.Fatalf("max binding requests = %d, want %d", got, maxDirectICEMaxBindingRequests)
		}
	})

	t.Run("leaves the relay acceptance wait at pion's default", func(t *testing.T) {
		se := &webrtc.SettingEngine{}
		applyDirectICESelectionTuning(se)
		_, set, ok := relayAcceptanceMinWaitOf(se)
		if ok && set {
			t.Fatal("relay acceptance min wait must stay unset: it is inert under aggressive " +
				"nomination and only slows pion's fallback paths")
		}
	})

	t.Run("nil engine", func(t *testing.T) {
		if applyDirectICESelectionTuning(nil) {
			t.Fatal("expected false for a nil SettingEngine")
		}
	})
}

// TestMaxDirectICEMaxBindingRequestsBounds guards the budget against being
// trimmed back toward pion's default: at the 200 ms check interval it has to
// keep a pair in the checklist for several seconds, long enough for a peer
// that gathered late to answer.
func TestMaxDirectICEMaxBindingRequestsBounds(t *testing.T) {
	const checkInterval = 200 * time.Millisecond
	pingWindow := time.Duration(maxDirectICEMaxBindingRequests) * checkInterval
	if pingWindow < 5*time.Second {
		t.Fatalf("binding-request budget covers only %s of checking", pingWindow)
	}
	if maxDirectICEMaxBindingRequests != 50 {
		t.Fatalf("budget = %d, want 50 to match initPCSFU", maxDirectICEMaxBindingRequests)
	}
}

func pairStats(id string, nominated bool, state webrtc.StatsICECandidatePairState, local, remote string, bytes uint64) webrtc.ICECandidatePairStats {
	return webrtc.ICECandidatePairStats{
		Type:              webrtc.StatsTypeCandidatePair,
		ID:                id,
		State:             state,
		Nominated:         nominated,
		LocalCandidateID:  local,
		RemoteCandidateID: remote,
		BytesSent:         bytes,
	}
}

func candStats(id string, typ webrtc.StatsType, candType webrtc.ICECandidateType) webrtc.ICECandidateStats {
	return webrtc.ICECandidateStats{Type: typ, ID: id, CandidateType: candType}
}

func reportOf(stats ...webrtc.Stats) webrtc.StatsReport {
	r := webrtc.StatsReport{}
	for i, s := range stats {
		switch v := s.(type) {
		case webrtc.ICECandidatePairStats:
			r[v.ID] = v
		case webrtc.ICECandidateStats:
			r[v.ID] = v
		default:
			r[fmt.Sprintf("other-%d", i)] = v
		}
	}
	return r
}

func TestSelectedCandidatePairTypes(t *testing.T) {
	cases := []struct {
		name       string
		report     webrtc.StatsReport
		wantOK     bool
		wantLocal  string
		wantRemote string
	}{
		{
			name: "nominated host/srflx pair",
			report: reportOf(
				pairStats("p1", true, webrtc.StatsICECandidatePairStateSucceeded, "lc1", "rc1", 10),
				candStats("lc1", webrtc.StatsTypeLocalCandidate, webrtc.ICECandidateTypeHost),
				candStats("rc1", webrtc.StatsTypeRemoteCandidate, webrtc.ICECandidateTypeSrflx),
			),
			wantOK: true, wantLocal: "host", wantRemote: "srflx",
		},
		{
			name: "relay pair is reported as relay",
			report: reportOf(
				pairStats("p1", true, webrtc.StatsICECandidatePairStateSucceeded, "lc1", "rc1", 10),
				candStats("lc1", webrtc.StatsTypeLocalCandidate, webrtc.ICECandidateTypeRelay),
				candStats("rc1", webrtc.StatsTypeRemoteCandidate, webrtc.ICECandidateTypeRelay),
			),
			wantOK: true, wantLocal: "relay", wantRemote: "relay",
		},
		{
			name: "ignores succeeded-but-not-nominated and nominated-but-failed pairs",
			report: reportOf(
				pairStats("p0", false, webrtc.StatsICECandidatePairStateSucceeded, "lc0", "rc0", 999),
				pairStats("p2", true, webrtc.StatsICECandidatePairStateFailed, "lc2", "rc2", 999),
				pairStats("p1", true, webrtc.StatsICECandidatePairStateSucceeded, "lc1", "rc1", 1),
				candStats("lc0", webrtc.StatsTypeLocalCandidate, webrtc.ICECandidateTypeRelay),
				candStats("rc0", webrtc.StatsTypeRemoteCandidate, webrtc.ICECandidateTypeRelay),
				candStats("lc2", webrtc.StatsTypeLocalCandidate, webrtc.ICECandidateTypeRelay),
				candStats("rc2", webrtc.StatsTypeRemoteCandidate, webrtc.ICECandidateTypeRelay),
				candStats("lc1", webrtc.StatsTypeLocalCandidate, webrtc.ICECandidateTypeHost),
				candStats("rc1", webrtc.StatsTypeRemoteCandidate, webrtc.ICECandidateTypeHost),
			),
			wantOK: true, wantLocal: "host", wantRemote: "host",
		},
		{
			name: "two nominated pairs: the busiest one wins, deterministically",
			report: reportOf(
				pairStats("pa", true, webrtc.StatsICECandidatePairStateSucceeded, "lc1", "rc1", 5),
				pairStats("pb", true, webrtc.StatsICECandidatePairStateSucceeded, "lc2", "rc2", 500),
				candStats("lc1", webrtc.StatsTypeLocalCandidate, webrtc.ICECandidateTypeRelay),
				candStats("rc1", webrtc.StatsTypeRemoteCandidate, webrtc.ICECandidateTypeRelay),
				candStats("lc2", webrtc.StatsTypeLocalCandidate, webrtc.ICECandidateTypeSrflx),
				candStats("rc2", webrtc.StatsTypeRemoteCandidate, webrtc.ICECandidateTypeSrflx),
			),
			wantOK: true, wantLocal: "srflx", wantRemote: "srflx",
		},
		{
			name: "remote candidate stats missing",
			report: reportOf(
				pairStats("p1", true, webrtc.StatsICECandidatePairStateSucceeded, "lc1", "rc1", 10),
				candStats("lc1", webrtc.StatsTypeLocalCandidate, webrtc.ICECandidateTypePrflx),
			),
			wantOK: true, wantLocal: "prflx", wantRemote: "unknown",
		},
		{
			name: "local candidate stats missing",
			report: reportOf(
				pairStats("p1", true, webrtc.StatsICECandidatePairStateSucceeded, "lc1", "rc1", 10),
				candStats("rc1", webrtc.StatsTypeRemoteCandidate, webrtc.ICECandidateTypeHost),
			),
			wantOK: false,
		},
		{name: "empty report", report: webrtc.StatsReport{}, wantOK: false},
		{name: "nil report", report: nil, wantOK: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// StatsReport is a map: run it repeatedly so a result that only
			// holds for one iteration order cannot pass.
			for i := 0; i < 20; i++ {
				got, ok := selectedCandidatePairTypes(tc.report)
				if ok != tc.wantOK {
					t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
				}
				if !tc.wantOK {
					if got != (SelectedCandidatePair{}) {
						t.Fatalf("expected the zero pair when ok is false, got %+v", got)
					}
					continue
				}
				if got.Local != tc.wantLocal || got.Remote != tc.wantRemote {
					t.Fatalf("pair = %+v, want local=%s remote=%s", got, tc.wantLocal, tc.wantRemote)
				}
			}
		})
	}
}

func TestSelectedCandidatePairString(t *testing.T) {
	got := SelectedCandidatePair{Local: "host", Remote: "relay"}.String()
	if got != "local=host remote=relay" {
		t.Fatalf("String() = %q", got)
	}
}

// TestNoteSelectedCandidatePairLatchesOnce covers what the operator actually
// consumes: one countable log line, a transcript line, and a latched value on
// the joiner that a later ICE/PC "connected" transition cannot overwrite.
func TestNoteSelectedCandidatePairLatchesOnce(t *testing.T) {
	h := &MaxHeadlessJoiner{}
	var buf bytes.Buffer
	h.Transcript = NewJSONLTranscript(&buf, "pion-offerer")
	var lines []string
	h.logFn = h.logAndTranscript(func(format string, args ...any) {
		lines = append(lines, fmt.Sprintf(format, args...))
	})

	if _, ok := h.SelectedCandidatePair(); ok {
		t.Fatal("no pair should be reported before ICE connects")
	}

	// Nothing to latch yet: a report without a nominated pair is a no-op.
	h.noteSelectedCandidatePair(webrtc.StatsReport{})
	if _, ok := h.SelectedCandidatePair(); ok {
		t.Fatal("an empty report must not latch a pair")
	}
	if len(lines) != 0 {
		t.Fatalf("unexpected log lines before a pair exists: %v", lines)
	}

	relay := reportOf(
		pairStats("p1", true, webrtc.StatsICECandidatePairStateSucceeded, "lc1", "rc1", 10),
		candStats("lc1", webrtc.StatsTypeLocalCandidate, webrtc.ICECandidateTypeRelay),
		candStats("rc1", webrtc.StatsTypeRemoteCandidate, webrtc.ICECandidateTypeRelay),
	)
	host := reportOf(
		pairStats("p2", true, webrtc.StatsICECandidatePairStateSucceeded, "lc2", "rc2", 10),
		candStats("lc2", webrtc.StatsTypeLocalCandidate, webrtc.ICECandidateTypeHost),
		candStats("rc2", webrtc.StatsTypeRemoteCandidate, webrtc.ICECandidateTypeHost),
	)

	h.noteSelectedCandidatePair(relay)
	h.noteSelectedCandidatePair(host) // second "connected" transition: must not overwrite

	got, ok := h.SelectedCandidatePair()
	if !ok {
		t.Fatal("expected a latched pair")
	}
	if got.Local != "relay" || got.Remote != "relay" {
		t.Fatalf("latched pair = %+v, want the first one seen (relay/relay)", got)
	}

	want := "max-joiner: selected candidate pair local=relay remote=relay"
	var matched int
	for _, l := range lines {
		if strings.Contains(l, "selected candidate pair") {
			matched++
			if l != want {
				t.Fatalf("log line = %q, want %q", l, want)
			}
		}
	}
	if matched != 1 {
		t.Fatalf("expected exactly 1 selected-candidate-pair log line, got %d: %v", matched, lines)
	}

	transcript := buf.String()
	if !strings.Contains(transcript, `"what":"iceSelectedPair"`) ||
		!strings.Contains(transcript, `"value":"local=relay remote=relay"`) {
		t.Fatalf("transcript missing the iceSelectedPair state line: %s", transcript)
	}
	if strings.Count(transcript, `"iceSelectedPair"`) != 1 {
		t.Fatalf("expected exactly one iceSelectedPair transcript line: %s", transcript)
	}
}

// TestRecordSelectedCandidatePairNilPC makes sure the "connected" hooks are
// safe to call before a PeerConnection exists.
func TestRecordSelectedCandidatePairNilPC(t *testing.T) {
	h := &MaxHeadlessJoiner{}
	h.logFn = h.logAndTranscript(func(string, ...any) {})
	h.recordSelectedCandidatePair(nil)
	if _, ok := h.SelectedCandidatePair(); ok {
		t.Fatal("nil PeerConnection must not latch a pair")
	}
}
