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

// TestApplyDirectICESelectionTuningPolicyGate pins the one decision that is
// easy to get wrong: the relay wait must be applied for iceTransportPolicy
// "all" and must NOT be applied for "relay", where relay is the only candidate
// type and delaying its nomination would only stall the connection.
func TestApplyDirectICESelectionTuningPolicyGate(t *testing.T) {
	t.Run("policy all applies the wait", func(t *testing.T) {
		se := &webrtc.SettingEngine{}
		if !applyDirectICESelectionTuning(se, webrtc.ICETransportPolicyAll) {
			t.Fatal("expected tuning to be applied for policy=all")
		}
		got, set, ok := relayAcceptanceMinWaitOf(se)
		if !ok {
			t.Skip("SettingEngine.timeout.ICERelayAcceptanceMinWait not introspectable in this pion/webrtc version")
		}
		if !set {
			t.Fatal("relay acceptance min wait was not set on the SettingEngine")
		}
		if got != maxRelayAcceptanceMinWait {
			t.Fatalf("relay acceptance min wait = %s, want %s", got, maxRelayAcceptanceMinWait)
		}
	})

	t.Run("policy relay leaves pion's relay-only default alone", func(t *testing.T) {
		se := &webrtc.SettingEngine{}
		if applyDirectICESelectionTuning(se, webrtc.ICETransportPolicyRelay) {
			t.Fatal("expected tuning to be skipped for policy=relay")
		}
		_, set, ok := relayAcceptanceMinWaitOf(se)
		if ok && set {
			t.Fatal("relay acceptance min wait must stay unset for policy=relay")
		}
	})

	t.Run("nil engine", func(t *testing.T) {
		if applyDirectICESelectionTuning(nil, webrtc.ICETransportPolicyAll) {
			t.Fatal("expected false for a nil SettingEngine")
		}
	})
}

// TestMaxRelayAcceptanceMinWaitBounds guards the two ends of the tradeoff the
// constant encodes: long enough to outlast pion's 2 s default (the window that
// produced the relay latch), short enough to stay inside ICE's 30 s
// disconnected+failed budget, and covered by the binding-request budget so the
// host/srflx pairs are still being pinged when the wait expires.
func TestMaxRelayAcceptanceMinWaitBounds(t *testing.T) {
	if maxRelayAcceptanceMinWait <= 2*time.Second {
		t.Fatalf("relay wait %s does not extend pion's 2s default", maxRelayAcceptanceMinWait)
	}
	if maxRelayAcceptanceMinWait >= 30*time.Second {
		t.Fatalf("relay wait %s exceeds ICE's 30s failure budget", maxRelayAcceptanceMinWait)
	}
	// pion pings every 200ms (defaultCheckInterval), so the budget covers
	// maxDirectICEMaxBindingRequests*200ms before a pair is retired.
	pingWindow := time.Duration(maxDirectICEMaxBindingRequests) * 200 * time.Millisecond
	if pingWindow <= maxRelayAcceptanceMinWait {
		t.Fatalf("binding-request budget covers only %s, which expires before the %s relay wait",
			pingWindow, maxRelayAcceptanceMinWait)
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
