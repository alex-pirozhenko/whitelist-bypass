// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// RELAY HEAD START (letmeout fork): tests for the grace window that keeps a
// relay-local pair from winning the aggressive-nomination race outright.

package ice

import (
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/stretchr/testify/require"
)

func TestRelayCheckDeferred(t *testing.T) {
	cases := []struct {
		name         string
		localType    CandidateType
		sinceStart   time.Duration
		relayOnly    bool
		pairSelected bool
		want         bool
	}{
		{
			name: "relay inside the grace is deferred",
			// The measured relay wins clustered at 338-546ms; that is exactly
			// the region the grace has to cover.
			localType: CandidateTypeRelay, sinceStart: 400 * time.Millisecond, want: true,
		},
		{
			name:      "relay at the slowest measured win is still deferred",
			localType: CandidateTypeRelay, sinceStart: 546 * time.Millisecond, want: true,
		},
		{
			name:      "relay just before the grace expires is deferred",
			localType: CandidateTypeRelay, sinceStart: relayHeadStartGrace - time.Millisecond, want: true,
		},
		{
			name:      "relay exactly at the grace boundary is not deferred",
			localType: CandidateTypeRelay, sinceStart: relayHeadStartGrace, want: false,
		},
		{
			name:      "relay well past the grace is not deferred",
			localType: CandidateTypeRelay, sinceStart: 10 * time.Second, want: false,
		},
		{
			name:      "relay-only candidate set is never deferred",
			localType: CandidateTypeRelay, sinceStart: time.Millisecond, relayOnly: true, want: false,
		},
		{
			name:      "keepalive on an already-selected relay pair is never deferred",
			localType: CandidateTypeRelay, sinceStart: time.Millisecond, pairSelected: true, want: false,
		},
		{
			name:      "host is never deferred",
			localType: CandidateTypeHost, sinceStart: time.Millisecond, want: false,
		},
		{
			name:      "srflx is never deferred",
			localType: CandidateTypeServerReflexive, sinceStart: time.Millisecond, want: false,
		},
		{
			name:      "prflx is never deferred",
			localType: CandidateTypePeerReflexive, sinceStart: time.Millisecond, want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := relayCheckDeferred(tc.localType, tc.sinceStart, tc.relayOnly, tc.pairSelected)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestRelayHeadStartGraceBounds pins the two ends of the tradeoff the constant
// encodes against the 2026-09-15 measurement.
func TestRelayHeadStartGraceBounds(t *testing.T) {
	// Must outlast the slowest observed relay win (546ms), otherwise it would
	// not have prevented the relay selections that motivated it.
	require.Greater(t, relayHeadStartGrace, 546*time.Millisecond)
	// Must stay well inside ICE's own 5s disconnected / 25s failed budget: on
	// a relay-only-in-practice network the grace is pure added connect time.
	require.Less(t, relayHeadStartGrace, 2*time.Second)
}

func TestAgentIsRelayOnly(t *testing.T) {
	require.True(t, (&Agent{candidateTypes: []CandidateType{CandidateTypeRelay}}).isRelayOnly())
	require.False(t, (&Agent{candidateTypes: defaultCandidateTypes()}).isRelayOnly())
	require.False(t, (&Agent{candidateTypes: nil}).isRelayOnly())
	require.False(t, (&Agent{
		candidateTypes: []CandidateType{CandidateTypeServerReflexive, CandidateTypeRelay},
	}).isRelayOnly())
	require.False(t, (&Agent{candidateTypes: []CandidateType{CandidateTypeHost}}).isRelayOnly())
}

func headStartTestCandidate(t *testing.T, typ CandidateType) Candidate {
	t.Helper()

	switch typ {
	case CandidateTypeHost:
		c, err := NewCandidateHost(&CandidateHostConfig{
			Network: "udp", Address: "192.0.2.1", Port: 4242, Component: 1,
		})
		require.NoError(t, err)

		return c
	case CandidateTypeRelay:
		c, err := NewCandidateRelay(&CandidateRelayConfig{
			Network: "udp", Address: "198.51.100.1", Port: 4242, Component: 1,
			RelAddr: "192.0.2.1", RelPort: 4242,
		})
		require.NoError(t, err)

		return c
	case CandidateTypeServerReflexive, CandidateTypePeerReflexive, CandidateTypeUnspecified:
	}
	t.Fatalf("unsupported candidate type %s", typ)

	return nil
}

// TestDeferRelayCheckAgentState covers the wiring from live agent state into
// relayCheckDeferred, including the two carve-outs that must make it a no-op.
func TestDeferRelayCheckAgentState(t *testing.T) {
	relay := headStartTestCandidate(t, CandidateTypeRelay)
	host := headStartTestCandidate(t, CandidateTypeHost)

	newSelector := func(agent *Agent) *controllingSelector {
		return &controllingSelector{agent: agent, log: logging.NewDefaultLoggerFactory().NewLogger("ice")}
	}

	t.Run("zero start time fails open", func(t *testing.T) {
		sel := newSelector(&Agent{candidateTypes: defaultCandidateTypes()})
		require.False(t, sel.deferRelayCheck(relay), "no Start() means no window to be inside of")
	})

	t.Run("policy all defers relay but not host", func(t *testing.T) {
		sel := newSelector(&Agent{candidateTypes: defaultCandidateTypes()})
		sel.Start()
		require.True(t, sel.deferRelayCheck(relay))
		require.False(t, sel.deferRelayCheck(host))
	})

	t.Run("relay-only policy is a no-op", func(t *testing.T) {
		sel := newSelector(&Agent{candidateTypes: []CandidateType{CandidateTypeRelay}})
		sel.Start()
		require.False(t, sel.deferRelayCheck(relay),
			"iceTransportPolicy=relay: a relay pair is the only thing that can ever be selected")
	})

	t.Run("stops gating once the grace expires", func(t *testing.T) {
		sel := newSelector(&Agent{candidateTypes: defaultCandidateTypes()})
		sel.Start()
		require.True(t, sel.deferRelayCheck(relay))
		// Rewind startTime rather than sleeping the full grace.
		sel.startTime = sel.startTime.Add(-relayHeadStartGrace)
		require.False(t, sel.deferRelayCheck(relay))
	})

	t.Run("already-selected pair is not gated", func(t *testing.T) {
		agent := &Agent{candidateTypes: defaultCandidateTypes()}
		sel := newSelector(agent)
		sel.Start()
		require.True(t, sel.deferRelayCheck(relay))
		agent.selectedPair.Store(&CandidatePair{Local: relay, Remote: relay})
		require.False(t, sel.deferRelayCheck(relay), "keepalive checks must never be suppressed")
	})
}

// TestPingAllCandidatesRelayBudget is the reason the grace is also consulted
// in pingAllCandidates: a deferred check must not consume the pair's
// binding-request budget, and the pair must stay in the checklist so it is
// retried once the grace expires.
//
// The pairs here have no sockets, so the test is arranged so that no check is
// ever actually put on the wire: every pair that is NOT skipped is already
// over its binding-request budget, which makes pingAllCandidates retire it
// instead of sending. "Skipped" and "not skipped" are therefore
// distinguishable as InProgress vs Failed, with no I/O either way.
func TestPingAllCandidatesRelayBudget(t *testing.T) {
	relay := headStartTestCandidate(t, CandidateTypeRelay)
	host := headStartTestCandidate(t, CandidateTypeHost)

	const maxBindingRequests uint16 = 7

	newAgent := func(candidateTypes []CandidateType) (
		*Agent, *controllingSelector, *CandidatePair, *CandidatePair,
	) {
		agent := &Agent{
			candidateTypes:     candidateTypes,
			maxBindingRequests: maxBindingRequests,
			log:                logging.NewDefaultLoggerFactory().NewLogger("ice"),
		}
		relayPair := &CandidatePair{
			Local: relay, Remote: host,
			state: CandidatePairStateWaiting, bindingRequestCount: maxBindingRequests + 1,
		}
		hostPair := &CandidatePair{
			Local: host, Remote: host,
			state: CandidatePairStateWaiting, bindingRequestCount: maxBindingRequests + 1,
		}
		agent.checklist = []*CandidatePair{relayPair, hostPair}
		sel := &controllingSelector{agent: agent, log: agent.log}
		sel.Start()
		agent.selector = sel

		return agent, sel, relayPair, hostPair
	}

	t.Run("policy all: relay is skipped, host is not", func(t *testing.T) {
		agent, _, relayPair, hostPair := newAgent(defaultCandidateTypes())
		for i := 0; i < 4; i++ {
			agent.pingAllCandidates()
		}
		require.Equal(t, CandidatePairStateInProgress, relayPair.state,
			"a deferred relay pair must stay in the checklist, not be retired")
		require.Equal(t, maxBindingRequests+1, relayPair.bindingRequestCount,
			"a deferred relay check must not be charged to the pair's budget")
		require.Equal(t, CandidatePairStateFailed, hostPair.state,
			"non-relay pairs must go through pingAllCandidates unchanged")
	})

	t.Run("policy all: gating stops when the grace expires", func(t *testing.T) {
		agent, sel, relayPair, _ := newAgent(defaultCandidateTypes())
		agent.pingAllCandidates()
		require.Equal(t, CandidatePairStateInProgress, relayPair.state)

		// Rewind startTime past the grace rather than sleeping it out.
		sel.startTime = sel.startTime.Add(-relayHeadStartGrace)
		agent.pingAllCandidates()
		require.Equal(t, CandidatePairStateFailed, relayPair.state,
			"after the grace the relay pair must take exactly the path it takes today")
	})

	t.Run("relay-only policy: relay is never skipped", func(t *testing.T) {
		agent, _, relayPair, _ := newAgent([]CandidateType{CandidateTypeRelay})
		agent.pingAllCandidates()
		require.Equal(t, CandidatePairStateFailed, relayPair.state,
			"iceTransportPolicy=relay must be completely unaffected by the grace")
	})
}

// TestControllingPingCandidateDefersRelay exercises the patch site itself. The
// agent has no sockets, so a check that were actually built and sent would
// fault; the relay check returning quietly inside the grace is the assertion.
func TestControllingPingCandidateDefersRelay(t *testing.T) {
	relay := headStartTestCandidate(t, CandidateTypeRelay)
	host := headStartTestCandidate(t, CandidateTypeHost)

	agent := &Agent{
		candidateTypes: defaultCandidateTypes(),
		log:            logging.NewDefaultLoggerFactory().NewLogger("ice"),
		remoteUfrag:    "rufrag", localUfrag: "lufrag", remotePwd: "remotepwdremotepwd",
	}
	sel := &controllingSelector{agent: agent, log: agent.log}
	sel.Start()

	sel.PingCandidate(relay, host)

	require.True(t, sel.deferRelayCheck(relay))
	require.False(t, sel.deferRelayCheck(host))
}
