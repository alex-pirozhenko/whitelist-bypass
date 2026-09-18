package joiner

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

// The ICE server set from the real 2026-09-18 02:54Z device capture: one
// hostname that resolves instantly (stun.rtc.yandex.net) and one that the
// device's resolver stalls on, named by four separate URLs across four
// servers (turn.tel.yandex.net).
const (
	tmFastICEHost  = "stun.rtc.yandex.net"
	tmFastICEIP    = "213.180.205.180"
	tmStallICEHost = "turn.tel.yandex.net"
	tmStallICEIP   = "77.88.7.55"
)

func tmServerHelloFixture() map[string]interface{} {
	raw := `{
	  "rtcConfiguration": {
	    "iceServers": [
	      {"urls": ["stun:turn.tel.yandex.net", "stun:stun.rtc.yandex.net"]},
	      {"urls": ["turn:turn.tel.yandex.net:443"], "username": "u", "credential": "c"},
	      {"urls": ["turn:turn.tel.yandex.net:443"], "username": "u", "credential": "c"},
	      {"urls": ["turn:turn.tel.yandex.net:443?transport=tcp"], "username": "u", "credential": "c"}
	    ]
	  }
	}`
	var sh map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &sh); err != nil {
		panic(err)
	}
	return sh
}

// fakeICEResolver counts calls per host and can be told to stall or fail on a
// given host, standing in for the device's platform resolver.
type fakeICEResolver struct {
	mu     sync.Mutex
	calls  map[string]int
	stall  map[string]time.Duration
	fail   map[string]bool
	answer map[string]string
}

func newFakeICEResolver() *fakeICEResolver {
	return &fakeICEResolver{
		calls:  map[string]int{},
		stall:  map[string]time.Duration{},
		fail:   map[string]bool{},
		answer: map[string]string{},
	}
}

func (f *fakeICEResolver) resolve(host string) (string, error) {
	f.mu.Lock()
	f.calls[host]++
	stall, fail, answer := f.stall[host], f.fail[host], f.answer[host]
	f.mu.Unlock()
	if stall > 0 {
		time.Sleep(stall)
	}
	if fail {
		return "", fmt.Errorf("lookup %s: i/o timeout", host)
	}
	if answer == "" {
		return "", fmt.Errorf("no addresses for %s", host)
	}
	return answer, nil
}

func (f *fakeICEResolver) callCount(host string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[host]
}

func newTelemostTestJoiner(resolve ResolveFunc) *TelemostHeadlessJoiner {
	return NewTelemostHeadlessJoiner(
		func(string, ...any) {},
		resolve,
		stubStatusEmitter{},
		nil,
		stubMaxAddTracks,
		stubMaxReadTrack,
	)
}

func iceURLsOf(j *TelemostHeadlessJoiner) []string {
	var urls []string
	for _, s := range j.iceServers {
		urls = append(urls, s.URLs...)
	}
	return urls
}

// TestTelemostICEResolveStallDoesNotDelayPeerConnections is the regression
// test for letmeout#187: a resolver that stalls 5s on the TURN hostname used
// to push PeerConnection creation 20.1s past serverHello (5s x 4 URLs,
// serially, with no negative caching), well past the client's 15s
// per-provider readiness deadline. The whole serverHello -> PCs path must now
// complete inside ~2s, and the stalled host must be left as a hostname URL
// for pion to resolve lazily.
func TestTelemostICEResolveStallDoesNotDelayPeerConnections(t *testing.T) {
	f := newFakeICEResolver()
	f.answer[tmFastICEHost] = tmFastICEIP
	f.stall[tmStallICEHost] = 5 * time.Second
	f.answer[tmStallICEHost] = tmStallICEIP

	j := newTelemostTestJoiner(f.resolve)
	t.Cleanup(j.Close)

	raw, err := json.Marshal(map[string]interface{}{
		"uid":         "",
		"serverHello": tmServerHelloFixture(),
	})
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	j.handleMessage(raw)
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("serverHello handling took %s, want <= 2s (15s provider deadline)", elapsed)
	}
	if j.subPC == nil || j.pubPC == nil {
		t.Fatalf("PeerConnections not created: subPC=%v pubPC=%v", j.subPC, j.pubPC)
	}
	if len(j.iceServers) != 4 {
		t.Fatalf("got %d ICE servers, want 4", len(j.iceServers))
	}

	urls := iceURLsOf(j)
	var sawStallHostname, sawFastIP bool
	for _, u := range urls {
		if u == "stun:"+tmStallICEHost || u == "turn:"+tmStallICEHost+":443" || u == "turn:"+tmStallICEHost+":443?transport=tcp" {
			sawStallHostname = true
		}
		if u == "stun:"+tmFastICEIP {
			sawFastIP = true
		}
		if u == "stun:"+tmStallICEIP || u == "turn:"+tmStallICEIP+":443" {
			t.Fatalf("stalled host was substituted anyway: %v", urls)
		}
	}
	if !sawStallHostname {
		t.Fatalf("stalled TURN host did not survive as a hostname URL: %v", urls)
	}
	if !sawFastIP {
		t.Fatalf("fast host was not substituted for its IP: %v", urls)
	}

	// One lookup per host, not one per URL: the four turn.tel.yandex.net URLs
	// must share a single in-flight resolution.
	if n := f.callCount(tmStallICEHost); n != 1 {
		t.Fatalf("resolved %s %d times, want 1 (once per host, not per URL)", tmStallICEHost, n)
	}
	if n := f.callCount(tmFastICEHost); n != 1 {
		t.Fatalf("resolved %s %d times, want 1", tmFastICEHost, n)
	}
}

// TestTelemostICEResolveFailureKeepsHostnameURL proves an outright resolver
// failure is non-fatal and leaves every URL byte-identical to what the SFU
// sent, so pion can still resolve it at gathering time.
func TestTelemostICEResolveFailureKeepsHostnameURL(t *testing.T) {
	f := newFakeICEResolver()
	f.fail[tmFastICEHost] = true
	f.fail[tmStallICEHost] = true

	j := newTelemostTestJoiner(f.resolve)
	t.Cleanup(j.Close)

	j.parseICEServersFromHello(tmServerHelloFixture())

	want := []string{
		"stun:" + tmStallICEHost,
		"stun:" + tmFastICEHost,
		"turn:" + tmStallICEHost + ":443",
		"turn:" + tmStallICEHost + ":443",
		"turn:" + tmStallICEHost + ":443?transport=tcp",
	}
	got := iceURLsOf(j)
	if len(got) != len(want) {
		t.Fatalf("got %d URLs %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("URL %d = %q, want %q (failed resolution must not rewrite it)", i, got[i], want[i])
		}
	}
	if j.iceServers[1].Username != "u" || j.iceServers[1].Credential != "c" {
		t.Fatalf("TURN credentials lost: %+v", j.iceServers[1])
	}
}

// TestTelemostICEResolveSuccessSubstitutesIP proves the optimisation still
// happens when the resolver is healthy: every hostname is replaced by its IP,
// exactly as before the fix.
func TestTelemostICEResolveSuccessSubstitutesIP(t *testing.T) {
	f := newFakeICEResolver()
	f.answer[tmFastICEHost] = tmFastICEIP
	f.answer[tmStallICEHost] = tmStallICEIP

	j := newTelemostTestJoiner(f.resolve)
	t.Cleanup(j.Close)

	j.parseICEServersFromHello(tmServerHelloFixture())

	want := []string{
		"stun:" + tmStallICEIP,
		"stun:" + tmFastICEIP,
		"turn:" + tmStallICEIP + ":443",
		"turn:" + tmStallICEIP + ":443",
		"turn:" + tmStallICEIP + ":443?transport=tcp",
	}
	got := iceURLsOf(j)
	if len(got) != len(want) {
		t.Fatalf("got %d URLs %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("URL %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestTelemostICEResolveIsConcurrent proves the hosts are resolved in
// parallel, not one after another: two hosts that each take 600ms must both
// land inside the 1.5s budget, which serial resolution of the original code
// would not guarantee as the host count grows.
func TestTelemostICEResolveIsConcurrent(t *testing.T) {
	f := newFakeICEResolver()
	for _, h := range []string{tmFastICEHost, tmStallICEHost} {
		f.stall[h] = 600 * time.Millisecond
	}
	f.answer[tmFastICEHost] = tmFastICEIP
	f.answer[tmStallICEHost] = tmStallICEIP

	j := newTelemostTestJoiner(f.resolve)
	t.Cleanup(j.Close)

	start := time.Now()
	resolved := j.resolveICEHosts([]string{tmStallICEHost, tmFastICEHost})
	elapsed := time.Since(start)

	if len(resolved) != 2 {
		t.Fatalf("resolved %d/2 hosts in %s: %v", len(resolved), elapsed, resolved)
	}
	if elapsed >= 1100*time.Millisecond {
		t.Fatalf("two 600ms lookups took %s, want < 1.1s (concurrent, not serial)", elapsed)
	}
}

// TestTelemostICEResolveBudgetIsBounded pins the budget itself: a resolver
// that never answers must cost the joiner no more than iceResolveBudget.
func TestTelemostICEResolveBudgetIsBounded(t *testing.T) {
	if iceResolveBudget > 1500*time.Millisecond {
		t.Fatalf("iceResolveBudget = %s, want <= 1.5s", iceResolveBudget)
	}
	f := newFakeICEResolver()
	f.stall[tmStallICEHost] = 30 * time.Second

	j := newTelemostTestJoiner(f.resolve)
	t.Cleanup(j.Close)

	start := time.Now()
	resolved := j.resolveICEHosts([]string{tmStallICEHost})
	elapsed := time.Since(start)

	if len(resolved) != 0 {
		t.Fatalf("stalled host resolved anyway: %v", resolved)
	}
	if elapsed > iceResolveBudget+500*time.Millisecond {
		t.Fatalf("gave up after %s, want ~%s", elapsed, iceResolveBudget)
	}
}

// TestTelemostICEResolveNilResolver proves a joiner with no ResolveFn keeps
// every hostname instead of panicking.
func TestTelemostICEResolveNilResolver(t *testing.T) {
	j := newTelemostTestJoiner(nil)
	t.Cleanup(j.Close)

	j.parseICEServersFromHello(tmServerHelloFixture())

	if len(j.iceServers) != 4 {
		t.Fatalf("got %d ICE servers, want 4", len(j.iceServers))
	}
	if got := iceURLsOf(j)[0]; got != "stun:"+tmStallICEHost {
		t.Fatalf("URL 0 = %q, want the untouched hostname", got)
	}
}

// TestTelemostICEHostsOfSkipsIPLiterals proves IP literals are never handed to
// the resolver.
func TestTelemostICEHostsOfSkipsIPLiterals(t *testing.T) {
	hosts := iceHostsOf([]webrtc.ICEServer{
		{URLs: []string{"stun:1.2.3.4:3478", "stun:" + tmFastICEHost}},
		{URLs: []string{"turn:" + tmFastICEHost + ":443?transport=tcp"}},
	})
	if len(hosts) != 1 || hosts[0] != tmFastICEHost {
		t.Fatalf("iceHostsOf = %v, want exactly [%s]", hosts, tmFastICEHost)
	}
}
