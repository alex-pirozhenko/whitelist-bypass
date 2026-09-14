package joiner

import (
	"net"
	"strings"

	"github.com/pion/webrtc/v4"
)

// loopbackOnlyPCConfigurer keeps the replay test's PeerConnection off the real
// network: local candidates come only from the loopback interface, so the
// connectivity checks the joiner starts against the captured server host
// candidates (155.212.x, a real OK media endpoint) can never leave this
// machine. The test asserts the signalling sequence and that ICE *starts*
// with the server candidates applied; it must not depend on -- or produce --
// traffic to the provider.
type loopbackOnlyPCConfigurer struct{}

func (loopbackOnlyPCConfigurer) ConfigureSettingEngine(se *webrtc.SettingEngine) {
	se.SetInterfaceFilter(func(name string) bool {
		return name == "lo0" || name == "lo" || strings.HasPrefix(name, "lo")
	})
	se.SetIPFilter(func(ip net.IP) bool { return ip.IsLoopback() })
}
