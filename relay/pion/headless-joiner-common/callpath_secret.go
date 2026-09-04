package joiner

import (
	"encoding/base64"

	"github.com/alex-pirozhenko/whitelist-bypass/relay/tunnel"
)

// callpath modification.
//
// Upstream seeds the tunnel obfuscator with tunnel.DeriveSecretFromJoinLink(...),
// which returns the join token itself. The platform that issued the room knows
// that token, and SRTP terminates at the platform's SFU — so a token-derived key
// lets the PLATFORM decrypt the tunnel and read the relay protocol inside,
// including a "connect host:port" for every destination.
//
// callpathTunnelSecret prefers an out-of-band per-device secret, provisioned at
// enrollment and never sent over the media platform. When it is absent we fall
// back to upstream behaviour so unmodified callers keep working.
//
// Both ends MUST agree: if one side uses the device secret and the other the
// join token, the tunnel silently carries undecryptable frames.
func callpathTunnelSecret(tunnelSecretB64, joinRef string) []byte {
	if tunnelSecretB64 != "" {
		if b, err := base64.StdEncoding.DecodeString(tunnelSecretB64); err == nil && len(b) >= 16 {
			return b
		}
	}
	return tunnel.DeriveSecretFromJoinLink(joinRef)
}
