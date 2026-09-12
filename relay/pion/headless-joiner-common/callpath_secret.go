package joiner

import (
	"encoding/base64"
	"fmt"

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
// If the required parameter is true, callpathTunnelSecret will fail instead of
// falling back to the token-derived secret when no TunnelSecret is provided.
//
// Both ends MUST agree: if one side uses the device secret and the other the
// join token, the tunnel silently carries undecryptable frames.
// A bad or short explicit secret (invalid base64 or fewer than 16 bytes) is
// always rejected with an error instead of silently falling back.
func callpathTunnelSecret(tunnelSecretB64, joinRef string, required bool) ([]byte, error) {
	if tunnelSecretB64 != "" {
		b, err := base64.StdEncoding.DecodeString(tunnelSecretB64)
		if err != nil || len(b) < 16 {
			return nil, fmt.Errorf("callpath: tunnelSecret is invalid or shorter than 16 bytes")
		}
		return b, nil
	}
	if required {
		return nil, fmt.Errorf("callpath: tunnelSecret is required (RequireTunnelSecret=true) but none was provided")
	}
	return tunnel.DeriveSecretFromJoinLink(joinRef), nil
}
