package maxproto

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
)

// 2FA password opcodes. Setting a 2FA password is what turns a fresh
// registration token into a durable, long-lived master: the server otherwise
// rotates/expires short-lived tokens, but a master with a 2FA password can be
// re-authenticated with the password (op115) instead of a fresh SMS. The
// server blocks AUTH_SET_2FA for ~24h after the account's first LOGIN, so this
// can only succeed on an aged account (the caller schedules it accordingly).
const (
	opAuthSet2FA      = 111 // {trackId, password, expectedCapabilities:[0]} -> success (may rotate token)
	opAuthCreateTrack = 112 // {type:0} -> {trackId}
)

// capSetPassword is expectedCapabilities[0] for a brand-new password
// (SET_PASSWORD=0; UPDATE_PASSWORD=1, RESTORE_PASSWORD=2 are the others).
const capSetPassword = 0

// ErrSet2FARestricted is returned by SetAccountPassword when the server refuses
// because the account is still inside its post-login 24h lockout. The caller
// should treat this as "not eligible yet", not a hard failure.
var ErrSet2FARestricted = errors.New("maxproto: set-2fa restricted (24h post-login lockout)")

// SetAccountPassword sets a 2FA password on the account the client is currently
// logged in as (op112 create-track -> op111 set-2fa). It must be called on a
// Client that has already completed Connect+SessionInit+Login with the master
// token. The password is caller-supplied so the caller can persist exactly what
// was set. Returns the (possibly rotated) long-lived token; adopt it in place
// of the pre-password token.
func (c *Client) SetAccountPassword(ctx context.Context, password string) (rotatedToken string, err error) {
	if password == "" {
		return "", errors.New("maxproto: empty password")
	}

	trackResp, err := c.Cmd(ctx, opAuthCreateTrack, map[string]any{"type": 0})
	if err != nil {
		return "", err
	}
	trackID, err := parseTrackID(trackResp)
	if err != nil {
		return "", err
	}

	setResp, err := c.Cmd(ctx, opAuthSet2FA, map[string]any{
		"trackId":              trackID,
		"password":             password,
		"expectedCapabilities": []int{capSetPassword},
	})
	if err != nil {
		if isSet2FARestricted(err) {
			return "", ErrSet2FARestricted
		}
		return "", err
	}
	return parseRotatedToken(setResp, ""), nil
}

// GenPassword returns a 24-character alphanumeric password suitable for a 2FA
// master password, drawn from crypto/rand.
func GenPassword() (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	var b strings.Builder
	for i := 0; i < 24; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		b.WriteByte(alphabet[n.Int64()])
	}
	return b.String(), nil
}

// --- pure parse helpers (unit-tested without a live server) ---

func parseTrackID(resp any) (string, error) {
	m, ok := resp.(map[string]any)
	if !ok {
		return "", errors.New("unexpected AuthCreateTrack response type")
	}
	trackID, _ := m["trackId"].(string)
	if trackID == "" {
		return "", errors.New("trackId missing in AuthCreateTrack response")
	}
	return trackID, nil
}

// parseRotatedToken pulls a rotated token out of a set-2fa (or similar)
// response: the top-level "token", else tokenAttrs.LOGIN.token. Returns fallback
// when neither is present (the operation succeeded but the token did not rotate).
func parseRotatedToken(resp any, fallback string) string {
	m, ok := resp.(map[string]any)
	if !ok {
		return fallback
	}
	if t, _ := m["token"].(string); t != "" {
		return t
	}
	if attrs, ok := m["tokenAttrs"].(map[string]any); ok {
		if login, ok := attrs["LOGIN"].(map[string]any); ok {
			if t, _ := login["token"].(string); t != "" {
				return t
			}
		}
	}
	return fallback
}

// isSet2FARestricted detects the server's 24h post-login lockout error.
func isSet2FARestricted(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "restricted.set_2fa") ||
		strings.Contains(msg, "24 hour") ||
		strings.Contains(msg, "24h")
}
