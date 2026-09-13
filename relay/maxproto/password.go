package maxproto

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
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

// opAuthLoginCheckPassword (op115, AUTH_LOGIN_CHECK_PASSWORD) answers the 2FA
// password challenge that op19 LOGIN raises for an account carrying a 2FA
// password. When such an account logs in, the server does not complete the
// login: instead of a token it returns a passwordChallenge{trackId,hint}, and
// the client must present the password against that trackId with op115. op115
// is a pre-auth opcode, so it runs on the same pre-LOGIN session that raised the
// challenge — the sequence is op6 SessionInit -> op19 LOGIN -> op115(password).
//
// Payload {trackId, password}; the completed-login token comes back as top-level
// "token" or nested under tokenAttrs.LOGIN / tokenTypes.LOGIN. This is the only
// path that logs a password-bearing master in without a fresh SMS, and its
// absence is what made the 2FA-password backfill a time bomb (letmeout #118):
// SetAccountPassword (op111/op112) succeeds and persists a password that,
// without op115, no login can ever present.
const opAuthLoginCheckPassword = 115

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

// CheckPassword answers a 2FA password challenge (op115). trackID is the
// passwordChallenge trackId a prior op19 LOGIN (or op18/op291) response carried;
// password is the account's 2FA password. It returns the completed-login token
// the server issues on success. op115 is a pre-auth opcode, so this is called on
// the same Client that ran SessionInit+Login and received the challenge, with no
// fresh Login in between.
//
// A wrong password comes back from Cmd as "Server error on opcode 115: ...",
// which isTransportErr (qr.go) classifies as a server rejection, NOT transport —
// callers depend on that distinction to tell a dead credential from a network
// blip.
func (c *Client) CheckPassword(ctx context.Context, trackID, password string) (token string, err error) {
	if trackID == "" {
		return "", errors.New("maxproto: empty trackId")
	}
	if password == "" {
		return "", errors.New("maxproto: empty password")
	}
	resp, err := c.Cmd(ctx, opAuthLoginCheckPassword, map[string]any{
		"trackId":  trackID,
		"password": password,
	})
	if err != nil {
		return "", err
	}
	return parseCheckPasswordToken(resp)
}

// --- pure parse helpers (unit-tested without a live server) ---

// parsePasswordChallenge extracts a passwordChallenge trackId from an auth
// response (op19 LOGIN / op18 AUTH / op291 QR-complete). present is false when
// the response carries no challenge — i.e. the account has no 2FA password and
// the login already completed normally.
func parsePasswordChallenge(resp any) (trackID string, present bool) {
	m, ok := resp.(map[string]any)
	if !ok {
		return "", false
	}
	pc, ok := m["passwordChallenge"].(map[string]any)
	if !ok {
		return "", false
	}
	t, _ := pc["trackId"].(string)
	if t == "" {
		return "", false
	}
	return t, true
}

// parseCheckPasswordToken pulls the completed-login token out of an op115
// response. Recorded responses carry it as top-level "token", or nested under
// tokenAttrs.LOGIN / tokenTypes.LOGIN (the container key varies by server
// build; both have been observed), where LOGIN is either a {token:...} object
// or the token string itself.
func parseCheckPasswordToken(resp any) (string, error) {
	m, ok := resp.(map[string]any)
	if !ok {
		return "", fmt.Errorf("unexpected AuthLoginCheckPassword response type: %T", resp)
	}
	if t, _ := m["token"].(string); t != "" {
		return t, nil
	}
	for _, key := range []string{"tokenAttrs", "tokenTypes"} {
		attrs, ok := m[key].(map[string]any)
		if !ok {
			continue
		}
		if login, ok := attrs["LOGIN"].(map[string]any); ok {
			if t, _ := login["token"].(string); t != "" {
				return t, nil
			}
		}
		if t, _ := attrs["LOGIN"].(string); t != "" {
			return t, nil
		}
	}
	return "", errors.New("no token in AuthLoginCheckPassword response")
}

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
