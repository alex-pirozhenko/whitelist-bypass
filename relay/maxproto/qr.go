package maxproto

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// QR device-authorization opcodes. The web client mints a login "track", the
// logged-in Android master approves it, and the web client polls then completes
// to obtain its own session token — all without a fresh SMS/phone auth. This is
// the same self-service flow web.max.ru runs when a user scans the QR with their
// phone; here both legs are the operator's own accounts.
const (
	opQRCreateTrack = 288 // web (pre-auth): create a login track -> {trackId, qrLink, pollingInterval}
	opQRPoll        = 289 // web (pre-auth): poll a track -> {status:{loginAvailable}}
	opQRApprove     = 290 // android master (logged in): approve a qrLink -> {}
	opQRComplete    = 291 // web (pre-auth): complete an approved track -> {token, tokenAttrs:{LOGIN:{token}}}
)

// QRCreateTrack (op288) creates a QR login track on a fresh, pre-auth web
// connection. Returns the track id, the qrLink the master must approve, and the
// server's suggested polling interval in milliseconds.
func (c *Client) QRCreateTrack(ctx context.Context) (trackID, qrLink string, pollingIntervalMs int, err error) {
	resp, err := c.Cmd(ctx, opQRCreateTrack, map[string]any{})
	if err != nil {
		return "", "", 0, err
	}
	return parseQRCreateTrack(resp)
}

// QRPoll (op289) polls a track for approval. loginAvailable becomes true once a
// master has approved the qrLink.
func (c *Client) QRPoll(ctx context.Context, trackID string) (loginAvailable bool, err error) {
	resp, err := c.Cmd(ctx, opQRPoll, map[string]any{"trackId": trackID})
	if err != nil {
		return false, err
	}
	return parseQRPoll(resp)
}

// QRApprove (op290) approves a qrLink. It MUST be called on a Client that has
// already completed Login with a live Android master token; the server rejects
// it otherwise.
func (c *Client) QRApprove(ctx context.Context, qrLink string) error {
	_, err := c.Cmd(ctx, opQRApprove, map[string]any{"qrLink": qrLink})
	return err
}

// QRComplete (op291) completes an approved track and returns the newly minted
// session token plus the account's own user id (profile.contact.id) — the uid
// is what a caller needs to op76-invite this account into a room, and it is
// available here WITHOUT phone resolution (op46/op41), which fails for numbers
// not in MAX's directory.
func (c *Client) QRComplete(ctx context.Context, trackID string) (token string, uid int64, err error) {
	resp, err := c.Cmd(ctx, opQRComplete, map[string]any{"trackId": trackID})
	if err != nil {
		return "", 0, err
	}
	return parseQRComplete(resp)
}

// DeriveWebSession derives a fresh session token from a live master account,
// entirely over the wire and without any SMS/phone step: it opens a fresh web
// connection, creates a QR track (op288), has the already-logged-in master
// approve it (op290), polls until the approval lands (op289), and completes the
// track (op291). master must already be Connect+SessionInit+Login'd.
//
// Returns the session token and the fresh web device id it was bound to (the
// caller pairs the two when using the session).
func DeriveWebSession(ctx context.Context, master *Client, resolve ResolveFunc) (sessionToken, webDeviceID string, uid int64, err error) {
	if master == nil {
		return "", "", 0, errors.New("nil master client")
	}
	webDeviceID, err = randHex16()
	if err != nil {
		return "", "", 0, fmt.Errorf("generate web device id: %w", err)
	}

	// The web leg MUST identify as WEB: op288 (QR create-track) is refused
	// ("qr_login.disabled") on an ANDROID-identified session.
	web := NewWeb("", webDeviceID)
	if err := web.Connect(ctx, resolve); err != nil {
		return "", "", 0, fmt.Errorf("web connect: %w", err)
	}
	defer web.Close()
	if _, err := web.SessionInit(ctx); err != nil {
		return "", "", 0, fmt.Errorf("web session init: %w", err)
	}

	trackID, qrLink, pollMs, err := web.QRCreateTrack(ctx)
	if err != nil {
		return "", "", 0, fmt.Errorf("qr create track: %w", err)
	}
	if err := master.QRApprove(ctx, qrLink); err != nil {
		return "", "", 0, fmt.Errorf("qr approve: %w", err)
	}

	pollInterval := time.Duration(pollMs) * time.Millisecond
	if pollInterval <= 0 || pollInterval > 5*time.Second {
		pollInterval = 2 * time.Second
	}
	// Bound the wait so a never-approved track can't hang the lease path.
	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		ok, err := web.QRPoll(waitCtx, trackID)
		if err != nil {
			return "", "", 0, fmt.Errorf("qr poll: %w", err)
		}
		if ok {
			break
		}
		select {
		case <-waitCtx.Done():
			return "", "", 0, fmt.Errorf("qr approval not observed: %w", waitCtx.Err())
		case <-time.After(pollInterval):
		}
	}

	sessionToken, uid, err = web.QRComplete(waitCtx, trackID)
	if err != nil {
		return "", "", 0, fmt.Errorf("qr complete: %w", err)
	}
	if sessionToken == "" {
		return "", "", 0, errors.New("qr complete returned empty token")
	}
	return sessionToken, webDeviceID, uid, nil
}

// CheckAlive verifies whether a token is still valid by running the standard
// op6+op19 handshake on a throwaway connection. A transport failure (dial, TLS,
// session-init, dropped connection, or a context timeout) is returned as err
// with alive=false and cannot be interpreted as dead. A token the server
// actively rejects at Login is reported as alive=false, err=nil. When the token
// is alive, rotatedToken carries the (possibly refreshed) token from the Login
// response so the caller can adopt it.
func CheckAlive(ctx context.Context, token, deviceID string, resolve ResolveFunc) (alive bool, rotatedToken string, err error) {
	c := New(token, deviceID)
	if err := c.Connect(ctx, resolve); err != nil {
		return false, "", fmt.Errorf("connect: %w", err)
	}
	defer c.Close()
	if _, err := c.SessionInit(ctx); err != nil {
		return false, "", fmt.Errorf("session init: %w", err)
	}
	loginResp, err := c.Login(ctx)
	if err != nil {
		// Distinguish a transport blip (indeterminate) from the server actively
		// rejecting the token (dead). Connect+SessionInit already succeeded, so a
		// clean server error here means the token is dead; a dropped connection or
		// a context error is transport and must not be read as dead.
		if isTransportErr(err) {
			return false, "", err
		}
		return false, "", nil
	}
	alive, rotatedToken = parseAlive(loginResp, token)
	return alive, rotatedToken, nil
}

// isTransportErr reports whether err is a transport/timeout failure rather than
// a server-side rejection. Server rejections come back from Cmd as
// "Server error on opcode ..."; the readLoop injects "connection_closed" on a
// dropped socket, and context deadline/cancel are timeouts.
func isTransportErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	return strings.Contains(err.Error(), "connection_closed") ||
		strings.Contains(err.Error(), "not connected")
}

// randHex16 returns a fresh 16-character lowercase hex device id (8 random
// bytes), matching MAX's device_id shape.
func randHex16() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// --- pure parse helpers (unit-tested without a live server) ---

func parseQRCreateTrack(resp any) (trackID, qrLink string, pollingIntervalMs int, err error) {
	m, ok := resp.(map[string]any)
	if !ok {
		return "", "", 0, fmt.Errorf("unexpected QRCreateTrack response type: %T", resp)
	}
	trackID, _ = m["trackId"].(string)
	qrLink, _ = m["qrLink"].(string)
	if trackID == "" {
		return "", "", 0, errors.New("trackId missing in QRCreateTrack response")
	}
	if qrLink == "" {
		return "", "", 0, errors.New("qrLink missing in QRCreateTrack response")
	}
	if pi, ok := toInt64(m["pollingInterval"]); ok {
		pollingIntervalMs = int(pi)
	}
	return trackID, qrLink, pollingIntervalMs, nil
}

func parseQRPoll(resp any) (loginAvailable bool, err error) {
	m, ok := resp.(map[string]any)
	if !ok {
		return false, fmt.Errorf("unexpected QRPoll response type: %T", resp)
	}
	status, ok := m["status"].(map[string]any)
	if !ok {
		return false, nil // no status yet — treat as not-yet-available
	}
	b, _ := status["loginAvailable"].(bool)
	return b, nil
}

func parseQRComplete(resp any) (token string, uid int64, err error) {
	m, ok := resp.(map[string]any)
	if !ok {
		return "", 0, fmt.Errorf("unexpected QRComplete response type: %T", resp)
	}
	// uid = profile.contact.id (the account's own user id), when present.
	if profile, ok := m["profile"].(map[string]any); ok {
		if contact, ok := profile["contact"].(map[string]any); ok {
			uid, _ = toInt64(contact["id"])
		}
	}
	if t, _ := m["token"].(string); t != "" {
		return t, uid, nil
	}
	// Fall back to tokenAttrs.LOGIN.token.
	if attrs, ok := m["tokenAttrs"].(map[string]any); ok {
		if login, ok := attrs["LOGIN"].(map[string]any); ok {
			if t, _ := login["token"].(string); t != "" {
				return t, uid, nil
			}
		}
	}
	return "", 0, errors.New("no token in QRComplete response")
}

// parseAlive interprets a successful Login response. A successful Login means
// the token is alive; rotatedToken is the token from the response when the
// server issued a fresh one (differs from the presented token), else "".
func parseAlive(loginResp map[string]any, presented string) (alive bool, rotatedToken string) {
	if loginResp == nil {
		return false, ""
	}
	if t, _ := loginResp["token"].(string); t != "" && t != presented {
		return true, t
	}
	return true, ""
}
