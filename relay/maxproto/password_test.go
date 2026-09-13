package maxproto

import (
	"context"
	"strings"
	"testing"
)

func TestParsePasswordChallenge(t *testing.T) {
	// A 2FA-protected op19 LOGIN response carries the challenge in place of a
	// completed login.
	trackID, present := parsePasswordChallenge(map[string]any{
		"passwordChallenge": map[string]any{"trackId": "trk-9", "hint": "h"},
	})
	if !present || trackID != "trk-9" {
		t.Errorf("challenge: present=%v trackID=%q, want true/trk-9", present, trackID)
	}
	// No challenge (the common, no-2FA-password case): login already complete.
	if _, present := parsePasswordChallenge(map[string]any{"token": "tok"}); present {
		t.Error("no passwordChallenge field must report present=false")
	}
	// A challenge object without a usable trackId is not actionable.
	if _, present := parsePasswordChallenge(map[string]any{"passwordChallenge": map[string]any{"hint": "h"}}); present {
		t.Error("empty trackId must report present=false")
	}
	if _, present := parsePasswordChallenge("nope"); present {
		t.Error("non-map must report present=false")
	}
	if _, present := parsePasswordChallenge(map[string]any{"passwordChallenge": "wrong-type"}); present {
		t.Error("non-map challenge must report present=false")
	}
}

func TestParseCheckPasswordToken(t *testing.T) {
	cases := []struct {
		name string
		resp any
		want string
	}{
		{"top-level token", map[string]any{"token": "top"}, "top"},
		{"tokenAttrs.LOGIN.token", map[string]any{"tokenAttrs": map[string]any{"LOGIN": map[string]any{"token": "attr"}}}, "attr"},
		{"tokenTypes.LOGIN.token", map[string]any{"tokenTypes": map[string]any{"LOGIN": map[string]any{"token": "types"}}}, "types"},
		{"LOGIN bare string", map[string]any{"tokenAttrs": map[string]any{"LOGIN": "bare"}}, "bare"},
		{"top-level preferred", map[string]any{"token": "top", "tokenAttrs": map[string]any{"LOGIN": map[string]any{"token": "attr"}}}, "top"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseCheckPasswordToken(tc.resp)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("token = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseCheckPasswordToken_Missing(t *testing.T) {
	cases := []struct {
		name string
		resp any
	}{
		{"wrong type", 7},
		{"empty map", map[string]any{}},
		{"empty token", map[string]any{"token": ""}},
		{"attrs without login", map[string]any{"tokenAttrs": map[string]any{}}},
		{"login without token", map[string]any{"tokenAttrs": map[string]any{"LOGIN": map[string]any{}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseCheckPasswordToken(tc.resp); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestCheckPassword_ValidatesArgs(t *testing.T) {
	// These must fail before any wire call, so a nil-conn Client is fine.
	c := New("tok", "dev")
	if _, err := c.CheckPassword(context.Background(), "", "pw"); err == nil {
		t.Error("empty trackId must error")
	}
	if _, err := c.CheckPassword(context.Background(), "trk", ""); err == nil {
		t.Error("empty password must error")
	}
}

// TestCheckPasswordRejectionIsNotTransport pins the regression the liveness
// loop depends on: a wrong-password rejection surfacing from op115 is a server
// rejection (dead credential), NOT a transport blip. If isTransportErr ever
// classified it as transport, CheckAlive would treat a genuinely bad password
// as an indeterminate network error and never mark the account dead.
func TestCheckPasswordRejectionIsNotTransport(t *testing.T) {
	err := errString("Server error on opcode 115: FAIL_WRONG_PASSWORD — bad password")
	if isTransportErr(err) {
		t.Error("a FAIL_WRONG_PASSWORD rejection from op115 must NOT be transport")
	}
}

func TestParseTrackID(t *testing.T) {
	id, err := parseTrackID(map[string]any{"trackId": "trk-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "trk-1" {
		t.Errorf("trackID = %q", id)
	}
	if _, err := parseTrackID(map[string]any{}); err == nil {
		t.Error("expected error for missing trackId")
	}
	if _, err := parseTrackID("nope"); err == nil {
		t.Error("expected error for non-map")
	}
}

func TestParseRotatedToken(t *testing.T) {
	if got := parseRotatedToken(map[string]any{"token": "top"}, "fb"); got != "top" {
		t.Errorf("top-level = %q", got)
	}
	nested := map[string]any{"tokenAttrs": map[string]any{"LOGIN": map[string]any{"token": "nest"}}}
	if got := parseRotatedToken(nested, "fb"); got != "nest" {
		t.Errorf("nested = %q", got)
	}
	if got := parseRotatedToken(map[string]any{}, "fb"); got != "fb" {
		t.Errorf("fallback = %q, want fb", got)
	}
	if got := parseRotatedToken("x", "fb"); got != "fb" {
		t.Errorf("non-map fallback = %q, want fb", got)
	}
}

func TestIsSet2FARestricted(t *testing.T) {
	if isSet2FARestricted(nil) {
		t.Error("nil is not restricted")
	}
	if !isSet2FARestricted(errString("Server error on opcode 111: restricted.set_2fa — blocked")) {
		t.Error("restricted.set_2fa should be detected")
	}
	if !isSet2FARestricted(errString("must wait 24 hours")) {
		t.Error("24 hour should be detected")
	}
	if isSet2FARestricted(errString("Server error on opcode 111: proto.payload — bad")) {
		t.Error("unrelated error must not be restricted")
	}
}

func TestGenPassword(t *testing.T) {
	a, err := GenPassword()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(a) != 24 {
		t.Errorf("len = %d, want 24", len(a))
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	for _, r := range a {
		if !strings.ContainsRune(alphabet, r) {
			t.Errorf("char %q not in alphabet", r)
		}
	}
	if b, _ := GenPassword(); a == b {
		t.Error("expected distinct passwords")
	}
}
