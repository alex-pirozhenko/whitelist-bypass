package maxproto

import (
	"strings"
	"testing"
)

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
