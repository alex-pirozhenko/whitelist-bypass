package maxproto

import "testing"

func TestParseQRCreateTrack(t *testing.T) {
	// deepDecode always hands us map[string]any at every level, and integers may
	// arrive as any width; pollingInterval as int64 exercises toInt64.
	resp := map[string]any{
		"trackId":         "trk-abc-123",
		"qrLink":          "https://ru.oneme.app/qr/xyz",
		"pollingInterval": int64(5000),
	}
	trackID, qrLink, pollMs, err := parseQRCreateTrack(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if trackID != "trk-abc-123" {
		t.Errorf("trackID = %q", trackID)
	}
	if qrLink != "https://ru.oneme.app/qr/xyz" {
		t.Errorf("qrLink = %q", qrLink)
	}
	if pollMs != 5000 {
		t.Errorf("pollMs = %d, want 5000", pollMs)
	}
}

func TestParseQRCreateTrack_MissingFields(t *testing.T) {
	cases := []struct {
		name string
		resp any
	}{
		{"wrong type", []any{1, 2}},
		{"no trackId", map[string]any{"qrLink": "https://x"}},
		{"no qrLink", map[string]any{"trackId": "t"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, err := parseQRCreateTrack(tc.resp); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestParseQRCreateTrack_NoPollingInterval(t *testing.T) {
	resp := map[string]any{"trackId": "t", "qrLink": "q"}
	_, _, pollMs, err := parseQRCreateTrack(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pollMs != 0 {
		t.Errorf("pollMs = %d, want 0 (absent)", pollMs)
	}
}

func TestParseQRPoll(t *testing.T) {
	cases := []struct {
		name string
		resp any
		want bool
	}{
		{"available", map[string]any{"status": map[string]any{"loginAvailable": true}}, true},
		{"not available", map[string]any{"status": map[string]any{"loginAvailable": false}}, false},
		{"no status yet", map[string]any{}, false},
		{"status without flag", map[string]any{"status": map[string]any{}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseQRPoll(tc.resp)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("loginAvailable = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseQRPoll_WrongType(t *testing.T) {
	if _, err := parseQRPoll("nope"); err == nil {
		t.Fatal("expected error for non-map response")
	}
}

func TestParseQRComplete_TopLevel(t *testing.T) {
	resp := map[string]any{"token": "An_Sx6HQ9top"}
	tok, err := parseQRComplete(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "An_Sx6HQ9top" {
		t.Errorf("token = %q", tok)
	}
}

func TestParseQRComplete_TokenAttrsFallback(t *testing.T) {
	resp := map[string]any{
		"tokenAttrs": map[string]any{
			"LOGIN": map[string]any{"token": "An_Sx6HQ9nested"},
		},
	}
	tok, err := parseQRComplete(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "An_Sx6HQ9nested" {
		t.Errorf("token = %q", tok)
	}
}

func TestParseQRComplete_TopLevelPreferred(t *testing.T) {
	resp := map[string]any{
		"token":      "top",
		"tokenAttrs": map[string]any{"LOGIN": map[string]any{"token": "nested"}},
	}
	tok, err := parseQRComplete(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "top" {
		t.Errorf("token = %q, want top-level preferred", tok)
	}
}

func TestParseQRComplete_Missing(t *testing.T) {
	cases := []struct {
		name string
		resp any
	}{
		{"wrong type", 42},
		{"empty map", map[string]any{}},
		{"empty token string", map[string]any{"token": ""}},
		{"attrs without login", map[string]any{"tokenAttrs": map[string]any{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseQRComplete(tc.resp); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestParseAlive(t *testing.T) {
	t.Run("rotated token", func(t *testing.T) {
		alive, rotated := parseAlive(map[string]any{"token": "fresh", "chats": []any{}}, "old")
		if !alive {
			t.Error("expected alive")
		}
		if rotated != "fresh" {
			t.Errorf("rotated = %q, want fresh", rotated)
		}
	})
	t.Run("same token no rotation", func(t *testing.T) {
		alive, rotated := parseAlive(map[string]any{"token": "same"}, "same")
		if !alive {
			t.Error("expected alive")
		}
		if rotated != "" {
			t.Errorf("rotated = %q, want empty (no rotation)", rotated)
		}
	})
	t.Run("no token field still alive", func(t *testing.T) {
		alive, rotated := parseAlive(map[string]any{"chats": []any{}, "config": map[string]any{}}, "old")
		if !alive {
			t.Error("expected alive (login succeeded)")
		}
		if rotated != "" {
			t.Errorf("rotated = %q, want empty", rotated)
		}
	})
	t.Run("nil response", func(t *testing.T) {
		alive, _ := parseAlive(nil, "old")
		if alive {
			t.Error("nil response must not be alive")
		}
	})
}

func TestIsTransportErr(t *testing.T) {
	if isTransportErr(nil) {
		t.Error("nil is not a transport error")
	}
	if !isTransportErr(errString("connection_closed: EOF")) {
		t.Error("connection_closed should be transport")
	}
	if !isTransportErr(errString("not connected")) {
		t.Error("not connected should be transport")
	}
	if isTransportErr(errString("Server error on opcode 19: SESSION_EXPIRED — dead")) {
		t.Error("a server rejection must NOT be classified as transport")
	}
}

func TestRandHex16(t *testing.T) {
	a, err := randHex16()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(a) != 16 {
		t.Errorf("len = %d, want 16", len(a))
	}
	b, _ := randHex16()
	if a == b {
		t.Error("expected distinct device ids across calls")
	}
	for _, r := range a {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			t.Errorf("non-hex char %q in %q", r, a)
		}
	}
}

// errString is a minimal error type for isTransportErr tests.
type errString string

func (e errString) Error() string { return string(e) }
