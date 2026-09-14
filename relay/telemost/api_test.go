package telemost

import (
	"testing"
)

func TestSetSlotsMessageWithSize(t *testing.T) {
	key := 42
	width := 160
	height := 90
	msg := SetSlotsMessageWithSize(key, width, height)

	setSlots, ok := msg["setSlots"].(map[string]interface{})
	if !ok {
		t.Fatal("missing or invalid setSlots field")
	}

	if msgKey, _ := setSlots["key"].(int); msgKey != key {
		t.Errorf("expected key %d, got %v", key, setSlots["key"])
	}

	rawSlots, ok := setSlots["slots"].([]map[string]interface{})
	if !ok {
		// fallback check as []interface{} just in case
		ifs, ok := setSlots["slots"].([]interface{})
		if !ok {
			t.Fatal("missing or invalid slots field")
		}
		if len(ifs) != 12 {
			t.Fatalf("expected 12 slots, got %d", len(ifs))
		}
		for i, s := range ifs {
			slot, ok := s.(map[string]interface{})
			if !ok {
				t.Fatalf("slot %d is not a map", i)
			}
			w, _ := slot["width"].(int)
			h, _ := slot["height"].(int)
			if w != width || h != height {
				t.Errorf("slot %d: expected %dx%d, got %dx%d", i, width, height, w, h)
			}
		}
		return
	}

	if len(rawSlots) != 12 {
		t.Fatalf("expected 12 slots, got %d", len(rawSlots))
	}
	for i, slot := range rawSlots {
		w, _ := slot["width"].(int)
		h, _ := slot["height"].(int)
		if w != width || h != height {
			t.Errorf("slot %d: expected %dx%d, got %dx%d", i, width, height, w, h)
		}
	}
}
