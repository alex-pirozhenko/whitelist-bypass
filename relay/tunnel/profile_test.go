package tunnel

import (
	"testing"
)

func TestTier_String(t *testing.T) {
	tests := []struct {
		tier     Tier
		expected string
	}{
		{TierActive, "active"},
		{TierDrain, "drain"},
		{TierIdle, "idle"},
		{TierDeepIdle, "deep-idle"},
		{Tier(-1), "unknown"},
		{Tier(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.tier.String(); got != tt.expected {
				t.Errorf("Tier.String() = %q, expected %q", got, tt.expected)
			}
		})
	}
}
