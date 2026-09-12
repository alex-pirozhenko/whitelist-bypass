package tunnel

import (
	"testing"
)

func TestRTCPFeedback(t *testing.T) {
	// Construct an RTCPFeedback
	fb := &RTCPFeedback{}

	// whitebox testing: direct field updates
	fb.keyframeReqs.Add(2)
	fb.bwEstimate.Store(500000)

	if got := fb.KeyframeRequests(); got != 2 {
		t.Errorf("KeyframeRequests() = %d, expected 2", got)
	}

	bps, ok := fb.BandwidthEstimate()
	if !ok || bps != 500000 {
		t.Errorf("BandwidthEstimate() = (%d, %t), expected (500000, true)", bps, ok)
	}

	// Test nil safety
	var nilFb *RTCPFeedback
	if got := nilFb.KeyframeRequests(); got != 0 {
		t.Errorf("nil feedback KeyframeRequests() should be 0, got %d", got)
	}
	if bps, ok := nilFb.BandwidthEstimate(); ok || bps != 0 {
		t.Errorf("nil feedback BandwidthEstimate() should be (0, false), got (%d, %t)", bps, ok)
	}
}
