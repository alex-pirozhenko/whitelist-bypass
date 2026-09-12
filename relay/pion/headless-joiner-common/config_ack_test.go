package joiner

import (
	"sync"
	"testing"
	"time"
)

func TestConfigAckTracker(t *testing.T) {
	tracker := &configAckTracker{}

	// Case 1: Fresh tracker: acknowledged() is false.
	if tracker.acknowledged() {
		t.Errorf("fresh tracker should not be acknowledged")
	}

	// Case 2: arm the first cycle
	acked1, cancel1 := tracker.arm()
	if tracker.acknowledged() {
		t.Errorf("acknowledged should be false after arming")
	}

	select {
	case <-acked1:
		t.Errorf("acked1 should not be closed yet")
	case <-cancel1:
		t.Errorf("cancel1 should not be closed yet")
	default:
	}

	// mark first cycle
	tracker.mark()
	if !tracker.acknowledged() {
		t.Errorf("expected acknowledged to be true after mark")
	}

	select {
	case <-acked1:
		// success: acked1 channel is closed
	default:
		t.Errorf("expected acked1 channel to be closed")
	}

	// Case 3: Second cycle arming
	acked2, cancel2 := tracker.arm()

	// Assert cancel1 is now closed
	select {
	case <-cancel1:
		// success
	default:
		t.Errorf("expected cancel1 to be closed after second arm")
	}

	// Assert acknowledged() immediately becomes false again
	if tracker.acknowledged() {
		t.Errorf("expected acknowledged to reset to false on second arm")
	}

	select {
	case <-acked2:
		t.Errorf("acked2 should not be closed yet")
	case <-cancel2:
		t.Errorf("cancel2 should not be closed yet")
	default:
	}

	// Case 4: mark again
	tracker.mark()
	if !tracker.acknowledged() {
		t.Errorf("expected acknowledged to be true after second mark")
	}

	select {
	case <-acked2:
		// success
	default:
		t.Errorf("expected acked2 to be closed")
	}
}

func TestConfigAckTracker_ConcurrentSmoke(t *testing.T) {
	tracker := &configAckTracker{}
	var wg sync.WaitGroup

	// Run multiple goroutines doing arm/mark/acknowledged concurrently
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				acked, cancel := tracker.arm()
				_ = tracker.acknowledged()
				tracker.mark()
				_ = tracker.acknowledged()

				select {
				case <-acked:
				case <-time.After(50 * time.Millisecond):
				}
				select {
				case <-cancel:
				default:
				}
			}
		}()
	}

	wg.Wait()
}
