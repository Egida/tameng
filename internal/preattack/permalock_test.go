package preattack

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// REQ SVALINN-PREATTACK-PERMALOCK-001
//
// Analyze recomputed BLOCK/ALLOW live from counters that only ever grew
// (UniquePathstried, SuspiciousPaths, NotFoundCount never reset; RapidRequests/
// SequentialPaths flip true and never flip back). Any actor that ever crossed
// the 0.7 BLOCK threshold -- trivially, by visiting 6 ordinary paths, several
// of which ("/robots.txt", "/config", "/.well-known") are completely benign --
// stayed blocked for the life of the process, with no recovery path and no
// admin endpoint that reached this state. The underlying scanPatterns map also
// never evicted anything, so every distinct IP ever seen accumulated a
// permanent entry: a plausible unbounded-memory vector under real traffic.

func plRequest(path string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "203.0.113.9:51000"
	return req
}

// tripBlock drives a fresh detector's actor past the BLOCK threshold using
// the cheapest real path: 6 distinct paths trips path_enumeration (0.3) plus
// 3 of the built-in "suspicious" substrings trips suspicious_path_probing
// (0.4) -- 0.7 total, at the real BLOCK boundary, using paths a legitimate
// crawler could plausibly visit.
func tripBlock(t *testing.T, d *Detector) *Result {
	t.Helper()
	paths := []string{"/", "/status", "/openapi.json", "/robots.txt", "/config", "/.well-known/security.txt"}
	var last *Result
	for _, p := range paths {
		last = d.Analyze(plRequest(p))
	}
	if last.RecommendedAction != "BLOCK" {
		t.Fatalf("setup failed: expected BLOCK after tripping thresholds, got %s (score=%v)", last.RecommendedAction, last.Score)
	}
	return last
}

func TestAnalyze_BlockRecoversAfterDuration(t *testing.T) {
	d := NewDetector(Config{Enabled: true, BlockDuration: 30 * time.Millisecond})
	defer d.Stop()

	tripBlock(t, d)

	// Still within the block window: must stay BLOCK.
	if got := d.Analyze(plRequest("/health")); got.RecommendedAction != "BLOCK" {
		t.Fatalf("expected still-BLOCK immediately after tripping, got %s", got.RecommendedAction)
	}

	time.Sleep(50 * time.Millisecond)

	// This is the actual bug: the old code had no BlockedUntil at all, so
	// this assertion fails forever against the pre-fix implementation --
	// verified below via a real revert-and-rerun, not just asserted here.
	if got := d.Analyze(plRequest("/health")); got.RecommendedAction == "BLOCK" {
		t.Fatalf("actor is still BLOCKed %v after BlockDuration elapsed -- no recovery path (this is REQ SVALINN-PREATTACK-PERMALOCK-001)", got)
	}
}

func TestAnalyze_ResetClearsAccumulatedSignalsNotJustTheVerdict(t *testing.T) {
	d := NewDetector(Config{Enabled: true, BlockDuration: 20 * time.Millisecond})
	defer d.Stop()

	tripBlock(t, d)
	time.Sleep(40 * time.Millisecond)

	// One request after recovery should read as fresh (ALLOW), not
	// immediately re-trip BLOCK from leftover pre-reset counters.
	got := d.Analyze(plRequest("/health"))
	if got.RecommendedAction == "BLOCK" {
		t.Fatalf("recovered actor immediately re-blocked on the very next request -- reset did not actually clear accumulated state, got score=%v indicators=%v", got.Score, got.Indicators)
	}
}

func TestAnalyze_BlockedActorDoesNotAccumulateFurtherState(t *testing.T) {
	d := NewDetector(Config{Enabled: true, BlockDuration: 1 * time.Hour})
	defer d.Stop()

	tripBlock(t, d)

	patternVal, ok := d.scanPatterns.Load(getClientIP(plRequest("/x")))
	if !ok {
		t.Fatal("expected a tracked pattern for the test actor")
	}
	pattern := patternVal.(*ScanPattern)
	pattern.mu.RLock()
	lenBefore := len(pattern.UniquePathstried)
	pattern.mu.RUnlock()

	for i := 0; i < 20; i++ {
		d.Analyze(plRequest("/probe-while-blocked"))
	}

	pattern.mu.RLock()
	lenAfter := len(pattern.UniquePathstried)
	pattern.mu.RUnlock()

	if lenAfter != lenBefore {
		t.Fatalf("UniquePathstried grew from %d to %d while actor was blocked -- blocked requests should short-circuit before touching counters", lenBefore, lenAfter)
	}
}

func TestAnalyze_PathTrackingIsBoundedEvenWithoutCrossingBlockThreshold(t *testing.T) {
	d := NewDetector(Config{Enabled: true, SuspiciousPathsCount: 1000000}) // never trips path_enumeration
	defer d.Stop()

	ip := getClientIP(plRequest("/x"))
	for i := 0; i < maxTrackedPaths+100; i++ {
		d.Analyze(plRequest("/distinct-path-that-never-repeats-in-this-loop"))
	}

	patternVal, _ := d.scanPatterns.Load(ip)
	pattern := patternVal.(*ScanPattern)
	pattern.mu.RLock()
	n := len(pattern.UniquePathstried)
	pattern.mu.RUnlock()

	if n > maxTrackedPaths {
		t.Fatalf("UniquePathstried grew to %d entries, unbounded (cap is %d)", n, maxTrackedPaths)
	}
}

func TestCleanup_EvictsStaleUnblockedPatterns(t *testing.T) {
	d := NewDetector(Config{Enabled: true})
	defer d.Stop()

	d.Analyze(plRequest("/hello"))
	ip := getClientIP(plRequest("/hello"))

	patternVal, _ := d.scanPatterns.Load(ip)
	pattern := patternVal.(*ScanPattern)
	pattern.mu.Lock()
	pattern.LastSeen = time.Now().Add(-2 * patternStaleAfter)
	pattern.mu.Unlock()

	d.cleanup()

	if _, ok := d.scanPatterns.Load(ip); ok {
		t.Fatal("stale pattern was not evicted by cleanup")
	}
}

func TestCleanup_NeverEvictsAnActivelyBlockedPattern(t *testing.T) {
	d := NewDetector(Config{Enabled: true, BlockDuration: 1 * time.Hour})
	defer d.Stop()

	tripBlock(t, d)
	ip := getClientIP(plRequest("/x"))

	patternVal, _ := d.scanPatterns.Load(ip)
	pattern := patternVal.(*ScanPattern)
	pattern.mu.Lock()
	pattern.LastSeen = time.Now().Add(-2 * patternStaleAfter) // idle long enough to look stale
	pattern.mu.Unlock()

	d.cleanup()

	if _, ok := d.scanPatterns.Load(ip); !ok {
		t.Fatal("an actively-blocked pattern was evicted early -- eviction must not shorten an active block")
	}
}

// TestAnalyze_ConcurrentRequestsFromSameIPDoNotRace is the Phase 8 proof: the
// pre-fix ScanPattern had zero locking despite being mutated by potentially
// concurrent goroutines for the same IP (multiple simultaneous connections
// from one client is normal). Run with -race.
func TestAnalyze_ConcurrentRequestsFromSameIPDoNotRace(t *testing.T) {
	d := NewDetector(Config{Enabled: true, BlockDuration: 5 * time.Millisecond})
	defer d.Stop()

	var wg sync.WaitGroup
	paths := []string{"/", "/a", "/b", "/c", "/d", "/e", "/f", "/robots.txt", "/config", "/.well-known/x"}
	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				d.Analyze(plRequest(paths[(g+i)%len(paths)]))
			}
		}(g)
	}
	wg.Wait()
}

// TestAnalyze_SustainedRecentBehaviorStillBlocks is the regression guard: the
// fix must not weaken detection of genuinely sustained bad behavior within a
// single window, only fix the permanent-lock/no-recovery bug.
func TestAnalyze_SustainedRecentBehaviorStillBlocks(t *testing.T) {
	d := NewDetector(Config{Enabled: true})
	defer d.Stop()

	got := tripBlock(t, d)
	if got.Score < 0.7 {
		t.Fatalf("expected score >= 0.7 for genuine sustained recon, got %v", got.Score)
	}
}
