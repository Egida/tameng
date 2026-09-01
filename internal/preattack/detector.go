/*
Package preattack implements pre-attack signal detection

Detects reconnaissance, port scanning, and other pre-attack indicators
*/
package preattack

import (
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/koodoxz/tameng/internal/netutil"
)

// maxTrackedPaths bounds ScanPattern.UniquePathstried/SuspiciousPaths growth.
// It sits well above SuspiciousPathsCount's default (5) so behaviour is
// unaffected below the cap; past it, further paths are still analyzed for
// the current request but stop being retained.
const maxTrackedPaths = 50

// patternStaleAfter is how long a pattern with no BLOCK-worthy state may sit
// idle before evictionLoop reclaims it. Blocked patterns are never evicted
// early -- eviction and BlockedUntil are independent, so a slow periodic
// sweep can't accidentally shorten an active block.
const patternStaleAfter = 1 * time.Hour

// patternEvictionInterval is how often evictionLoop sweeps for stale entries.
const patternEvictionInterval = 5 * time.Minute

// Detector detects pre-attack signals
type Detector struct {
	scanPatterns sync.Map // IP -> *ScanPattern
	dnsQueries   sync.Map // Domain -> []Query
	config       Config
	patternCount int64
	shutdown     chan struct{}
}

// Config holds detector configuration
type Config struct {
	Enabled              bool
	ReconThreshold       int
	PortScanWindow       time.Duration
	DNSEnumThreshold     int
	SuspiciousPathsCount int
	// BlockDuration is how long a BLOCK recommendation stays in effect once
	// triggered. REQ SVALINN-PREATTACK-PERMALOCK-001: previously there was no
	// such duration -- the block was recomputed live from counters that only
	// ever grew, so a tripped actor (including a legitimate crawler or
	// monitor that merely visited a handful of common paths) was blocked for
	// the life of the process with no recovery path.
	BlockDuration time.Duration
}

// ScanPattern tracks potential scanning behavior for a single actor. All
// fields are guarded by mu -- Analyze can run concurrently for the same IP
// (multiple simultaneous connections from one client is normal), and the
// pre-fix version of this struct had no lock at all.
type ScanPattern struct {
	mu               sync.RWMutex
	IP               string
	FirstSeen        time.Time
	LastSeen         time.Time
	RequestCount     int
	UniquePathstried []string
	SequentialPaths  bool
	RapidRequests    bool
	SuspiciousPaths  []string
	NotFoundCount    int
	// BlockedUntil is zero when not blocked. While non-zero and in the
	// future, Analyze short-circuits to a cached BLOCK result without
	// touching the counters below (so a blocked actor's own repeated
	// requests can't grow UniquePathstried/SuspiciousPaths further). Once it
	// elapses, the next Analyze call resets the pattern to a clean slate.
	BlockedUntil   time.Time
	LastScore      float64
	LastIndicators []string
}

// reset clears all accumulated signal state, as if this were a newly-seen
// actor. Callers must hold mu for writing.
func (p *ScanPattern) reset() {
	p.FirstSeen = time.Now()
	p.RequestCount = 0
	p.UniquePathstried = []string{}
	p.SequentialPaths = false
	p.RapidRequests = false
	p.SuspiciousPaths = []string{}
	p.NotFoundCount = 0
	p.BlockedUntil = time.Time{}
	p.LastScore = 0
	p.LastIndicators = nil
}

// Result contains detection results
type Result struct {
	IsRecon           bool
	IsPortScan        bool
	IsDNSEnum         bool
	IsPathEnum        bool
	Score             float64
	Indicators        []string
	RecommendedAction string
}

// NewDetector creates a new pre-attack detector
func NewDetector(cfg Config) *Detector {
	if cfg.ReconThreshold == 0 {
		cfg.ReconThreshold = 20
	}
	if cfg.PortScanWindow == 0 {
		cfg.PortScanWindow = 1 * time.Minute
	}
	if cfg.DNSEnumThreshold == 0 {
		cfg.DNSEnumThreshold = 10
	}
	if cfg.SuspiciousPathsCount == 0 {
		cfg.SuspiciousPathsCount = 5
	}
	if cfg.BlockDuration == 0 {
		cfg.BlockDuration = 15 * time.Minute
	}

	d := &Detector{
		config:   cfg,
		shutdown: make(chan struct{}),
	}
	go d.evictionLoop()
	return d
}

// evictionLoop periodically reclaims idle scan patterns so scanPatterns
// (keyed by every distinct IP the detector has ever seen) stays bounded
// instead of growing for the life of the process.
func (d *Detector) evictionLoop() {
	ticker := time.NewTicker(patternEvictionInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			d.cleanup()
		case <-d.shutdown:
			return
		}
	}
}

// cleanup removes patterns that are both idle and not currently blocked.
// A pattern still under an active BlockedUntil is never evicted early --
// eviction is purely a memory-bound concern, independent of block duration.
func (d *Detector) cleanup() {
	staleThreshold := time.Now().Add(-patternStaleAfter)
	d.scanPatterns.Range(func(key, value interface{}) bool {
		pattern := value.(*ScanPattern)
		pattern.mu.RLock()
		lastSeen := pattern.LastSeen
		blockedUntil := pattern.BlockedUntil
		pattern.mu.RUnlock()

		stillBlocked := !blockedUntil.IsZero() && time.Now().Before(blockedUntil)
		if !stillBlocked && lastSeen.Before(staleThreshold) {
			d.scanPatterns.Delete(key)
			atomic.AddInt64(&d.patternCount, -1)
		}
		return true
	})
}

// Stop halts the background eviction goroutine. Safe to call once; intended
// for tests and graceful shutdown, not for repeated/concurrent use.
func (d *Detector) Stop() {
	close(d.shutdown)
}

// Analyze analyzes request for pre-attack signals
func (d *Detector) Analyze(r *http.Request) *Result {
	result := &Result{
		Indicators: []string{},
	}

	if !d.config.Enabled {
		return result
	}

	ip := getClientIP(r)
	path := r.URL.Path

	// Get or create scan pattern. LoadOrStore (not Load-then-Store) closes a
	// race where two concurrent first-requests from the same new IP would
	// otherwise each create and store their own pattern, silently dropping
	// one goroutine's tracking.
	newPattern := &ScanPattern{
		IP:               ip,
		FirstSeen:        time.Now(),
		UniquePathstried: []string{},
		SuspiciousPaths:  []string{},
	}
	patternVal, loaded := d.scanPatterns.LoadOrStore(ip, newPattern)
	if !loaded {
		atomic.AddInt64(&d.patternCount, 1)
	}
	pattern := patternVal.(*ScanPattern)

	pattern.mu.Lock()
	defer pattern.mu.Unlock()

	// REQ SVALINN-PREATTACK-PERMALOCK-001: a still-active block short-circuits
	// to the cached verdict without touching any counters below, so a blocked
	// actor's own continued requests can't grow UniquePathstried/
	// SuspiciousPaths further. Once BlockedUntil has passed, reset gives this
	// actor a genuinely clean slate -- the bug this fixes is that the old
	// code had no such reset at all, so any actor that ever crossed the BLOCK
	// threshold stayed blocked for the life of the process.
	if !pattern.BlockedUntil.IsZero() {
		if time.Now().Before(pattern.BlockedUntil) {
			result.Score = pattern.LastScore
			result.Indicators = pattern.LastIndicators
			result.RecommendedAction = "BLOCK"
			return result
		}
		pattern.reset()
	}

	// Update pattern
	pattern.LastSeen = time.Now()
	pattern.RequestCount++
	if len(pattern.UniquePathstried) < maxTrackedPaths {
		pattern.UniquePathstried = append(pattern.UniquePathstried, path)
	}

	// 1. Detect reconnaissance (many 404s)
	if r.Context().Value("status") == 404 {
		pattern.NotFoundCount++
	}

	if pattern.NotFoundCount > d.config.ReconThreshold {
		result.IsRecon = true
		result.Indicators = append(result.Indicators, "excessive_404s")
	}

	// 2. Detect path enumeration
	if len(pattern.UniquePathstried) > d.config.SuspiciousPathsCount {
		result.IsPathEnum = true
		result.Indicators = append(result.Indicators, "path_enumeration")
	}

	// 3. Detect rapid sequential requests (automation)
	timeSinceFirst := pattern.LastSeen.Sub(pattern.FirstSeen)
	if timeSinceFirst < d.config.PortScanWindow && pattern.RequestCount > 50 {
		pattern.RapidRequests = true
		result.Indicators = append(result.Indicators, "rapid_requests")
	}

	// 4. Check for suspicious paths
	suspiciousPaths := []string{
		"/.git", "/.env", "/.aws", "/.ssh",
		"/admin", "/phpmyadmin", "/wp-admin",
		"/config", "/backup", "/test",
		"/.well-known", "/robots.txt", "/sitemap.xml",
	}

	for _, susPath := range suspiciousPaths {
		if strings.Contains(path, susPath) && len(pattern.SuspiciousPaths) < maxTrackedPaths {
			pattern.SuspiciousPaths = append(pattern.SuspiciousPaths, path)
		}
	}

	if len(pattern.SuspiciousPaths) >= 3 {
		result.IsRecon = true
		result.Indicators = append(result.Indicators, "suspicious_path_probing")
	}

	// 5. Sequential path testing (1, 2, 3, 4...)
	if d.detectSequentialPaths(pattern.UniquePathstried) {
		pattern.SequentialPaths = true
		result.Indicators = append(result.Indicators, "sequential_enumeration")
	}

	// Calculate score
	score := 0.0
	if result.IsRecon {
		score += 0.4
	}
	if result.IsPathEnum {
		score += 0.3
	}
	if pattern.RapidRequests {
		score += 0.2
	}
	if pattern.SequentialPaths {
		score += 0.1
	}

	result.Score = score

	// Determine action
	if score >= 0.7 {
		result.RecommendedAction = "BLOCK"
		pattern.BlockedUntil = time.Now().Add(d.config.BlockDuration)
		pattern.LastScore = result.Score
		pattern.LastIndicators = result.Indicators
	} else if score >= 0.4 {
		result.RecommendedAction = "MONITOR"
	} else {
		result.RecommendedAction = "ALLOW"
	}

	return result
}

// detectSequentialPaths detects sequential path testing
func (d *Detector) detectSequentialPaths(paths []string) bool {
	if len(paths) < 5 {
		return false
	}

	// Check last 5 paths for numeric sequences
	recent := paths[len(paths)-5:]
	sequential := 0

	for i := 0; i < len(recent)-1; i++ {
		// Simple heuristic: check if paths differ by single digit
		if d.pathsDifferBySingleChar(recent[i], recent[i+1]) {
			sequential++
		}
	}

	return sequential >= 3
}

// pathsDifferBySingleChar checks if two paths differ by a single character
func (d *Detector) pathsDifferBySingleChar(a, b string) bool {
	if len(a) != len(b) {
		return false
	}

	diff := 0
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			diff++
		}
	}

	return diff == 1
}

// GetStats returns detector statistics
func (d *Detector) GetStats() map[string]interface{} {
	trackedIPs := 0
	reconDetected := 0

	d.scanPatterns.Range(func(_, val interface{}) bool {
		trackedIPs++
		pattern := val.(*ScanPattern)
		pattern.mu.RLock()
		notFound := pattern.NotFoundCount
		pattern.mu.RUnlock()
		if notFound > d.config.ReconThreshold {
			reconDetected++
		}
		return true
	})

	return map[string]interface{}{
		"tracked_ips":    trackedIPs,
		"recon_detected": reconDetected,
		"enabled":        d.config.Enabled,
	}
}

// Helper
// getClientIP resolves the request's client address, which keys the scan
// patterns behind recon and path-enumeration detection. Trust decisions live in
// netutil (REQ SVALINN-CLIENTIP-SPOOF-002): only the local nginx peer may speak
// for another address, so a scanner cannot rotate a forged header to stay under
// the recon thresholds.
func getClientIP(r *http.Request) string {
	return netutil.TrustedClientIP(r)
}
