package waf

import (
	"path/filepath"
	"testing"
)

// REQ SVALINN-WAF-SSRF002-UAFP-001: SSRF-002's pattern `0\.0\.0\.0` scans
// the user_agent target, and Chrome/Chromium/Edge's frozen UA version format
// (MAJOR.0.0.0, e.g. "Chrome/120.0.0.0") always contains the literal
// substring "0.0.0.0" -- confirmed against 18 days of production logs from
// shield.svalinn.id, where this alone (score 0.8 == block_threshold 0.8)
// 403'd ordinary Chromium-family browsers on requests to "/".

func newSSRFTestEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := NewEngine(filepath.Join(t.TempDir(), "nonexistent-signatures.json"), 0.8, 0.5)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

func hasSignature(matches []Match, id string) bool {
	for _, m := range matches {
		if m.Signature != nil && m.Signature.ID == id {
			return true
		}
	}
	return false
}

func TestSSRF002_DoesNotFalsePositiveOnChromeUserAgent(t *testing.T) {
	e := newSSRFTestEngine(t)

	chromeUAs := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	}

	for _, ua := range chromeUAs {
		result := e.Scan("/", "", "", map[string]string{}, ua)
		if hasSignature(result.Matches, "SSRF-002") {
			t.Errorf("Scan(ua=%q): SSRF-002 matched a plain browser User-Agent (false positive)", ua)
		}
		if result.Blocked {
			t.Errorf("Scan(ua=%q): request blocked (score=%.2f) on an ordinary browser homepage visit", ua, result.Score)
		}
	}
}

func TestSSRF002_StillDetectsRealSSRFInQuery(t *testing.T) {
	e := newSSRFTestEngine(t)

	result := e.Scan("/fetch", "url=http://0.0.0.0:8080/admin", "", map[string]string{}, "curl/8.0")
	if !hasSignature(result.Matches, "SSRF-002") {
		t.Fatalf("Scan: SSRF-002 did not match a genuine 0.0.0.0 SSRF payload in the query string")
	}
	if !result.Blocked {
		t.Errorf("Scan: expected block (score=%.2f) for an SSRF payload targeting 0.0.0.0", result.Score)
	}
}

func TestSSRF002_StillDetectsRealSSRFInBody(t *testing.T) {
	e := newSSRFTestEngine(t)

	result := e.Scan("/webhook", "", `{"callback_url":"http://0.0.0.0/internal"}`, map[string]string{}, "curl/8.0")
	if !hasSignature(result.Matches, "SSRF-002") {
		t.Fatalf("Scan: SSRF-002 did not match a genuine 0.0.0.0 SSRF payload in the body")
	}
	if !result.Blocked {
		t.Errorf("Scan: expected block (score=%.2f) for an SSRF payload targeting 0.0.0.0", result.Score)
	}
}

func TestSSRF002_StillDetectsBareIPAtStringBoundary(t *testing.T) {
	e := newSSRFTestEngine(t)

	result := e.Scan("/fetch", "host=0.0.0.0", "", map[string]string{}, "curl/8.0")
	if !hasSignature(result.Matches, "SSRF-002") {
		t.Fatalf("Scan: SSRF-002 did not match a bare 0.0.0.0 preceded by a non-digit boundary")
	}
}

func TestSSRF002_StillDetectsQueryExactlyAtStringStart(t *testing.T) {
	e := newSSRFTestEngine(t)

	// Exercises the `^` alternation branch specifically: the query value IS
	// the entire scanned string, nothing precedes it.
	result := e.Scan("/fetch", "0.0.0.0", "", map[string]string{}, "curl/8.0")
	if !hasSignature(result.Matches, "SSRF-002") {
		t.Fatalf("Scan: SSRF-002 did not match 0.0.0.0 at the very start of the scanned string")
	}
}

func TestSSRF002_StillDetectsInPath(t *testing.T) {
	e := newSSRFTestEngine(t)

	// "path" remains a declared target for SSRF-002; this was previously
	// untested even though query/body were.
	result := e.Scan("/proxy/0.0.0.0/admin", "", "", map[string]string{}, "curl/8.0")
	if !hasSignature(result.Matches, "SSRF-002") {
		t.Fatalf("Scan: SSRF-002 did not match 0.0.0.0 in the request path")
	}
}

func TestSSRF002_TargetsExcludeUserAgent(t *testing.T) {
	e := newSSRFTestEngine(t)

	sig := e.GetSignature("SSRF-002")
	if sig == nil {
		t.Fatal("SSRF-002 signature not found in engine")
	}
	for _, target := range sig.Targets {
		if target == "user_agent" {
			t.Fatalf("SSRF-002.Targets includes user_agent (got %v) -- this is what caused the Chrome/Edge false positive", sig.Targets)
		}
	}
}

func TestSSRF002_RecoversWildcardDNSBypassAfterDroppingTrailingBoundary(t *testing.T) {
	e := newSSRFTestEngine(t)

	// A trailing boundary group would have blocked these known SSRF-bypass
	// forms (wildcard-DNS services that resolve to whatever IP is embedded
	// in the hostname, and a trailing-dot FQDN) for zero FP-reduction
	// benefit, since the Chrome FP was only ever caused by the leading
	// digit. Confirms the fix doesn't regress detection of these.
	cases := []string{
		"url=http://0.0.0.0.nip.io/",
		"url=http://0.0.0.0.xip.io/",
		"url=http://0.0.0.0./",
	}
	for _, q := range cases {
		result := e.Scan("/fetch", q, "", map[string]string{}, "curl/8.0")
		if !hasSignature(result.Matches, "SSRF-002") {
			t.Errorf("Scan(query=%q): SSRF-002 did not match a known wildcard-DNS/trailing-dot SSRF bypass form", q)
		}
	}
}
