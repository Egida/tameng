package orchestrator

import (
	"net/http/httptest"
	"testing"
)

// TestDetectTechnique_DecodedFormNotFlagged is a regression guard against
// re-adding the decoded-query fallback a Category-C Opus judge review
// (2026-08-26) found unsafe on this path: detectTechnique feeds a live
// enforcement path (ThreatScore, Exploitation stage, can escalate to
// Block/IP-ban via determineCountermeasure), and "-- "/"' or " are common
// enough in ordinary decoded text to false-positive-escalate real users.
// This exact payload ("text=hello+--+world" -> decodes to "hello -- world")
// was the review's concrete failure case; it must stay unflagged.
func TestDetectTechnique_DecodedFormNotFlagged(t *testing.T) {
	req := httptest.NewRequest("GET", "/comments", nil)
	req.URL.RawQuery = "text=hello+--+world"

	if got := detectTechnique(req); got != "" {
		t.Fatalf("detectTechnique(%q) = %q, want empty (decoded-form SQLi indicators must not be checked here -- see REQ SVALINN-HEURISTICS-RAWQUERY-001)", req.URL.RawQuery, got)
	}
}

// TestDetectTechnique_RawFormStillWorks confirms "union"/"select" (single
// words, unaffected by '+'-encoding) still match on the raw query without
// needing any decode.
func TestDetectTechnique_RawFormStillWorks(t *testing.T) {
	req := httptest.NewRequest("GET", "/search", nil)
	req.URL.RawQuery = "q=union+select+password+from+users"

	if got := detectTechnique(req); got != "SQL Injection" {
		t.Fatalf("detectTechnique(%q) = %q, want %q", req.URL.RawQuery, got, "SQL Injection")
	}
}

// TestDetectTechnique_BenignQueryNotFlagged is the anti-theater guard: the
// test above only means something if ordinary traffic isn't flagged too.
// Uses a '+'-containing query (so it isn't vacuous the way a query with no
// '%'/'+' would be -- such a query never exercises any decode path at all).
func TestDetectTechnique_BenignQueryNotFlagged(t *testing.T) {
	req := httptest.NewRequest("GET", "/products", nil)
	req.URL.RawQuery = "category=running+shoes&sort=price"

	if got := detectTechnique(req); got != "" {
		t.Fatalf("detectTechnique(%q) = %q, want empty", req.URL.RawQuery, got)
	}
}
