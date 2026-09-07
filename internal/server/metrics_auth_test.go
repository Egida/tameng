package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// REQ SVALINN-METRICS-AUTHGATE-001
//
// /metrics was registered with no auth middleware at all -- any caller could
// read svalinn_requests_total, svalinn_blocked_requests_total,
// svalinn_threats_detected_total, svalinn_active_actors, and
// svalinn_uptime_seconds with a plain unauthenticated GET. Found by a
// red-team assessment. Fix: gate it behind the same apiKeyMiddleware already
// protecting /api/v1/* and /taxii/collections/default/objects, rather than
// inventing a new auth mechanism.

// TestMetrics_RejectsUnauthenticatedCaller proves the vulnerability is
// closed: a plain GET with no key must never reach handleMetrics.
func TestMetrics_RejectsUnauthenticatedCaller(t *testing.T) {
	s := newRealTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET /metrics: got status %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if strings.Contains(rec.Body.String(), "svalinn_requests_total") {
		t.Fatalf("unauthenticated response leaked metrics body: %q", rec.Body.String())
	}
}

// TestMetrics_AcceptsValidAPIKey proves the fix isn't a blanket lockout --
// any key in Security.APIKeys still works.
func TestMetrics_AcceptsValidAPIKey(t *testing.T) {
	s := newRealTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("X-API-Key", "validapikey")
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics with a valid API key: got status %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "svalinn_requests_total") {
		t.Fatalf("authenticated response did not contain the expected metrics body: %q", rec.Body.String())
	}
}

// TestMetrics_AcceptsGodModeKey proves the shared apiKeyMiddleware behavior
// (God Mode key also satisfies any API-key-gated endpoint) applies here too,
// consistent with every other endpoint it already protects.
func TestMetrics_AcceptsGodModeKey(t *testing.T) {
	s := newRealTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("X-API-Key", "validgodkey")
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics with the God Mode key: got status %d, want 200", rec.Code)
	}
}
