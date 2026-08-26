package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/koodoxz/tameng/internal/logger"
)

func newQueryLenTestServer(t *testing.T) *Server {
	t.Helper()
	return &Server{
		log:   logger.New("test"),
		stats: &Stats{},
	}
}

// TestQueryLengthLimitMiddleware_PassesQueryAtOrUnderCapUnchanged confirms
// ordinary and boundary-sized queries reach the downstream handler
// untouched.
func TestQueryLengthLimitMiddleware_PassesQueryAtOrUnderCapUnchanged(t *testing.T) {
	s := newQueryLenTestServer(t)
	reached := false
	chain := s.queryLengthLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/search?q=hello+world", nil)
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	if !reached || rec.Code != http.StatusOK {
		t.Fatalf("reached=%v status=%d, want reached=true status=200 for an ordinary query", reached, rec.Code)
	}
}

// TestQueryLengthLimitMiddleware_ExactBoundary_8KiBPassesOneByteOverFails
// pins the precise 8KiB boundary with an absolute byte count, not derived
// from maxScannedQueryBytes, so an off-by-one on the constant itself can't
// silently make this test vacuous (same rationale as
// TestBodySizeLimitMiddleware_ExactBoundary_8KiBPassesOneByteOverFails).
func TestQueryLengthLimitMiddleware_ExactBoundary_8KiBPassesOneByteOverFails(t *testing.T) {
	s := newQueryLenTestServer(t)

	atCap := "q=" + strings.Repeat("a", 8*1024-2)
	chainAtCap := s.queryLengthLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	reqAtCap := httptest.NewRequest(http.MethodGet, "/search", nil)
	reqAtCap.URL.RawQuery = atCap
	if len(reqAtCap.URL.RawQuery) != 8*1024 {
		t.Fatalf("test setup bug: query len = %d, want exactly %d", len(reqAtCap.URL.RawQuery), 8*1024)
	}
	recAtCap := httptest.NewRecorder()
	chainAtCap.ServeHTTP(recAtCap, reqAtCap)
	if recAtCap.Code != http.StatusOK {
		t.Errorf("exactly 8KiB query: status = %d, want 200", recAtCap.Code)
	}

	overCap := "q=" + strings.Repeat("a", 8*1024-1)
	chainOverCap := s.queryLengthLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("downstream handler must not be reached for a query one byte over the 8KiB cap")
	}))
	reqOverCap := httptest.NewRequest(http.MethodGet, "/search", nil)
	reqOverCap.URL.RawQuery = overCap
	if len(reqOverCap.URL.RawQuery) != 8*1024+1 {
		t.Fatalf("test setup bug: query len = %d, want exactly %d", len(reqOverCap.URL.RawQuery), 8*1024+1)
	}
	recOverCap := httptest.NewRecorder()
	chainOverCap.ServeHTTP(recOverCap, reqOverCap)
	if recOverCap.Code != http.StatusRequestURITooLong {
		t.Errorf("8KiB+1 byte query: status = %d, want %d", recOverCap.Code, http.StatusRequestURITooLong)
	}
}

// TestQueryLengthLimitMiddleware_RejectionBodyIsWellFormed pins the exact
// response shape so a future refactor can't silently change the
// client-visible contract.
func TestQueryLengthLimitMiddleware_RejectionBodyIsWellFormed(t *testing.T) {
	s := newQueryLenTestServer(t)
	chain := s.queryLengthLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("downstream handler must not be reached for an oversized query")
	}))

	req := httptest.NewRequest(http.MethodGet, "/search", nil)
	req.URL.RawQuery = "q=" + strings.Repeat("z", maxScannedQueryBytes+1)
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestURITooLong {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestURITooLong)
	}
	body := rec.Body.String()
	for _, want := range []string{`"error":"URI_TOO_LONG"`, `"max_bytes":8192`} {
		if !strings.Contains(body, want) {
			t.Errorf("response body %q missing %q", body, want)
		}
	}
}

// TestQueryLengthLimitMiddleware_RealServerReachesAppUnrejectedAtCap proves
// the Phase-0 finding this REQ depends on: an 8KiB query is NOT already
// rejected by net/http's own stdlib request-line/header ceiling before this
// middleware runs, using a real listening server (httptest.NewServer), not
// httptest.NewRequest (which bypasses wire-level request-line parsing
// entirely and would prove nothing about reachability).
func TestQueryLengthLimitMiddleware_RealServerReachesAppUnrejectedAtCap(t *testing.T) {
	reached := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	q := "q=" + strings.Repeat("a", 8*1024-2)
	resp, err := http.Get(srv.URL + "/?" + q)
	if err != nil {
		t.Fatalf("http.Get: %v", err)
	}
	resp.Body.Close()

	if !reached {
		t.Fatal("an 8KiB query never reached the app -- stdlib rejected it before this middleware could, contradicting this REQ's Phase-0 measurement")
	}
}
