package waf

import "testing"

// REQ SVALINN-WAF-QUERYDECODE-001 (body-target follow-up): the same
// raw-vs-decoded gap that made SQLI-004 dead on the query target is
// identical on the body target for application/x-www-form-urlencoded
// POST bodies -- the canonical shape for login/search forms, exactly
// where classic SQLi lands. Confirmed by Opus judge review: a real
// UNION SELECT payload in a urlencoded body scored 0.00 (not blocked) on
// this session's WAFB-005-narrowed-but-not-yet-body-decoded state.

func formURLEncodedHeaders() map[string]string {
	return map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
}

func TestScan_URLEncodedFormBodyUnionSelectIsDetected(t *testing.T) {
	e := newSSRFTestEngine(t)

	result := e.Scan("/login", "", "id=1%27+UNION+SELECT+username%2Cpassword+FROM+users--", formURLEncodedHeaders(), "curl/8.0")
	if !hasSignature(result.Matches, "SQLI-004") {
		t.Fatalf("Scan: SQLI-004 did not match a real UNION SELECT payload in a +-encoded urlencoded form body")
	}
	if !result.Blocked {
		t.Errorf("Scan: expected block (score=%.2f) for a real SQLi payload in a form-urlencoded body", result.Score)
	}
}

func TestScan_URLEncodedFormBodyOtherSQLiVariantsDetected(t *testing.T) {
	e := newSSRFTestEngine(t)

	cases := []string{
		"u=admin%27+OR+1%3D1--",
		"x=%3Bcat+%2Fetc%2Fpasswd",
	}
	for _, body := range cases {
		result := e.Scan("/login", "", body, formURLEncodedHeaders(), "curl/8.0")
		if !result.Blocked {
			t.Errorf("Scan(body=%q): expected block (score=%.2f)", body, result.Score)
		}
	}
}

func TestScan_NonFormBodyIsNotDecoded(t *testing.T) {
	e := newSSRFTestEngine(t)

	// A JSON body containing a literal '+' must NOT be mangled by the
	// urlencoded decoder -- Content-Type gates this deliberately, since a
	// JSON/multipart/base64 '+' is data, not an encoded space.
	jsonBody := `{"formula":"1+1=2","note":"UNION+SELECT is not urlencoded here"}`
	result := e.Scan("/api/notes", "", jsonBody, map[string]string{"Content-Type": "application/json"}, "curl/8.0")
	if result.Blocked {
		t.Errorf("Scan: a JSON body was incorrectly decoded/blocked (score=%.2f) -- Content-Type gating failed", result.Score)
	}
}

func TestScan_BodyPrefilterDoesNotHideDecodedOnlyLiterals(t *testing.T) {
	e := newSSRFTestEngine(t)

	// The AC literal-presence prefilter runs against the RAW body. A
	// signature whose required literal only appears after decoding (here,
	// the raw body contains "%3Cscript" not "<script") must still be
	// reachable via the decoded-body union, not silently skipped.
	result := e.Scan("/comment", "", "text=hello+%3Cscript%3Ealert(1)%3C%2Fscript%3E", formURLEncodedHeaders(), "curl/8.0")
	if !result.Blocked {
		t.Errorf("Scan: a urlencoded XSS payload was not blocked (score=%.2f) -- decoded-body literal presence not reaching the prefilter", result.Score)
	}
}

func TestScan_FormBodyDoubleCountingPrevented(t *testing.T) {
	e := newSSRFTestEngine(t)

	result := e.Scan("/fetch", "", "url=http://127.0.0.1:8080/admin", formURLEncodedHeaders(), "curl/8.0")
	count := 0
	for _, m := range result.Matches {
		if m.Signature != nil && m.Signature.ID == "SSRF-001" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("SSRF-001 matched %d times on a form body needing no decoding, want exactly 1", count)
	}
}
