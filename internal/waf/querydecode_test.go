package waf

import "testing"

func TestDecodeQueryLenient_PlusBecomesSpace(t *testing.T) {
	got := decodeQueryLenient("id=1%27+UNION+SELECT+username%2Cpassword+FROM+users--")
	want := "id=1' UNION SELECT username,password FROM users--"
	if got != want {
		t.Fatalf("decodeQueryLenient() = %q, want %q", got, want)
	}
}

func TestDecodeQueryLenient_NoEncodingIsNoOp(t *testing.T) {
	in := "search=hello+world+no+percent+here" // still has '+', so not a true no-op path; test that separately
	got := decodeQueryLenient(in)
	if got != "search=hello world no percent here" {
		t.Fatalf("decodeQueryLenient(%q) = %q", in, got)
	}

	plain := "id=42&name=alice"
	if decodeQueryLenient(plain) != plain {
		t.Fatalf("decodeQueryLenient(%q) should be unchanged, got %q", plain, decodeQueryLenient(plain))
	}
}

func TestDecodeQueryLenient_MalformedPercentDoesNotFailOrPanic(t *testing.T) {
	// A single stray '%' at the end, or not followed by two hex digits,
	// must NOT cause an error/panic/truncation -- url.QueryUnescape would
	// fail outright here, which (if used naively) would let an attacker
	// disable the entire decoded scan pass with one extra '%'.
	cases := []struct{ in, want string }{
		{"id=1%27+UNION+SELECT+x--%", "id=1' UNION SELECT x--%"},
		{"a=%zz", "a=%zz"},
		{"a=100%", "a=100%"},
		{"a=%", "a=%"},
	}
	for _, c := range cases {
		got := decodeQueryLenient(c.in)
		if got != c.want {
			t.Errorf("decodeQueryLenient(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDecodeQueryLenient_MalformedPercentDoesNotHideRealPayload(t *testing.T) {
	// The exact bypass this decoder must resist: appending a stray '%'
	// must not prevent the real SQLi payload elsewhere in the same string
	// from still being decoded correctly.
	got := decodeQueryLenient("id=1%27+UNION+SELECT+username%2Cpassword+FROM+users--&x=%")
	want := "id=1' UNION SELECT username,password FROM users--&x=%"
	if got != want {
		t.Fatalf("decodeQueryLenient() = %q, want %q", got, want)
	}
}

// --- Engine.Scan integration tests ---

func TestScan_URLEncodedUnionSelectIsDetected(t *testing.T) {
	e := newSSRFTestEngine(t) // block_threshold 0.8, log_threshold 0.5 -- reused helper, unrelated to SSRF specifically

	result := e.Scan("/app/search", "id=1%27+UNION+SELECT+username%2Cpassword+FROM+users--", "", map[string]string{}, "curl/8.0")
	if !hasSignature(result.Matches, "SQLI-004") {
		t.Fatalf("Scan: SQLI-004 did not match a real UNION SELECT payload in +-encoded query form (this is the exact bypass that slipped a real payload past the WAF in production-shaped traffic)")
	}
	if !result.Blocked {
		t.Errorf("Scan: expected block (score=%.2f) for a real SQLi payload", result.Score)
	}
}

func TestScan_QueryDecodePassDoesNotDoubleCountRawMatches(t *testing.T) {
	e := newSSRFTestEngine(t)

	// "127.0.0.1" (SSRF-001) needs no decoding at all -- matches identically
	// on raw and decoded forms. Must be counted exactly once, not twice.
	result := e.Scan("/fetch", "url=http://127.0.0.1:8080/admin", "", map[string]string{}, "curl/8.0")

	count := 0
	for _, m := range result.Matches {
		if m.Signature != nil && m.Signature.ID == "SSRF-001" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("SSRF-001 matched %d times on a query needing no decoding, want exactly 1 (double-counting would inflate scores and manufacture new false positives)", count)
	}
}

func TestScan_EVADE006ExcludedFromDecodedQueryPass(t *testing.T) {
	e := newSSRFTestEngine(t)

	// %0A decodes to a real control byte (LF). EVADE-006 targets control
	// bytes but is deliberately excluded from the decoded pass -- it adds
	// no real detection value here (CRLF-001/003/004 and EVADE-005 already
	// flag these on the raw percent-encoded form) and would otherwise
	// silently promote a query from CRLF-003's log-only 0.7 to a hard block.
	result := e.Scan("/", "note=hello%0Aworld", "", map[string]string{}, "curl/8.0")
	if hasSignature(result.Matches, "EVADE-006") {
		t.Errorf("Scan: EVADE-006 matched via the decoded-query pass -- it should only ever be evaluated against the raw form")
	}
}

func TestScan_MalformedPercentInQueryDoesNotDisableDetection(t *testing.T) {
	e := newSSRFTestEngine(t)

	// The end-to-end version of the decoder-level bypass test: a stray '%'
	// appended to an otherwise-real SQLi payload must not suppress the block.
	result := e.Scan("/app/search", "id=1%27+UNION+SELECT+username%2Cpassword+FROM+users--&x=%", "", map[string]string{}, "curl/8.0")
	if !result.Blocked {
		t.Errorf("Scan: a trailing malformed '%%' suppressed detection of a real SQLi payload (score=%.2f) -- this is exactly the bypass decodeQueryLenient exists to prevent", result.Score)
	}
}
