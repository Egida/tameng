package waf

import (
	"path/filepath"
	"testing"
)

// REQ SVALINN-WAF-WAFB005-PLAINWORD-001: WAFB-005 "Leet speak evasion"
// (`s[e3]l[e3]c[t7]|u[n7][i1][o0]n`) is supposed to catch digit-substituted
// obfuscation of "select"/"union", but a character class always matches its
// literal member too -- so the plain, unobfuscated English words "select"
// and "union" match it as well, defeating half the signature's own purpose
// while creating unnecessary block risk for any site whose organic traffic
// mentions either word (a form field named "select", "credit union", etc).
// 18 days of shield.svalinn.id production logs show 0 confirmed benign hits
// from this specific signature (all 9 real blocks were genuine SQLi/scanner
// traffic) -- this is a latent code-quality bug, not one with observed
// production harm on that deployment, unlike SSRF-002.

func newWAFBypassTestEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := NewEngine(filepath.Join(t.TempDir(), "nonexistent-signatures.json"), 0.9, 0.5)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

func TestWAFB005_DoesNotFalsePositiveOnPlainEnglishWords(t *testing.T) {
	e := newWAFBypassTestEngine(t)

	benign := []struct{ path, query, body string }{
		{"/", "field=select", ""},
		{"/products", "sort=select", ""},
		{"/", "", `{"plan":"credit union membership"}`},
		{"/", "q=please+select+an+option", ""},
		{"/", "q=european+union+policy", ""},
	}

	for _, c := range benign {
		result := e.Scan(c.path, c.query, c.body, map[string]string{}, "Mozilla/5.0")
		if hasSignature(result.Matches, "WAFB-005") {
			t.Errorf("Scan(query=%q, body=%q): WAFB-005 matched a plain, unobfuscated English word (false positive)", c.query, c.body)
		}
	}
}

func TestWAFB005_StillDetectsLeetspeakSubstitutions(t *testing.T) {
	e := newWAFBypassTestEngine(t)

	// Every non-literal digit-substitution combination for "select" and
	// "union" -- proves the fix didn't just narrow the pattern down to a
	// handful of examples while missing others.
	leetForms := []string{
		"s3lect", "sel3ct", "selec7", "s3l3ct", "s3lec7", "sel3c7", "s3l3c7",
		"u7ion", "un1on", "uni0n", "u71on", "u7i0n", "un10n", "u710n",
	}

	for _, form := range leetForms {
		result := e.Scan("/", "q="+form, "", map[string]string{}, "curl/8.0")
		if !hasSignature(result.Matches, "WAFB-005") {
			t.Errorf("Scan(query=%q): WAFB-005 did not match a genuine leetspeak substitution", "q="+form)
		}
	}
}

func TestWAFB005_CaseInsensitiveLeetspeakStillDetected(t *testing.T) {
	e := newWAFBypassTestEngine(t)

	result := e.Scan("/", "q=S3LECT", "", map[string]string{}, "curl/8.0")
	if !hasSignature(result.Matches, "WAFB-005") {
		t.Fatalf("Scan: WAFB-005 did not match an uppercase leetspeak substitution (addSignature applies (?i))")
	}
}
