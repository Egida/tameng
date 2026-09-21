package server

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// REQ SVALINN-HONEYPOT-DEFP-001
//
// handleHoneypot injected the taunt (which always starts with SvalinnRune,
// "ᛊᚹᚨᛚᛁᚾᚾ") into nearly every trap-type response body, and independently
// of the taunt variable, ~15 of the ~25 case blocks also hardcoded literal
// "SVALINN"/"HONEYPOT" strings directly into the fake payload (comments,
// JSON fields, fake secret values). A single case-insensitive grep for
// "svalinn" or the rune sequence across any two responses fingerprinted
// nearly every trap type in one pass -- an attacker who ever saw one
// trap's body could enumerate and skip every other trap without probing
// it, defeating the entire point of the deception. Found in an external
// blind red-team round.
//
// Fix: removed the taunt injection and every hardcoded SVALINN/rune/
// HONEYPOT literal from the deceptive payload bodies across all trap
// types. Detection stays entirely server-side (s.log.HoneypotTriggered,
// already called on every trigger -- unchanged).
//
// handleBlocked's overt block page (and its own X-Svalinn-Shield /
// X-Blocked-By headers) is deliberately untouched: that response already
// tells the caller "SVALINN blocked you", so a taunt there isn't a
// deception leak -- it's not part of this finding.

// fingerprintMarkers must never appear (case-insensitively) in a honeypot
// trap response body after this fix.
var fingerprintMarkers = []string{"svalinn", strings.ToLower(SvalinnRune), "honeypot"}

// honeypotTrapCase pairs a trapType label handleHoneypot's switch
// recognizes with a representative request path, so failures are
// reported against a realistic-looking probe.
type honeypotTrapCase struct {
	trapType string
	path     string
}

// allHoneypotTrapCases covers every branch of handleHoneypot's switch,
// including both sub-paths of "ide_leak" and "laravel_internal".
func allHoneypotTrapCases() []honeypotTrapCase {
	return []honeypotTrapCase{
		{"admin", "/admin"},
		{"env", "/.env"},
		{"git", "/.git/config"},
		{"backup", "/backup.zip"},
		{"api", "/api/internal"},
		{"database", "/backup.sql"},
		{"phpunit_rce", "/eval-stdin.php"},
		{"scanner_bait", "/version"},
		{"api_docs", "/swagger.json"},
		{"graphql", "/graphql"},
		{"framework_debug", "/actuator/env"},
		{"server_info", "/server-status"},
		{"ide_leak", "/.vscode/sftp.json"},
		{"ide_leak", "/.DS_Store"},
		{"docker", "/v2/_catalog"},
		{"exchange_probe", "/owa"},
		{"jira_probe", "/rest/api/2/serverInfo"},
		{"enterprise_probe", "/login.action"},
		{"setup_wizard", "/setup/"},
		{"docker_config", "/docker-compose.yml"},
		{"credential_leak", "/credentials.json"},
		{"k8s_secrets", "/api/v1/namespaces/default/secrets"},
		{"payment_config", "/api/payment/config"},
		{"wordpress_config", "/wp-config.php.bak"},
		{"laravel_internal", "/_ignition/health-check"},
		{"laravel_internal", "/horizon/api/stats"},
		{"cve_probe", "/__cve_probe_cve_test_404"},
	}
}

// TestHandleHoneypot_ResponseBodiesCarryNoFingerprint proves the
// vulnerability is closed: no trap type's response body may contain any
// marker an attacker could grep for across trap types.
func TestHandleHoneypot_ResponseBodiesCarryNoFingerprint(t *testing.T) {
	s := newRealTestServer(t)

	for _, tc := range allHoneypotTrapCases() {
		tc := tc
		t.Run(tc.trapType+"_"+tc.path, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.path, nil)
			rec := httptest.NewRecorder()
			s.handleHoneypot(rec, req, tc.trapType)

			body := strings.ToLower(rec.Body.String())
			for _, marker := range fingerprintMarkers {
				if strings.Contains(body, marker) {
					t.Fatalf("trapType %q body contains fingerprintable marker %q:\n%s", tc.trapType, marker, rec.Body.String())
				}
			}
		})
	}
}

// TestHandleHoneypot_StillRespondsNormally proves the fix only removed the
// in-band leak, not the deceptive response itself.
func TestHandleHoneypot_StillRespondsNormally(t *testing.T) {
	s := newRealTestServer(t)

	req := httptest.NewRequest("GET", "/.env", nil)
	rec := httptest.NewRecorder()
	s.handleHoneypot(rec, req, "env")

	if rec.Code != 200 {
		t.Fatalf("env trap: got status %d, want 200", rec.Code)
	}
	if rec.Body.Len() == 0 {
		t.Fatalf("env trap: response body is empty")
	}
	if !strings.Contains(rec.Body.String(), "DB_PASSWORD") {
		t.Fatalf("env trap: response no longer looks like a fake .env file: %s", rec.Body.String())
	}
}

// TestHandleHoneypot_UnknownTrapTypeFallsBackToBlocked covers the switch's
// default branch -- an unrecognized trapType must still fall back to the
// overt handleBlocked response (unaffected by this fix; that response is
// allowed to carry SVALINN branding, see the package doc comment) rather
// than panicking or falling through silently.
func TestHandleHoneypot_UnknownTrapTypeFallsBackToBlocked(t *testing.T) {
	s := newRealTestServer(t)

	req := httptest.NewRequest("GET", "/never-registered", nil)
	rec := httptest.NewRecorder()
	s.handleHoneypot(rec, req, "unrecognized_trap_type")

	if rec.Code != 403 {
		t.Fatalf("unknown trapType: got status %d, want 403 (handleBlocked)", rec.Code)
	}
}

// TestHandleHoneypot_PaymentConfigShortIP covers minDisplayLen's
// len(s) < maxLen branch: payment_config slices clientIP to build a fake
// publishable key, and every other subtest uses a >=8-char IP, which only
// ever exercises the maxLen-clamped branch.
func TestHandleHoneypot_PaymentConfigShortIP(t *testing.T) {
	s := newRealTestServer(t)

	req := httptest.NewRequest("GET", "/api/payment/config", nil)
	req.RemoteAddr = "1.2.3.4:1234" // 7-char IP, shorter than minDisplayLen's 8-char cap
	rec := httptest.NewRecorder()
	s.handleHoneypot(rec, req, "payment_config")

	if rec.Code != 200 {
		t.Fatalf("payment_config with short IP: got status %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "1.2.3.4") {
		t.Fatalf("payment_config with short IP: response doesn't reflect the short clientIP: %s", rec.Body.String())
	}
}
