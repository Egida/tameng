package waf

import "strings"

// REQ SVALINN-WAF-QUERYDECODE-001: internal/server/middleware.go passes
// r.URL.RawQuery (Go's raw, undecoded query string) into Scan. Go's HTTP
// request-line parser rejects any literal whitespace or control byte in a
// request URI before the application ever sees it (net/http's
// parseRequestLine cuts on the first two spaces; a URI space makes the
// third field an invalid HTTP version and the request 400s; stdlib also
// rejects raw control bytes outright) -- so no signature requiring `\s+`
// can EVER match on the raw query target in production, not "evadable",
// structurally impossible. Confirmed via 26 affected signatures (SQLI,
// RCE command-exec family, XSS-049, CLOUD-015, SUPPLY-004/010, EVADE-001)
// and a real regression: `UNION+SELECT` (the standard application/
// x-www-form-urlencoded space encoding used by essentially every browser
// and HTTP client) never matched SQLI-004's `UNION\s+(ALL\s+)?SELECT`.
//
// decodeQueryLenient percent/plus-decodes a query string the way
// url.QueryUnescape does, but never fails: url.QueryUnescape is
// all-or-nothing and errors on any '%' not followed by two hex digits,
// which would itself be a bypass -- an attacker appends one stray '%'
// anywhere in the query to make decoding fail and disable the decoded
// scan pass entirely. Malformed sequences are copied through literally
// instead. Single-pass by design: double encoding (e.g. %2527) is already
// caught on the raw form by NGBYP-009, so recursive decoding buys nothing
// and opens the double-decode bug class.
// DecodeQueryLenient is the exported form of decodeQueryLenient, for other
// internal packages (orchestrator, heuristics) that read r.URL.RawQuery
// directly and need the same lenient decode fallback the WAF's own scan path
// uses -- REQ SVALINN-HEURISTICS-RAWQUERY-001. See decodeQueryLenient for
// full behavior and rationale.
func DecodeQueryLenient(s string) string {
	return decodeQueryLenient(s)
}

func decodeQueryLenient(s string) string {
	if !strings.ContainsAny(s, "%+") {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '+':
			b.WriteByte(' ')
		case '%':
			if i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
				b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
				i += 2
			} else {
				b.WriteByte('%')
			}
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// isFormURLEncoded reports whether a Content-Type header value indicates a
// application/x-www-form-urlencoded body -- the one body encoding where
// '+'/percent-decoding via decodeQueryLenient is correct (unlike JSON,
// multipart, or raw binary bodies, where blind-decoding would corrupt
// content: a base64 '+' is data, not an encoded space).
func isFormURLEncoded(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "application/x-www-form-urlencoded")
}

func isHex(c byte) bool {
	switch {
	case '0' <= c && c <= '9':
		return true
	case 'a' <= c && c <= 'f':
		return true
	case 'A' <= c && c <= 'F':
		return true
	}
	return false
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}
