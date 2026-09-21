/*
Package server - SVALINN Taunts and Norse Rune Responses

This file contains the signature SVALINN features:
- Norse taunt messages for attackers
- Rune error responses (Elder Futhark)
- Honeypot responses with mock data

Taunts (and any SVALINN/rune branding) only ever appear on the *overt*
handleBlocked response, which already tells the caller "SVALINN blocked
you" -- there's no deception to protect there. handleHoneypot's response
bodies are deliberately kept free of any such branding: their entire job
is to look like a real leaked file/endpoint, and a taunt embedded in every
one of them is a free fingerprint that lets an attacker identify (and
then skip) every other honeypot after seeing just one (REQ
SVALINN-HONEYPOT-DEFP-001).
*/
package server

import (
	"fmt"
	"math/rand"
	"net/http"
	"time"
)

// SVALINN Rune - ᛊᚹᚨᛚᛁᚾᚾ in Elder Futhark
const SvalinnRune = "ᛊᚹᚨᛚᛁᚾᚾ"

// Taunt messages for attackers - signature SVALINN feature!
// Every message includes the SVALINN rune for maximum trolling effect
var svalinnTaunts = []string{
	"ᛊᚹᚨᛚᛁᚾᚾ 🐺 SVALINN: What the hell are you doing here? lmao",
	"ᛊᚹᚨᛚᛁᚾᚾ 🛡️ Nice try, script kiddie. SVALINN sees everything.",
	"ᛊᚹᚨᛚᛁᚾᚾ ⚔️ Valhalla awaits... but not for you.",
	"ᛊᚹᚨᛚᛁᚾᚾ 🎭 You just fell into a honeypot. GG.",
	"ᛊᚹᚨᛚᛁᚾᚾ 🐺 Your IP is now famous. Congrats!",
	"ᛊᚹᚨᛚᛁᚾᚾ 🔮 SVALINN predicted you'd try this. Boring.",
	"ᛊᚹᚨᛚᛁᚾᚾ 🪓 Odin's watching. So is SVALINN.",
	"ᛊᚹᚨᛚᛁᚾᚾ 💀 You call that hacking? My grandmother scans better.",
	"ᛊᚹᚨᛚᛁᚾᚾ 🐕 Good boy! Now go fetch somewhere else.",
	"ᛊᚹᚨᛚᛁᚾᚾ 🎪 Welcome to the circus. You're the clown.",
	"ᛊᚹᚨᛚᛁᚾᚾ 🗡️ The Einherjar are laughing at you.",
	"ᛊᚹᚨᛚᛁᚾᚾ 🌪️ Thor's hammer has struck. Your request is dust.",
	"ᛊᚹᚨᛚᛁᚾᚾ 🦅 Huginn and Muninn saw you coming. Try harder.",
	"ᛊᚹᚨᛚᛁᚾᚾ 🔥 Ragnarok won't save you from this honeypot.",
	"ᛊᚹᚨᛚᛁᚾᚾ 💎 Achievement unlocked: Caught by SVALINN!",
	"ᛊᚹᚨᛚᛁᚾᚾ 🏰 Asgard's gates remain shut. Try /robots.txt maybe?",
	"ᛊᚹᚨᛚᛁᚾᚾ 🐉 Níðhöggr is impressed. You fell for EVERYTHING.",
	"ᛊᚹᚨᛚᛁᚾᚾ ⚡ Mjölnir would be disappointed in this attack.",
	"ᛊᚹᚨᛚᛁᚾᚾ 🌈 Bifrost logged your IP. The Norns know your fate.",
	"ᛊᚹᚨᛚᛁᚾᚾ 🎯 Loki tricks better than you. And he's a trickster god.",
	"ᛊᚹᚨᛚᛁᚾᚾ 🦌 Even Freya's cats are faster than your scan.",
	"ᛊᚹᚨᛚᛁᚾᚾ 🔱 Return to /dev/null where you belong.",
	"ᛊᚹᚨᛚᛁᚾᚾ 🎲 The Norns already knew you'd fail. They're never wrong.",
	"ᛊᚹᚨᛚᛁᚾᚾ 🏹 Ullr's archery is more accurate than your exploits.",
	"ᛊᚹᚨᛚᛁᚾᚾ 🌊 Welcome to Hel. Population: You (and your bot).",
}

// GetRandomTaunt returns a random taunt message
func GetRandomTaunt() string {
	rand.Seed(time.Now().UnixNano())
	return svalinnTaunts[rand.Intn(len(svalinnTaunts))]
}

// SvalinnShieldResponse is the signature error response format
type SvalinnShieldResponse struct {
	Error  string      `json:"error"`
	Shield *ShieldInfo `json:"_shield"`
}

// ShieldInfo contains Norse mythology themed security info
type ShieldInfo struct {
	Rune     string `json:"rune"`
	Name     string `json:"name"`
	Message  string `json:"message"`
	Warning  string `json:"warning"`
	Prophecy string `json:"prophecy,omitempty"`
	Taunt    string `json:"taunt,omitempty"`
}

// NewShieldResponse creates a new SVALINN shield error response
func NewShieldResponse(errorMsg string, includeTaunt bool) SvalinnShieldResponse {
	shield := &ShieldInfo{
		Rune:    SvalinnRune,
		Name:    "SVALINN",
		Message: "You stand before the Shield of Asgard.",
		Warning: "Heimdall watches. Your path has been recorded in the Bifrost logs.",
	}

	if includeTaunt {
		shield.Taunt = GetRandomTaunt()
		shield.Prophecy = "Turn back, or face the wrath of the Einherjar."
	}

	return SvalinnShieldResponse{
		Error:  errorMsg,
		Shield: shield,
	}
}

// handleBlocked returns a SVALINN shield response for blocked requests
func (s *Server) handleBlocked(w http.ResponseWriter, r *http.Request, reason string) {
	clientIP := s.getClientIP(r)

	s.log.Warn("Request blocked by SVALINN",
		"ip", clientIP,
		"path", r.URL.Path,
		"reason", reason,
		"user_agent", r.UserAgent(),
	)

	response := NewShieldResponse(reason, true)
	w.Header().Set("X-Svalinn-Shield", "active")
	w.Header().Set("X-Blocked-By", "SVALINN")
	s.jsonResponse(w, http.StatusForbidden, response)
}

// handleHoneypot returns a deceptive honeypot response. Response bodies
// deliberately carry no SVALINN/rune/HONEYPOT branding -- see the package
// doc comment (REQ SVALINN-HONEYPOT-DEFP-001). Detection is entirely
// server-side via HoneypotTriggered below.
func (s *Server) handleHoneypot(w http.ResponseWriter, r *http.Request, trapType string) {
	clientIP := s.getClientIP(r)

	// Rich colorful logging with emoji 🍯
	s.log.HoneypotTriggered(clientIP, trapType, 75)

	// Different responses based on what they're looking for
	switch trapType {
	case "admin":
		// Fake admin login page
		html := `<!DOCTYPE html>
<html>
<head><title>Admin Panel</title></head>
<body style="font-family: Arial; max-width: 400px; margin: 100px auto; text-align: center;">
<h1>AEGIS Admin</h1>
<form action="/admin/login" method="POST">
<input name="user" placeholder="Username" style="margin: 10px; padding: 10px; width: 80%;">
<input name="pass" type="password" placeholder="Password" style="margin: 10px; padding: 10px; width: 80%;">
<button style="margin: 10px; padding: 10px 30px;">Login</button>
</form>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))

	case "env":
		// Fake .env file
		env := fmt.Sprintf(`DB_PASSWORD=fake_password_12345
API_KEY=sk-fake-key-do-not-use
SECRET_KEY=this_is_a_trap
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
# Your IP has been logged: %s`, clientIP)
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(env))

	case "git":
		// Fake .git/config
		git := fmt.Sprintf(`[core]
  repositoryformatversion = 0
  filemode = true
# Logged: %s`, clientIP)
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(git))

	case "backup":
		// Fake backup response
		s.jsonResponse(w, http.StatusOK, map[string]interface{}{
			"status": "downloading",
			"file":   "backup.sql.gz",
			"size":   "2.4GB",
			"note":   "Just kidding. Your IP is now famous.",
		})

	case "api":
		// Fake sensitive API response
		s.jsonResponse(w, http.StatusOK, map[string]interface{}{
			"users": []map[string]string{
				{"id": "1", "email": "admin@fake.com", "password": "nice_try_lol"},
				{"id": "2", "email": "root@fake.com", "password": "password123"},
			},
			"_note": "Your IP has been logged.",
		})

	case "database":
		// Fake database dump
		sql := fmt.Sprintf(`-- Your IP: %s - Now famous!
CREATE TABLE hackers_caught (ip VARCHAR, timestamp DATETIME, shame_level INT);
INSERT INTO hackers_caught VALUES ('%s', NOW(), 9001);
-- Over 9000!`, clientIP, clientIP)
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(sql))

	case "phpunit_rce":
		// Fake PHPUnit eval-stdin.php — look like a vulnerable PHP app
		php := `<!DOCTYPE html>
<html><head><title>PHPUnit</title></head>
<body>
<h1>PHPUnit 4.8.28 by Sebastian Bergmann and contributors.</h1>
<pre>
Runtime:       PHP 7.2.10-0ubuntu0.18.04.1
Configuration: /var/www/html/phpunit.xml

Time: 0 ms, Memory: 2.00MB
OK (0 tests, 0 assertions)
</pre>
</body></html>`
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("X-Powered-By", "PHP/7.2.10")
		w.Header().Set("Server", "Apache/2.4.29 (Ubuntu)")
		w.Write([]byte(php))

	case "scanner_bait":
		// Generic scanner bait — return just enough to be interesting
		s.jsonResponse(w, http.StatusOK, map[string]interface{}{
			"status":  "ok",
			"version": "1.0.3",
			"server":  "nginx/1.18.0",
		})

	case "api_docs":
		// Fake Swagger/OpenAPI spec — juicy enough to keep them probing
		s.jsonResponse(w, http.StatusOK, map[string]interface{}{
			"openapi": "3.0.1",
			"info": map[string]interface{}{
				"title":   "AEGIS Internal API",
				"version": "2.1.0",
			},
			"paths": map[string]interface{}{
				"/api/users":   map[string]string{"get": "List users"},
				"/api/tokens":  map[string]string{"post": "Generate token"},
				"/api/configs": map[string]string{"get": "System configuration"},
			},
		})

	case "graphql":
		// Fake GraphQL introspection response
		s.jsonResponse(w, http.StatusOK, map[string]interface{}{
			"data": map[string]interface{}{
				"__schema": map[string]interface{}{
					"types": []map[string]string{
						{"name": "User", "kind": "OBJECT"},
						{"name": "Token", "kind": "OBJECT"},
						{"name": "Query", "kind": "OBJECT"},
					},
				},
			},
		})

	case "framework_debug":
		// Fake Spring Boot actuator / Laravel Telescope / debug response
		s.jsonResponse(w, http.StatusOK, map[string]interface{}{
			"activeProfiles": []string{"production"},
			"propertySources": []map[string]interface{}{
				{
					"name": "systemEnvironment",
					"properties": map[string]interface{}{
						"DB_HOST":    map[string]string{"value": "10.0.0.2"},
						"SECRET_KEY": map[string]string{"value": "s3cr3t_prod_" + clientIP},
						"API_KEY":    map[string]string{"value": "fake_api_key_do_not_use"},
					},
				},
			},
		})

	case "server_info":
		// Fake server status page
		s.jsonResponse(w, http.StatusOK, map[string]interface{}{
			"server":  "Apache/2.4.41 (Ubuntu)",
			"uptime":  "45 days 12:34:56",
			"load":    "0.42 0.38 0.35",
			"workers": map[string]int{"idle": 12, "busy": 3},
		})

	case "ide_leak":
		// Fake VSCode SFTP config or DS_Store
		if r.URL.Path == "/.vscode/sftp.json" {
			s.jsonResponse(w, http.StatusOK, map[string]interface{}{
				"host":       "10.0.0.5",
				"port":       22,
				"username":   "deploy",
				"password":   "nice_try_" + clientIP,
				"remotePath": "/var/www/html",
			})
		} else {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write([]byte(fmt.Sprintf("\x00\x00\x00\x01Bud1\x00%s", clientIP)))
		}

	case "docker":
		// Fake Docker Registry catalog
		s.jsonResponse(w, http.StatusOK, map[string]interface{}{
			"repositories": []string{"app/backend", "app/frontend", "infra/nginx"},
			"_logged":      clientIP,
		})

	case "exchange_probe":
		// Fake Exchange response
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("X-OWA-Version", "15.1.2507.6")
		html := fmt.Sprintf(`<!DOCTYPE html><html><head><title>Outlook</title></head><body>
<div id="owa_loading">Loading Outlook Web App...</div>
<!-- IP: %s --></body></html>`, clientIP)
		w.Write([]byte(html))

	case "jira_probe":
		// Fake Jira/Confluence response
		s.jsonResponse(w, http.StatusOK, map[string]interface{}{
			"groupId":    "com.atlassian.jira",
			"artifactId": "jira-webapp-dist",
			"version":    "8.20.1",
		})

	case "enterprise_probe":
		// Fake Struts login
		w.Header().Set("Content-Type", "text/html")
		html := fmt.Sprintf(`<!DOCTYPE html><html><head><title>Login</title></head><body>
<form action="/login.action" method="POST">
<input name="username" placeholder="Username">
<input name="password" type="password" placeholder="Password">
<button type="submit">Login</button>
</form><!-- %s --></body></html>`, clientIP)
		w.Write([]byte(html))

	case "setup_wizard":
		// Fake setup wizard — look like an unfinished installation
		s.jsonResponse(w, http.StatusOK, map[string]interface{}{
			"status":   "setup_required",
			"step":     1,
			"steps":    []string{"database", "admin_account", "configuration", "complete"},
			"database": map[string]string{"type": "mysql", "host": "localhost", "status": "pending"},
		})

	case "docker_config":
		// Fake docker-compose.yml — juicy infrastructure details
		yaml := fmt.Sprintf(`version: "3.8"
services:
  app:
    image: registry.internal:5000/aegis-app:latest
    environment:
      - DATABASE_URL=postgres://admin:S3cr3t_Pr0d!@db:5432/aegis
      - REDIS_URL=redis://:r3d1s_p4ss@redis:6379
      - JWT_SECRET=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9_trap
      - STRIPE_SECRET_KEY=sk_live_FAKE_%s
    ports:
      - "8080:3000"
    depends_on:
      - db
      - redis
  db:
    image: postgres:15
    environment:
      - POSTGRES_PASSWORD=S3cr3t_Pr0d!
    volumes:
      - pgdata:/var/lib/postgresql/data
  redis:
    image: redis:7-alpine
    command: redis-server --requirepass r3d1s_p4ss
# Logged IP: %s | Nice infrastructure hunting!`, clientIP, clientIP)
		w.Header().Set("Content-Type", "text/yaml")
		w.Write([]byte(yaml))

	case "credential_leak":
		// Fake GCP/Firebase credentials — they'll try to use these
		s.jsonResponse(w, http.StatusOK, map[string]interface{}{
			"type":           "service_account",
			"project_id":     "aegis-prod-382917",
			"private_key_id": "a1b2c3d4e5f6" + clientIP,
			"private_key":    "-----BEGIN RSA PRIVATE KEY-----\nFAKE_KEY_" + clientIP + "\n-----END RSA PRIVATE KEY-----",
			"client_email":   "aegis-sa@aegis-prod-382917.iam.gserviceaccount.com",
			"client_id":      "109876543210",
			"auth_uri":       "https://accounts.google.com/o/oauth2/auth",
			"token_uri":      "https://oauth2.googleapis.com/token",
			"_note":          "Your attempt has been logged and reported.",
		})

	case "k8s_secrets":
		// Fake Kubernetes secrets — irresistible to cloud attackers
		s.jsonResponse(w, http.StatusOK, map[string]interface{}{
			"kind":       "SecretList",
			"apiVersion": "v1",
			"items": []map[string]interface{}{
				{
					"metadata": map[string]string{"name": "db-credentials", "namespace": "default"},
					"type":     "Opaque",
					"data": map[string]string{
						"username": "YWRtaW4=",
						"password": "ZmFrZV9wYXNzd29yZF8xMjM=",
					},
				},
				{
					"metadata": map[string]string{"name": "stripe-api-key", "namespace": "default"},
					"type":     "Opaque",
					"data": map[string]string{
						"secret_key": "c2tfbGl2ZV9GQUtFX3Rlc3RfdHJhcA==",
					},
				},
				{
					"metadata": map[string]string{"name": "tls-cert", "namespace": "default"},
					"type":     "kubernetes.io/tls",
					"data": map[string]string{
						"tls.crt": "FAKE_TLS_CERT",
						"tls.key": "FAKE_TLS_KEY_" + clientIP,
					},
				},
			},
		})

	case "payment_config":
		// Fake Stripe/payment config — maximum temptation
		s.jsonResponse(w, http.StatusOK, map[string]interface{}{
			"stripe": map[string]interface{}{
				"publishable_key": "pk_live_51Hx" + clientIP[:minDisplayLen(clientIP, 8)] + "FAKE",
				"secret_key":      "sk_live_51Hx_FAKE_TRAP_" + clientIP,
				"webhook_secret":  "whsec_fake_trap_" + clientIP,
			},
			"paypal": map[string]interface{}{
				"client_id":     "AeXiS-FAKE-" + clientIP,
				"client_secret": "EKt7_FAKE_SECRET",
			},
			"mode":     "production",
			"currency": "USD",
			"_warning": "Every credential you try to use here will be traced back to your IP.",
		})

	case "wordpress_config":
		// Fake wp-config.php — classic WordPress treasure
		php := fmt.Sprintf(`<?php
define('DB_NAME', 'wp_aegis_prod');
define('DB_USER', 'wp_admin');
define('DB_PASSWORD', 'FakePass_%s');
define('DB_HOST', '10.0.1.50:3306');
define('DB_CHARSET', 'utf8mb4');
$table_prefix = 'wp_aegis_';
define('AUTH_KEY',         'fake:trap:%s');
define('SECURE_AUTH_KEY',  'your-ip-is-logged');
define('LOGGED_IN_KEY',    'nice-try-script-kiddie');
define('NONCE_KEY',        'einherjar-are-watching');
define('WP_DEBUG', false);
define('WP_SITEURL', 'https://aegis-internal.example.com');
// Logged IP: %s
`, clientIP, clientIP, clientIP)
		w.Header().Set("Content-Type", "application/x-httpd-php")
		w.Header().Set("X-Powered-By", "PHP/8.1.2")
		w.Write([]byte(php))

	case "laravel_internal":
		// Fake Laravel Ignition/Horizon — framework internals
		if r.URL.Path == "/_ignition/health-check" {
			s.jsonResponse(w, http.StatusOK, map[string]interface{}{
				"can_execute_commands": true,
				"version":              "2.5.2",
				"laravel_version":      "9.52.16",
			})
		} else {
			// Horizon stats
			s.jsonResponse(w, http.StatusOK, map[string]interface{}{
				"status":    "running",
				"processes": 8,
				"jobs": map[string]interface{}{
					"completed": 145823,
					"failed":    12,
					"pending":   3,
					"recent_failed": []map[string]string{
						{"job": "ProcessPayment", "error": "Stripe timeout", "failed_at": "2026-02-12 10:30:00"},
					},
				},
				"wait": map[string]int{"default": 0, "payments": 2, "emails": 0},
			})
		}

	case "cve_probe":
		// CVE baseline probe — return a convincing 404-like response
		// Scanners use this to calibrate their 404 detection, so we return
		// something that looks like a real custom error page
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		html := `<!DOCTYPE html>
<html><head><title>404 Not Found</title></head>
<body style="font-family:Arial;text-align:center;padding:50px">
<h1>404</h1><p>The requested resource was not found.</p>
<hr><p style="color:#999">nginx/1.24.0</p>
</body></html>`
		w.Write([]byte(html))

	default:
		// Generic blocked with taunt
		s.handleBlocked(w, r, "Honeypot triggered")
	}
}

// minDisplayLen returns the smaller of the string length and maxLen (for safe slicing)
func minDisplayLen(s string, maxLen int) int {
	if len(s) < maxLen {
		return len(s)
	}
	return maxLen
}
