package server

import (
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"zentloop/internal/lures"
	"zentloop/internal/model"
)

var intelURLPattern = regexp.MustCompile(`(?i)https?://[^\s'"<>]+`)
var intelSensitiveJSONPattern = regexp.MustCompile(`(?i)("(?:password|passwd|pwd|secret|token|access_token|refresh_token|otp|code|authorization)"\s*:\s*)"(?:\\.|[^"\\])*"`)

func sensitiveIntelKey(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	for _, needle := range []string{"password", "passwd", "pwd", "secret", "token", "authorization", "credential", "otp", "mfa", "code"} {
		if strings.Contains(key, needle) {
			return true
		}
	}
	return false
}

func safeHTTPIntelText(rawQuery, body string) string {
	parts := []string{}
	if values, err := url.ParseQuery(rawQuery); err == nil {
		for key, rows := range values {
			if sensitiveIntelKey(key) {
				continue
			}
			parts = append(parts, rows...)
		}
	} else {
		parts = append(parts, rawQuery)
	}

	// Form posts are common for login probes. Never retain or inspect values
	// from credential-like fields. For non-form bodies, redact common JSON
	// credential fields before extracting passive URL indicators.
	if values, err := url.ParseQuery(body); err == nil && len(values) > 0 && strings.Contains(body, "=") {
		for key, rows := range values {
			if sensitiveIntelKey(key) {
				continue
			}
			parts = append(parts, rows...)
		}
	} else {
		redacted := intelSensitiveJSONPattern.ReplaceAllString(body, `${1}"[redacted]"`)
		parts = append(parts, redacted)
	}
	return strings.Join(parts, "\n")
}

func sanitizeIntelURL(raw string) (safe, host, filename string, ok bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", "", "", false
	}
	host = u.Hostname()
	filename = path.Base(u.Path)
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	return u.String(), host, filename, true
}

func commandTechnique(command string) (tool, technique string) {
	low := strings.ToLower(command)
	switch {
	case strings.Contains(low, "curl "):
		tool, technique = "curl", "download"
	case strings.Contains(low, "wget "):
		tool, technique = "wget", "download"
	case strings.Contains(low, "scp "):
		tool, technique = "scp", "file-transfer"
	case strings.Contains(low, "ssh "):
		tool, technique = "ssh", "lateral-movement"
	case strings.Contains(low, "nc ") || strings.Contains(low, "netcat ") || strings.Contains(low, "ncat "):
		tool, technique = "netcat", "network-transfer"
	}
	if strings.Contains(low, "| bash") || strings.Contains(low, "| sh") || strings.Contains(low, "chmod +x") || strings.Contains(low, "./") {
		technique = "payload-execution"
	}
	if strings.Contains(low, "crontab") || strings.Contains(low, "systemctl enable") || strings.Contains(low, "/etc/systemd/system") {
		technique = "persistence"
	}
	return tool, technique
}

func (s *TrapServer) recordHTTPIntelligence(ip, sessionID, rawQuery, body string) {
	rawForCanaries := rawQuery + "\n" + body
	joined := safeHTTPIntelText(rawQuery, body)
	seen := map[string]bool{}
	for _, raw := range intelURLPattern.FindAllString(joined, 6) {
		raw = strings.TrimRight(raw, ").,;]")
		if seen[raw] {
			continue
		}
		seen[raw] = true
		safeURL, host, filename, ok := sanitizeIntelURL(raw)
		if !ok {
			continue
		}
		tool, technique := commandTechnique(joined)
		if technique == "" {
			technique = "payload-reference"
		}
		_ = s.store.AddIntelSignal(model.IntelSignal{ID: newID(6), At: time.Now(), IP: ip, Protocol: "http", SessionID: sessionID, Kind: "payload", Tool: tool, Technique: technique, URL: safeURL, Host: host, Filename: filename, Summary: "HTTP payload/remote URL indicator: " + host})
	}
	for label, token := range lures.CanaryLabels(ip) {
		// Exact matches against ZentLoop's own synthetic values are safe to
		// detect even inside otherwise sensitive form fields. The raw form is
		// never persisted or copied into the signal.
		if token != "" && strings.Contains(rawForCanaries, token) {
			_ = s.store.AddIntelSignal(model.IntelSignal{ID: newID(6), At: time.Now(), IP: ip, Protocol: "http", SessionID: sessionID, Kind: "canary", Canary: label, Summary: "decoy token reused over HTTP: " + label})
		}
	}
}
