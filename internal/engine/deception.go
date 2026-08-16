package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"

	"zentloop/internal/config"
	"zentloop/internal/lures"
	"zentloop/internal/model"
)

type Deception struct{ cfg config.Config }

func NewDeception(cfg config.Config) *Deception { return &Deception{cfg: cfg} }

type Response struct {
	Status      int
	ContentType string
	Body        []byte
	Headers     map[string]string
	Label       string
	Depth       int
	LoopInc     int
	Delay       time.Duration
}

func tokens(sessionID string) (string, string) {
	h := sha256.Sum256([]byte("hp:" + sessionID))
	return hex.EncodeToString(h[:6]), hex.EncodeToString(h[6:12])
}

func (d *Deception) Build(r *http.Request, ss *model.Session) Response {
	p := strings.ToLower(r.URL.Path)
	a, b := tokens(ss.ID)
	canaries := lures.CanaryLabels(ss.IP)
	depth := ss.Depth
	fr := ss.Frustration
	delay := time.Duration(min(fr*180, d.cfg.MaxDelayMS)) * time.Millisecond
	resp := Response{Status: 200, ContentType: "text/html; charset=utf-8", Depth: depth, Delay: delay}

	// Scanner control paths deliberately designed to test whether arbitrary names
	// suddenly exist must stay boring. Serving a lure here would reveal the deception
	// layer instead of attracting the scanner through a realistic product surface.
	if isSyntheticExistenceProbe(p) {
		resp.Status = http.StatusNotFound
		resp.Label = "plausible-404-control-probe"
		resp.ContentType = "text/html; charset=utf-8"
		resp.Body = []byte("<!doctype html><title>404 Not Found</title><h1>Not Found</h1><p>The requested resource was not found.</p>")
		return resp
	}

	if family, ok := buildFamilyDeception(r, ss, a, b); ok {
		family.Delay = delay
		return family
	}

	switch {
	case strings.Contains(p, "/sdk/weblanguage"):
		resp.ContentType = "application/xml; charset=utf-8"
		resp.Label = "fake-hikvision-sdk"
		resp.Depth = max(depth, 1)
		resp.Body = []byte(`<?xml version="1.0" encoding="UTF-8"?><Language><version>V5.7.12</version><language>en</language><resource>/SDK/config/` + a + `</resource></Language>`)
	case strings.Contains(p, "/.env"):
		resp.ContentType = "text/plain; charset=utf-8"
		resp.Label = "fake-env"
		resp.Depth = max(depth, 1)
		resp.Body = []byte(fmt.Sprintf("APP_NAME=Portal\nAPP_ENV=production\nAPP_DEBUG=false\nAPP_URL=https://portal.internal\nDB_HOST=db-primary\nDB_PORT=5432\nDB_NAME=customers\nDB_USER=svc_web\nDB_PASSWORD=%s\nCACHE_URL=redis://cache-01:6379/2\nREGISTRY_HOST=registry.internal\nGIT_HOST=git.prod.internal\nOPS_GATEWAY=ops-gw-01\nJWT_PRIVATE_KEY_PATH=/run/secrets/jwt-prod.key\nINTERNAL_API=/api/v1/internal/%s\nINTERNAL_API_TOKEN=%s\nBACKUP_HOST=backup-01\nBACKUP_TOKEN=%s\nOPS_STATUS=/manage/status/%s\nBACKUP_INDEX=/backup/%s/\n", b+a, a, canaries["internal-api"], canaries["backup"], b, b))
	case p == "/+cscoe+/logon.html":
		resp.Label = "fake-cisco-webvpn-login"
		resp.Depth = max(depth, 1)
		resp.Body = []byte(remoteAccessHTML("Secure Remote Access", "/+CSCOE+/login.html?session="+a, "Corporate", "Continue"))
	case strings.HasPrefix(p, "/+cscoe+/login.html"):
		resp.Status = http.StatusFound
		resp.Headers = map[string]string{"Location": "/+CSCOE+/portal.html?token=" + b}
		resp.Label = "fake-webvpn-auth-redirect"
		resp.Depth = max(depth, 2)
		resp.Body = []byte("<html><body>Redirecting to portal...</body></html>")
	case strings.HasPrefix(p, "/+cscoe+/portal.html"):
		resp.Label = "fake-webvpn-portal"
		resp.Depth = max(depth, 3)
		resp.Body = []byte(managementHTML("Remote Access Portal", []linkItem{{"Diagnostics", "/diag/status/" + a}, {"Legacy VPN", "/remote/login?realm=legacy"}, {"Support bundle", "/backup/" + b + "/"}}))
	case strings.HasPrefix(p, "/remote/logincheck"):
		resp.Status = http.StatusFound
		resp.Headers = map[string]string{"Location": "/remote/login?realm=corp&reason=expired"}
		resp.Label = "fake-ssl-vpn-expired"
		resp.Depth = max(depth, 2)
		resp.LoopInc = 1
		resp.Body = []byte("<html><body>Session expired. Redirecting...</body></html>")
	case strings.HasPrefix(p, "/remote/login"):
		resp.Label = "fake-ssl-vpn-login"
		resp.Depth = max(depth, 1)
		resp.Body = []byte(remoteAccessHTML("SSL VPN", "/remote/logincheck?sid="+a, "Corporate", "Login"))
	case p == "/web/":
		resp.Status = http.StatusFound
		resp.Headers = map[string]string{"Location": "/webpages/login.html?sid=" + a}
		resp.Label = "fake-device-web-redirect"
		resp.Depth = max(depth, 1)
		resp.Body = []byte("<html><body>Loading device console...</body></html>")
	case p == "/webpages/login.html" || p == "/doc/index.html":
		resp.Label = "fake-embedded-login"
		resp.Depth = max(depth, 1)
		resp.Body = []byte(deviceLoginHTML("Device Management", "/auth/session/"+a, "admin", "Firmware 3.4.17 build 240712"))
	case p == "/dispatch.asp":
		resp.Label = "fake-gateway-dispatch"
		resp.Depth = max(depth, 1)
		resp.Body = []byte(managementHTML("Gateway Maintenance", []linkItem{{"System status", "/manage/status/" + a}, {"Diagnostics", "/diag/status/" + b}, {"Configuration backup", "/config/export/" + a + ".cfg"}}))
	case p == "/manage/account/login" || p == "/login" || p == "/login.html" || p == "/login.htm" || p == "/login.jsp":
		title := "Operations Portal"
		if p == "/login.jsp" {
			title = "Application Management Console"
		}
		resp.Label = "fake-management-login"
		resp.Depth = max(depth, 1)
		if r.Method == http.MethodPost {
			ss.LoginAttempts++
			if ss.LoginAttempts == 1 {
				resp.Status = http.StatusUnauthorized
				resp.Label = "fake-login-rejected"
				resp.Body = []byte(loginHTMLMessage(title, p, "administrator", "Sign in", "Invalid username or password. 2 attempts remaining."))
			} else {
				resp.Status = http.StatusFound
				resp.Headers = map[string]string{"Location": "/auth/mfa/" + a}
				resp.Label = "fake-login-mfa-redirect"
				resp.Depth = max(depth, 2)
				resp.Body = []byte("<html><body>Additional verification required. Redirecting...</body></html>")
			}
		} else {
			resp.Body = []byte(loginHTMLMessage(title, p, "administrator", "Sign in", "Single sign-on temporarily unavailable. Local administrator access remains enabled."))
		}
	case strings.HasPrefix(p, "/auth/mfa/"):
		resp.Depth = max(depth, 2)
		resp.Label = "fake-mfa-challenge"
		if r.Method == http.MethodPost {
			resp.Status = http.StatusFound
			resp.Headers = map[string]string{"Location": "/auth/recovery/" + b}
			resp.Label = "fake-mfa-recovery-redirect"
			resp.LoopInc = 1
			resp.Body = []byte("<html><body>Verification service unavailable. Loading recovery options...</body></html>")
		} else {
			resp.Body = []byte(mfaHTML("Two-factor authentication", p, "/sso/status", "/help/admin"))
		}
	case strings.HasPrefix(p, "/auth/recovery/"):
		resp.Label = "fake-auth-recovery"
		resp.Depth = max(depth, 3)
		resp.Body = []byte(managementHTML("Account Recovery", []linkItem{{"Check identity provider status", "/sso/status?ref=" + a}, {"Administrator recovery guide", "/help/admin?ref=" + b}, {"Try local login again", "/login?reason=mfa_unavailable"}}))
	case p == "/sso/status":
		resp.ContentType = "application/json"
		resp.Label = "fake-sso-status"
		resp.Depth = max(depth, 4)
		resp.Body = mustJSON(map[string]any{"provider": "corp-idp", "status": "degraded", "local_admin_fallback": true, "incident": "IAM-" + strings.ToUpper(a[:6]), "retry_after": 90})
	case p == "/help/admin":
		resp.Label = "fake-admin-help"
		resp.Depth = max(depth, 4)
		resp.Body = []byte(managementHTML("Administrator Recovery", []linkItem{{"Legacy operations console", "/admin/" + a}, {"Configuration export", "/config/export/" + b + ".cfg"}, {"Authentication diagnostics", "/diag/status/" + a}}))
	case strings.HasPrefix(p, "/auth/session/"):
		resp.Status = http.StatusFound
		resp.Headers = map[string]string{"Location": "/manage/status/" + b}
		resp.Label = "fake-auth-follow"
		resp.Depth = max(depth, 2)
		resp.Body = []byte("<html><body>Authentication accepted. Loading console...</body></html>")
	case strings.HasPrefix(p, "/manage/status/"):
		resp.Label = "fake-management-status"
		resp.Depth = max(depth, 3)
		resp.Body = []byte(managementHTML("System Management", []linkItem{{"Runtime diagnostics", "/diag/status/" + a}, {"Export configuration", "/config/export/" + b + ".cfg"}, {"Nightly backups", "/backup/" + b + "/"}, {"Internal inventory", "/ops/inventory?ref=" + a}}))
	case strings.HasPrefix(p, "/diag/status/"):
		resp.ContentType = "application/json"
		resp.Label = "fake-device-diagnostics"
		resp.Depth = max(depth, 4)
		resp.Body = mustJSON(map[string]any{"status": "ok", "uptime": "41d 07:18:22", "wan": "connected", "firmware": "3.4.17", "support_bundle": "/backup/" + b + "/", "config_export": "/config/export/" + a + ".cfg"})
	case strings.HasPrefix(p, "/config/export/"):
		resp.ContentType = "text/plain; charset=utf-8"
		resp.Label = "fake-config-export"
		resp.Depth = max(depth, 4)
		resp.Body = []byte(fmt.Sprintf("# configuration export\nhostname=ops-gw-01\nadmin_user=administrator\nauth_backend=local\nmanagement_vlan=30\napplication_host=prod-app-02\ndatabase_host=db-primary\nbackup_host=backup-01\nregistry_host=registry.internal\ninternal_api=/api/v1/internal/%s\ninternal_api_token=%s\nbackup_path=/backup/%s/\nbackup_token=%s\nsupport_token=%s\n", a, canaries["internal-api"], b, canaries["backup"], a+b))
	case p == "/ops/inventory" || p == "/internal/inventory":
		resp.ContentType = "text/plain; charset=utf-8"
		resp.Label = "fake-internal-inventory"
		resp.Depth = max(depth, 5)
		resp.Body = []byte(lures.Inventory() + "\n# ssh jump: ops-gw-01\n# backup auth token: " + canaries["backup"] + "\n")
	case p == "/v2/" || strings.HasPrefix(p, "/registry/v2/"):
		resp.ContentType = "application/json"
		resp.Label = "fake-container-registry"
		resp.Depth = max(depth, 5)
		resp.Headers = map[string]string{"Docker-Distribution-Api-Version": "registry/2.0", "Www-Authenticate": `Bearer realm="https://registry.internal/token",service="registry.internal"`}
		resp.Body = mustJSON(map[string]any{"repositories": []string{"platform/web", "platform/worker", "ops/backup-agent"}, "token_hint": canaries["registry"]})
	case strings.Contains(p, "/.git/config") || strings.HasPrefix(p, "/.git"):
		resp.ContentType = "text/plain; charset=utf-8"
		resp.Label = "fake-git"
		resp.Depth = max(depth, 1)
		resp.Body = []byte(fmt.Sprintf("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://git.internal.local/platform/web-%s.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n", a))
	case strings.Contains(p, "/swagger") || strings.Contains(p, "/openapi"):
		resp.ContentType = "application/json"
		resp.Label = "fake-openapi"
		resp.Depth = max(depth, 1)
		resp.Body = mustJSON(map[string]any{"openapi": "3.0.3", "info": map[string]string{"title": "Internal Platform API", "version": "1.8.4"}, "paths": map[string]any{"/api/v1/internal/" + a: map[string]any{"get": map[string]string{"summary": "internal status"}}}})
	case strings.Contains(p, "/wp-admin") || strings.Contains(p, "/wp-login"):
		resp.Label = "fake-wordpress"
		resp.Depth = max(depth, 1)
		resp.Body = []byte(loginHTML("WordPress", "/wp-admin/"+a, "Administrator", "Sign in"))
	case p == "/phpmyadmin" || strings.HasPrefix(p, "/phpmyadmin/"):
		resp.Label = "fake-db-admin"
		resp.Depth = max(depth, 1)
		resp.Body = []byte(loginHTML("phpMyAdmin", "/phpmyadmin/"+a, "Database server", "Log in"))
	case strings.Contains(p, "/api/v1/internal/") || strings.Contains(p, "/wp-admin/"+a) || strings.Contains(p, "/phpmyadmin/"+a):
		resp.ContentType = "application/json"
		resp.Label = "fake-internal-api"
		resp.Depth = max(depth, 2)
		resp.Body = mustJSON(map[string]any{"status": "ok", "node": "prod-app-02", "node_ip": "10.10.30.21", "build": "2026.08.14", "database": "db-primary:5432", "cache": "cache-01:6379", "registry": "registry.internal", "backup": "backup-01", "ops_gateway": "ops-gw-01", "api_token": canaries["internal-api"], "backup_index": "/backup/" + b + "/", "inventory": "/ops/inventory", "debug": false, "warning": "legacy export endpoint still enabled"})
	case strings.HasPrefix(p, "/backup/") && strings.HasSuffix(p, "config.old"):
		resp.ContentType = "text/plain; charset=utf-8"
		resp.Label = "fake-old-config"
		resp.Depth = max(depth, 4)
		resp.Body = []byte(fmt.Sprintf("REPORTING_MODE=legacy\nREPORTING_API=/api/v2/private/%s\nMIGRATION_PANEL=/admin/%s\n", b, a))
	case strings.HasPrefix(p, "/backup/") && strings.HasSuffix(p, "readme-migration.txt"):
		resp.ContentType = "text/plain; charset=utf-8"
		resp.Label = "fake-migration-note"
		resp.Depth = max(depth, 4)
		resp.Body = []byte(fmt.Sprintf("Migration unfinished. Old operations panel remains at /admin/%s until export service is retired.\n", a))
	case strings.HasPrefix(p, "/backup/") && strings.HasSuffix(p, "customers.sql"):
		resp.ContentType = "text/plain; charset=utf-8"
		resp.Label = "fake-sql-export"
		resp.Depth = max(depth, 4)
		resp.Body = []byte(fmt.Sprintf("-- nightly export\n-- generated 02:14 UTC\nINSERT INTO admins VALUES (1,'ops-admin','%s');\n-- panel moved during migration: /admin/%s\n", b+a, a))
	case strings.HasPrefix(p, "/backup/"):
		resp.Label = "fake-backup-index"
		resp.Depth = max(depth, 3)
		resp.Body = []byte(directoryHTML("/backup/"+b+"/", []string{"customers.sql", "config.old", "README-migration.txt"}))
	case strings.HasPrefix(p, "/admin/"):
		resp.Label = "fake-admin"
		resp.Depth = max(depth, 5)
		resp.Body = []byte(loginHTML("Operations Console", "/debug/"+b, "ops-admin", "Continue"))
	case strings.HasPrefix(p, "/debug/"):
		resp.ContentType = "application/json"
		resp.Label = "fake-debug"
		resp.Depth = max(depth, 6)
		resp.Body = mustJSON(map[string]any{"cluster": "green", "legacy_api": "/api/v2/private/" + b, "migration": "incomplete", "note": "v2 still reads export credentials"})
	case strings.HasPrefix(p, "/api/v2/private/"):
		resp.ContentType = "application/json"
		resp.Label = "loop-bait"
		resp.Depth = max(depth, 7)
		resp.LoopInc = 1
		resp.Body = mustJSON(map[string]any{"status": "degraded", "export_service": map[string]string{"index": "/backup/" + b + "/", "token": canaries["backup"]}, "retry_after_ms": 300 + fr*170})
	case strings.Contains(p, "/server-status"):
		resp.ContentType = "text/html; charset=utf-8"
		resp.Label = "fake-apache-status"
		resp.Depth = max(depth, 1)
		resp.Body = []byte(apacheStatusHTML(a, b))
	case strings.Contains(p, "/graphql"):
		resp.ContentType = "application/json"
		resp.Label = "fake-graphql"
		resp.Depth = max(depth, 1)
		resp.Body = mustJSON(map[string]any{"errors": []map[string]any{{"message": "GET query missing", "extensions": map[string]string{"internal_schema": "/api/v1/internal/" + a}}}})
	case strings.Contains(p, "/solr/"):
		resp.ContentType = "application/json"
		resp.Label = "fake-solr-admin"
		resp.Depth = max(depth, 1)
		resp.Body = mustJSON(map[string]any{"responseHeader": map[string]any{"status": 0, "QTime": 2}, "mode": "solrcloud", "node": "search-02", "backupLocation": "/backup/" + b + "/"})
	case strings.Contains(p, "/boaform/"):
		resp.Label = "fake-embedded-router"
		resp.Depth = max(depth, 1)
		resp.Body = []byte(deviceLoginHTML("Broadband Gateway", "/auth/session/"+a, "admin", "System software 1.0.9"))
	case strings.Contains(p, "/.aws/credentials"):
		resp.ContentType = "text/plain; charset=utf-8"
		resp.Label = "fake-cloud-credentials"
		resp.Depth = max(depth, 1)
		resp.Body = []byte(fmt.Sprintf("[production]\naws_access_key_id=AKIA%s\naws_secret_access_key=%s%s\nregion=eu-central-1\n# deployment metadata: /api/v1/internal/%s\n", strings.ToUpper(a)+strings.ToUpper(b[:4]), a+b, b+a, a))
	case strings.Contains(p, "/actuator"):
		resp.ContentType = "application/json"
		resp.Label = "fake-actuator"
		resp.Depth = max(depth, 1)
		resp.Body = []byte(`{"status":"UP","groups":["liveness","readiness"],"details":{"config":"/api/v1/internal/` + a + `"}}`)
	case strings.Contains(p, "/jenkins"):
		resp.Label = "fake-jenkins"
		resp.Depth = max(depth, 1)
		resp.Body = []byte(loginHTML("Jenkins", "/api/v1/internal/"+a, "Build server", "Sign in"))
	default:
		resp.Status = 404
		resp.Label = "plausible-404"
		resp.ContentType = "text/html; charset=utf-8"
		resp.Body = []byte("<!doctype html><title>404 Not Found</title><h1>Not Found</h1><p>The requested resource was not found.</p><!-- build:" + a + " -->")
	}
	// Escalation remains bounded and passive: at higher frustration levels, an occasional
	// plausible transient error wastes a retry without creating large responses or touching the client.
	if fr >= 4 && ss.RequestCount%7 == 0 {
		resp.Headers = nil
		resp.Status = http.StatusBadGateway
		resp.ContentType = "text/plain; charset=utf-8"
		resp.Body = []byte("upstream temporarily unavailable\n")
		resp.Label = "transient-upstream-error"
	}
	return resp
}

func isSyntheticExistenceProbe(p string) bool {
	p = strings.ToLower(strings.TrimSpace(p))
	if strings.Contains(p, "not_exist") || strings.Contains(p, "not-exist") || strings.Contains(p, "does-not-exist") || strings.Contains(p, "debug-trigger") {
		return true
	}
	base := strings.Trim(strings.TrimSpace(p), "/")
	if len(base) >= 18 && !strings.Contains(base, "/") {
		digits, letters := 0, 0
		for _, r := range base {
			switch {
			case r >= '0' && r <= '9':
				digits++
			case r >= 'a' && r <= 'z':
				letters++
			}
		}
		if digits >= 4 && letters >= 8 && (strings.Contains(base, "trigger") || strings.Contains(base, "probe")) {
			return true
		}
	}
	return false
}

func directoryHTML(base string, files []string) string {
	var b strings.Builder
	b.WriteString("<!doctype html><title>Index of " + html.EscapeString(base) + "</title><h1>Index of " + html.EscapeString(base) + "</h1><hr><pre>")
	for _, f := range files {
		b.WriteString(`<a href="` + html.EscapeString(base+f) + `">` + html.EscapeString(f) + `</a>` + "\n")
	}
	b.WriteString("</pre><hr><address>nginx/1.24</address>")
	return b.String()
}
func loginHTML(title, action, user, button string) string {
	return fmt.Sprintf(`<!doctype html><html><head><title>%s</title><meta name="robots" content="noindex"><style>body{font:14px system-ui;background:#f4f4f4}.box{width:320px;margin:12vh auto;background:white;padding:28px;border:1px solid #ddd}input{box-sizing:border-box;width:100%%;padding:10px;margin:7px 0}button{padding:10px 14px}</style></head><body><form class="box" method="post" action="%s"><h2>%s</h2><label>User</label><input name="user" value="%s"><label>Password</label><input name="password" type="password"><button>%s</button></form></body></html>`, html.EscapeString(title), html.EscapeString(action), html.EscapeString(title), html.EscapeString(user), html.EscapeString(button))
}

func loginHTMLMessage(title, action, user, button, message string) string {
	msg := ""
	if strings.TrimSpace(message) != "" {
		msg = `<div style="margin:12px 0;padding:9px;background:#fff6df;border:1px solid #e5cf95;color:#594813">` + html.EscapeString(message) + `</div>`
	}
	return fmt.Sprintf(`<!doctype html><html><head><title>%s</title><meta name="robots" content="noindex"><style>body{font:14px system-ui;background:#f4f4f4}.box{width:340px;margin:12vh auto;background:white;padding:28px;border:1px solid #ddd}input{box-sizing:border-box;width:100%%;padding:10px;margin:7px 0}button{padding:10px 14px}.foot{margin-top:18px;color:#777;font-size:11px}</style></head><body><form class="box" method="post" action="%s"><h2>%s</h2>%s<label>User</label><input name="user" value="%s" autocomplete="username"><label>Password</label><input name="password" type="password" autocomplete="current-password"><button>%s</button><div class="foot">Operations authentication service</div></form></body></html>`, html.EscapeString(title), html.EscapeString(action), html.EscapeString(title), msg, html.EscapeString(user), html.EscapeString(button))
}

func mfaHTML(title, action, statusHref, helpHref string) string {
	return fmt.Sprintf(`<!doctype html><html><head><title>%s</title><meta name="robots" content="noindex"><style>body{font:14px system-ui;background:#eef1f4}.box{width:350px;margin:12vh auto;background:white;padding:28px;border:1px solid #c9d0d5}input{box-sizing:border-box;width:100%%;padding:10px;margin:8px 0;letter-spacing:4px}button{padding:10px 14px}.links{margin-top:18px;font-size:12px}.links a{margin-right:12px}</style></head><body><form class="box" method="post" action="%s"><h2>%s</h2><p>Enter the 6-digit code from your authenticator.</p><input name="code" inputmode="numeric" maxlength="6" autocomplete="one-time-code"><button>Verify</button><div class="links"><a href="%s">Identity provider status</a><a href="%s">Recovery</a></div></form></body></html>`, html.EscapeString(title), html.EscapeString(action), html.EscapeString(title), html.EscapeString(statusHref), html.EscapeString(helpHref))
}

type linkItem struct{ Label, Href string }

func managementHTML(title string, links []linkItem) string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><title>` + html.EscapeString(title) + `</title><meta name="robots" content="noindex"><style>body{font:14px Arial;background:#e9ecef;color:#222}.wrap{width:620px;margin:7vh auto;background:#fff;border:1px solid #aeb5bb}.head{padding:18px 22px;background:#37424a;color:white}.body{padding:22px}.row{display:block;padding:12px 14px;margin:8px 0;border:1px solid #d9dddf;background:#f7f8f8;color:#174f78;text-decoration:none}.foot{padding:10px 22px;background:#f1f2f2;color:#777;font-size:11px}</style></head><body><div class="wrap"><div class="head"><b>` + html.EscapeString(title) + `</b></div><div class="body"><p>System online. Select a management function.</p>`)
	for _, l := range links {
		b.WriteString(`<a class="row" href="` + html.EscapeString(l.Href) + `">` + html.EscapeString(l.Label) + `</a>`)
	}
	b.WriteString(`</div><div class="foot">Management service · session protected</div></div></body></html>`)
	return b.String()
}

func remoteAccessHTML(title, action, realm, button string) string {
	return fmt.Sprintf(`<!doctype html><html><head><title>%s</title><meta name="robots" content="noindex"><style>body{font:14px Arial;background:#eef1f4}.card{width:350px;margin:11vh auto;background:#fff;border:1px solid #bbc2c7;padding:28px}h2{margin-top:0;color:#263746}label{display:block;margin-top:12px;color:#555}input,select{box-sizing:border-box;width:100%%;padding:9px;margin-top:5px;border:1px solid #aeb7bd}button{margin-top:18px;width:100%%;padding:10px;background:#356b92;color:white;border:0}</style></head><body><form class="card" method="post" action="%s"><h2>%s</h2><label>Group</label><select name="group"><option>%s</option><option>Employees</option><option>Contractors</option></select><label>Username</label><input name="username" autocomplete="off"><label>Password</label><input name="password" type="password"><button>%s</button></form></body></html>`, html.EscapeString(title), html.EscapeString(action), html.EscapeString(title), html.EscapeString(realm), html.EscapeString(button))
}

func deviceLoginHTML(title, action, user, firmware string) string {
	return fmt.Sprintf(`<!doctype html><html><head><title>%s</title><meta name="robots" content="noindex"><style>body{font:13px Arial;background:#1e272d;color:#dce4e8}.box{width:330px;margin:12vh auto;background:#2b363d;border:1px solid #485860;padding:26px}input{box-sizing:border-box;width:100%%;padding:9px;margin:7px 0;background:#20292e;border:1px solid #586a73;color:white}button{padding:9px 18px;background:#4b819c;border:0;color:white}.fw{margin-top:18px;color:#82939b;font-size:11px}</style></head><body><form class="box" method="post" action="%s"><h2>%s</h2><input name="username" value="%s"><input name="password" type="password" placeholder="Password"><button>Login</button><div class="fw">%s</div></form></body></html>`, html.EscapeString(title), html.EscapeString(action), html.EscapeString(title), html.EscapeString(user), html.EscapeString(firmware))
}

func apacheStatusHTML(a, b string) string {
	return fmt.Sprintf(`<!doctype html><title>Apache Status</title><h1>Apache Server Status for app-gw</h1><dl><dt>Server Version</dt><dd>Apache/2.4.58</dd><dt>Server MPM</dt><dd>event</dd><dt>Server uptime</dt><dd>18 days 4 hours</dd><dt>Active workers</dt><dd>7</dd></dl><pre>Srv PID   Acc       M   CPU   Request
0-0 1821  0/84/982  W   1.2   GET /api/v1/internal/%s
1-0 1822  0/51/611  K   0.8   GET /backup/%s/</pre>`, html.EscapeString(a), html.EscapeString(b))
}

func mustJSON(v any) []byte { b, _ := json.MarshalIndent(v, "", "  "); return b }
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
