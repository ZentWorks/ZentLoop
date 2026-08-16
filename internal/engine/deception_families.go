package engine

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"path"
	"strings"

	"zentloop/internal/lures"
	"zentloop/internal/model"
)

func buildFamilyDeception(r *http.Request, ss *model.Session, a, b string) (Response, bool) {
	p := normalizeFamilyPath(r.URL.Path)
	base := path.Base(p)
	canaries := lures.CanaryLabels(ss.IP)
	depth := max(ss.Depth, 1)

	if p == "/mcp" || p == "/mcp/" || p == "/api/mcp" || p == "/sse" {
		accept := strings.ToLower(r.Header.Get("Accept"))
		if strings.Contains(accept, "text/event-stream") || p == "/sse" {
			return Response{Status: http.StatusOK, ContentType: "text/event-stream", Label: "fake-mcp-sse", Depth: depth, Body: []byte("event: endpoint\ndata: {\"endpoint\":\"/mcp\",\"protocolVersion\":\"2025-03-26\"}\n\n")}, true
		}
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "error": map[string]any{"code": -32000, "message": "client must accept text/event-stream or application/json"}, "id": nil})
		return Response{Status: http.StatusNotAcceptable, ContentType: "application/json", Label: "fake-mcp-discovery", Depth: depth, Body: body}, true
	}

	if isSSRFFamily(p) {
		return buildSSRFFamily(r, ss, a, b, canaries), true
	}

	if isVirtualFileReadFamily(p) {
		return buildVirtualFileReadFamily(p, ss, a, canaries), true
	}

	if isTerraformFamily(p) {
		if !adaptiveRevealSensitive(ss, p) {
			return Response{Status: 404, ContentType: "text/plain; charset=utf-8", Label: "adaptive-terraform-miss", Depth: max(ss.Depth, 1), Body: []byte("Not Found\n")}, true
		}
		return buildTerraformFamily(p, ss, canaries), true
	}

	if isSQLDumpFamily(p) {
		if !adaptiveRevealSensitive(ss, p) {
			return Response{Status: 404, ContentType: "text/plain; charset=utf-8", Label: "adaptive-sql-dump-miss", Depth: max(ss.Depth, 1), Body: []byte("Not Found\n")}, true
		}
		return buildSQLDumpFamily(ss, canaries), true
	}

	if isDebugToolFamily(p) {
		return buildDebugToolFamily(p, ss, a, b), true
	}

	if isSSHMaterialFamily(p) {
		return buildSSHMaterialFamily(p, ss, a, canaries), true
	}

	if isManagementSurfaceFamily(p) {
		return buildManagementSurfaceFamily(p, ss, a, b), true
	}

	if isWordPressSurfaceFamily(p) {
		return buildWordPressSurfaceFamily(p, ss, a, b), true
	}

	if isPHPWebshellFamily(p) {
		return buildPHPWebshellFamily(p, ss, a, b), true
	}

	if isEnvFamily(p) {
		env := "production"
		if strings.Contains(p, "dev") || strings.Contains(p, "local") {
			env = "development"
		} else if strings.Contains(p, "stag") {
			env = "staging"
		}
		body := fmt.Sprintf("APP_NAME=OperationsPortal\nAPP_ENV=%s\nAPP_DEBUG=%t\nAPP_URL=https://portal.internal\nDB_HOST=db-primary\nDB_PORT=5432\nDB_NAME=customers\nDB_USER=svc_web\nDB_PASSWORD=%s\nCACHE_URL=redis://cache-01:6379/2\nREGISTRY_HOST=registry.internal\nGIT_HOST=git.prod.internal\nOPS_GATEWAY=ops-gw-01\nINTERNAL_API=/api/v1/internal/%s\nINTERNAL_API_TOKEN=%s\nBACKUP_HOST=backup-01\nBACKUP_TOKEN=%s\n", env, env != "production", b+a, a, canaries["internal-api"], canaries["backup"])
		return Response{Status: 200, ContentType: "text/plain; charset=utf-8", Label: "fake-env-family", Depth: depth, Body: []byte(body)}, true
	}

	if base == ".passwd-s3fs" {
		body := "archive-prod:" + canaries["backup"] + "\n"
		return Response{Status: 200, ContentType: "text/plain; charset=utf-8", Label: "fake-s3fs-credentials", Depth: max(ss.Depth, 2), Body: []byte(body)}, true
	}

	if p == "/id_rsa" || p == "/id_ed25519" || strings.HasSuffix(p, "/.ssh/id_rsa") || strings.HasSuffix(p, "/.ssh/id_ed25519") {
		keyType := "OPENSSH"
		comment := "backup-agent@backup-01"
		payload := base64.StdEncoding.EncodeToString([]byte("zentloop-decoy|" + ss.IP + "|" + p + "|" + canaries["backup"]))
		body := "-----BEGIN " + keyType + " PRIVATE KEY-----\n" + payload + "\n-----END " + keyType + " PRIVATE KEY-----\n# " + comment + "\n"
		return Response{Status: 200, ContentType: "text/plain; charset=utf-8", Label: "fake-ssh-private-key", Depth: max(ss.Depth, 3), Body: []byte(body)}, true
	}

	if p == "/.docker/config.json" || strings.HasSuffix(p, "/.docker/config.json") {
		auth := base64.StdEncoding.EncodeToString([]byte("svc_registry:" + canaries["registry"]))
		body, _ := json.MarshalIndent(map[string]any{"auths": map[string]any{"registry.internal": map[string]string{"auth": auth}}, "credsStore": ""}, "", "  ")
		return Response{Status: 200, ContentType: "application/json", Label: "fake-docker-credentials", Depth: max(ss.Depth, 3), Body: append(body, '\n')}, true
	}

	if isCloudCredentialFamily(p) {
		if !legacyCloudCredentialPath(p) && !adaptiveRevealSensitive(ss, p) {
			return Response{Status: 404, ContentType: "text/plain; charset=utf-8", Label: "adaptive-credential-miss", Depth: max(ss.Depth, 1), Body: []byte("Not Found\n")}, true
		}
		return buildCloudCredentialFamily(p, ss, a+b, canaries), true
	}

	if p == "/wp/" || p == "/wordpress/" || p == "/blog/" || p == "/blog/robots.txt" {
		if p == "/blog/robots.txt" {
			body := "User-agent: *\nDisallow: /wp-admin/\nDisallow: /backup/\nDisallow: /staging/\nAllow: /wp-admin/admin-ajax.php\n"
			return Response{Status: 200, ContentType: "text/plain; charset=utf-8", Label: "fake-wordpress-robots", Depth: max(ss.Depth, 2), Body: []byte(body)}, true
		}
		body := `<!doctype html><html><head><meta name="generator" content="WordPress 6.6.1"><title>Operations Notes</title></head><body><h1>Operations Notes</h1><p>Maintenance window completed.</p><a href="/wp-login.php">Log in</a><script src="/wp-includes/js/jquery/jquery.min.js"></script></body></html>`
		return Response{Status: 200, ContentType: "text/html; charset=utf-8", Label: "fake-wordpress-site", Depth: max(ss.Depth, 1), Body: []byte(body)}, true
	}

	if p == "/index.php" || p == "/temp.php" {
		if p == "/temp.php" && ss.Depth < 2 {
			return Response{Status: 404, ContentType: "text/html; charset=utf-8", Label: "adaptive-php-miss", Depth: max(ss.Depth, 1), Body: []byte("<html><body>Not Found</body></html>")}, true
		}
		body := `<!doctype html><html><head><title>Operations Portal</title></head><body><h1>Operations Portal</h1><p>Legacy compatibility endpoint.</p><a href="/login">Continue</a></body></html>`
		return Response{Status: 200, ContentType: "text/html; charset=utf-8", Label: "fake-legacy-php", Depth: max(ss.Depth, 2), Body: []byte(body)}, true
	}

	if base == "wp-config.php" || strings.HasPrefix(base, "wp-config.php.") || strings.Contains(p, "/wp-content/w3tc-config/") {
		body := fmt.Sprintf("<?php\ndefine('DB_NAME','portal_prod');\ndefine('DB_USER','wp_svc');\ndefine('DB_PASSWORD','%s');\ndefine('DB_HOST','db-primary');\ndefine('WP_CACHE', true);\ndefine('AUTH_KEY','%s');\n$table_prefix='wp_';\n", b+a, canaries["internal-api"])
		return Response{Status: 200, ContentType: "text/plain; charset=utf-8", Label: "fake-wordpress-config", Depth: max(ss.Depth, 2), Body: []byte(body)}, true
	}

	if isPHPInfoFamily(p) {
		body := fmt.Sprintf(`<!doctype html><html><head><title>PHP 8.3.6 - phpinfo()</title></head><body><h1>PHP Version 8.3.6</h1><table><tr><td>System</td><td>Linux prod-app-02 6.8.0-64-generic x86_64</td></tr><tr><td>Server API</td><td>FPM/FastCGI</td></tr><tr><td>DOCUMENT_ROOT</td><td>/var/www/html</td></tr><tr><td>SERVER_ADDR</td><td>10.10.30.21</td></tr><tr><td>DB_HOST</td><td>db-primary</td></tr><tr><td>REDIS_HOST</td><td>cache-01</td></tr><tr><td>CONFIG_HINT</td><td>/config/services.php?ref=%s</td></tr></table></body></html>`, html.EscapeString(a))
		return Response{Status: 200, ContentType: "text/html; charset=utf-8", Label: "fake-phpinfo", Depth: max(ss.Depth, 2), Body: []byte(body)}, true
	}

	if isApplicationConfigFamily(p) {
		return buildConfigFamily(p, ss, a, b, canaries), true
	}

	if isFrontendConfigFamily(p) {
		body := fmt.Sprintf("window.__RUNTIME_CONFIG__={apiBase:\"https://prod-app-02/api/v1/internal/%s\",registry:\"https://registry.internal\",git:\"https://git.prod.internal\",environment:\"production\",build:\"2026.08.%s\"};\n", a, b[:4])
		return Response{Status: 200, ContentType: "application/javascript; charset=utf-8", Label: "fake-frontend-config", Depth: max(ss.Depth, 2), Body: []byte(body)}, true
	}
	return Response{}, false
}

func isEnvFamily(p string) bool {
	base := path.Base(p)
	return base == ".env" || strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".env") || base == "env" || base == "env.txt" || strings.HasSuffix(base, ".env.txt")
}

func isPHPInfoFamily(p string) bool {
	base := path.Base(p)
	return p == "/info" || base == "phpinfo.php" || base == "phpinfo.php3" || base == "info.php" || base == "pinfo.php" || base == "i.php" || p == "/_profiler" || strings.HasPrefix(p, "/_profiler/phpinfo")
}

func isFrontendConfigFamily(p string) bool {
	base := path.Base(p)
	switch base {
	case "env.js", "env.prod.js", "env.production.js", "env.dev.js", "env.development.js", "environment.js", "config.js", "configuration.js", "runtime-config.js", "__env.js", "aws-exports.js", "google-services.json", "firebase-config.json", "service-worker.js", "sw.js", "runtime.js", "ngsw.json", "manifest.webmanifest":
		return true
	}
	return p == "/main.js" || strings.HasSuffix(p, "/scripts/main.js") || strings.HasSuffix(p, "/static/js/main.js") || strings.HasSuffix(p, "/static/js/main.chunk.js") || strings.HasSuffix(p, "/static/js/bundle.js")
}

func adaptiveRevealSensitive(ss *model.Session, p string) bool {
	if ss.AutomationScore >= 85 || ss.RequestCount >= 12 || ss.Depth >= 3 {
		return true
	}
	sum := 0
	for _, r := range ss.ID + "|" + p {
		sum += int(r)
	}
	return sum%5 == 0
}

func legacyCloudCredentialPath(p string) bool {
	base := path.Base(p)
	switch base {
	case "serviceaccountkey.json", "service-account.json", "firebase-adminsdk.json", "credentials.json", "secrets.json":
		return true
	}
	return p == "/__/firebase/init.json" || p == "/assets/credentials.json"
}

func isSSRFFamily(p string) bool {
	if strings.HasPrefix(p, "/latest/meta-data/") {
		return true
	}
	switch p {
	case "/fetch", "/proxy", "/download", "/preview", "/image", "/screenshot", "/webhook", "/redirect", "/read", "/api/fetch", "/api/proxy", "/api/download", "/api/preview", "/api/image", "/api/webhook", "/api/v1/fetch", "/api/file":
		return true
	}
	return false
}

func buildSSRFFamily(r *http.Request, ss *model.Session, a, b string, canaries map[string]string) Response {
	if strings.HasPrefix(normalizeFamilyPath(r.URL.Path), "/latest/meta-data/") {
		if strings.Contains(strings.ToLower(r.URL.Path), "security-credentials") {
			return Response{Status: 200, ContentType: "text/plain; charset=utf-8", Label: "fake-metadata-role", Depth: max(ss.Depth, 5), Body: []byte("prod-app-role\n")}
		}
	}
	raw := firstQuery(r.URL.Query(), "url", "uri", "target", "src", "source", "image", "webhook", "redirect", "file")
	depth := max(ss.Depth, 2)
	if raw == "" {
		return Response{Status: 200, ContentType: "application/json", Label: "fake-fetch-service", Depth: depth, Body: mustJSON(map[string]any{"service": "media-fetch", "status": "ready", "accepted": []string{"http", "https"}, "max_bytes": 8388608, "internal_dns": true, "request_id": "rf_" + a})}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return Response{Status: 400, ContentType: "application/json", Label: "fake-fetch-invalid", Depth: depth, Body: mustJSON(map[string]any{"error": "invalid URL", "request_id": "rf_" + a})}
	}
	host := strings.ToLower(u.Hostname())
	pathPart := u.EscapedPath()
	if pathPart == "" {
		pathPart = "/"
	}
	if host == "169.254.169.254" || host == "fd00:ec2::254" {
		if strings.Contains(strings.ToLower(pathPart), "security-credentials") {
			body := mustJSON(map[string]any{"Code": "Success", "LastUpdated": "2026-08-15T16:32:11Z", "Type": "AWS-HMAC", "AccessKeyId": "ASIA" + strings.ToUpper(a+b), "SecretAccessKey": canaries["backup"], "Token": canaries["internal-api"], "Expiration": "2026-08-15T23:32:11Z"})
			return Response{Status: 200, ContentType: "application/json", Label: "fake-ssrf-metadata-credentials", Depth: max(ss.Depth, 5), Body: body}
		}
		return Response{Status: 200, ContentType: "text/plain; charset=utf-8", Label: "fake-ssrf-metadata-role", Depth: max(ss.Depth, 4), Body: []byte("prod-app-role\n")}
	}
	if host == "registry.internal" || host == "10.10.30.25" {
		return Response{Status: 200, ContentType: "application/json", Label: "fake-ssrf-internal-registry", Depth: max(ss.Depth, 5), Body: mustJSON(map[string]any{"repositories": []string{"platform/web", "platform/worker", "ops/backup-agent"}, "auth_hint": canaries["registry"]})}
	}
	if host == "prod-app-02" || host == "10.10.30.21" {
		return Response{Status: 200, ContentType: "application/json", Label: "fake-ssrf-internal-api", Depth: max(ss.Depth, 5), Body: mustJSON(map[string]any{"service": "platform-api", "environment": "production", "database": "db-primary", "cache": "cache-01", "ops": "ops-gw-01", "token": canaries["internal-api"]})}
	}
	return Response{Status: 200, ContentType: "application/json", Label: "fake-fetch-result", Depth: depth, Body: mustJSON(map[string]any{"status": "fetched", "url": u.Scheme + "://" + u.Host + pathPart, "content_type": "text/html; charset=utf-8", "bytes": 1842 + len(raw)%900, "request_id": "rf_" + b})}
}

func firstQuery(q url.Values, names ...string) string {
	for _, n := range names {
		if v := strings.TrimSpace(q.Get(n)); v != "" {
			return v
		}
	}
	return ""
}

func isVirtualFileReadFamily(p string) bool {
	return strings.HasPrefix(p, "/@fs/") || strings.Contains(p, "../etc/passwd") || strings.Contains(p, "../proc/self/environ") || p == "/proc/self/environ"
}

func buildVirtualFileReadFamily(p string, ss *model.Session, a string, canaries map[string]string) Response {
	virtual := strings.TrimPrefix(p, "/@fs")
	if i := strings.Index(virtual, "../"); i >= 0 {
		virtual = "/" + strings.TrimLeft(virtual[i:], "./")
	}
	depth := max(ss.Depth, 4)
	switch {
	case strings.Contains(virtual, "/etc/passwd"):
		body := "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Operations Administrator:/home/admin:/bin/bash\nsvc-web:x:998:998:Platform Web:/opt/app:/usr/sbin/nologin\nsvc-backup:x:997:997:Backup Agent:/var/lib/backup:/bin/bash\n"
		return Response{Status: 200, ContentType: "text/plain; charset=utf-8", Label: "fake-devserver-passwd-read", Depth: depth, Body: []byte(body)}
	case strings.Contains(virtual, "/proc/self/environ"):
		body := "NODE_ENV=production\x00HOSTNAME=prod-app-02\x00DB_HOST=db-primary\x00REDIS_HOST=cache-01\x00REGISTRY_URL=https://registry.internal\x00INTERNAL_API_TOKEN=" + canaries["internal-api"] + "\x00BACKUP_TOKEN=" + canaries["backup"] + "\x00"
		return Response{Status: 200, ContentType: "application/octet-stream", Label: "fake-devserver-environ-read", Depth: max(ss.Depth, 5), Body: []byte(body)}
	case strings.Contains(virtual, "/proc/self/cmdline"):
		return Response{Status: 200, ContentType: "application/octet-stream", Label: "fake-devserver-cmdline-read", Depth: depth, Body: []byte("node\x00/opt/app/current/server.js\x00--config\x00/opt/app/current/config/production.json\x00")}
	case strings.Contains(virtual, "/etc/nginx/nginx.conf"):
		return Response{Status: 200, ContentType: "text/plain; charset=utf-8", Label: "fake-devserver-nginx-read", Depth: depth, Body: []byte("user www-data;\nworker_processes auto;\nhttp { upstream platform { server 127.0.0.1:8081; } server { listen 80; server_name _; location / { proxy_pass http://platform; } } }\n")}
	default:
		if isCloudCredentialFamily(virtual) {
			return buildCloudCredentialFamily(virtual, ss, a, canaries)
		}
		if isApplicationConfigFamily(virtual) {
			return buildConfigFamily(virtual, ss, a, "fs", canaries)
		}
		if isFrontendConfigFamily(virtual) {
			body := fmt.Sprintf("window.__RUNTIME_CONFIG__={apiBase:\"https://prod-app-02/api/v1/internal/%s\",registry:\"https://registry.internal\",environment:\"production\"};\n", a)
			return Response{Status: 200, ContentType: "application/javascript; charset=utf-8", Label: "fake-devserver-frontend-read", Depth: depth, Body: []byte(body)}
		}
		return Response{Status: 404, ContentType: "text/plain; charset=utf-8", Label: "fake-devserver-file-miss", Depth: depth, Body: []byte("Not Found\n")}
	}
}

func isSSHMaterialFamily(p string) bool {
	base := path.Base(p)
	if strings.Contains(p, "/.ssh/") {
		switch base {
		case "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "known_hosts", "authorized_keys", "config":
			return true
		}
	}
	switch base {
	case "id_ecdsa", "id_dsa", "host.key", "server.key", "localhost.key", "privatekey.key", "key.pem", "private-key":
		return true
	}
	return strings.HasPrefix(p, "/ssl/") && strings.HasSuffix(base, ".key")
}

func buildSSHMaterialFamily(p string, ss *model.Session, a string, canaries map[string]string) Response {
	base := path.Base(p)
	depth := max(ss.Depth, 4)
	switch base {
	case "known_hosts":
		return Response{Status: 200, ContentType: "text/plain; charset=utf-8", Label: "fake-ssh-known-hosts", Depth: depth, Body: []byte("backup-01 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIVIRTUAL" + a + "\nregistry.internal ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIREGISTRY" + a + "\n")}
	case "authorized_keys":
		return Response{Status: 200, ContentType: "text/plain; charset=utf-8", Label: "fake-ssh-authorized-keys", Depth: depth, Body: []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIVIRTUAL" + a + " backup-agent@backup-01\n")}
	case "config":
		return Response{Status: 200, ContentType: "text/plain; charset=utf-8", Label: "fake-ssh-client-config", Depth: depth, Body: []byte("Host backup-01\n    HostName 10.10.30.12\n    User svc-backup\n    IdentityFile ~/.ssh/id_ed25519\n")}
	default:
		payload := base64.StdEncoding.EncodeToString([]byte("zentloop-invalid-key|" + ss.IP + "|" + canaries["backup"]))
		return Response{Status: 200, ContentType: "text/plain; charset=utf-8", Label: "fake-ssh-private-key", Depth: max(ss.Depth, 5), Body: []byte("-----BEGIN OPENSSH " + "PRIVATE KEY-----\n" + payload + "\n-----END OPENSSH PRIVATE KEY-----\n")}
	}
}

func isManagementSurfaceFamily(p string) bool {
	switch p {
	case "/dashboard", "/workspace", "/my", "/account", "/user/login", "/settings", "/portal", "/app", "/profile", "/admin", "/auth/login", "/signin", "/manage", "/console", "/api/account":
		return true
	}
	return false
}

func buildManagementSurfaceFamily(p string, ss *model.Session, a, b string) Response {
	if strings.Contains(p, "login") || p == "/signin" || p == "/admin" || p == "/console" {
		return Response{Status: 200, ContentType: "text/html; charset=utf-8", Label: "fake-management-surface", Depth: max(ss.Depth, 2), Body: []byte(loginHTML("Operations Console", "/auth/session/"+a, "administrator", "Sign in"))}
	}
	return Response{Status: 200, ContentType: "text/html; charset=utf-8", Label: "fake-management-surface", Depth: max(ss.Depth, 2), Body: []byte(managementHTML("Operations Workspace", []linkItem{{"System status", "/manage/status/" + a}, {"Configuration", "/config/export/" + b + ".cfg"}, {"Sign in", "/login"}}))}
}

func isWordPressSurfaceFamily(p string) bool {
	base := path.Base(p)
	return p == "/wp-json" || strings.HasPrefix(p, "/wp-includes/") || strings.HasPrefix(p, "/wp-content/") ||
		base == "wp-blog.php" || strings.HasPrefix(base, "wp-ws") || strings.Contains(p, "/wordpress/")
}

func buildWordPressSurfaceFamily(p string, ss *model.Session, a, b string) Response {
	depth := max(ss.Depth, 3)
	if strings.HasSuffix(p, "/") {
		body := directoryHTML(p, []string{"index.php", "cache/", "uploads/", "readme.txt"})
		return Response{Status: 200, ContentType: "text/html; charset=utf-8", Label: "fake-wordpress-surface", Depth: depth, Body: []byte(body)}
	}
	if strings.Contains(p, "wp_filemanager.php") || strings.Contains(p, "filemanager") {
		body := managementHTML("WordPress File Manager", []linkItem{{"Uploads", "/wp-content/uploads/"}, {"Backup archive", "/backup/" + b + "/"}, {"Environment", "/.env?ref=" + a}})
		return Response{Status: 200, ContentType: "text/html; charset=utf-8", Label: "fake-wordpress-filemanager", Depth: max(ss.Depth, 5), Body: []byte(body)}
	}
	if strings.HasSuffix(p, ".php") {
		body := "<?php\n// Silence is golden.\n// build " + a + "\n"
		return Response{Status: 200, ContentType: "text/plain; charset=utf-8", Label: "fake-wordpress-php", Depth: depth, Body: []byte(body)}
	}
	return Response{Status: 200, ContentType: "text/html; charset=utf-8", Label: "fake-wordpress-surface", Depth: depth, Body: []byte("<!doctype html><title>WordPress</title><meta name=generator content=\"WordPress 6.6.2\"><p>Maintenance mode.</p>")}
}

func isPHPWebshellFamily(p string) bool {
	base := strings.ToLower(path.Base(p))
	if !strings.HasSuffix(base, ".php") || strings.Contains(p, "/wp-includes/") || strings.Contains(p, "/wp-content/") {
		return false
	}
	name := strings.TrimSuffix(base, ".php")
	if name == "index" || name == "temp" || name == "phpinfo" || name == "info" || name == "pinfo" || name == "i" {
		return false
	}
	// Root-level arbitrary PHP names are a common webshell/backdoor scanner
	// pattern. In a deception catch-all there is no legitimate application route
	// to preserve, so treat these as one family instead of memorizing filenames.
	if strings.Count(strings.Trim(p, "/"), "/") == 0 && name != "index" {
		return true
	}
	for _, prefix := range []string{"admin", "adminer", "adminner", "shell", "file", "upload", "ops", "media", "images", "image", "random", "class", "coff", "biu", "rt", "av", "mac", "wp-"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	allDigits := name != ""
	digit, letter := false, false
	for _, r := range name {
		if r >= '0' && r <= '9' {
			digit = true
		} else {
			allDigits = false
			if r >= 'a' && r <= 'z' {
				letter = true
			}
		}
	}
	return allDigits || (len(name) >= 8 && letter && digit) || strings.Contains(name, "tostring")
}

func buildPHPWebshellFamily(p string, ss *model.Session, a, b string) Response {
	name := path.Base(p)
	body := "<!doctype html><html><head><title>File Manager</title></head><body><h3>Server: prod-app-02</h3><pre>PHP 8.3.6\nLinux prod-app-02 6.8.0-64-generic x86_64\nDocument root: /var/www/html\nCurrent file: /var/www/html/" + html.EscapeString(name) + "\nUID: www-data (33)\n</pre><a href=\"/wp-content/uploads/\">uploads</a> · <a href=\"/backup/" + b + "/\">backup</a> · <a href=\"/diag/status/" + a + "\">system</a></body></html>"
	return Response{Status: 200, ContentType: "text/html; charset=utf-8", Label: "fake-php-backdoor", Depth: max(ss.Depth, 5), LoopInc: 1, Body: []byte(body)}
}

func isTerraformFamily(p string) bool {
	base := path.Base(p)
	return base == "terraform.tfvars" || base == "terraform.tfstate" || strings.HasSuffix(p, "/.terraform/terraform.tfstate")
}

func buildTerraformFamily(p string, ss *model.Session, canaries map[string]string) Response {
	if strings.HasSuffix(p, ".tfvars") {
		body := "environment = \"production\"\nregion = \"eu-central-1\"\nbackup_host = \"10.10.30.12\"\nregistry_host = \"10.10.30.25\"\nbackup_token = \"" + canaries["backup"] + "\"\n"
		return Response{Status: 200, ContentType: "text/plain; charset=utf-8", Label: "fake-terraform-vars", Depth: max(ss.Depth, 5), Body: []byte(body)}
	}
	body := mustJSON(map[string]any{"version": 4, "terraform_version": "1.9.2", "serial": 37, "outputs": map[string]any{"db_primary": map[string]any{"value": "10.10.30.14", "sensitive": false}, "backup_host": map[string]any{"value": "10.10.30.12", "sensitive": false}, "registry_password": map[string]any{"value": canaries["registry"], "sensitive": true}, "backup_token": map[string]any{"value": canaries["backup"], "sensitive": true}}})
	return Response{Status: 200, ContentType: "application/json", Label: "fake-terraform-state", Depth: max(ss.Depth, 6), Body: body}
}

func isSQLDumpFamily(p string) bool {
	base := path.Base(p)
	return base == "db.sql" || base == "database.sql" || base == "dump.sql" || base == "backup.sql"
}

func buildSQLDumpFamily(ss *model.Session, canaries map[string]string) Response {
	body := "-- PostgreSQL database dump\n-- Dumped from database version 16.3\nCREATE TABLE app_settings (key text PRIMARY KEY, value text);\nINSERT INTO app_settings VALUES ('backup_host','backup-01'),('registry','registry.internal'),('internal_api_token','" + canaries["internal-api"] + "');\nCREATE TABLE service_accounts (name text, role text, token_hint text);\nINSERT INTO service_accounts VALUES ('svc-backup','archive_writer','" + canaries["backup"] + "');\n-- customer row data omitted from support export\n"
	return Response{Status: 200, ContentType: "application/sql; charset=utf-8", Label: "fake-database-dump", Depth: max(ss.Depth, 5), Body: []byte(body)}
}

func isDebugToolFamily(p string) bool {
	return strings.HasPrefix(p, "/horizon/") || strings.HasPrefix(p, "/telescope/") || strings.HasPrefix(p, "/_debugbar/") || p == "/log-viewer" || strings.HasPrefix(p, "/rails/info/") || strings.HasPrefix(p, "/_profiler/") || p == "/__debug__/" || p == "/trace.axd" || p == "/elmah.axd" || strings.Contains(p, "/app_dev.php/_profiler") || p == "/_ignition/health-check" || p == "/nginx_status" || p == "/server-info" || p == "/health" || p == "/api/health"
}

func buildDebugToolFamily(p string, ss *model.Session, a, b string) Response {
	depth := max(ss.Depth, 3)
	if strings.HasPrefix(p, "/telescope/") {
		return Response{Status: 200, ContentType: "application/json", Label: "fake-telescope", Depth: depth, Body: mustJSON(map[string]any{"entries": []any{map[string]any{"type": "request", "uri": "/api/v1/internal/" + a, "status": 200}, map[string]any{"type": "job", "name": "NightlyBackup", "connection": "redis", "host": "cache-01"}}, "next": "/telescope/requests?cursor=" + b})}
	}
	body := "<!doctype html><html><head><title>Operations Diagnostics</title></head><body><h1>Diagnostics</h1><ul><li><a href=\"/debug/config/" + a + "\">Application configuration</a></li><li><a href=\"/log-viewer?channel=production\">Production log</a></li><li><a href=\"/ops/inventory\">Service inventory</a></li></ul></body></html>"
	return Response{Status: 200, ContentType: "text/html; charset=utf-8", Label: "fake-debug-console", Depth: depth, Body: []byte(body)}
}

func normalizeFamilyPath(raw string) string {
	p := strings.ToLower(strings.TrimSpace(raw))
	if u, err := url.PathUnescape(p); err == nil {
		p = u
	}
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

func isCloudCredentialFamily(p string) bool {
	base := path.Base(strings.ToLower(p))
	low := strings.ToLower(p)
	switch base {
	case "credentials", "serviceaccountkey.json", "service-account.json", "service_account.json", "firebase-adminsdk.json", "firebase-admin.json", "firebase-service-account.json", "firebase-credentials.json", "credentials.json", "google-credentials.json", "gcp-credentials.json", "gcp-key.json", "gcp-service.json", "gcp-service-account.json", "google-service-account.json", "gc-service.json", "application_default_credentials.json", "key.json", "sa.json", "secrets.json", "aws.json", "aws-credentials.json", "aws_credentials.txt", "aws_credentials.json", "aws_creds.js", ".aws_creds.json", "s3-credentials.json", "s3-credentials.bak", "aws-config.js", "rclone.conf", ".boto", ".s3cfg", ".netrc", ".npmrc", "accesstokens.json", "openai.json", "anthropic.json", "claude_desktop_config.json", ".mcp.json", "rootkey.csv":
		return true
	}
	return strings.HasPrefix(low, "/latest/meta-data/") || strings.Contains(low, "ecs/task-credentials") || p == "/__/firebase/init.json" || strings.Contains(low, "/.azure/") || strings.Contains(low, "/.gcloud/") || strings.Contains(low, "/.config/gcloud/") || strings.Contains(low, "/.aws/") || strings.Contains(low, "/aws/") || strings.Contains(low, "/secrets/aws") || strings.Contains(low, "/secrets/gcp") || strings.Contains(low, "/k8s/eks/credentials") || strings.Contains(low, "/.kube/config") || strings.Contains(low, "/serviceaccount/token") || strings.Contains(low, "/.openai/") || strings.Contains(low, "/.anthropic/") || strings.Contains(low, "/.config/anthropic/") || strings.Contains(low, "/.claude") || strings.Contains(low, "/.cursor/") || strings.Contains(low, "/.continue/") || strings.Contains(low, "/.codex/") || strings.Contains(low, "/.hermes/") || strings.Contains(low, "/.aider") || strings.Contains(low, "/.openclaw/")
}

func buildCloudCredentialFamily(p string, ss *model.Session, a string, canaries map[string]string) Response {
	low := strings.ToLower(p)
	depth := max(ss.Depth, 4)
	switch {
	case strings.Contains(low, ".aws") || strings.Contains(low, "/aws") || strings.Contains(low, "s3") || strings.Contains(low, "boto"):
		body := "[production]\naws_access_key_id = AKIA" + strings.ToUpper(a[:min(len(a), 12)]) + "\naws_secret_access_key = " + canaries["backup"] + "\nregion = eu-central-1\ncredential_process = /usr/local/bin/assume-prod-role\n"
		return Response{Status: 200, ContentType: "text/plain; charset=utf-8", Label: "fake-aws-credentials", Depth: depth, Body: []byte(body)}
	case strings.Contains(low, ".azure"):
		return Response{Status: 200, ContentType: "application/json", Label: "fake-azure-credentials", Depth: depth, Body: mustJSON(map[string]any{"subscription": "Production Platform", "tenant": "61a7d8fa-87a9-4e35-8d8a-" + a, "accessToken": canaries["internal-api"], "expiresOn": "2026-08-15 23:45:00.000000"})}
	case strings.HasSuffix(low, ".npmrc"):
		return Response{Status: 200, ContentType: "text/plain; charset=utf-8", Label: "fake-npm-credentials", Depth: depth, Body: []byte("registry=https://registry.internal/npm/\n//registry.internal/npm/:_authToken=" + canaries["registry"] + "\nalways-auth=true\n")}
	case strings.HasSuffix(low, ".netrc"):
		return Response{Status: 200, ContentType: "text/plain; charset=utf-8", Label: "fake-netrc", Depth: depth, Body: []byte("machine git.prod.internal login svc-ci password " + canaries["internal-api"] + "\nmachine backup-01 login svc-backup password " + canaries["backup"] + "\n")}
	case strings.HasSuffix(low, "rclone.conf"):
		return Response{Status: 200, ContentType: "text/plain; charset=utf-8", Label: "fake-rclone-config", Depth: depth, Body: []byte("[archive-prod]\ntype = s3\nprovider = AWS\naccess_key_id = AKIA" + strings.ToUpper(a[:min(len(a), 12)]) + "\nsecret_access_key = " + canaries["backup"] + "\nendpoint = https://backup-01\n")}
	case strings.Contains(low, "openai") || strings.Contains(low, "anthropic") || strings.Contains(low, "claude") || strings.Contains(low, "cursor") || strings.Contains(low, "mcp") || strings.Contains(low, "codex"):
		return Response{Status: 200, ContentType: "application/json", Label: "fake-ai-tool-credentials", Depth: depth, Body: mustJSON(map[string]any{"endpoint": "http://prod-app-02/api/v1/internal/" + a, "api_key": canaries["internal-api"], "mcpServers": map[string]any{"ops": map[string]string{"url": "http://ops-gw-01:8080/mcp"}}})}
	default:
		fakeKey := "-----BEGIN " + "PRIVATE KEY-----\n" + base64.StdEncoding.EncodeToString([]byte("zentloop-invalid-service-account|"+ss.IP+"|"+canaries["backup"])) + "\n-----END PRIVATE KEY-----\n"
		return Response{Status: 200, ContentType: "application/json", Label: "fake-cloud-service-account", Depth: depth, Body: mustJSON(map[string]any{"type": "service_account", "project_id": "prod-platform-ops", "private_key_id": a, "private_key": fakeKey, "client_email": "backup-agent@prod-platform-ops.iam.gserviceaccount.com", "token_uri": "https://oauth2.googleapis.com/token", "internal_api_token": canaries["internal-api"]})}
	}
}

func isApplicationConfigFamily(p string) bool {
	base := path.Base(p)
	if base == ".bash_history" || base == "secrets.yml" || base == "secrets.yaml" || strings.HasPrefix(base, "config.php.") {
		return true
	}
	if p == "/config" || p == "/config.json" || p == "/config.py" || p == "/instance/config.py" || p == "/application.yml" || p == "/application.yaml" || p == "/api/config" || p == "/api/config.json" || p == "/api/settings" || p == "/api/v1/config" || p == "/api/v1/settings" || p == "/database.yml" || p == "/vault.yml" || p == "/kubernetes.yml" || p == "/k8s/secrets.yaml" || p == "/web.config" || p == "/local.settings.json" || p == "/settings.py" || p == "/settings.local.py" || strings.HasSuffix(p, "/settings.py") || p == "/gradle.properties" || p == "/.gradle/gradle.properties" || p == "/dockerfile" || p == "/values.yaml" || p == "/.pypirc" || p == "/.htpasswd" || p == "/config/master.key" || p == "/config.toml" || p == "/config.yaml" || p == "/.vscode/launch.json" || p == "/.svn/entries" || p == "/metrics" || p == "/_health" || p == "/push_config.json" || p == "/firebase.json" || p == "/public/admin.json" || p == "/auth.json" || p == "/bootstrap.properties" || p == "/bootstrap.yml" || p == "/configuration.php.bak" || p == "/storage/logs/laravel.log" || p == "/.bashrc" || p == "/.bash_profile" || p == "/.zshrc" || p == "/.profile" || p == "/.well-known/jwks.json" || p == "/api/v2/config" || p == "/api/v2/settings" || p == "/.streamlit/secrets.toml" || p == "/.circleci/config.yml" || p == "/web-inf/web.xml" || p == "/web-inf/classes/application.properties" {
		return true
	}
	if strings.HasPrefix(p, "/config/") {
		return strings.HasSuffix(p, ".php") || strings.HasSuffix(p, ".exs") || strings.HasSuffix(p, ".json") || strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".properties") || strings.Contains(p, "/environments/")
	}
	if strings.HasPrefix(base, "appsettings.") && strings.HasSuffix(base, ".json") {
		return true
	}
	if strings.HasPrefix(base, "application-") && (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".properties")) {
		return true
	}
	return base == "application.properties" || base == "docker-compose.yml" || base == "docker-compose.yaml" || strings.HasPrefix(base, "docker-compose.") || base == "bitbucket-pipelines.yml" || base == "amplifyconfiguration.json" || base == "app-config.json" || base == "env.json" || base == "settings.json"
}

func buildConfigFamily(p string, ss *model.Session, a, b string, canaries map[string]string) Response {
	r := Response{Status: 200, ContentType: "text/plain; charset=utf-8", Label: "fake-app-config", Depth: max(ss.Depth, 2)}
	switch {
	case strings.HasSuffix(p, ".json"):
		r.ContentType = "application/json"
		r.Body = mustJSON(map[string]any{"environment": "production", "database": map[string]string{"host": "db-primary", "name": "customers"}, "registry": "registry.internal", "backupHost": "backup-01", "apiToken": canaries["internal-api"], "backupToken": canaries["backup"]})
	case strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml"):
		r.Body = []byte("environment: production\nservices:\n  web: prod-app-02\n  database: db-primary\n  cache: cache-01\n  backup: backup-01\nregistry: registry.internal\ninternal_api_token: " + canaries["internal-api"] + "\n")
	case strings.HasSuffix(p, ".properties"):
		r.Body = []byte("spring.datasource.url=jdbc:postgresql://db-primary:5432/customers\nspring.datasource.username=svc_web\nmanagement.endpoints.web.exposure.include=health,info,env\nplatform.registry=https://registry.internal\nplatform.backup.host=backup-01\nplatform.internal.token=" + canaries["internal-api"] + "\n")
	case strings.HasSuffix(p, ".py"):
		r.Body = []byte("DEBUG = False\nDATABASE_HOST = 'db-primary'\nREDIS_HOST = 'cache-01'\nBACKUP_HOST = 'backup-01'\nINTERNAL_API_TOKEN = '" + canaries["internal-api"] + "'\n")
	case strings.HasSuffix(p, ".toml"):
		r.Body = []byte("environment = \"production\"\ndb_host = \"db-primary\"\nbackup_host = \"backup-01\"\nregistry = \"registry.internal\"\n")
	case strings.HasSuffix(p, ".exs"):
		r.Body = []byte("import Config\nconfig :platform, db_host: \"db-primary\", backup_host: \"backup-01\", registry: \"registry.internal\"\n")
	case strings.HasSuffix(p, ".rb"):
		r.Body = []byte("Rails.application.configure do\n  config.cache_store = :redis_cache_store, { url: 'redis://cache-01:6379/2' }\n  config.x.internal_api = 'http://prod-app-02/api/v1/internal/" + a + "'\nend\n")
	case strings.HasSuffix(p, ".php"):
		r.Body = []byte("<?php\nreturn [\n  'host' => 'db-primary',\n  'cache' => 'cache-01',\n  'backup' => 'backup-01',\n  'token' => '" + canaries["backup"] + "',\n];\n")
	default:
		r.Body = []byte("environment=production\ndb_host=db-primary\nbackup_host=backup-01\nregistry=registry.internal\nref=" + a + b + "\n")
	}
	return r
}
