package server

import (
	"net/url"
	"path"
	"strings"
)

// normalizeProbePath is used only for matching. The original request path remains
// untouched in events so scanner quirks such as //wp/ are still observable.
func normalizeProbePath(raw string) string {
	p := strings.ToLower(strings.TrimSpace(raw))
	if p == "" {
		return "/"
	}
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

// identifyProbeFamily keeps high-volume scanner variants out of the static rule
// table. Matching is intentionally conservative: families describe concrete
// discovery patterns rather than a generic substring such as "config".
func identifyProbeFamily(raw string) (probeInfo, bool) {
	p := normalizeProbePath(raw)
	base := path.Base(p)

	if p == "/mcp" || p == "/mcp/" || p == "/api/mcp" || p == "/sse" {
		return probeInfo{"MCP / SSE transport discovery", "Model Context Protocol endpoint", ""}, true
	}
	if isSSRFProbeFamily(p) {
		return probeInfo{"Server-side fetch / SSRF discovery", "URL fetcher / proxy endpoint", ""}, true
	}
	if isVirtualFileReadProbe(p) {
		return probeInfo{"Development server file-read discovery", "Vite / static file server", ""}, true
	}
	if isEnvProbeFamily(p) {
		return probeInfo{"Environment / secret file discovery", "Generic web application", ""}, true
	}
	if base == "wp-config.php" || strings.HasPrefix(base, "wp-config.php.") || strings.Contains(p, "/wp-content/w3tc-config/") {
		return probeInfo{"WordPress configuration discovery", "WordPress", ""}, true
	}
	if p == "/wp/" || p == "/wordpress/" || p == "/blog/" || p == "/blog/robots.txt" {
		return probeInfo{"WordPress installation discovery", "WordPress", ""}, true
	}
	if isWordPressSurfaceProbe(p) {
		return probeInfo{"WordPress surface / upload discovery", "WordPress", ""}, true
	}
	if isPHPWebshellProbe(p) {
		return probeInfo{"PHP webshell / backdoor discovery", "PHP web application", ""}, true
	}
	if p == "/info" || base == "phpinfo.php" || base == "phpinfo.php3" || base == "info.php" || base == "pinfo.php" || base == "i.php" || p == "/_profiler" || strings.HasPrefix(p, "/_profiler/phpinfo") {
		return probeInfo{"PHP runtime / profiler discovery", "PHP / Symfony", ""}, true
	}
	if p == "/index.php" || p == "/temp.php" || isHiddenPHPProbe(p) {
		return probeInfo{"Legacy / hidden PHP endpoint discovery", "PHP web application", ""}, true
	}
	if isSSHMaterialProbe(p) {
		return probeInfo{"SSH key / client material discovery", "OpenSSH", ""}, true
	}
	if isManagementSurfaceProbe(p) {
		return probeInfo{"Management / account surface discovery", "Generic web application", ""}, true
	}
	if p == "/id_rsa" || p == "/id_ed25519" || strings.HasSuffix(p, "/.ssh/id_rsa") || strings.HasSuffix(p, "/.ssh/id_ed25519") {
		return probeInfo{"SSH private key discovery", "OpenSSH", ""}, true
	}
	if p == "/.docker/config.json" || strings.HasSuffix(p, "/.docker/config.json") {
		return probeInfo{"Docker registry credential discovery", "Docker", ""}, true
	}
	if isCloudCredentialProbe(p) {
		return probeInfo{"Cloud / DevOps credential discovery", "Cloud / developer tooling", ""}, true
	}
	if isTerraformProbe(p) {
		return probeInfo{"Terraform state / variable discovery", "Terraform", ""}, true
	}
	if isSQLDumpProbe(p) {
		return probeInfo{"Database dump / backup discovery", "SQL database", ""}, true
	}
	if isDebugToolProbe(p) {
		return probeInfo{"Debug / operations console discovery", "Web framework tooling", ""}, true
	}
	if isApplicationConfigProbe(p) {
		return probeInfo{"Application configuration discovery", "Web application framework", ""}, true
	}
	if base == ".passwd-s3fs" {
		return probeInfo{"S3FS credential file discovery", "s3fs / object storage", ""}, true
	}
	if isFrontendConfigProbe(p) {
		return probeInfo{"Frontend runtime configuration discovery", "JavaScript web application", ""}, true
	}
	return probeInfo{}, false
}

func isSSRFProbeFamily(p string) bool {
	if strings.HasPrefix(p, "/latest/meta-data/") {
		return true
	}
	switch p {
	case "/fetch", "/proxy", "/download", "/preview", "/image", "/screenshot", "/webhook", "/redirect", "/read", "/api/fetch", "/api/proxy", "/api/download", "/api/preview", "/api/image", "/api/webhook", "/api/v1/fetch", "/api/file":
		return true
	}
	return false
}

func isVirtualFileReadProbe(p string) bool {
	return strings.HasPrefix(p, "/@fs/") || strings.Contains(p, "../etc/passwd") || strings.Contains(p, "../proc/self/environ") || p == "/proc/self/environ"
}

func isEnvProbeFamily(p string) bool {
	base := path.Base(p)
	return base == ".env" || strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".env") || base == "env" || base == "env.txt" || strings.HasSuffix(base, ".env.txt")
}

func isCloudCredentialProbe(p string) bool {
	base := path.Base(p)
	low := strings.ToLower(p)
	switch base {
	case "credentials", "serviceaccountkey.json", "service-account.json", "service_account.json", "firebase-adminsdk.json", "firebase-admin.json", "firebase-service-account.json", "firebase-credentials.json", "credentials.json", "google-credentials.json", "gcp-credentials.json", "gcp-key.json", "gcp-service.json", "gcp-service-account.json", "google-service-account.json", "gc-service.json", "application_default_credentials.json", "key.json", "sa.json", "secrets.json", "aws.json", "aws-credentials.json", "aws_credentials.txt", "aws_credentials.json", "aws_creds.js", ".aws_creds.json", "s3-credentials.json", "s3-credentials.bak", "aws-config.js", "rclone.conf", ".boto", ".s3cfg", ".netrc", ".npmrc", "accessTokens.json", "openai.json", "anthropic.json", "claude_desktop_config.json", ".mcp.json", "rootkey.csv":
		return true
	}
	if strings.HasPrefix(low, "/latest/meta-data/") || strings.Contains(low, "ecs/task-credentials") {
		return true
	}
	if p == "/__/firebase/init.json" || p == "/assets/credentials.json" || strings.Contains(low, "/.azure/") || strings.Contains(low, "/.gcloud/") || strings.Contains(low, "/.config/gcloud/") || strings.Contains(low, "/.aws/") || strings.Contains(low, "/aws/") || strings.Contains(low, "/secrets/aws") || strings.Contains(low, "/secrets/gcp") || strings.Contains(low, "/k8s/eks/credentials") || strings.Contains(low, "/.kube/config") || strings.Contains(low, "/serviceaccount/token") {
		return true
	}
	if strings.Contains(low, "/.openai/") || strings.Contains(low, "/.anthropic/") || strings.Contains(low, "/.config/anthropic/") || strings.Contains(low, "/.claude") || strings.Contains(low, "/.cursor/") || strings.Contains(low, "/.continue/") || strings.Contains(low, "/.codex/") || strings.Contains(low, "/.hermes/") || strings.Contains(low, "/.aider") || strings.Contains(low, "/.openclaw/") {
		return true
	}
	return strings.Contains(low, "credentials") && (strings.Contains(low, "aws") || strings.Contains(low, "gcp") || strings.Contains(low, "google") || strings.Contains(low, "firebase") || strings.Contains(low, "azure"))
}

func isTerraformProbe(p string) bool {
	base := path.Base(p)
	return base == "terraform.tfvars" || base == "terraform.tfstate" || strings.HasSuffix(p, "/.terraform/terraform.tfstate")
}

func isSQLDumpProbe(p string) bool {
	base := path.Base(p)
	return base == "db.sql" || base == "database.sql" || base == "dump.sql" || base == "backup.sql"
}

func isDebugToolProbe(p string) bool {
	return strings.HasPrefix(p, "/horizon/") || strings.HasPrefix(p, "/telescope/") || strings.HasPrefix(p, "/_debugbar/") || p == "/log-viewer" || strings.HasPrefix(p, "/rails/info/") || strings.HasPrefix(p, "/_profiler/") || p == "/__debug__/" || p == "/trace.axd" || p == "/elmah.axd" || strings.Contains(p, "/app_dev.php/_profiler") || p == "/_ignition/health-check" || p == "/nginx_status" || p == "/server-info" || p == "/health" || p == "/api/health"
}

func isHiddenPHPProbe(p string) bool {
	return strings.HasPrefix(p, "/.well-known/") && strings.HasSuffix(p, ".php")
}

func isWordPressSurfaceProbe(p string) bool {
	base := path.Base(p)
	return p == "/wp-json" || strings.HasPrefix(p, "/wp-includes/") || strings.HasPrefix(p, "/wp-content/") ||
		base == "wp-blog.php" || strings.HasPrefix(base, "wp-ws") || strings.Contains(p, "/wordpress/")
}

func isPHPWebshellProbe(p string) bool {
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

func isSSHMaterialProbe(p string) bool {
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

func isManagementSurfaceProbe(p string) bool {
	switch p {
	case "/dashboard", "/workspace", "/my", "/account", "/user/login", "/settings", "/portal", "/app", "/profile", "/admin", "/auth/login", "/signin", "/manage", "/console", "/api/account":
		return true
	}
	return false
}

func isApplicationConfigProbe(p string) bool {
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
	if base == "application.properties" || base == "docker-compose.yml" || base == "docker-compose.yaml" || strings.HasPrefix(base, "docker-compose.") || base == "bitbucket-pipelines.yml" || base == "amplifyconfiguration.json" || base == "app-config.json" || base == "env.json" || base == "settings.json" {
		return true
	}
	return false
}

func isFrontendConfigProbe(p string) bool {
	base := path.Base(strings.ToLower(p))
	switch base {
	case "env.js", "env.prod.js", "env.production.js", "env.dev.js", "env.development.js", "environment.js", "config.js", "configuration.js", "runtime-config.js", "__env.js", "aws-exports.js", "google-services.json", "firebase-config.json", "service-worker.js", "sw.js", "runtime.js", "ngsw.json", "manifest.webmanifest":
		return true
	}
	return strings.HasSuffix(p, "/static/js/main.js") || strings.HasSuffix(p, "/static/js/main.chunk.js") || strings.HasSuffix(p, "/static/js/bundle.js") || strings.HasSuffix(p, "/scripts/main.js") || p == "/main.js"
}
