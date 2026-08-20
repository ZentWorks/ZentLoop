package engine

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"zentloop/internal/lures"
	"zentloop/internal/model"
)

// buildObservedWebDeception turns recurring high-signal paths learned from the
// unknown-path feed into a small number of coherent families. It intentionally
// does not make every scanner dictionary entry exist.
func buildObservedWebDeception(r *http.Request, ss *model.Session, a, b string) (Response, bool) {
	p := canonicalObservedWebPath(r.URL.Path)
	canaries := lures.CanaryLabels(ss.IP)

	if isObservedWordPressREST(p) {
		return buildObservedWordPressREST(r, p, ss, a, b), true
	}
	if isObservedRailsArtifact(p) {
		return buildObservedRailsArtifact(p, ss, a, b, canaries), true
	}
	if isObservedSCMArtifact(p) {
		return buildObservedSCMArtifact(p, ss, a), true
	}
	if isObservedCloudConfig(p) {
		return buildObservedCloudConfig(p, ss, a, canaries), true
	}
	if isObservedBackupArtifact(p) {
		if !adaptiveRevealSensitive(ss, p) {
			return Response{Status: http.StatusNotFound, ContentType: "text/plain; charset=utf-8", Label: "adaptive-backup-artifact-miss", Depth: max(ss.Depth, 1), Body: []byte("Not Found\n")}, true
		}
		return buildObservedBackupArtifact(p, ss, a, b, canaries), true
	}
	if isObservedSecretArtifact(p) {
		if !adaptiveRevealSensitive(ss, p) {
			return Response{Status: http.StatusNotFound, ContentType: "text/plain; charset=utf-8", Label: "adaptive-secret-artifact-miss", Depth: max(ss.Depth, 1), Body: []byte("Not Found\n")}, true
		}
		return buildObservedSecretArtifact(p, ss, a, canaries), true
	}
	if isObservedPHPBackdoor(p) {
		// A first arbitrary backdoor probe only hits one deterministic path in five.
		// Once the actor has actually found a PHP surface, keep that story coherent.
		if !deterministicObservedReveal(storyTarget(ss), p, 5) {
			return Response{Status: http.StatusNotFound, ContentType: "text/html; charset=utf-8", Label: "adaptive-php-backdoor-miss", Depth: max(ss.Depth, 1), Body: []byte("<!doctype html><title>404 Not Found</title><h1>Not Found</h1>")}, true
		}
		return buildPHPWebshellFamily(p, ss, a, b), true
	}
	return Response{}, false
}

func canonicalObservedWebPath(raw string) string {
	p := strings.ToLower(strings.TrimSpace(raw))
	if u, err := url.PathUnescape(p); err == nil {
		p = u
	}
	p = strings.ReplaceAll(p, "\\", "/")
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = path.Clean(p)
	if p == "." {
		return "/"
	}
	return p
}

func isWordPressStoryPath(p string) bool {
	base := path.Base(p)
	return isObservedWordPressREST(p) || isWordPressSurfaceFamily(p) || p == "/wp/" || p == "/wordpress/" || p == "/blog/" || p == "/blog/robots.txt" ||
		base == "wp-config.php" || strings.HasPrefix(base, "wp-config.php.") || strings.Contains(p, "/wp-admin") || strings.Contains(p, "/wp-login") || p == "/xmlrpc.php"
}

func isRailsStoryPath(p string) bool {
	return isObservedRailsArtifact(p) || strings.HasPrefix(p, "/rails/") || strings.HasPrefix(p, "/redmine/")
}

func isObservedWordPressREST(p string) bool {
	return strings.Contains(p, "/wp-json/") || strings.Contains(p, "/wp/v2/") || p == "/wp-json" || p == "/wp-json/"
}

func buildObservedWordPressREST(r *http.Request, p string, ss *model.Session, a, b string) Response {
	depth := max(ss.Depth, 3)
	headers := map[string]string{"X-Powered-By": "PHP/8.2.22", "Link": `</wp-json/>; rel="https://api.w.org/"`}
	switch {
	case strings.Contains(p, "/gravitysmtp/v1/tests/mock-data"):
		body := mustJSON(map[string]any{"success": true, "data": map[string]any{"provider": "smtp", "host": "smtp-relay.internal", "port": 587, "encryption": "tls", "from_email": "wordpress@portal.internal", "debug_log": "/wp-content/uploads/gravitysmtp/logs/", "config_hint": "/wp-config.php.bak?ref=" + a}})
		return Response{Status: 200, ContentType: "application/json", Headers: headers, Label: "fake-wordpress-gravitysmtp", Depth: max(depth, 4), Body: body}
	case strings.Contains(p, "/batch/v1"):
		if r.Method == http.MethodPost {
			return Response{Status: 200, ContentType: "application/json", Headers: headers, Label: "fake-wordpress-rest-batch", Depth: max(depth, 4), Body: mustJSON(map[string]any{"responses": []any{}, "validation": "passed", "next": "/wp-json/wp/v2/users?context=view", "request_id": "wp_" + a})}
		}
		return Response{Status: 200, ContentType: "application/json", Headers: headers, Label: "fake-wordpress-rest-batch", Depth: depth, Body: mustJSON(map[string]any{"namespace": "batch/v1", "routes": map[string]any{"/batch/v1": map[string]any{"methods": []string{"POST"}}}, "auth": false})}
	case strings.Contains(p, "/users"):
		return Response{Status: 200, ContentType: "application/json", Headers: headers, Label: "fake-wordpress-rest-users", Depth: max(depth, 4), Body: mustJSON([]map[string]any{{"id": 1, "name": "Operations", "slug": "ops", "link": "https://portal.internal/author/ops/", "avatar_urls": map[string]string{"96": "https://portal.internal/wp-content/uploads/avatars/ops.png"}}})}
	case strings.Contains(p, "/posts") || strings.Contains(p, "/pages"):
		return Response{Status: 200, ContentType: "application/json", Headers: headers, Label: "fake-wordpress-rest-content", Depth: max(depth, 4), Body: mustJSON([]map[string]any{{"id": 47, "date": "2026-08-12T02:17:00", "slug": "maintenance-window", "status": "publish", "link": "https://portal.internal/maintenance-window/", "title": map[string]string{"rendered": "Maintenance window"}, "content": map[string]string{"rendered": `<p>Legacy backup migration remains enabled.</p><p>See <code>/wp-content/uploads/ops/</code>.</p>`}, "meta": map[string]string{"build": b[:4]}}})}
	case strings.Contains(p, "/media"):
		return Response{Status: 200, ContentType: "application/json", Headers: headers, Label: "fake-wordpress-rest-media", Depth: max(depth, 4), Body: mustJSON([]map[string]any{{"id": 92, "slug": "ops-export", "source_url": "https://portal.internal/wp-content/uploads/2026/08/ops-export.txt"}})}
	case strings.Contains(p, "/tags") || strings.Contains(p, "/categories"):
		return Response{Status: 200, ContentType: "application/json", Headers: headers, Label: "fake-wordpress-rest-taxonomy", Depth: depth, Body: mustJSON([]map[string]any{{"id": 3, "name": "operations", "slug": "operations", "count": 6}})}
	default:
		return Response{Status: 200, ContentType: "application/json", Headers: headers, Label: "fake-wordpress-rest-index", Depth: depth, Body: mustJSON(map[string]any{"name": "Operations Notes", "url": "https://portal.internal", "namespaces": []string{"wp/v2", "batch/v1", "gravitysmtp/v1"}, "routes": map[string]any{"/wp/v2/users": map[string]any{}, "/wp/v2/posts": map[string]any{}, "/batch/v1": map[string]any{}}})}
	}
}

func isObservedRailsArtifact(p string) bool {
	base := path.Base(p)
	return strings.HasSuffix(p, "/config/credentials.yml.enc") || strings.HasSuffix(p, "/config/initializers/secret_token.rb") || strings.HasSuffix(p, "/config/master.key") || strings.Contains(p, "/redmine/config/configuration.yml") || base == "secret_token.rb"
}

func buildObservedRailsArtifact(p string, ss *model.Session, a, b string, canaries map[string]string) Response {
	depth := max(ss.Depth, 4)
	switch {
	case strings.HasSuffix(p, "credentials.yml.enc"):
		blob := "QWN0aXZlU3VwcG9ydDo6TWVzc2FnZUVuY3J5cHRvcjo6TWVzc2FnZQ==--" + a + b + "\n"
		return Response{Status: 200, ContentType: "application/octet-stream", Label: "story-rails-encrypted-credentials", Depth: depth, Body: []byte(blob)}
	case strings.HasSuffix(p, "master.key"):
		return Response{Status: 200, ContentType: "text/plain; charset=utf-8", Label: "story-rails-master-key", Depth: max(depth, 5), Body: []byte(a + b + a[:8] + "\n")}
	case strings.HasSuffix(p, "secret_token.rb"):
		body := "Rails.application.config.secret_key_base = ENV.fetch('SECRET_KEY_BASE', '" + canaries["internal-api"] + "')\n# legacy deploy notes: /config/credentials.yml.enc\n"
		return Response{Status: 200, ContentType: "text/plain; charset=utf-8", Label: "story-rails-secret-token", Depth: max(depth, 5), Body: []byte(body)}
	default:
		body := "production:\n  email_delivery:\n    delivery_method: :smtp\n    smtp_settings:\n      address: smtp-relay.internal\n  database_host: db-primary\n  backup_host: backup-01\n  internal_api_token: " + canaries["internal-api"] + "\n"
		return Response{Status: 200, ContentType: "text/yaml; charset=utf-8", Label: "story-rails-redmine-config", Depth: max(depth, 5), Body: []byte(body)}
	}
}

func isObservedSCMArtifact(p string) bool {
	return p == "/.svn/wc.db" || p == "/.svn/entries" || p == "/.hg/hgrc" || p == "/.hg/requires" || p == "/.hg/branch"
}

func buildObservedSCMArtifact(p string, ss *model.Session, a string) Response {
	depth := max(ss.Depth, 3)
	switch p {
	case "/.svn/wc.db":
		// A forbidden wc.db is a realistic existence leak without shipping a fake,
		// invalid SQLite database that a scanner could trivially fingerprint.
		return Response{Status: http.StatusForbidden, ContentType: "text/html; charset=utf-8", Headers: map[string]string{"Server": "Apache/2.4.58 (Ubuntu)"}, Label: "fake-svn-wcdb-forbidden", Depth: depth, Body: []byte("<!doctype html><title>403 Forbidden</title><h1>Forbidden</h1>")}
	case "/.svn/entries":
		return Response{Status: 200, ContentType: "text/plain; charset=utf-8", Label: "fake-svn-entries", Depth: max(depth, 4), Body: []byte("12\ndir\n" + a + "\nhttps://svn.prod.internal/repos/portal/trunk\n")}
	case "/.hg/requires":
		return Response{Status: 200, ContentType: "text/plain; charset=utf-8", Label: "fake-hg-requires", Depth: depth, Body: []byte("revlogv1\nstore\nfncache\ndotencode\n")}
	case "/.hg/branch":
		return Response{Status: 200, ContentType: "text/plain; charset=utf-8", Label: "fake-hg-branch", Depth: depth, Body: []byte("production\n")}
	default:
		return Response{Status: 200, ContentType: "text/plain; charset=utf-8", Label: "fake-hg-config", Depth: max(depth, 4), Body: []byte("[paths]\ndefault = ssh://hg@git.prod.internal/portal\n[ui]\nusername = deploy-bot <deploy@prod.internal>\n[auth]\nprod.prefix = git.prod.internal\n")}
	}
}

func isObservedCloudConfig(p string) bool {
	base := path.Base(p)
	return base == "aws.ini" || p == "/.aws;/config" || p == "/.amplifyrc" || strings.HasSuffix(p, "/amplify/team-provider-info.json") || base == "s3.yml" || base == "s3.yaml"
}

func buildObservedCloudConfig(p string, ss *model.Session, a string, canaries map[string]string) Response {
	depth := max(ss.Depth, 4)
	base := path.Base(p)
	switch {
	case strings.Contains(p, "amplify"):
		if strings.HasSuffix(p, ".json") {
			return Response{Status: 200, ContentType: "application/json", Label: "fake-amplify-config", Depth: depth, Body: mustJSON(map[string]any{"prod": map[string]any{"awscloudformation": map[string]string{"Region": "eu-central-1", "DeploymentBucketName": "portal-prod-deploy-" + a[:6], "StackName": "portal-prod"}, "categories": map[string]any{"auth": map[string]string{"userPoolId": "eu-central-1_" + a[:8]}}}})}
		}
		return Response{Status: 200, ContentType: "application/json", Label: "fake-amplify-config", Depth: depth, Body: mustJSON(map[string]any{"projectPath": ".", "envName": "prod", "configLevel": "project"})}
	case base == "s3.yml" || base == "s3.yaml":
		return Response{Status: 200, ContentType: "text/yaml; charset=utf-8", Label: "fake-s3-config", Depth: depth, Body: []byte("bucket: portal-prod-archive\nregion: eu-central-1\nendpoint: https://backup-01\naccess_key_id: AKIA" + strings.ToUpper(a[:10]) + "\nsecret_access_key: " + canaries["backup"] + "\n")}
	default:
		return Response{Status: 200, ContentType: "text/plain; charset=utf-8", Label: "fake-aws-config", Depth: depth, Body: []byte("[profile production]\nregion = eu-central-1\noutput = json\ncredential_process = /usr/local/bin/assume-prod-role\nrole_arn = arn:aws:iam::482193761204:role/portal-prod\nsource_profile = deploy\n")}
	}
}

func isObservedBackupArtifact(p string) bool {
	base := path.Base(p)
	return strings.HasSuffix(base, ".sql.gz") || base == "api.zip" || base == "app.zip" || base == "site.zip" || base == "public_html.zip" || base == "www.tar.gz"
}

func buildObservedBackupArtifact(p string, ss *model.Session, a, b string, canaries map[string]string) Response {
	depth := max(ss.Depth, 5)
	base := path.Base(p)
	if strings.HasSuffix(base, ".sql.gz") {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write([]byte("-- PostgreSQL database dump\nCREATE TABLE app_settings (key text, value text);\nINSERT INTO app_settings VALUES ('backup_host','backup-01'),('internal_api_token','" + canaries["internal-api"] + "');\n"))
		_ = zw.Close()
		return Response{Status: 200, ContentType: "application/gzip", Label: "fake-compressed-sql-backup", Depth: depth, Body: buf.Bytes()}
	}
	if strings.HasSuffix(base, ".zip") {
		return Response{Status: 200, ContentType: "application/zip", Label: "fake-application-backup", Depth: depth, Body: observedZIPArchive(a, b, canaries)}
	}
	return Response{Status: 200, ContentType: "application/gzip", Label: "fake-application-backup", Depth: depth, Body: observedTarGZArchive(a, canaries)}
}

func observedZIPArchive(a, b string, canaries map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range map[string]string{
		"README.txt":                "production archive - migration hold\n",
		"config/backup.env.example": "BACKUP_HOST=backup-01\nINTERNAL_API=/api/v1/internal/" + a + "\nBACKUP_TOKEN=" + canaries["backup"] + "\nREF=" + b + "\n",
	} {
		w, _ := zw.Create(name)
		_, _ = w.Write([]byte(body))
	}
	_ = zw.Close()
	return buf.Bytes()
}

func observedTarGZArchive(a string, canaries map[string]string) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte("archive_host=backup-01\ninternal_api=/api/v1/internal/" + a + "\nbackup_token=" + canaries["backup"] + "\n")
	_ = tw.WriteHeader(&tar.Header{Name: "public_html/config/archive.env.example", Mode: 0640, Size: int64(len(body)), ModTime: time.Date(2026, 8, 16, 2, 0, 0, 0, time.UTC)})
	_, _ = tw.Write(body)
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func isObservedSecretArtifact(p string) bool {
	base := strings.TrimSuffix(path.Base(p), ";")
	low := strings.ToLower(base)
	if strings.Contains(low, "credentials.") && (strings.HasSuffix(low, ".bak") || strings.HasSuffix(low, ".save") || strings.HasSuffix(low, ".swp") || strings.HasSuffix(low, ".old")) {
		return true
	}
	return low == "credentials.yml.enc" || low == "secret_token.rb"
}

func buildObservedSecretArtifact(p string, ss *model.Session, a string, canaries map[string]string) Response {
	body := "# production IAM compatibility file\nrole=svc-backup\nbackup_host=backup-01\ninternal_api=/api/v1/internal/" + a + "\ntoken=" + canaries["backup"] + "\n"
	return Response{Status: 200, ContentType: "text/plain; charset=utf-8", Label: "fake-secret-backup-artifact", Depth: max(ss.Depth, 4), Body: []byte(body)}
}

func isObservedPHPBackdoor(p string) bool {
	base := path.Base(p)
	if !strings.HasSuffix(base, ".php") || strings.Contains(p, "/wp-content/") || strings.Contains(p, "/wp-includes/") {
		return false
	}
	name := strings.TrimSuffix(base, ".php")
	if name == "index" || name == "phpinfo" || name == "info" {
		return false
	}
	for _, n := range []string{"function", "database", "dialog", "autoload_classmap", "footer", "m", "css"} {
		if name == n {
			return true
		}
	}
	for _, dir := range []string{"/uploads/", "/filemanager/", "/plugins/", "/themes/", "/images/", "/css/", "/files/", "/public/", "/fw/", "/function/", "/about/"} {
		if strings.Contains(p, dir) {
			return true
		}
	}
	return false
}

func deterministicObservedReveal(sessionID, p string, modulo int) bool {
	if modulo <= 1 {
		return true
	}
	n := 0
	for _, r := range sessionID + "|" + p {
		n = (n*33 + int(r)) % modulo
	}
	return n == 0
}

// currentWebStory remains as a compatibility/introspection helper for tests and
// existing callers. Web Story v1 decisions are target-wide in Deception.story;
// this helper only describes what a single retained session already knows.
func currentWebStory(ss *model.Session) string {
	if ss == nil {
		return ""
	}
	if ss.WebStory != "" {
		return ss.WebStory
	}
	for i := len(ss.Journey) - 1; i >= 0; i-- {
		label := strings.ToLower(ss.Journey[i].Label)
		if strings.HasPrefix(label, "story-mismatch-") || strings.HasSuffix(label, "-miss") {
			continue
		}
		p := canonicalObservedWebPath(ss.Journey[i].Path)
		switch {
		case strings.Contains(label, "wordpress") || isWordPressStoryPath(p):
			return "wordpress"
		case strings.Contains(label, "rails") || isRailsStoryPath(p):
			return "rails"
		case strings.Contains(label, "php-backdoor") || strings.Contains(label, "legacy-php"):
			return "php"
		}
	}
	return ""
}
