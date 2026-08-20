package server

import (
	"net/url"
	"path"
	"strings"
)

// identifyObservedWebProbe maps recurring high-signal entries learned from the
// unknown-path export into families. Raw paths remain untouched in events.
func identifyObservedWebProbe(raw string) (probeInfo, bool) {
	p := canonicalObservedProbePath(raw)
	base := path.Base(p)

	switch {
	case strings.Contains(p, "/wp-json/") || strings.Contains(p, "/wp/v2/") || p == "/wp-json":
		return probeInfo{"WordPress REST / plugin API discovery", "WordPress", ""}, true
	case strings.HasSuffix(p, "/config/credentials.yml.enc") || strings.HasSuffix(p, "/config/initializers/secret_token.rb") || strings.HasSuffix(p, "/config/master.key") || strings.Contains(p, "/redmine/config/configuration.yml"):
		return probeInfo{"Rails secret / configuration discovery", "Ruby on Rails / Redmine", ""}, true
	case p == "/.svn/wc.db" || p == "/.svn/entries" || p == "/.hg/hgrc" || p == "/.hg/requires" || p == "/.hg/branch":
		return probeInfo{"Source control metadata discovery", "Subversion / Mercurial", ""}, true
	case base == "aws.ini" || p == "/.aws;/config" || p == "/.amplifyrc" || strings.HasSuffix(p, "/amplify/team-provider-info.json") || base == "s3.yml" || base == "s3.yaml":
		return probeInfo{"Cloud deployment configuration discovery", "AWS / Amplify / S3", ""}, true
	case strings.HasSuffix(base, ".sql.gz") || base == "api.zip" || base == "app.zip" || base == "site.zip" || base == "public_html.zip" || base == "www.tar.gz":
		return probeInfo{"Application backup / archive discovery", "Generic web application", ""}, true
	case observedSecretBackupProbe(base):
		return probeInfo{"Credential backup artifact discovery", "Generic web application", ""}, true
	case observedPHPBackdoorProbe(p):
		return probeInfo{"PHP webshell / backdoor discovery", "PHP web application", ""}, true
	default:
		return probeInfo{}, false
	}
}

func canonicalObservedProbePath(raw string) string {
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

func observedSecretBackupProbe(base string) bool {
	base = strings.TrimSuffix(strings.ToLower(base), ";")
	if !strings.Contains(base, "credentials.") {
		return false
	}
	return strings.HasSuffix(base, ".bak") || strings.HasSuffix(base, ".save") || strings.HasSuffix(base, ".swp") || strings.HasSuffix(base, ".old")
}

func observedPHPBackdoorProbe(p string) bool {
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
