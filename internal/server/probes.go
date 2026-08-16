package server

import (
	"net/http"
	"strings"
)

type probeInfo struct{ Name, Product, CVE string }

type probeMatch uint8

const (
	matchContains probeMatch = iota
	matchPrefix
	matchExact
)

type probeRule struct {
	needle string
	match  probeMatch
	info   probeInfo
}

var knownProbes = []probeRule{
	// Observed in the wild / high-signal appliance and remote-access probes.
	{needle: "/sdk/weblanguage", match: matchContains, info: probeInfo{"Hikvision webLanguage command-injection probe", "Hikvision IP camera/NVR", "CVE-2021-36260"}},
	{needle: "/+cscoe+/logon.html", match: matchContains, info: probeInfo{"Cisco WebVPN / Secure Client login discovery", "Cisco ASA / Firepower remote access", ""}},
	{needle: "/remote/logincheck", match: matchPrefix, info: probeInfo{"ZentLoop decoy SSL-VPN authentication follow", "ZentLoop", ""}},
	{needle: "/remote/login", match: matchPrefix, info: probeInfo{"SSL-VPN remote login discovery", "Fortinet / remote-access appliance", ""}},
	{needle: "/dispatch.asp", match: matchExact, info: probeInfo{"Embedded gateway dispatcher discovery", "Router / embedded web UI", ""}},
	{needle: "/webpages/login.html", match: matchExact, info: probeInfo{"Embedded device login discovery", "Network / embedded appliance", ""}},
	{needle: "/doc/index.html", match: matchExact, info: probeInfo{"Embedded device web console discovery", "Network / embedded appliance", ""}},
	{needle: "/manage/account/login", match: matchPrefix, info: probeInfo{"Management account login discovery", "Generic management portal", ""}},
	{needle: "/login.jsp", match: matchExact, info: probeInfo{"Java management login discovery", "Java web application / appliance", ""}},
	{needle: "/login.html", match: matchExact, info: probeInfo{"HTML login endpoint discovery", "Generic web application", ""}},
	{needle: "/login.htm", match: matchExact, info: probeInfo{"Legacy HTML login endpoint discovery", "Generic web application", ""}},
	{needle: "/login", match: matchExact, info: probeInfo{"Generic login endpoint discovery", "Generic web application", ""}},
	{needle: "/web/", match: matchExact, info: probeInfo{"Embedded web root discovery", "Network / embedded appliance", ""}},

	// ZentLoop's own bounded lure chain.
	{needle: "/api/v1/internal/", match: matchPrefix, info: probeInfo{"ZentLoop internal API bait follow", "ZentLoop", ""}},
	{needle: "/api/v2/private/", match: matchPrefix, info: probeInfo{"ZentLoop private API bait follow", "ZentLoop", ""}},
	{needle: "/backup/", match: matchPrefix, info: probeInfo{"Backup discovery / ZentLoop bait", "Generic web application", ""}},
	{needle: "/debug/", match: matchPrefix, info: probeInfo{"Debug endpoint discovery / ZentLoop bait", "Generic web application", ""}},
	{needle: "/admin/", match: matchPrefix, info: probeInfo{"Admin endpoint discovery / ZentLoop bait", "Generic web application", ""}},
	{needle: "/auth/session/", match: matchPrefix, info: probeInfo{"ZentLoop decoy authentication follow", "ZentLoop", ""}},
	{needle: "/auth/mfa/", match: matchPrefix, info: probeInfo{"ZentLoop decoy MFA follow", "ZentLoop", ""}},
	{needle: "/auth/recovery/", match: matchPrefix, info: probeInfo{"ZentLoop decoy recovery follow", "ZentLoop", ""}},
	{needle: "/sso/status", match: matchExact, info: probeInfo{"ZentLoop decoy SSO status follow", "ZentLoop", ""}},
	{needle: "/help/admin", match: matchExact, info: probeInfo{"ZentLoop decoy admin help follow", "ZentLoop", ""}},
	{needle: "/manage/status/", match: matchPrefix, info: probeInfo{"ZentLoop decoy management status follow", "ZentLoop", ""}},
	{needle: "/diag/status/", match: matchPrefix, info: probeInfo{"ZentLoop decoy diagnostics follow", "ZentLoop", ""}},
	{needle: "/config/export/", match: matchPrefix, info: probeInfo{"ZentLoop decoy configuration export follow", "ZentLoop", ""}},
	{needle: "/+cscoe+/portal.html", match: matchPrefix, info: probeInfo{"ZentLoop decoy WebVPN portal follow", "ZentLoop", ""}},
	{needle: "/+cscoe+/login.html", match: matchPrefix, info: probeInfo{"ZentLoop decoy WebVPN authentication follow", "ZentLoop", ""}},

	// Common discovery/fingerprint probes.
	{needle: "/.env", match: matchPrefix, info: probeInfo{"Environment file discovery", "Generic web application", ""}},
	{needle: "/.git", match: matchContains, info: probeInfo{"Exposed Git repository discovery", "Git", ""}},
	{needle: "/wp-login", match: matchContains, info: probeInfo{"WordPress login discovery", "WordPress", ""}},
	{needle: "/wp-admin", match: matchContains, info: probeInfo{"WordPress admin discovery", "WordPress", ""}},
	{needle: "/xmlrpc.php", match: matchContains, info: probeInfo{"WordPress XML-RPC discovery", "WordPress", ""}},
	{needle: "/phpmyadmin", match: matchContains, info: probeInfo{"phpMyAdmin discovery", "phpMyAdmin", ""}},
	{needle: "/actuator", match: matchContains, info: probeInfo{"Spring Boot actuator discovery", "Spring Boot", ""}},
	{needle: "/server-status", match: matchContains, info: probeInfo{"Apache server-status discovery", "Apache HTTP Server", ""}},
	{needle: "/vendor/phpunit", match: matchContains, info: probeInfo{"PHPUnit exposed endpoint probe", "PHPUnit", "CVE-2017-9841"}},
	{needle: "/phpunit/", match: matchContains, info: probeInfo{"PHPUnit eval-stdin endpoint probe", "PHPUnit", "CVE-2017-9841"}},
	{needle: "/lib/phpunit/", match: matchContains, info: probeInfo{"PHPUnit eval-stdin endpoint probe", "PHPUnit", "CVE-2017-9841"}},
	{needle: "/containers/json", match: matchExact, info: probeInfo{"Docker Engine API container discovery", "Docker Engine API", ""}},
	{needle: "/settings.js", match: matchExact, info: probeInfo{"Frontend runtime configuration discovery", "Web application", ""}},
	{needle: "/config.json.js", match: matchExact, info: probeInfo{"Frontend runtime configuration discovery", "Web application", ""}},
	{needle: "/credentials.js", match: matchExact, info: probeInfo{"Frontend credential/configuration discovery", "Web application", ""}},
	{needle: "/administrator/manifests/files/joomla.xml", match: matchExact, info: probeInfo{"Joomla version manifest discovery", "Joomla", ""}},
	{needle: "/language/en-gb/en-gb.xml", match: matchExact, info: probeInfo{"Joomla language/version discovery", "Joomla", ""}},
	{needle: "/media/system/js/core.js", match: matchExact, info: probeInfo{"Joomla core asset discovery", "Joomla", ""}},
	{needle: "/administrator/", match: matchExact, info: probeInfo{"Joomla administrator discovery", "Joomla", ""}},
	{needle: "/_next/webpack-hmr", match: matchExact, info: probeInfo{"Next.js development endpoint discovery", "Next.js", ""}},
	{needle: "/_next/static/", match: matchExact, info: probeInfo{"Next.js static asset discovery", "Next.js", ""}},
	{needle: "/cgi-bin/", match: matchContains, info: probeInfo{"CGI endpoint discovery", "Generic CGI", ""}},
	{needle: "/swagger", match: matchContains, info: probeInfo{"Swagger/OpenAPI discovery", "API", ""}},
	{needle: "/openapi", match: matchContains, info: probeInfo{"OpenAPI discovery", "API", ""}},
	{needle: "/graphql", match: matchContains, info: probeInfo{"GraphQL discovery", "GraphQL", ""}},
	{needle: "/jenkins", match: matchContains, info: probeInfo{"Jenkins discovery", "Jenkins", ""}},
	{needle: "/solr/", match: matchContains, info: probeInfo{"Apache Solr discovery", "Apache Solr", ""}},
	{needle: "/boaform/", match: matchContains, info: probeInfo{"Embedded router/webcam probe", "Embedded web server", ""}},
	{needle: "/hudson", match: matchContains, info: probeInfo{"Hudson/Jenkins discovery", "Hudson/Jenkins", ""}},
	{needle: "/.aws/credentials", match: matchContains, info: probeInfo{"Cloud credential discovery", "AWS", ""}},
}

func isBenignDiscovery(path string) bool {
	p := strings.ToLower(strings.TrimSpace(path))
	switch p {
	case "/.well-known/passkey-endpoints":
		return true
	default:
		return false
	}
}

func isActivityPubInboxRequest(r *http.Request) bool {
	if r == nil || r.Method != http.MethodPost || normalizeProbePath(r.URL.Path) != "/inbox" {
		return false
	}
	ua := strings.ToLower(r.UserAgent())
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	// Relay software seen in the wild as well as normal ActivityPub delivery.
	// The path alone is deliberately insufficient so a random POST /inbox is not
	// granted benign status merely by choosing a known federation endpoint.
	return strings.Contains(ua, "activity-relay") ||
		strings.Contains(ua, "toot relay") ||
		strings.Contains(ct, "application/activity+json") ||
		strings.Contains(ct, "application/ld+json")
}

func identifyProbe(path string) (probeInfo, bool) {
	if info, ok := identifyProbeFamily(path); ok {
		return info, true
	}
	p := strings.ToLower(path)
	for _, x := range knownProbes {
		matched := false
		switch x.match {
		case matchExact:
			matched = p == x.needle
		case matchPrefix:
			matched = strings.HasPrefix(p, x.needle)
		default:
			matched = strings.Contains(p, x.needle)
		}
		if matched {
			return x.info, true
		}
	}
	return probeInfo{}, false
}
