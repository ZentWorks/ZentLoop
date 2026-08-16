package engine

import (
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"zentloop/internal/config"
	"zentloop/internal/model"
)

type Scorer struct{ cfg config.Config }

func NewScorer(cfg config.Config) *Scorer { return &Scorer{cfg: cfg} }

type Assessment struct {
	Risk           int
	Automation     int
	Classification model.Classification
	Actor          model.ActorType
	Confidence     string
	Category       string
	Persona        string
}

var pathSignals = []struct {
	needle       string
	weight       int
	cat, persona string
}{
	{"/sdk/weblanguage", 52, "exploit-probe", "embedded"}, {"/.env", 42, "secret-discovery", "devops"}, {"/.git", 38, "source-discovery", "devops"}, {"/wp-admin", 28, "cms-enumeration", "wordpress"},
	{"/+cscoe+/logon.html", 34, "vpn-enumeration", "remote-access"}, {"/remote/login", 32, "vpn-enumeration", "remote-access"}, {"/dispatch.asp", 26, "appliance-enumeration", "embedded"},
	{"/webpages/login.html", 22, "appliance-enumeration", "embedded"}, {"/doc/index.html", 20, "appliance-enumeration", "embedded"}, {"/manage/account/login", 22, "admin-enumeration", "web"},
	{"/login.jsp", 20, "admin-enumeration", "web"}, {"/login.html", 14, "login-enumeration", "web"}, {"/login.htm", 14, "login-enumeration", "web"},
	{"/wp-login", 28, "cms-enumeration", "wordpress"}, {"/phpmyadmin", 35, "admin-enumeration", "web"}, {"/swagger", 28, "api-enumeration", "api"},
	{"/openapi", 28, "api-enumeration", "api"}, {"/graphql", 20, "api-enumeration", "api"}, {"/actuator", 35, "framework-enumeration", "devops"},
	{"/jenkins", 32, "ci-enumeration", "devops"}, {"/backup", 25, "backup-discovery", "web"}, {"/admin", 14, "admin-enumeration", "web"},
	{"/server-status", 30, "server-enumeration", "web"}, {"/vendor/phpunit", 45, "exploit-probe", "web"}, {"/phpunit/", 45, "exploit-probe", "web"}, {"/lib/phpunit/", 45, "exploit-probe", "web"}, {"/containers/json", 44, "container-enumeration", "containers"}, {"/credentials.js", 38, "credential-discovery", "devops"}, {"/config.json.js", 32, "config-discovery", "devops"}, {"/settings.js", 28, "config-discovery", "devops"}, {"/administrator/manifests/files/joomla.xml", 30, "cms-enumeration", "joomla"}, {"/_next/", 18, "framework-enumeration", "web"}, {"/cgi-bin", 30, "exploit-probe", "web"},
	{"/fetch", 32, "ssrf-discovery", "api"}, {"/proxy", 32, "ssrf-discovery", "api"}, {"/@fs/", 52, "file-read", "devops"}, {"/proc/self/environ", 52, "file-read", "devops"}, {"terraform.tfstate", 48, "credential-discovery", "cloud"}, {"terraform.tfvars", 46, "credential-discovery", "cloud"}, {".azure/", 46, "credential-discovery", "cloud"}, {".npmrc", 42, "credential-discovery", "devops"}, {".netrc", 44, "credential-discovery", "devops"}, {"rclone.conf", 44, "credential-discovery", "cloud"}, {"/latest/meta-data/", 52, "cloud-metadata-discovery", "cloud"}, {"/db.sql", 40, "backup-discovery", "database"}, {"/dump.sql", 40, "backup-discovery", "database"},
	{"/id_rsa", 48, "credential-discovery", "devops"}, {"/id_ed25519", 48, "credential-discovery", "devops"}, {"/.docker/config.json", 46, "credential-discovery", "containers"}, {"serviceaccountkey.json", 46, "credential-discovery", "cloud"}, {"service-account.json", 46, "credential-discovery", "cloud"}, {"firebase-adminsdk.json", 44, "credential-discovery", "cloud"}, {"/credentials.json", 42, "credential-discovery", "cloud"}, {"/secrets.json", 42, "credential-discovery", "cloud"},
	{"/api/v1/internal/", 35, "bait-follow", "api"}, {"/api/v2/private/", 40, "bait-follow", "api"}, {"/ops/inventory", 38, "bait-follow", "network"}, {"/internal/inventory", 38, "bait-follow", "network"}, {"/registry/v2/", 38, "bait-follow", "containers"}, {"/debug/", 32, "bait-follow", "devops"},
	{"../", 45, "path-traversal", "web"}, {"%2e%2e", 45, "path-traversal", "web"}, {"/etc/passwd", 55, "file-read", "web"},
}
var payloadSignals = []struct {
	needle string
	weight int
	cat    string
}{
	{"union select", 50, "sql-injection"}, {"or 1=1", 42, "sql-injection"}, {"<script", 40, "xss"}, {"${jndi:", 55, "jndi-probe"},
	{"/bin/sh", 45, "command-injection"}, {"cmd=", 20, "command-injection"}, {"wget ", 35, "command-injection"}, {"curl ", 25, "command-injection"},
}
var scannerUA = []string{"nuclei", "sqlmap", "nikto", "masscan", "zgrab", "gobuster", "ffuf", "dirbuster", "wpscan", "acunetix", "nessus", "openvas", "python-requests", "go-http-client", "genomecrawlerd"}

func (s *Scorer) Assess(r *http.Request, ss *model.Session, bodySample string) Assessment {
	return s.AssessAt(r, ss, bodySample, time.Now())
}

func (s *Scorer) AssessAt(r *http.Request, ss *model.Session, bodySample string, now time.Time) Assessment {
	path := strings.ToLower(r.URL.EscapedPath())
	query := strings.ToLower(r.URL.RawQuery)
	all := path + "?" + query + " " + strings.ToLower(bodySample)
	riskDelta := 0
	autoDelta := 0
	cat := "request"
	persona := ss.Persona
	for _, sig := range pathSignals {
		if strings.Contains(all, sig.needle) {
			riskDelta = max(riskDelta, sig.weight)
			cat = sig.cat
			if persona == "" {
				persona = sig.persona
			}
		}
	}
	for _, sig := range payloadSignals {
		if strings.Contains(all, sig.needle) {
			riskDelta = max(riskDelta, sig.weight)
			cat = sig.cat
		}
	}
	ua := strings.ToLower(r.UserAgent())
	for _, x := range scannerUA {
		if strings.Contains(ua, x) {
			riskDelta += 22
			autoDelta += 35
			cat = "scanner-fingerprint"
			break
		}
	}
	if r.Method == http.MethodTrace || r.Method == http.MethodConnect {
		riskDelta += 30
		autoDelta += 10
		cat = "unusual-method"
	}
	if strings.TrimSpace(r.UserAgent()) == "" {
		autoDelta += 12
	}
	if r.Header.Get("Sec-Fetch-Site") != "" || r.Header.Get("Sec-Fetch-Mode") != "" {
		autoDelta -= 8
	}
	if r.Header.Get("Accept-Language") != "" {
		autoDelta -= 4
	} else if r.Header.Get("Sec-Fetch-Mode") == "" {
		// Fast clients that also omit common browser navigation signals are more likely tools/bots.
		autoDelta += 8
	}

	times := append(append([]time.Time(nil), ss.RecentTimes...), now)
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	if len(times) > 12 {
		times = times[len(times)-12:]
	}
	avg, varMS := intervalStats(times)
	if len(times) >= 3 {
		switch {
		case avg < 150:
			autoDelta += 45
		case avg < 350:
			autoDelta += 32
		case avg < 800:
			autoDelta += 18
		case avg > 2500:
			autoDelta -= 18
		}
		if varMS < 80 && avg < 1200 {
			autoDelta += 12
		}
		if len(times) >= 6 && times[len(times)-1].Sub(times[len(times)-6]) < 2*time.Second {
			autoDelta += 18
		}
	}
	// Persistent scores decay slowly toward new evidence instead of jumping on one request.
	risk := clamp(max(ss.RiskScore-2, 0)+riskDelta, 0, 100)
	auto := clamp(int(math.Round(float64(ss.AutomationScore)*0.72))+autoDelta, 0, 100)
	class := model.ClassBenign
	if risk >= s.cfg.HostileThreshold {
		class = model.ClassHostile
	} else if risk >= s.cfg.SuspiciousThreshold {
		class = model.ClassSuspicious
	}
	actor := model.ActorUnknown
	confidence := "low"
	if ss.RequestCount+1 >= 3 {
		if auto >= 65 {
			actor = model.ActorAutomated
		} else if auto <= 30 {
			actor = model.ActorHuman
		}
		if auto >= 85 || auto <= 15 {
			confidence = "high"
		} else if actor != model.ActorUnknown {
			confidence = "medium"
		}
	}
	return Assessment{Risk: risk, Automation: auto, Classification: class, Actor: actor, Confidence: confidence, Category: cat, Persona: persona}
}

func intervalStats(ts []time.Time) (int64, int64) {
	if len(ts) < 2 {
		return 0, 0
	}
	vals := make([]float64, 0, len(ts)-1)
	var sum float64
	for i := 1; i < len(ts); i++ {
		v := float64(ts[i].Sub(ts[i-1]).Milliseconds())
		vals = append(vals, v)
		sum += v
	}
	avg := sum / float64(len(vals))
	var sq float64
	for _, v := range vals {
		d := v - avg
		sq += d * d
	}
	return int64(avg), int64(math.Sqrt(sq / float64(len(vals))))
}
func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
