package engine

import (
	"hash/fnv"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"zentloop/internal/model"
)

const maxWebStoryProfiles = 2048

type TargetRealityProvider interface {
	ResolveTargetReality(target string) model.TargetRealityResolved
	ObserveTargetReality(target, candidate, cloud string, weight int, success bool) model.TargetRealityResolved
}

func normalizedRealityApp(v string) string {
	switch v {
	case "php":
		return "generic-php"
	case "asp":
		return "aspnet"
	default:
		return v
	}
}

func realityHas(values []string, want string) bool {
	want = normalizedRealityApp(want)
	for _, v := range values {
		if normalizedRealityApp(v) == want {
			return true
		}
	}
	return false
}

type webStoryProfile struct {
	Technology string
	Locked     bool
	Confidence string
	Cloud      string
	Evidence   map[string]int
	LastSeen   time.Time
	Seed       uint32
}

type webStoryState struct {
	mu       sync.Mutex
	profiles map[string]*webStoryProfile
}

func newWebStoryState() *webStoryState {
	return &webStoryState{profiles: make(map[string]*webStoryProfile)}
}

func (s *webStoryState) profile(target string, ss *model.Session) *webStoryProfile {
	target = normalizeStoryTarget(target)
	now := time.Now()
	p := s.profiles[target]
	if p == nil {
		p = &webStoryProfile{Evidence: make(map[string]int), Seed: storyHash(target), LastSeen: now}
		if ss != nil && ss.WebStory != "" {
			p.Technology = ss.WebStory
			p.Locked = ss.WebStoryLocked
			p.Confidence = ss.WebStoryConfidence
		}
		s.profiles[target] = p
		if len(s.profiles) > maxWebStoryProfiles {
			s.pruneOldestLocked()
		}
	}
	p.LastSeen = now
	return p
}

func (s *webStoryState) pruneOldestLocked() {
	var oldestKey string
	var oldest time.Time
	for k, p := range s.profiles {
		if oldestKey == "" || p.LastSeen.Before(oldest) {
			oldestKey, oldest = k, p.LastSeen
		}
	}
	if oldestKey != "" {
		delete(s.profiles, oldestKey)
	}
}

func normalizeStoryTarget(target string) string {
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		return "default"
	}
	return target
}

func storyHash(v string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(v))
	return h.Sum32()
}

func storyTarget(ss *model.Session) string {
	if ss == nil {
		return "default"
	}
	if ss.Target != "" {
		return ss.Target
	}
	if ss.RequestHost != "" {
		return ss.RequestHost
	}
	return ss.ID
}

func storyCandidate(p, label string) (string, int) {
	p = canonicalObservedWebPath(p)
	label = strings.ToLower(label)
	switch {
	case p == "/+cscoe+/logon.html" || strings.HasPrefix(p, "/+cscoe+/"):
		return "cisco-remote-access", 3
	case p == "/remote/login" || strings.HasPrefix(p, "/remote/"):
		return "fortinet-remote-access", 3
	case p == "/web/" || p == "/webpages/login.html" || p == "/doc/index.html" || strings.Contains(label, "embedded") || strings.Contains(label, "device-web"):
		return "embedded-appliance", 2
	case isWordPressStoryPath(p) || strings.Contains(label, "wordpress"):
		return "wordpress", 3
	case strings.HasPrefix(p, "/_next") || p == "/_rsc" || p == "/__rsc" || strings.HasPrefix(p, "/rsc/") || strings.HasPrefix(p, "/api/auth/") || strings.Contains(label, "nextjs"):
		return "nextjs", 3
	case isRailsStoryPath(p) || strings.Contains(label, "rails"):
		return "rails", 3
	case strings.Contains(p, "/app_dev.php/_profiler") || strings.HasPrefix(p, "/_profiler") || strings.Contains(label, "phpinfo") || strings.Contains(label, "php-backdoor"):
		return "php", 2
	case strings.HasSuffix(p, ".jsp"):
		return "java", 2
	case strings.HasSuffix(p, ".asp") || strings.HasSuffix(p, ".aspx"):
		return "asp", 2
	}
	return "", 0
}

func storyCompatible(locked, requested string) bool {
	if locked == "" || requested == "" || locked == requested {
		return true
	}
	// WordPress commonly exposes ordinary PHP runtime surfaces. Do not let that
	// compatibility turn into a second framework story, though.
	if locked == "wordpress" && normalizedRealityApp(requested) == "generic-php" {
		return true
	}
	return false
}

func storyCloudProvider(p, label string) string {
	p = strings.ToLower(p)
	label = strings.ToLower(label)
	switch {
	case strings.Contains(p, "/.azure/") || strings.Contains(label, "azure"):
		return "azure"
	case strings.Contains(p, "gcloud") || strings.Contains(p, "google") || strings.Contains(p, "service-account") || strings.Contains(p, "serviceaccount") || strings.Contains(p, "firebase") || strings.Contains(label, "cloud-service-account") || strings.Contains(label, "amplify"):
		return "gcp"
	case strings.Contains(p, "/.aws/") || strings.Contains(p, "/aws/") || strings.Contains(p, "s3") || strings.Contains(p, "boto") || strings.Contains(label, "aws") || strings.Contains(label, "s3"):
		return "aws"
	}
	return ""
}

func isGenericCloudCredential(label string) bool {
	label = strings.ToLower(label)
	return strings.Contains(label, "cloud-service-account") || strings.Contains(label, "app-config")
}

func storyMiss(ss *model.Session, what string) Response {
	return Response{
		Status:      http.StatusNotFound,
		ContentType: "text/html; charset=utf-8",
		Label:       "story-mismatch-" + what,
		Depth:       ss.Depth,
		Body:        []byte("<!doctype html><title>404 Not Found</title><h1>Not Found</h1>"),
	}
}

func storyArtifactFamily(p, label string) string {
	p = canonicalObservedWebPath(p)
	label = strings.ToLower(label)
	switch {
	case strings.Contains(label, "ssh-private-key") || strings.Contains(p, "/.ssh/") || strings.Contains(p, "id_rsa") || strings.Contains(p, "id_dsa") || strings.Contains(p, "id_ecdsa"):
		return "ssh-keys"
	case strings.Contains(label, "git") || strings.Contains(p, "/.git"):
		return "git"
	case strings.Contains(label, "database-dump") || strings.Contains(label, "sql-export") || strings.HasSuffix(p, ".sql"):
		return "database-dumps"
	case strings.Contains(label, "backup") || strings.HasSuffix(p, ".bak") || strings.HasSuffix(p, ".old"):
		return "backups"
	case strings.Contains(label, "debug") || strings.Contains(p, "/debug") || strings.Contains(p, "trace.axd"):
		return "debug"
	case strings.Contains(label, "docker-api") || strings.HasPrefix(p, "/containers/") || strings.HasPrefix(p, "/exec/"):
		return "docker-api"
	case strings.Contains(label, "metadata") || strings.Contains(label, "cloud-"):
		return "cloud-metadata"
	case strings.Contains(label, "ci-") || strings.Contains(p, "jenkins"):
		return "cicd"
	case strings.Contains(label, "app-config") || strings.Contains(p, "compose") || strings.Contains(p, "appsettings") || strings.Contains(p, "serverless") || strings.Contains(p, "kubernetes"):
		return "app-config"
	case strings.Contains(label, "env") || strings.Contains(p, ".env"):
		return "env"
	}
	return ""
}

func storyArtifactAllowed(profile *webStoryProfile, p, label string) bool {
	p = canonicalObservedWebPath(p)
	label = strings.ToLower(label)
	base := path.Base(p)

	if strings.HasPrefix(label, "fake-env") || strings.HasPrefix(base, ".env") || strings.HasSuffix(base, ".env") {
		if p == "/.env" || p == "/.env.example" || p == "/laravel/.env" {
			return true
		}
		return (storyHash(p+"|env")^profile.Seed)%4 == 0
	}

	if strings.Contains(label, "ssh-private-key") {
		choices := []string{"/.ssh/id_rsa", "/id_rsa", "/server.key"}
		managed := false
		for _, choice := range choices {
			if p == choice {
				managed = true
				break
			}
		}
		if !managed {
			return true
		}
		chosen := choices[int(profile.Seed%uint32(len(choices)))]
		return p == chosen
	}

	if strings.Contains(label, "application-backup") || strings.Contains(label, "compressed-sql-backup") || strings.Contains(label, "secret-backup-artifact") {
		return (storyHash(p+"|artifact")^profile.Seed)%3 != 0
	}
	return true
}

func semanticArtifactPath(p string) string {
	p = canonicalObservedWebPath(p)
	switch p {
	case "/@fs/proc/self/cwd/.env", "/$(pwd)/.env", "/var/www/html/.env", "/srv/app/.env":
		return "/.env"
	case "/@fs/root/.aws/credentials":
		return "/.aws/credentials"
	case "/@fs/root/.aws/config":
		return "/.aws/config"
	}
	return p
}

func storyEnvBody(resp Response, p string, profile *webStoryProfile) Response {
	if resp.Status != http.StatusOK || !strings.HasPrefix(strings.ToLower(resp.Label), "fake-env") || !strings.HasPrefix(resp.ContentType, "text/plain") {
		return resp
	}
	p = semanticArtifactPath(p)
	name := path.Base(p)
	if name == "." || name == "/" || name == "" {
		name = ".env"
	}
	// Small, stable differences keep environment variants believable instead of
	// returning byte-identical files for every dictionary entry.
	extra := "\n# source=" + name + "\nCONFIG_REV=" + storyRevision(profile, p) + "\n"
	resp.Body = append(resp.Body, []byte(extra)...)
	return resp
}

func storyRevision(profile *webStoryProfile, p string) string {
	v := storyHash(p) ^ profile.Seed
	const hex = "0123456789abcdef"
	out := make([]byte, 8)
	for i := range out {
		out[i] = hex[(v>>uint((7-i)*4))&0xf]
	}
	return string(out)
}

func explicitStoryFollow(r *http.Request, ss *model.Session) bool {
	if r == nil || ss == nil || r.Referer() == "" {
		return false
	}
	u, err := url.Parse(r.Referer())
	if err != nil {
		return false
	}
	ref := canonicalObservedWebPath(u.Path)
	cur := canonicalObservedWebPath(r.URL.Path)
	if ref == "/web" || ref == "/web/" {
		return cur == "/webpages/login.html"
	}
	if strings.HasPrefix(ref, "/+cscoe+/login.html") {
		return strings.HasPrefix(cur, "/+cscoe+/portal.html")
	}
	if strings.HasPrefix(ref, "/remote/logincheck") {
		return strings.HasPrefix(cur, "/remote/login")
	}
	if strings.HasPrefix(ref, "/auth/mfa/") {
		return strings.HasPrefix(cur, "/auth/recovery/")
	}
	return false
}

func realisticWebDepth(ss *model.Session, resp Response, p string, follow bool) int {
	current := 0
	if ss != nil {
		current = ss.Depth
	}
	label := strings.ToLower(resp.Label)
	wanted := 0
	switch {
	case resp.Status == http.StatusNotFound || strings.HasPrefix(label, "story-mismatch-") || strings.HasSuffix(label, "-miss"):
		wanted = current
	case follow:
		wanted = 5
	case strings.Contains(label, "loop-bait"):
		wanted = 6
	case strings.Contains(label, "backup") || strings.Contains(label, "database-dump") || strings.Contains(label, "terraform-state") || strings.Contains(label, "internal-api") || strings.Contains(label, "config-export"):
		wanted = 5
	case strings.Contains(label, "credential") || strings.Contains(label, "private-key") || strings.Contains(label, "master-key") || strings.Contains(label, "secret"):
		wanted = 4
	case strings.Contains(label, "env") || strings.Contains(label, "debug") || strings.Contains(label, "profiler") || strings.Contains(label, "phpinfo") || strings.Contains(label, "webshell") || strings.Contains(label, "app-config") || strings.Contains(label, "git") || strings.Contains(label, "svn") || strings.Contains(label, "hg"):
		wanted = 3
	case strings.Contains(label, "wordpress") || strings.Contains(label, "embedded") || strings.Contains(label, "device-web") || strings.Contains(label, "webvpn") || strings.Contains(label, "ssl-vpn") || strings.Contains(label, "php") || strings.Contains(label, "joomla") || strings.Contains(label, "nextjs"):
		wanted = 2
	case resp.Status >= 200 && resp.Status < 400 && resp.Label != "benign":
		wanted = 1
	}
	if wanted < current {
		return current
	}
	return wanted
}

func (d *Deception) finalizeWebStoryResponse(r *http.Request, ss *model.Session, resp Response, delay time.Duration) Response {
	if d.story == nil {
		d.story = newWebStoryState()
	}
	d.story.mu.Lock()
	defer d.story.mu.Unlock()
	target := storyTarget(ss)
	profile := d.story.profile(target, ss)
	p := semanticArtifactPath(canonicalObservedWebPath(r.URL.Path))
	candidate, weight := storyCandidate(p, resp.Label)
	follow := explicitStoryFollow(r, ss)
	provider := d.reality
	resolved := model.TargetRealityResolved{Target: target, Mode: "automatic", Source: "memory", Coherent: true}
	if provider != nil {
		resolved = provider.ResolveTargetReality(target)
		profile.Technology, profile.Locked, profile.Confidence, profile.Cloud = resolved.State.Technology, resolved.State.Locked, resolved.State.Confidence, resolved.State.Cloud
	}

	configuredApps := (resolved.Mode == "guided" || resolved.Mode == "fixed") && len(resolved.Applications) > 0
	if candidate != "" && resolved.State.Locked && resolved.State.Technology != "" && !storyCompatible(resolved.State.Technology, candidate) {
		miss := storyMiss(ss, candidate)
		miss.Delay = delay
		ss.WebStory = resolved.State.Technology
		ss.WebStoryLocked = true
		ss.WebStoryConfidence = resolved.State.Confidence
		return miss
	}
	if candidate != "" {
		if configuredApps && !realityHas(resolved.Applications, candidate) {
			miss := storyMiss(ss, candidate)
			miss.Delay = delay
			return miss
		}
		if !configuredApps && profile.Locked && !storyCompatible(profile.Technology, candidate) {
			miss := storyMiss(ss, candidate)
			miss.Delay = delay
			ss.WebStory = profile.Technology
			ss.WebStoryLocked = true
			ss.WebStoryConfidence = profile.Confidence
			return miss
		}
	}

	providerCloud := storyCloudProvider(p, resp.Label)
	if provider != nil {
		if follow {
			weight += 3
		}
		resolved = provider.ObserveTargetReality(target, candidate, providerCloud, weight, resp.Status >= 200 && resp.Status < 300)
		profile.Technology, profile.Locked, profile.Confidence, profile.Cloud = resolved.State.Technology, resolved.State.Locked, resolved.State.Confidence, resolved.State.Cloud
	} else if candidate != "" && weight > 0 {
		if follow {
			weight += 3
		}
		profile.Evidence[candidate] += weight
		if !profile.Locked {
			best, score := "", 0
			for tech, v := range profile.Evidence {
				if v > score {
					best, score = tech, v
				}
			}
			if score >= 5 {
				profile.Technology = best
				profile.Locked = true
				profile.Confidence = "high"
			} else if score >= 3 {
				profile.Technology = best
				profile.Confidence = "medium"
			}
		}
	}

	if provider == nil && providerCloud != "" && profile.Cloud == "" && resp.Status >= 200 && resp.Status < 300 {
		profile.Cloud = providerCloud
	}
	if providerCloud != "" {
		configuredClouds := []string{}
		for _, v := range resolved.Infrastructure {
			if v == "aws" || v == "azure" || v == "gcp" {
				configuredClouds = append(configuredClouds, v)
			}
		}
		if len(configuredClouds) > 0 && !realityHas(configuredClouds, providerCloud) {
			miss := storyMiss(ss, "cloud-"+providerCloud)
			miss.Delay = delay
			return miss
		}
		if len(configuredClouds) == 0 && profile.Cloud != "" && providerCloud != profile.Cloud {
			miss := storyMiss(ss, "cloud-"+providerCloud)
			miss.Delay = delay
			return miss
		}
	}

	artifactFamily := storyArtifactFamily(p, resp.Label)
	configuredArtifacts := (resolved.Mode == "guided" || resolved.Mode == "fixed") && len(resolved.Artifacts) > 0
	if resp.Status >= 200 && resp.Status < 300 && artifactFamily != "" && configuredArtifacts && !realityHas(resolved.Artifacts, artifactFamily) {
		miss := storyMiss(ss, "artifact")
		miss.Label = "story-artifact-miss"
		miss.Delay = delay
		return miss
	}
	if resp.Status >= 200 && resp.Status < 300 && !configuredArtifacts && !storyArtifactAllowed(profile, p, resp.Label) {
		miss := storyMiss(ss, "artifact")
		miss.Label = "story-artifact-miss"
		miss.Delay = delay
		return miss
	}

	resp = storyEnvBody(resp, p, profile)
	resp.Depth = realisticWebDepth(ss, resp, p, follow)
	if resp.LoopInc > 0 && !follow && !strings.Contains(strings.ToLower(resp.Label), "loop-bait") {
		resp.LoopInc = 0
	}
	resp.Delay = delay
	ss.WebStory = profile.Technology
	ss.WebStoryLocked = profile.Locked
	ss.WebStoryConfidence = profile.Confidence
	return resp
}
