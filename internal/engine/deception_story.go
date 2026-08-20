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
	if locked == "wordpress" && requested == "php" {
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

func storyEnvBody(resp Response, p string, profile *webStoryProfile) Response {
	if resp.Status != http.StatusOK || !strings.HasPrefix(strings.ToLower(resp.Label), "fake-env") || !strings.HasPrefix(resp.ContentType, "text/plain") {
		return resp
	}
	name := path.Base(canonicalObservedWebPath(p))
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
	profile := d.story.profile(storyTarget(ss), ss)
	p := canonicalObservedWebPath(r.URL.Path)
	candidate, weight := storyCandidate(p, resp.Label)
	follow := explicitStoryFollow(r, ss)

	// A locked target identity wins over scanner dictionary guesses. Generic
	// surfaces remain available, but contradictory product/framework jackpots do not.
	if profile.Locked && candidate != "" && !storyCompatible(profile.Technology, candidate) {
		miss := storyMiss(ss, candidate)
		miss.Delay = delay
		ss.WebStory = profile.Technology
		ss.WebStoryLocked = true
		ss.WebStoryConfidence = profile.Confidence
		return miss
	}

	if candidate != "" && weight > 0 {
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

	provider := storyCloudProvider(p, resp.Label)
	if provider != "" {
		if profile.Cloud == "" && resp.Status >= 200 && resp.Status < 300 {
			profile.Cloud = provider
		} else if profile.Cloud != "" && provider != profile.Cloud {
			miss := storyMiss(ss, "cloud-"+provider)
			miss.Delay = delay
			ss.WebStory = profile.Technology
			ss.WebStoryLocked = profile.Locked
			ss.WebStoryConfidence = profile.Confidence
			return miss
		}
	} else if isGenericCloudCredential(resp.Label) && profile.Cloud != "" {
		// Generic cloud files are allowed to exist without creating a second
		// provider identity; their content is still synthetic and inert.
	}

	if resp.Status >= 200 && resp.Status < 300 && !storyArtifactAllowed(profile, p, resp.Label) {
		miss := storyMiss(ss, "artifact")
		miss.Label = "story-artifact-miss"
		miss.Delay = delay
		ss.WebStory = profile.Technology
		ss.WebStoryLocked = profile.Locked
		ss.WebStoryConfidence = profile.Confidence
		return miss
	}

	resp = storyEnvBody(resp, p, profile)
	resp.Depth = realisticWebDepth(ss, resp, p, follow)
	// Dictionary hits are not deception loops. Only explicit followed chains and
	// the dedicated deep loop bait may increase frustration/loop state.
	if resp.LoopInc > 0 && !follow && !strings.Contains(strings.ToLower(resp.Label), "loop-bait") {
		resp.LoopInc = 0
	}
	resp.Delay = delay
	ss.WebStory = profile.Technology
	ss.WebStoryLocked = profile.Locked
	ss.WebStoryConfidence = profile.Confidence
	return resp
}
