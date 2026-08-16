package store

import (
	"sort"
	"strings"
	"time"

	"zentloop/internal/model"
)

type HTTPBehaviorSignals struct {
	AutomationBoost  int
	RiskBoost        int
	Fingerprints     []string
	RecentRequests   int
	DistinctSessions int
	DistinctUAs      int
	DistinctPaths    int
}

func (s *Store) HTTPBehavior(ip, currentUA string, now time.Time) HTTPBehaviorSignals {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out HTTPBehaviorSignals
	sessions := map[string]struct{}{}
	uas := map[string]struct{}{}
	paths := map[string]struct{}{}
	botClaims := map[string]struct{}{}
	ssrfPaths, credentialPaths, fileReadPaths, phpPaths, wordpressPaths := 0, 0, 0, 0, 0
	for i := len(s.events) - 1; i >= 0; i-- {
		e := s.events[i]
		age := now.Sub(e.At)
		if age > 45*time.Second {
			break
		}
		if e.IP != ip {
			continue
		}
		out.RecentRequests++
		sessions[e.SessionID] = struct{}{}
		ua := strings.TrimSpace(strings.ToLower(e.UserAgent))
		if ua != "" {
			uas[ua] = struct{}{}
		}
		if e.Path != "" {
			paths[e.Path] = struct{}{}
			lowPath := strings.ToLower(e.Path)
			if strings.Contains(lowPath, "/fetch") || strings.Contains(lowPath, "/proxy") || strings.Contains(lowPath, "/webhook") || strings.Contains(lowPath, "/preview") || strings.Contains(lowPath, "/screenshot") {
				ssrfPaths++
			}
			if strings.Contains(lowPath, "credential") || strings.Contains(lowPath, ".aws") || strings.Contains(lowPath, ".azure") || strings.Contains(lowPath, "terraform") || strings.Contains(lowPath, ".npmrc") || strings.Contains(lowPath, ".netrc") || strings.Contains(lowPath, "service_account") || strings.Contains(lowPath, "service-account") {
				credentialPaths++
			}
			if strings.Contains(lowPath, "/@fs/") || strings.Contains(lowPath, "/proc/self/environ") || strings.Contains(lowPath, "../etc/passwd") {
				fileReadPaths++
			}
			if strings.HasSuffix(lowPath, ".php") {
				phpPaths++
			}
			if strings.Contains(lowPath, "/wp-includes/") || strings.Contains(lowPath, "/wp-content/") || strings.Contains(lowPath, "/wp-") {
				wordpressPaths++
			}
		}
		if c := botClaimLabel(e.UserAgent); c != "" {
			botClaims[c] = struct{}{}
		}
	}
	if u := strings.TrimSpace(strings.ToLower(currentUA)); u != "" {
		uas[u] = struct{}{}
	}
	if c := botClaimLabel(currentUA); c != "" {
		botClaims[c] = struct{}{}
	}
	out.DistinctSessions = len(sessions)
	out.DistinctUAs = len(uas)
	out.DistinctPaths = len(paths)

	// Actor-wide evidence intentionally dominates one browser-looking request.
	if out.RecentRequests >= 4 && out.DistinctSessions >= 3 {
		out.AutomationBoost += 45
		out.Fingerprints = append(out.Fingerprints, "http:parallel-prober")
	}
	if out.RecentRequests >= 8 && out.DistinctPaths >= 6 {
		out.AutomationBoost += 30
		out.RiskBoost += 8
		out.Fingerprints = append(out.Fingerprints, "http:config-hunter")
	}
	if out.DistinctUAs >= 3 {
		out.AutomationBoost += 35
		out.Fingerprints = append(out.Fingerprints, "http:ua-rotation")
	}
	if len(botClaims) >= 3 {
		out.AutomationBoost += 30
		out.RiskBoost += 8
		out.Fingerprints = append(out.Fingerprints, "http:spoofed-crawler-rotation")
	}
	if out.RecentRequests >= 16 {
		out.AutomationBoost += 20
		out.Fingerprints = append(out.Fingerprints, "http:burst-automation")
	}
	if ssrfPaths >= 2 {
		out.RiskBoost += 10
		out.Fingerprints = append(out.Fingerprints, "http:ssrf-prober")
	}
	if credentialPaths >= 4 {
		out.RiskBoost += 12
		out.Fingerprints = append(out.Fingerprints, "http:cloud-credential-hunter")
	}
	if fileReadPaths >= 2 {
		out.RiskBoost += 12
		out.Fingerprints = append(out.Fingerprints, "http:dev-file-reader")
	}
	if phpPaths >= 4 {
		out.RiskBoost += 10
		out.Fingerprints = append(out.Fingerprints, "http:php-backdoor-hunter")
	}
	if wordpressPaths >= 3 {
		out.RiskBoost += 8
		out.Fingerprints = append(out.Fingerprints, "http:wordpress-webshell-scanner")
	}
	sort.Strings(out.Fingerprints)
	return out
}

func botClaimLabel(ua string) string {
	l := strings.ToLower(ua)
	for _, row := range []struct{ needle, label string }{
		{"googlebot", "google"}, {"googleother", "google"}, {"google-cloudvertexbot", "google"},
		{"applebot", "apple"}, {"duckduckbot", "duckduckgo"}, {"duckassistbot", "duckduckgo"},
		{"oai-searchbot", "openai"}, {"gptbot", "openai"}, {"chatgpt-user", "openai"},
		{"perplexitybot", "perplexity"}, {"bingbot", "bing"}, {"baiduspider", "baidu"},
		{"yandexbot", "yandex"}, {"ccbot", "commoncrawl"},
	} {
		if strings.Contains(l, row.needle) {
			return row.label
		}
	}
	return ""
}

func clampAutomation(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// PromoteHTTPAutomation retroactively corrects currently retained HTTP sessions
// for an IP once actor-wide behavior proves the source is automated. This keeps
// parallel scanner sessions from remaining labelled human simply because their
// first individual request looked browser-like.
func (s *Store) PromoteHTTPAutomation(ip string, automationMin int) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return
	}
	if automationMin < 65 {
		automationMin = 65
	}
	if automationMin > 100 {
		automationMin = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ss := range s.sessions {
		if ss.IP != ip {
			continue
		}
		ss.Actor = model.ActorAutomated
		if ss.AutomationScore < automationMin {
			ss.AutomationScore = automationMin
		}
		if ss.Confidence == "" || ss.Confidence == "low" {
			ss.Confidence = "high"
		}
	}
	a := s.ensureActorLocked(ip, "", time.Now())
	a.Actor = model.ActorAutomated
}

func (s *Store) ApplyHTTPActorFingerprint(ip string, fps []string) {
	if strings.TrimSpace(ip) == "" || len(fps) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.ensureActorLocked(ip, "", time.Now())
	for _, fp := range fps {
		if addFingerprint(a, fp) {
			s.actorFingerprints[fp]++
		}
	}
}

// SSHRecurrence returns lightweight actor-level recurrence metrics derived from
// connection events. It is deliberately passive and does not affect listener limits.
type SSHRecurrence struct {
	Connections   int
	MedianSeconds int64
	JitterSeconds int64
	LowAndSlow    bool
}

func (s *Store) SSHRecurrence(ip string, now time.Time) SSHRecurrence {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sshRecurrenceLocked(ip, now)
}

func (s *Store) sshRecurrenceLocked(ip string, now time.Time) SSHRecurrence {
	var ts []time.Time
	for i := len(s.sshEvents) - 1; i >= 0; i-- {
		e := s.sshEvents[i]
		if now.Sub(e.At) > 24*time.Hour {
			break
		}
		if e.IP == ip && e.Type == "connect" {
			ts = append(ts, e.At)
		}
	}
	if len(ts) < 3 {
		return SSHRecurrence{Connections: len(ts)}
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
	ds := make([]int64, 0, len(ts)-1)
	for i := 1; i < len(ts); i++ {
		ds = append(ds, int64(ts[i].Sub(ts[i-1])/time.Second))
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	med := ds[len(ds)/2]
	dev := make([]int64, len(ds))
	for i, d := range ds {
		x := d - med
		if x < 0 {
			x = -x
		}
		dev[i] = x
	}
	sort.Slice(dev, func(i, j int) bool { return dev[i] < dev[j] })
	jitter := dev[len(dev)/2]
	return SSHRecurrence{Connections: len(ts), MedianSeconds: med, JitterSeconds: jitter, LowAndSlow: len(ts) >= 6 && med >= 20 && med <= 3600 && jitter <= max64(20, med/5)}
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
