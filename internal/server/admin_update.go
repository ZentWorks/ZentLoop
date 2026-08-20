package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	zentLoopGitHubRepoURL   = "https://github.com/ZentWorks/ZentLoop"
	zentLoopGitHubLatestAPI = "https://api.github.com/repos/ZentWorks/ZentLoop/releases/latest"
	zentLoopUpdateInterval  = 12 * time.Hour
	zentLoopUpdateTimeout   = 3 * time.Second
)

type adminUpdateState struct {
	CheckedAt     time.Time
	LatestVersion string
	Available     bool
	Checking      bool
}

type githubLatestRelease struct {
	TagName    string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
}

func normalizeStableVersion(v string) (string, [3]int, bool) {
	var parts [3]int
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")
	segments := strings.Split(v, ".")
	if len(segments) != 3 {
		return "", parts, false
	}
	for i, segment := range segments {
		if segment == "" {
			return "", parts, false
		}
		n, err := strconv.Atoi(segment)
		if err != nil || n < 0 {
			return "", parts, false
		}
		parts[i] = n
	}
	return strconv.Itoa(parts[0]) + "." + strconv.Itoa(parts[1]) + "." + strconv.Itoa(parts[2]), parts, true
}

func stableVersionNewer(candidate, current string) bool {
	_, c, ok := normalizeStableVersion(candidate)
	if !ok {
		return false
	}
	_, cur, ok := normalizeStableVersion(current)
	if !ok {
		return false
	}
	for i := range c {
		if c[i] != cur[i] {
			return c[i] > cur[i]
		}
	}
	return false
}

func (s *AdminServer) updateHTTPClient() *http.Client {
	if s.updateClient != nil {
		return s.updateClient
	}
	return &http.Client{Timeout: zentLoopUpdateTimeout}
}

func (s *AdminServer) updateAPIURL() string {
	if strings.TrimSpace(s.updateURL) != "" {
		return s.updateURL
	}
	return zentLoopGitHubLatestAPI
}

// kickAdminUpdateCheck starts at most one release lookup per 12-hour cache window.
// The caller never waits for GitHub: the Admin UI always renders from the last
// completed cached result and quietly retries after login/page load while a check runs.
func (s *AdminServer) kickAdminUpdateCheck(now time.Time) bool {
	s.updateMu.Lock()
	if s.updateState.Checking || (!s.updateState.CheckedAt.IsZero() && now.Sub(s.updateState.CheckedAt) < zentLoopUpdateInterval) {
		s.updateMu.Unlock()
		return false
	}
	s.updateState.Checking = true
	s.updateMu.Unlock()
	go s.refreshAdminUpdateState(now)
	return true
}

func (s *AdminServer) refreshAdminUpdateState(checkedAt time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), zentLoopUpdateTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.updateAPIURL(), nil)
	if err == nil {
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("User-Agent", "ZentLoop/"+currentZentLoopVersion+" update-check")
	}

	var latest string
	if err == nil {
		resp, reqErr := s.updateHTTPClient().Do(req)
		if reqErr == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var release githubLatestRelease
				if json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&release) == nil && !release.Draft && !release.Prerelease {
					if normalized, _, ok := normalizeStableVersion(release.TagName); ok {
						latest = normalized
					}
				}
			}
		}
	}

	s.updateMu.Lock()
	s.updateState.CheckedAt = checkedAt
	s.updateState.LatestVersion = latest
	s.updateState.Available = latest != "" && stableVersionNewer(latest, currentZentLoopVersion)
	s.updateState.Checking = false
	s.updateMu.Unlock()
}

func (s *AdminServer) adminUpdateInfo() map[string]any {
	s.updateMu.Lock()
	state := s.updateState
	s.updateMu.Unlock()
	out := map[string]any{
		"update_available": state.Available,
		"update_checking":  state.Checking,
		"update_url":       zentLoopGitHubRepoURL,
	}
	if state.Available {
		out["latest_version"] = state.LatestVersion
	}
	if !state.CheckedAt.IsZero() {
		out["update_checked_at"] = state.CheckedAt
	}
	return out
}
