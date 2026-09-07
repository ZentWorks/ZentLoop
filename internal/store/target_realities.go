package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"zentloop/internal/model"
)

const targetRealitiesFile = "target-realities.json"

var ErrInvalidTargetReality = errors.New("invalid target reality")

type targetRealityDisk struct {
	Profiles []model.TargetRealityProfile `json:"profiles"`
	States   []model.TargetRealityState   `json:"states"`
}

func canonicalRealityTarget(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if strings.HasPrefix(raw, "*.") {
		base := canonicalTrustedHost(strings.TrimPrefix(raw, "*."))
		if base == "" || net.ParseIP(base) != nil {
			return ""
		}
		return "*." + base
	}
	return canonicalTrustedHost(raw)
}

func normalizeRealityMode(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "fixed":
		return "fixed"
	case "guided":
		return "guided"
	default:
		return "automatic"
	}
}

func normalizeRealityValues(in []string, allowed map[string]bool) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.ToLower(strings.TrimSpace(v))
		if !allowed[v] || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

var realityApps = map[string]bool{"wordpress": true, "nextjs": true, "laravel": true, "generic-php": true, "generic-node": true, "java": true, "aspnet": true, "rails": true, "embedded-appliance": true, "cisco-remote-access": true, "fortinet-remote-access": true}
var realityInfra = map[string]bool{"nginx": true, "apache": true, "docker": true, "mysql": true, "postgresql": true, "redis": true, "aws": true, "azure": true, "gcp": true, "cicd": true}
var realityArtifacts = map[string]bool{"env": true, "git": true, "ssh-keys": true, "backups": true, "database-dumps": true, "debug": true, "docker-api": true, "cloud-metadata": true, "app-config": true, "cicd": true}

func (s *Store) loadTargetRealities() error {
	b, err := os.ReadFile(filepath.Join(s.dataDir, targetRealitiesFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var disk targetRealityDisk
	if err := json.Unmarshal(b, &disk); err != nil {
		return err
	}
	for _, p := range disk.Profiles {
		if t := canonicalRealityTarget(p.Target); t != "" {
			p.Target = t
			p.Mode = normalizeRealityMode(p.Mode)
			p.Applications = normalizeRealityValues(p.Applications, realityApps)
			p.Infrastructure = normalizeRealityValues(p.Infrastructure, realityInfra)
			p.Artifacts = normalizeRealityValues(p.Artifacts, realityArtifacts)
			s.realityProfiles[t] = p
		}
	}
	for _, st := range disk.States {
		if t := canonicalTrustedHost(st.Target); t != "" {
			st.Target = t
			if st.Evidence == nil {
				st.Evidence = map[string]int{}
			}
			if st.PublicFacts == nil {
				st.PublicFacts = map[string]string{}
			}
			if st.Revision == 0 && (st.Technology != "" || st.Cloud != "" || st.Locked) {
				st.Revision = 1
			}
			s.realityStates[t] = st
		}
	}
	return nil
}

func (s *Store) persistTargetRealitiesLocked() error {
	disk := targetRealityDisk{}
	for _, p := range s.realityProfiles {
		disk.Profiles = append(disk.Profiles, p)
	}
	for _, st := range s.realityStates {
		disk.States = append(disk.States, st)
	}
	sort.Slice(disk.Profiles, func(i, j int) bool { return disk.Profiles[i].Target < disk.Profiles[j].Target })
	sort.Slice(disk.States, func(i, j int) bool { return disk.States[i].Target < disk.States[j].Target })
	b, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	path := filepath.Join(s.dataDir, targetRealitiesFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func normalizedStoredRealityApp(v string) string {
	switch v {
	case "php":
		return "generic-php"
	case "asp":
		return "aspnet"
	}
	return v
}
func profileContains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func realityApplicationStates(p model.TargetRealityProfile, st model.TargetRealityState) map[string]string {
	states := map[string]string{}
	for app := range realityApps {
		states[app] = "absent"
	}
	for _, app := range p.Applications {
		states[normalizedStoredRealityApp(app)] = "active"
	}
	active := normalizedStoredRealityApp(st.Technology)
	if active != "" {
		states[active] = "active"
	}
	// Frameworks built on PHP may plausibly expose a few generic PHP remnants,
	// but that does not make every other PHP framework active.
	if active == "wordpress" || active == "laravel" {
		if states["generic-php"] != "active" {
			states["generic-php"] = "residual"
		}
	}
	return states
}

func realityWarnings(p model.TargetRealityProfile) []string {
	var w []string
	if profileContains(p.Applications, "cisco-remote-access") && len(p.Applications) > 1 {
		w = append(w, "Cisco remote-access is normally a dedicated appliance surface; mixing it with application frameworks reduces realism.")
	}
	if profileContains(p.Applications, "fortinet-remote-access") && len(p.Applications) > 1 {
		w = append(w, "Fortinet remote-access is normally a dedicated appliance surface; mixing it with application frameworks reduces realism.")
	}
	if profileContains(p.Applications, "wordpress") && profileContains(p.Applications, "nextjs") && !profileContains(p.Infrastructure, "docker") {
		w = append(w, "WordPress + Next.js is plausible for dev/proxy targets, but Docker or a reverse-proxy context makes the combination more coherent.")
	}
	if profileContains(p.Infrastructure, "aws") && profileContains(p.Infrastructure, "azure") && profileContains(p.Infrastructure, "gcp") {
		w = append(w, "Three cloud providers on one target is unusual; keep this only for intentionally messy dev/lab targets.")
	}
	return w
}

func (s *Store) realityProfileForLocked(target string) (model.TargetRealityProfile, string) {
	target = canonicalTrustedHost(target)
	if target == "" || !s.realityTargetTrustedLocked(target) {
		return model.TargetRealityProfile{Mode: "automatic"}, "global"
	}
	if p, ok := s.realityProfiles[target]; ok {
		return p, "exact"
	}
	best := ""
	for key := range s.realityProfiles {
		if !strings.HasPrefix(key, "*.") {
			continue
		}
		suffix := strings.TrimPrefix(key, "*")
		if strings.HasSuffix(target, suffix) && len(key) > len(best) {
			best = key
		}
	}
	if best != "" {
		return s.realityProfiles[best], "wildcard"
	}
	// Parent domain profiles may be inherited by subdomains when requested.
	parent := ""
	for key, p := range s.realityProfiles {
		if strings.HasPrefix(key, "*.") || !p.Inherit {
			continue
		}
		if target != key && strings.HasSuffix(target, "."+key) && len(key) > len(parent) {
			parent = key
		}
	}
	if parent != "" {
		return s.realityProfiles[parent], "parent"
	}
	return model.TargetRealityProfile{Target: target, Mode: "automatic"}, "global"
}

func (s *Store) resolveRealityLocked(target string) model.TargetRealityResolved {
	target = canonicalTrustedHost(target)
	p, source := s.realityProfileForLocked(target)
	st := s.realityStates[target]
	st.Target = target
	if st.Evidence == nil {
		st.Evidence = map[string]int{}
	}
	if st.PublicFacts == nil {
		st.PublicFacts = map[string]string{}
	}
	warnings := realityWarnings(p)
	if st.Locked && len(p.Applications) > 0 && !profileContains(p.Applications, normalizedStoredRealityApp(st.Technology)) {
		warnings = append(warnings, "Configured application set conflicts with the persistent learned commitment "+st.Technology+". Reset learned state explicitly before migrating this target.")
	}
	return model.TargetRealityResolved{Target: target, Mode: normalizeRealityMode(p.Mode), Applications: append([]string(nil), p.Applications...), Infrastructure: append([]string(nil), p.Infrastructure...), Artifacts: append([]string(nil), p.Artifacts...), ApplicationStates: realityApplicationStates(p, st), State: st, Source: source, Coherent: len(warnings) == 0, Warnings: warnings}
}

func (s *Store) realityTargetTrustedLocked(target string) bool {
	_, _, ok := s.trustedTargetRootLocked(target)
	return ok
}

func (s *Store) ResolveTargetReality(target string) model.TargetRealityResolved {
	s.mu.RLock()
	defer s.mu.RUnlock()
	target = canonicalTrustedHost(target)
	if target == "" || !s.realityTargetTrustedLocked(target) {
		return model.TargetRealityResolved{Target: target, Mode: "automatic", Source: "global", Coherent: true}
	}
	return s.resolveRealityLocked(target)
}

func (s *Store) ObserveTargetReality(target, candidate, cloud string, weight int, success bool) model.TargetRealityResolved {
	s.mu.Lock()
	defer s.mu.Unlock()
	target = canonicalTrustedHost(target)
	if target == "" {
		return model.TargetRealityResolved{Mode: "automatic", Source: "global", Coherent: true}
	}
	now := time.Now()
	st := s.realityStates[target]
	st.Target = target
	if st.Evidence == nil {
		st.Evidence = map[string]int{}
	}
	if st.PublicFacts == nil {
		st.PublicFacts = map[string]string{}
	}
	beforeTech, beforeConf, beforeLocked, beforeCloud := st.Technology, st.Confidence, st.Locked, st.Cloud
	beforeFacts := len(st.PublicFacts)
	p, _ := s.realityProfileForLocked(target)
	mode := normalizeRealityMode(p.Mode)
	if candidate != "" && weight > 0 {
		st.Evidence[candidate] += weight
		best, score := "", 0
		for tech, v := range st.Evidence {
			if v > score {
				best, score = tech, v
			}
		}
		if mode == "automatic" || len(p.Applications) == 0 {
			// A successful high-specificity response is itself a public claim. Commit
			// it atomically so a later scanner cannot turn an already-served Laravel,
			// WordPress, Next.js or Spring surface into another primary technology.
			if !st.Locked {
				if success && weight >= 3 {
					st.Technology = candidate
					st.Confidence = "high"
					st.Locked = true
					st.PublicFacts["technology:"+candidate] = "active"
				} else if score >= 5 {
					st.Technology = best
					st.Confidence = "high"
					st.Locked = true
				} else if score >= 3 {
					st.Technology = best
					st.Confidence = "medium"
				}
			}
		} else if profileContains(p.Applications, candidate) && st.Technology == "" {
			st.Technology = candidate
			st.Confidence = "configured"
			if len(p.Applications) == 1 {
				st.Locked = true
			}
		}
	}
	if cloud != "" && success {
		allowed := len(p.Infrastructure) == 0 || profileContains(p.Infrastructure, cloud)
		if allowed && st.Cloud == "" {
			st.Cloud = cloud
			st.PublicFacts["cloud:"+cloud] = "active"
		}
	}
	st.LastSeen = now
	changed := st.Technology != beforeTech || st.Confidence != beforeConf || st.Locked != beforeLocked || st.Cloud != beforeCloud || len(st.PublicFacts) != beforeFacts
	if changed {
		st.Revision++
		if st.Revision == 0 {
			st.Revision = 1
		}
		st.UpdatedAt = now
		if st.Locked && !beforeLocked && st.CommittedAt.IsZero() {
			st.CommittedAt = now
		}
	}
	s.realityStates[target] = st
	if changed {
		_ = s.persistTargetRealitiesLocked()
	}
	return s.resolveRealityLocked(target)
}

func (s *Store) TargetRealitySettings() model.TargetRealitySettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := model.TargetRealitySettings{}
	for _, p := range s.realityProfiles {
		check := strings.TrimPrefix(p.Target, "*.")
		if s.realityTargetTrustedLocked(check) {
			out.Profiles = append(out.Profiles, p)
		}
	}
	sort.Slice(out.Profiles, func(i, j int) bool { return out.Profiles[i].Target < out.Profiles[j].Target })
	targets := map[string]bool{}
	for d := range s.trustedManual {
		targets[d] = true
	}
	for _, p := range out.Profiles {
		if !strings.HasPrefix(p.Target, "*.") {
			targets[p.Target] = true
		}
	}
	for t := range targets {
		out.Resolved = append(out.Resolved, s.resolveRealityLocked(t))
	}
	sort.Slice(out.Resolved, func(i, j int) bool { return out.Resolved[i].Target < out.Resolved[j].Target })
	return out
}

func (s *Store) SetTargetRealityProfiles(profiles []model.TargetRealityProfile, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := map[string]model.TargetRealityProfile{}
	for key, oldProfile := range s.realityProfiles {
		check := strings.TrimPrefix(key, "*.")
		if !s.realityTargetTrustedLocked(check) {
			next[key] = oldProfile
		}
	}
	for _, p := range profiles {
		t := canonicalRealityTarget(p.Target)
		if t == "" {
			return fmt.Errorf("%w: %q", ErrInvalidTargetReality, p.Target)
		}
		// Profiles may only describe a trusted root, its subdomain, or a wildcard below it.
		check := strings.TrimPrefix(t, "*.")
		allowed := false
		for root := range s.trustedManual {
			if check == root || strings.HasSuffix(check, "."+root) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("%w: target %q is not below a trusted domain/IP", ErrInvalidTargetReality, t)
		}
		p.Target = t
		p.Mode = normalizeRealityMode(p.Mode)
		p.UpdatedAt = now
		p.Applications = normalizeRealityValues(p.Applications, realityApps)
		p.Infrastructure = normalizeRealityValues(p.Infrastructure, realityInfra)
		p.Artifacts = normalizeRealityValues(p.Artifacts, realityArtifacts)
		next[t] = p
	}
	old := s.realityProfiles
	s.realityProfiles = next
	if err := s.persistTargetRealitiesLocked(); err != nil {
		s.realityProfiles = old
		return err
	}
	return nil
}

func (s *Store) ResetTargetRealityState(target string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	target = canonicalTrustedHost(target)
	if target == "" {
		return ErrInvalidTargetReality
	}
	delete(s.realityStates, target)
	return s.persistTargetRealitiesLocked()
}
