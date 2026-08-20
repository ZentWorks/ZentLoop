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

var ErrInvalidTrustedDomain = errors.New("invalid trusted domain")

type rawHostStat struct {
	Requests      int64
	SweepRequests int64
	FirstSeen     time.Time
	LastSeen      time.Time
	Sources       map[string]struct{}
}

func (s *Store) countRequestHost(e model.Event) {
	host := canonicalTrustedHost(e.RequestHost)
	if host == "" {
		host = canonicalTrustedHost(e.Target)
	}
	if host == "" {
		return
	}
	if _, ok := s.requestHostStats[host]; !ok && len(s.requestHostStats) >= maxPathKeys {
		host = "(other request hosts)"
	}
	row := s.requestHostStats[host]
	if row == nil {
		row = &rawHostStat{FirstSeen: e.At, Sources: map[string]struct{}{}}
		s.requestHostStats[host] = row
	}
	row.Requests++
	if e.HostSweep {
		row.SweepRequests++
	}
	if e.IP != "" && len(row.Sources) < 256 {
		row.Sources[e.IP] = struct{}{}
	}
	if row.FirstSeen.IsZero() || e.At.Before(row.FirstSeen) {
		row.FirstSeen = e.At
	}
	if e.At.After(row.LastSeen) {
		row.LastSeen = e.At
	}
}

const trustedDomainsFile = "trusted-domains.json"

func canonicalTrustedHost(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(v); err == nil {
		v = h
	}
	v = strings.Trim(strings.TrimSuffix(v, "."), "[]")
	if ip := net.ParseIP(v); ip != nil {
		return ip.String()
	}
	if len(v) > 253 || strings.ContainsAny(v, "/\\?#@ :") {
		return ""
	}
	labels := strings.Split(v, ".")
	if len(labels) < 2 {
		return ""
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
				return ""
			}
		}
	}
	return v
}

func internalUntrustedHost(raw string) bool {
	host := canonicalTrustedHost(raw)
	if host == "" {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast())
}

func (s *Store) loadTrustedDomains() error {
	b, err := os.ReadFile(filepath.Join(s.dataDir, trustedDomainsFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var cfg model.TrustedDomainSettings
	if err := json.Unmarshal(b, &cfg); err != nil {
		return err
	}
	for _, row := range cfg.Manual {
		if d := canonicalTrustedHost(row.Domain); d != "" {
			row.Domain, row.Source = d, "manual"
			s.trustedManual[d] = row
		}
	}
	return nil
}

func (s *Store) persistTrustedDomainsLocked() error {
	cfg := model.TrustedDomainSettings{Manual: trustedDomainRows(s.trustedManual), Proxy: []model.TrustedDomain{}}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	path := filepath.Join(s.dataDir, trustedDomainsFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func trustedDomainRows(in map[string]model.TrustedDomain) []model.TrustedDomain {
	out := make([]model.TrustedDomain, 0, len(in))
	for _, row := range in {
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

func (s *Store) TrustedDomains() model.TrustedDomainSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return model.TrustedDomainSettings{Manual: trustedDomainRows(s.trustedManual), Proxy: []model.TrustedDomain{}}
}

func (s *Store) SetManualTrustedDomains(domains []string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make(map[string]model.TrustedDomain)
	for _, raw := range domains {
		d := canonicalTrustedHost(raw)
		if d == "" {
			return fmt.Errorf("%w %q", ErrInvalidTrustedDomain, strings.TrimSpace(raw))
		}
		added := now
		if old, ok := s.trustedManual[d]; ok && !old.AddedAt.IsZero() {
			added = old.AddedAt
		}
		next[d] = model.TrustedDomain{Domain: d, Source: "manual", AddedAt: added}
	}
	previous := s.trustedManual
	s.trustedManual = next
	if err := s.persistTrustedDomainsLocked(); err != nil {
		s.trustedManual = previous
		return err
	}
	return nil
}

func (s *Store) trustedTargetRootLocked(raw string) (string, string, bool) {
	host := canonicalTrustedHost(raw)
	if host == "" {
		return "", "", false
	}
	root := ""
	for domain := range s.trustedManual {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			if len(domain) > len(root) {
				root = domain
			}
		}
	}
	if root != "" {
		return root, "manual", true
	}
	return "", "", false
}

func (s *Store) trustedHostLocked(raw string) (bool, string) {
	_, source, ok := s.trustedTargetRootLocked(raw)
	return ok, source
}

func (s *Store) targetFilterMatchesLocked(raw, filter string) bool {
	filter = canonicalTrustedHost(filter)
	if filter == "" {
		return true
	}
	root, _, ok := s.trustedTargetRootLocked(raw)
	return ok && root == filter
}

func (s *Store) IsTrustedHost(raw string) (bool, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.trustedHostLocked(raw)
}

func (s *Store) decorateSessionLocked(ss *model.Session) model.Session {
	cp := *cloneSession(ss)
	raw := cp.Target
	if raw == "" {
		raw = cp.RequestHost
	}
	if ok, source := s.trustedHostLocked(raw); ok {
		cp.Target = canonicalTrustedHost(raw)
		cp.TargetTrust = source
	} else {
		cp.Target = ""
		cp.TargetTrust = "untrusted"
		if internalUntrustedHost(cp.RequestHost) {
			cp.RequestHost = ""
		}
	}
	return cp
}

func (s *Store) decorateEventLocked(e model.Event) model.Event {
	raw := e.Target
	if raw == "" {
		raw = e.RequestHost
	}
	if ok, source := s.trustedHostLocked(raw); ok {
		e.Target = canonicalTrustedHost(raw)
		e.TargetTrust = source
	} else {
		e.Target = ""
		e.TargetTrust = "untrusted"
		if internalUntrustedHost(e.RequestHost) {
			e.RequestHost = ""
		}
	}
	return e
}

func (s *Store) UntrustedHosts(limit int) model.UntrustedHostOverview {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.UntrustedHostStat, 0, len(s.requestHostStats))
	var total, sweeps int64
	for host, raw := range s.requestHostStats {
		if host != "(other request hosts)" {
			if ok, _ := s.trustedHostLocked(host); ok {
				continue
			}
			if internalUntrustedHost(host) {
				continue
			}
		}
		row := model.UntrustedHostStat{Host: host, Requests: raw.Requests, Sources: len(raw.Sources), SweepRequests: raw.SweepRequests, FirstSeen: raw.FirstSeen, LastSeen: raw.LastSeen}
		total += row.Requests
		sweeps += row.SweepRequests
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Requests == out[j].Requests {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].Requests > out[j].Requests
	})
	totalHosts := len(out)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return model.UntrustedHostOverview{RequestsTotal: total, HostsTotal: totalHosts, SweepRequests: sweeps, Hosts: out}
}

func (s *Store) EventView(e model.Event) model.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.decorateEventLocked(e)
}
