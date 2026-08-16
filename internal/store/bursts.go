package store

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"sort"
	"strings"
	"time"

	"zentloop/internal/model"
)

// ScanBursts derives coordinated HTTP bursts from the bounded in-memory event
// ring. Actors remain separate; this is an analytical grouping only.
func (s *Store) ScanBursts(limit int) []model.ScanBurst {
	if limit <= 0 {
		limit = 50
	}
	s.mu.RLock()
	events := append([]model.Event(nil), s.events...)
	s.mu.RUnlock()

	type group struct {
		first, last        time.Time
		target, ua, prefix string
		ips                map[string]struct{}
		paths              map[string]struct{}
		requests           int
	}
	var groups []*group
	for _, e := range events {
		if e.IP == "" || e.At.IsZero() || e.UserAgent == "" {
			continue
		}
		prefix := sourceGroup(e.IP)
		var g *group
		for i := len(groups) - 1; i >= 0; i-- {
			candidate := groups[i]
			if e.At.Sub(candidate.last) > 4*time.Second {
				break
			}
			if candidate.target == e.Target && candidate.ua == e.UserAgent && candidate.prefix == prefix {
				g = candidate
				break
			}
		}
		if g == nil {
			g = &group{first: e.At, last: e.At, target: e.Target, ua: e.UserAgent, prefix: prefix, ips: map[string]struct{}{}, paths: map[string]struct{}{}}
			groups = append(groups, g)
		}
		if e.At.Before(g.first) {
			g.first = e.At
		}
		if e.At.After(g.last) {
			g.last = e.At
		}
		g.requests++
		g.ips[e.IP] = struct{}{}
		if e.Path != "" {
			g.paths[e.Path] = struct{}{}
		}
	}

	out := make([]model.ScanBurst, 0)
	for _, g := range groups {
		if len(g.ips) < 3 || g.requests < 3 {
			continue
		}
		paths := make([]string, 0, len(g.paths))
		for p := range g.paths {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		if len(paths) > 12 {
			paths = paths[:12]
		}
		h := sha256.Sum256([]byte(g.target + "|" + g.ua + "|" + g.prefix + "|" + g.first.UTC().Format(time.RFC3339)))
		fp := burstFingerprint(g.ua, paths)
		out = append(out, model.ScanBurst{ID: "burst-" + hex.EncodeToString(h[:5]), FirstSeen: g.first, LastSeen: g.last, Target: g.target, UserAgent: g.ua, SourceGroup: g.prefix, Sources: len(g.ips), Requests: g.requests, Paths: paths, Fingerprint: fp})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func sourceGroup(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		return net.IP(v4).Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	return parsed.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

func burstFingerprint(ua string, paths []string) string {
	low := strings.ToLower(ua)
	if strings.Contains(low, "infrawatch") {
		return "http:internet-measurement"
	}
	mcp := 0
	for _, p := range paths {
		if p == "/mcp" || p == "/mcp/" || p == "/api/mcp" || p == "/sse" {
			mcp++
		}
	}
	if mcp >= 2 {
		return "http:mcp-discovery-burst"
	}
	return "http:coordinated-scan"
}
