package server

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"zentloop/internal/model"
)

type adminTimeRange struct {
	From time.Time
	To   time.Time
	Set  bool
	All  bool
}

func requestTimeRange(r *http.Request) adminTimeRange {
	var out adminTimeRange
	if r.URL.Query().Get("all") == "1" {
		out.Set = true
		out.All = true
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("from")); raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			out.From = t
			out.Set = true
		}
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("to")); raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			out.To = t
			out.Set = true
		}
	}
	return out
}

func (tr adminTimeRange) contains(t time.Time) bool {
	if !tr.Set {
		return true
	}
	if !tr.From.IsZero() && t.Before(tr.From) {
		return false
	}
	if !tr.To.IsZero() && !t.Before(tr.To) {
		return false
	}
	return true
}

func limitSessions(rows []model.Session, tr adminTimeRange, limit int) []model.Session {
	out := make([]model.Session, 0, len(rows))
	for _, x := range rows {
		if tr.contains(x.LastSeen) {
			out = append(out, x)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
func limitEvents(rows []model.Event, tr adminTimeRange, limit int) []model.Event {
	out := make([]model.Event, 0, len(rows))
	for _, x := range rows {
		if tr.contains(x.At) {
			out = append(out, x)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
func limitSSHSessions(rows []model.SSHSession, tr adminTimeRange, limit int) []model.SSHSession {
	out := make([]model.SSHSession, 0, len(rows))
	for _, x := range rows {
		if tr.contains(x.LastSeen) {
			out = append(out, x)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
func limitSSHEvents(rows []model.SSHEvent, tr adminTimeRange, limit int) []model.SSHEvent {
	out := make([]model.SSHEvent, 0, len(rows))
	for _, x := range rows {
		if tr.contains(x.At) {
			out = append(out, x)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
func limitIntel(rows []model.IntelSignal, tr adminTimeRange, limit int) []model.IntelSignal {
	out := make([]model.IntelSignal, 0, len(rows))
	for _, x := range rows {
		if tr.contains(x.At) {
			out = append(out, x)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func limitActors(rows []model.ActorProfile, tr adminTimeRange, limit int) []model.ActorProfile {
	out := make([]model.ActorProfile, 0, len(rows))
	for _, x := range rows {
		if tr.contains(x.LastSeen) {
			out = append(out, x)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
func actorOverviewFromRows(rows []model.ActorProfile) model.ActorOverview {
	var o model.ActorOverview
	fp := map[string]int64{}
	for _, a := range rows {
		o.ActorsTotal++
		if len(a.Protocols) > 1 {
			o.CrossProtocol++
		}
		o.EngagementSeconds += a.EngagementSeconds
		o.CanaryTouches += a.CanaryTouches
		o.PayloadAttempts += a.PayloadAttempts
		for _, f := range a.Fingerprints {
			fp[f]++
		}
	}
	type kv struct {
		name string
		n    int64
	}
	vals := make([]kv, 0, len(fp))
	for k, v := range fp {
		vals = append(vals, kv{k, v})
	}
	sort.Slice(vals, func(i, j int) bool { return vals[i].n > vals[j].n })
	if len(vals) > 10 {
		vals = vals[:10]
	}
	for _, x := range vals {
		o.TopFingerprints = append(o.TopFingerprints, model.Count{Name: x.name, Count: x.n})
	}
	return o
}
func limitBursts(rows []model.ScanBurst, tr adminTimeRange, limit int) []model.ScanBurst {
	out := make([]model.ScanBurst, 0, len(rows))
	for _, x := range rows {
		if tr.contains(x.LastSeen) {
			out = append(out, x)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func untrustedFromEvents(rows []model.Event, tr adminTimeRange, limit int) model.UntrustedHostOverview {
	type acc struct {
		requests, sweeps int64
		sources          map[string]struct{}
		first, last      time.Time
	}
	m := map[string]*acc{}
	for _, e := range rows {
		if !tr.contains(e.At) || e.Target != "" || strings.TrimSpace(e.RequestHost) == "" {
			continue
		}
		h := strings.ToLower(strings.TrimSpace(e.RequestHost))
		a := m[h]
		if a == nil {
			a = &acc{sources: map[string]struct{}{}, first: e.At}
			m[h] = a
		}
		a.requests++
		a.sources[e.IP] = struct{}{}
		if e.HostSweep {
			a.sweeps++
		}
		if e.At.Before(a.first) {
			a.first = e.At
		}
		if e.At.After(a.last) {
			a.last = e.At
		}
	}
	out := model.UntrustedHostOverview{}
	for h, a := range m {
		row := model.UntrustedHostStat{Host: h, Requests: a.requests, Sources: len(a.sources), SweepRequests: a.sweeps, FirstSeen: a.first, LastSeen: a.last}
		out.RequestsTotal += a.requests
		out.SweepRequests += a.sweeps
		out.Hosts = append(out.Hosts, row)
	}
	sort.Slice(out.Hosts, func(i, j int) bool {
		if out.Hosts[i].Requests == out.Hosts[j].Requests {
			return out.Hosts[i].LastSeen.After(out.Hosts[j].LastSeen)
		}
		return out.Hosts[i].Requests > out.Hosts[j].Requests
	})
	out.HostsTotal = len(out.Hosts)
	if limit > 0 && len(out.Hosts) > limit {
		out.Hosts = out.Hosts[:limit]
	}
	return out
}

func unknownFromEvents(rows []model.Event, tr adminTimeRange, limit int) []model.UnknownPath {
	m := map[string]*model.UnknownPath{}
	for _, e := range rows {
		if !tr.contains(e.At) {
			continue
		}
		path := normalizeProbePath(e.Path)
		if path == "" || path == "/" || path == "/favicon.ico" || path == "/robots.txt" || path == "/sitemap.xml" || isHistoricalActivityPubEvent(e) {
			continue
		}
		if _, ok := identifyProbe(path); ok || isBenignDiscovery(path) {
			continue
		}
		if e.Category == "request" && e.RiskScore < 20 && e.Status != 404 {
			continue
		}
		k := strings.ToUpper(e.Method) + "|" + path
		u := m[k]
		if u == nil {
			u = &model.UnknownPath{Path: path, Method: e.Method, FirstSeen: e.At, ExampleIP: e.IP, ExampleUserAgent: e.UserAgent}
			m[k] = u
		}
		u.Count++
		if e.At.After(u.LastSeen) {
			u.LastSeen = e.At
		}
	}
	out := make([]model.UnknownPath, 0, len(m))
	for _, u := range m {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].Count > out[j].Count
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
func probesFromEvents(rows []model.Event, tr adminTimeRange, limit int) []model.ProbeStat {
	m := map[string]*model.ProbeStat{}
	for _, e := range rows {
		if !tr.contains(e.At) {
			continue
		}
		info, ok := identifyProbe(e.Path)
		if !ok {
			continue
		}
		k := strings.ToLower(info.Name + "|" + info.Product + "|" + info.CVE)
		p := m[k]
		if p == nil {
			p = &model.ProbeStat{Name: info.Name, Product: info.Product, CVE: info.CVE, FirstSeen: e.At}
			m[k] = p
		}
		p.Count++
		if e.Classification == model.ClassHostile {
			p.HostileRequests++
		} else if e.Classification == model.ClassSuspicious {
			p.SuspiciousRequests++
		}
		if e.At.After(p.LastSeen) {
			p.LastSeen = e.At
		}
	}
	out := make([]model.ProbeStat, 0, len(m))
	for _, p := range m {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].Count > out[j].Count
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
func catchAllFromEvents(rows []model.Event, tr adminTimeRange, limit int) model.CatchAllOverview {
	m := map[string]*model.CatchAllHost{}
	ints := map[string]int64{}
	var total int64
	for _, e := range rows {
		if !tr.contains(e.At) || !e.CatchAll {
			continue
		}
		h := strings.ToLower(strings.TrimSpace(e.Target))
		if h == "" {
			h = strings.ToLower(strings.TrimSpace(e.RequestHost))
		}
		if h == "" {
			h = "(unknown)"
		}
		x := m[h]
		if x == nil {
			x = &model.CatchAllHost{Host: h, FirstSeen: e.At}
			m[h] = x
		}
		x.Requests++
		total++
		if e.Classification == model.ClassHostile {
			x.HostileRequests++
		} else if e.Classification == model.ClassSuspicious {
			x.SuspiciousRequests++
		}
		if e.At.After(x.LastSeen) {
			x.LastSeen = e.At
			x.LastIntegration = e.Integration
		}
		ints[e.Integration]++
	}
	hosts := make([]model.CatchAllHost, 0, len(m))
	for _, x := range m {
		hosts = append(hosts, *x)
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Requests > hosts[j].Requests })
	if limit > 0 && len(hosts) > limit {
		hosts = hosts[:limit]
	}
	type kv struct {
		name string
		n    int64
	}
	vals := make([]kv, 0, len(ints))
	for k, v := range ints {
		if k == "" {
			k = "(unspecified)"
		}
		vals = append(vals, kv{k, v})
	}
	sort.Slice(vals, func(i, j int) bool { return vals[i].n > vals[j].n })
	top := make([]model.Count, 0, len(vals))
	for _, x := range vals {
		top = append(top, model.Count{Name: x.name, Count: x.n})
	}
	return model.CatchAllOverview{RequestsTotal: total, HostsTotal: len(m), Hosts: hosts, TopIntegrations: top}
}
