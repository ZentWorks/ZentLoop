package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"zentloop/internal/model"
)

const (
	maxRing     = 5000
	maxPathKeys = 5000
	maxSessions = 10000
)

type Store struct {
	mu                    sync.RWMutex
	sessions              map[string]*model.Session
	fingerprints          map[string]string
	events                []model.Event
	subs                  map[chan model.Event]struct{}
	pathCounts            map[string]int64
	dayCounts             map[string]int64
	targetCounts          map[string]int64
	unknownPaths          map[string]*model.UnknownPath
	probeStats            map[string]*model.ProbeStat
	catchAllHosts         map[string]*model.CatchAllHost
	integrationCounts     map[string]int64
	catchAllRequests      int64
	requestsTotal         int64
	started               time.Time
	dataDir               string
	eventFile             *os.File
	sshSessions           map[string]*model.SSHSession
	sshEvents             []model.SSHEvent
	sshSubs               map[chan model.SSHEvent]struct{}
	sshUserCounts         map[string]int64
	sshCommandCounts      map[string]int64
	sshFamilyCounts       map[string]int64
	sshCountryCounts      map[string]int64
	sshClientCounts       map[string]int64
	sshDayConnections     map[string]int64
	sshDayAuth            map[string]int64
	sshDayShells          map[string]int64
	sshDayCommands        map[string]int64
	sshConnections        int64
	sshAuthAttempts       int64
	sshShells             int64
	sshCommands           int64
	sshEventFile          *os.File
	actors                map[string]*model.ActorProfile
	actorTimeline         map[string][]model.ActorActivity
	actorSessionLast      map[string]time.Time
	actorFingerprints     map[string]int64
	sshActorLastCommand   map[string]string
	sshActorLastCommandAt map[string]time.Time
	intelEvents           []model.IntelSignal
	intelEventFile        *os.File
	health                model.HealthOverview
	integrationPeers      map[string]*model.IntegrationPeer
	integrationPersist    map[string]time.Time
	retentionDays         int
	retentionStop         chan struct{}
	retentionDone         chan struct{}
}

func New(dataDir string) (*Store, error) {
	return NewWithRetention(dataDir, 30)
}

func NewWithRetention(dataDir string, retentionDays int) (*Store, error) {
	if retentionDays < 1 {
		retentionDays = 1
	}
	if retentionDays > 30 {
		retentionDays = 30
	}
	if err := os.MkdirAll(dataDir, 0750); err != nil {
		return nil, err
	}
	s := &Store{
		sessions: make(map[string]*model.Session), fingerprints: make(map[string]string),
		subs: make(map[chan model.Event]struct{}), pathCounts: make(map[string]int64), dayCounts: make(map[string]int64), targetCounts: make(map[string]int64), unknownPaths: make(map[string]*model.UnknownPath), probeStats: make(map[string]*model.ProbeStat), catchAllHosts: make(map[string]*model.CatchAllHost), integrationCounts: make(map[string]int64),
		actors: make(map[string]*model.ActorProfile), actorTimeline: make(map[string][]model.ActorActivity), actorSessionLast: make(map[string]time.Time), actorFingerprints: make(map[string]int64), sshActorLastCommand: make(map[string]string), sshActorLastCommandAt: make(map[string]time.Time),
		sshSessions: make(map[string]*model.SSHSession), sshSubs: make(map[chan model.SSHEvent]struct{}), sshUserCounts: make(map[string]int64), sshCommandCounts: make(map[string]int64), sshFamilyCounts: make(map[string]int64), sshCountryCounts: make(map[string]int64), sshClientCounts: make(map[string]int64), sshDayConnections: make(map[string]int64), sshDayAuth: make(map[string]int64), sshDayShells: make(map[string]int64), sshDayCommands: make(map[string]int64),
		integrationPeers: make(map[string]*model.IntegrationPeer), integrationPersist: make(map[string]time.Time),
		started: time.Now(), dataDir: dataDir, retentionDays: retentionDays,
		retentionStop: make(chan struct{}), retentionDone: make(chan struct{}),
	}
	if err := s.loadIntegrationPeers(); err != nil {
		return nil, err
	}
	if err := pruneJSONLPaths(dataDir, retentionDays, time.Now()); err != nil {
		return nil, err
	}
	path := filepath.Join(dataDir, "events.jsonl")
	if err := s.load(path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, err
	}
	s.eventFile = f
	if err := s.initIntel(); err != nil {
		_ = s.eventFile.Close()
		return nil, err
	}
	if err := s.initSSH(); err != nil {
		_ = s.eventFile.Close()
		if s.intelEventFile != nil {
			_ = s.intelEventFile.Close()
		}
		return nil, err
	}
	go s.retentionLoop()
	return s, nil
}

func (s *Store) Close() error {
	select {
	case <-s.retentionStop:
	default:
		close(s.retentionStop)
	}
	<-s.retentionDone
	s.mu.Lock()
	defer s.mu.Unlock()
	var first error
	if s.eventFile != nil {
		if err := s.eventFile.Close(); err != nil {
			first = err
		}
	}
	if s.sshEventFile != nil {
		if err := s.sshEventFile.Close(); err != nil && first == nil {
			first = err
		}
	}
	if s.intelEventFile != nil {
		if err := s.intelEventFile.Close(); err != nil && first == nil {
			first = err
		}
	}
	if err := s.persistIntegrationPeersLocked(); err != nil && first == nil {
		first = err
	}
	return first
}

func (s *Store) load(path string) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for sc.Scan() {
		var e model.Event
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		s.events = append(s.events, e)
		if len(s.events) > maxRing {
			s.events = s.events[len(s.events)-maxRing:]
		}
		s.requestsTotal++
		s.countPath(e.Path)
		s.dayCounts[dayKey(e.At)]++
		s.countTarget(e.Target)
		s.countUnknown(e)
		s.countProbe(e)
		s.countCatchAll(e)
		s.applyActorHTTPEventLocked(e)
		// Rebuild actor/session state from the complete durable event log, not only
		// from the in-memory event ring. This lets a returning actor continue an
		// older deception journey even when thousands of newer requests happened.
		s.applyEvent(e)
		if len(s.sessions) > maxSessions+1000 {
			s.pruneSessionsLocked(maxSessions)
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if len(s.sessions) > maxSessions {
		s.pruneSessionsLocked(maxSessions)
	}
	return nil
}

func (s *Store) applyEvent(e model.Event) {
	ss := s.sessions[e.SessionID]
	if ss == nil {
		first := e.SessionFirstSeen
		if first.IsZero() {
			first = e.At
		}
		ss = &model.Session{ID: e.SessionID, IP: e.IP, FirstSeen: first, UserAgent: e.UserAgent}
		s.sessions[e.SessionID] = ss
	}
	ss.LastSeen = e.At
	ss.IP = e.IP
	ss.IPSource = e.IPSource
	ss.Proxy = e.Proxy
	if e.Country != "" {
		ss.Country = e.Country
		ss.CountrySource = e.CountrySource
	}
	if e.CloudflareRay != "" {
		ss.CloudflareRay = e.CloudflareRay
	}
	if e.CloudflareColo != "" {
		ss.CloudflareColo = e.CloudflareColo
	}
	if ss.FirstPath == "" {
		ss.FirstPath = e.Path
	}
	if e.Referrer != "" {
		if ss.FirstReferrer == "" {
			ss.FirstReferrer = e.Referrer
		}
		ss.LastReferrer = e.Referrer
		ss.ReferrerHost = e.ReferrerHost
	}
	if e.RequestHost != "" {
		ss.RequestHost = e.RequestHost
	}
	if e.Target != "" {
		ss.Target = e.Target
	}
	if e.Origin != "" {
		ss.Origin = e.Origin
	}
	if e.AcceptLanguage != "" {
		ss.AcceptLanguage = e.AcceptLanguage
	}
	if e.HTTPProtocol != "" {
		ss.HTTPProtocol = e.HTTPProtocol
	}
	if e.Integration != "" {
		ss.Integration = e.Integration
		ss.IntegrationTrust = e.IntegrationTrust
	}
	if e.CatchAll {
		ss.CatchAll = true
	}
	if e.SessionRequests > 0 {
		ss.RequestCount = e.SessionRequests
	} else {
		ss.RequestCount++
	}
	if e.SessionVisits > 0 {
		ss.VisitCount = e.SessionVisits
	} else if ss.VisitCount == 0 {
		ss.VisitCount = 1
	}
	if !e.SessionVisitStarted.IsZero() {
		ss.VisitStarted = e.SessionVisitStarted
	} else if ss.VisitStarted.IsZero() {
		ss.VisitStarted = ss.FirstSeen
	}
	ss.RiskScore = e.RiskScore
	ss.AutomationScore = e.AutomationScore
	ss.Classification = e.Classification
	ss.Actor = e.Actor
	ss.Confidence = e.Confidence
	ss.AvgIntervalMS = e.AvgIntervalMS
	ss.IntervalVarMS = e.IntervalVarMS
	ss.Persona = e.Persona
	ss.Depth = e.Depth
	ss.Loop = e.Loop
	ss.Frustration = e.Frustration
	ss.CurrentPath = e.Path
	ss.LastMethod = e.Method
	ss.LastStatus = e.Status
	ss.RecentTimes = append(ss.RecentTimes, e.At)
	if len(ss.RecentTimes) > 12 {
		ss.RecentTimes = ss.RecentTimes[len(ss.RecentTimes)-12:]
	}
	if e.UserAgent != "" {
		s.fingerprints[e.IP+"|"+e.Target+"|"+e.UserAgent] = e.SessionID
	}
	if e.Depth > 0 && e.Message != "benign" {
		if len(ss.Journey) == 0 || ss.Journey[len(ss.Journey)-1].Path != e.Path {
			ss.Journey = append(ss.Journey, model.JourneyStep{At: e.At, Path: e.Path, Label: e.Message})
			if len(ss.Journey) > 30 {
				ss.Journey = ss.Journey[len(ss.Journey)-30:]
			}
		}
	}
}

func (s *Store) GetSession(id string) (*model.Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ss, ok := s.sessions[id]
	if !ok {
		return nil, false
	}
	return cloneSession(ss), true
}
func (s *Store) GetSessionByFingerprint(fp string) (*model.Session, bool) {
	s.mu.RLock()
	id, ok := s.fingerprints[fp]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	return s.GetSession(id)
}

func (s *Store) UpsertSession(ss *model.Session, fingerprint string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, existed := s.sessions[ss.ID]
	s.sessions[ss.ID] = cloneSession(ss)
	if fingerprint != "" {
		s.fingerprints[fingerprint] = ss.ID
	}
	if !existed && len(s.sessions) > maxSessions {
		s.pruneSessionsLocked(maxSessions - 1000)
	}
}

func (s *Store) pruneSessionsLocked(target int) {
	type pair struct {
		id string
		at time.Time
	}
	rows := make([]pair, 0, len(s.sessions))
	for id, ss := range s.sessions {
		rows = append(rows, pair{id, ss.LastSeen})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].at.Before(rows[j].at) })
	remove := len(rows) - target
	if remove <= 0 {
		return
	}
	dead := make(map[string]struct{}, remove)
	for i := 0; i < remove; i++ {
		dead[rows[i].id] = struct{}{}
		delete(s.sessions, rows[i].id)
	}
	for fp, id := range s.fingerprints {
		if _, ok := dead[id]; ok {
			delete(s.fingerprints, fp)
		}
	}
}

func (s *Store) AddEvent(e model.Event) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.eventFile != nil {
		if _, err = s.eventFile.Write(append(b, '\n')); err != nil {
			return err
		}
	}
	s.events = append(s.events, e)
	if len(s.events) > maxRing {
		s.events = s.events[len(s.events)-maxRing:]
	}
	s.requestsTotal++
	s.countPath(e.Path)
	s.dayCounts[dayKey(e.At)]++
	s.countTarget(e.Target)
	s.countUnknown(e)
	s.countProbe(e)
	s.countCatchAll(e)
	s.applyActorHTTPEventLocked(e)
	for ch := range s.subs {
		select {
		case ch <- e:
		default:
		}
	}
	return nil
}

func (s *Store) countTarget(target string) {
	target = strings.TrimSpace(strings.ToLower(target))
	if target == "" {
		target = "(unknown)"
	}
	s.targetCounts[target]++
}

func (s *Store) countUnknown(e model.Event) {
	path := normalizePath(e.Path)
	// Generic browser/navigation requests are not useful feedback for new probe signatures.
	// Keep this independent of event category so old/replayed events cannot re-add them.
	if e.KnownProbe || path == "/" || path == "/favicon.ico" || path == "/index.html" || path == "/index.htm" || path == "/robots.txt" || path == "/sitemap.xml" || path == "/.well-known/passkey-endpoints" || isStoredActivityPubRelay(e, path) {
		return
	}
	// Only collect things that look like discovery/probing or returned 404 while the actor is suspicious.
	if e.Category == "request" && e.RiskScore < 20 && e.Status != 404 {
		return
	}
	// Aggregate globally across targets. The target/domain is installation-specific and not
	// relevant when exporting unknown paths for signature/deception development.
	k := strings.ToUpper(e.Method) + "|" + path
	u := s.unknownPaths[k]
	if u == nil {
		u = &model.UnknownPath{Path: path, Method: e.Method, FirstSeen: e.At, ExampleIP: e.IP, ExampleUserAgent: e.UserAgent}
		s.unknownPaths[k] = u
	}
	u.Count++
	u.LastSeen = e.At
}

func isStoredActivityPubRelay(e model.Event, normalizedPath string) bool {
	if normalizedPath != "/inbox" || strings.ToUpper(strings.TrimSpace(e.Method)) != "POST" {
		return false
	}
	ua := strings.ToLower(e.UserAgent)
	return e.Message == "activitypub-relay" || strings.Contains(ua, "activity-relay") || strings.Contains(ua, "toot relay")
}

func (s *Store) UnknownPaths(limit int) []model.UnknownPath {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.UnknownPath, 0, len(s.unknownPaths))
	for _, u := range s.unknownPaths {
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

func (s *Store) countCatchAll(e model.Event) {
	if !e.CatchAll {
		return
	}
	host := strings.TrimSpace(strings.ToLower(e.Target))
	if host == "" {
		host = "(unknown)"
	}
	if _, ok := s.catchAllHosts[host]; !ok && len(s.catchAllHosts) >= maxPathKeys {
		host = "(other catch-all hosts)"
	}
	h := s.catchAllHosts[host]
	if h == nil {
		h = &model.CatchAllHost{Host: host, FirstSeen: e.At}
		s.catchAllHosts[host] = h
	}
	h.Requests++
	h.LastSeen = e.At
	if h.FirstSeen.IsZero() || e.At.Before(h.FirstSeen) {
		h.FirstSeen = e.At
	}
	switch e.Classification {
	case model.ClassHostile:
		h.HostileRequests++
	case model.ClassSuspicious:
		h.SuspiciousRequests++
	}
	if e.Integration != "" {
		h.LastIntegration = e.Integration
		s.integrationCounts[e.Integration]++
	} else {
		s.integrationCounts["(unspecified)"]++
	}
	s.catchAllRequests++
}

func (s *Store) countProbe(e model.Event) {
	if !e.KnownProbe || strings.TrimSpace(e.ProbeName) == "" {
		return
	}
	k := strings.ToLower(strings.TrimSpace(e.ProbeName) + "|" + strings.TrimSpace(e.ProbeProduct) + "|" + strings.TrimSpace(e.ProbeCVE))
	p := s.probeStats[k]
	if p == nil {
		p = &model.ProbeStat{Name: e.ProbeName, Product: e.ProbeProduct, CVE: e.ProbeCVE, FirstSeen: e.At}
		s.probeStats[k] = p
	}
	p.Count++
	if e.Classification == model.ClassHostile {
		p.HostileRequests++
	} else if e.Classification == model.ClassSuspicious {
		p.SuspiciousRequests++
	}
	if p.FirstSeen.IsZero() || e.At.Before(p.FirstSeen) {
		p.FirstSeen = e.At
	}
	if e.At.After(p.LastSeen) {
		p.LastSeen = e.At
	}
}

func (s *Store) ProbeStats(limit int) []model.ProbeStat {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows := make([]model.ProbeStat, 0, len(s.probeStats))
	for _, p := range s.probeStats {
		rows = append(rows, *p)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count == rows[j].Count {
			return rows[i].LastSeen.After(rows[j].LastSeen)
		}
		return rows[i].Count > rows[j].Count
	})
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

func (s *Store) CatchAllOverview(limit int) model.CatchAllOverview {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows := make([]model.CatchAllHost, 0, len(s.catchAllHosts))
	for _, h := range s.catchAllHosts {
		rows = append(rows, *h)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Requests == rows[j].Requests {
			return rows[i].LastSeen.After(rows[j].LastSeen)
		}
		return rows[i].Requests > rows[j].Requests
	})
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return model.CatchAllOverview{RequestsTotal: s.catchAllRequests, HostsTotal: len(s.catchAllHosts), Hosts: rows, TopIntegrations: rankedCounts(s.integrationCounts, 12)}
}

func (s *Store) countPath(path string) {
	k := normalizePath(path)
	if _, ok := s.pathCounts[k]; !ok && len(s.pathCounts) >= maxPathKeys {
		k = "(other unique paths)"
	}
	s.pathCounts[k]++
}

func normalizePath(path string) string {
	if path == "" {
		return "/"
	}
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if len(p) >= 8 && isHex(p) {
			parts[i] = ":token"
		} else if len(p) >= 3 && isDigits(p) {
			parts[i] = ":id"
		} else if len(p) > 48 {
			parts[i] = p[:47] + "…"
		}
	}
	out := strings.Join(parts, "/")
	if len(out) > 160 {
		out = out[:159] + "…"
	}
	return out
}
func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return s != ""
}
func isDigits(s string) bool {
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return s != ""
}
func dayKey(t time.Time) string { return t.In(time.Local).Format("2006-01-02") }
func cloneSession(ss *model.Session) *model.Session {
	cp := *ss
	cp.RecentTimes = append([]time.Time(nil), ss.RecentTimes...)
	cp.Journey = append([]model.JourneyStep(nil), ss.Journey...)
	return &cp
}

func (s *Store) Events(limit int, target ...string) []model.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	wantTarget := ""
	if len(target) > 0 {
		wantTarget = strings.TrimSpace(target[0])
	}
	if limit <= 0 {
		limit = len(s.events)
	}
	out := make([]model.Event, 0, minInt(limit, len(s.events)))
	for i := len(s.events) - 1; i >= 0 && len(out) < limit; i-- {
		e := s.events[i]
		if wantTarget != "" && !strings.EqualFold(e.Target, wantTarget) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func (s *Store) Sessions(activeWithin time.Duration, limit int, target ...string) []model.Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	out := make([]model.Session, 0, len(s.sessions))
	for _, ss := range s.sessions {
		if len(target) > 0 && target[0] != "" && !strings.EqualFold(ss.Target, target[0]) {
			continue
		}
		if activeWithin > 0 && now.Sub(ss.LastSeen) > activeWithin {
			continue
		}
		cp := *cloneSession(ss)
		cp.RecentTimes = nil
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (s *Store) History(inactiveFor time.Duration, limit int, target ...string) []model.Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	out := make([]model.Session, 0, len(s.sessions))
	for _, ss := range s.sessions {
		if len(target) > 0 && target[0] != "" && !strings.EqualFold(ss.Target, target[0]) {
			continue
		}
		if inactiveFor > 0 && now.Sub(ss.LastSeen) <= inactiveFor {
			continue
		}
		cp := *cloneSession(ss)
		cp.RecentTimes = nil
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (s *Store) Subscribe() (<-chan model.Event, func()) {
	ch := make(chan model.Event, 64)
	s.mu.Lock()
	s.subs[ch] = struct{}{}
	s.mu.Unlock()
	cancel := func() {
		s.mu.Lock()
		if _, ok := s.subs[ch]; ok {
			delete(s.subs, ch)
			close(ch)
		}
		s.mu.Unlock()
	}
	return ch, cancel
}

func (s *Store) Overview(activeWithin time.Duration) model.Overview {
	return s.OverviewTarget(activeWithin, "")
}
func (s *Store) OverviewTarget(activeWithin time.Duration, target string) model.Overview {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	if activeWithin <= 0 {
		activeWithin = 5 * time.Minute
	}
	activeSince := now.Add(-activeWithin)
	var benign, suspicious, hostile, human, auto, unknown int
	var depth, depthN int
	var loops int64
	persona := map[string]int64{}
	countries := map[string]int64{}
	referrers := map[string]int64{}
	for _, ss := range s.sessions {
		if target != "" && !strings.EqualFold(ss.Target, target) {
			continue
		}
		if ss.Country != "" {
			countries[ss.Country]++
		}
		ref := ss.ReferrerHost
		if ref == "" && ss.FirstReferrer == "" {
			ref = "(direct / none)"
		}
		if ref != "" {
			referrers[ref]++
		}
		if ss.LastSeen.Before(activeSince) {
			continue
		}
		switch ss.Classification {
		case model.ClassBenign:
			benign++
		case model.ClassSuspicious:
			suspicious++
		case model.ClassHostile:
			hostile++
		}
		switch ss.Actor {
		case model.ActorHuman:
			human++
		case model.ActorAutomated:
			auto++
		default:
			unknown++
		}
		if ss.Depth > 0 {
			depth += ss.Depth
			depthN++
		}
		loops += int64(ss.Loop)
		if ss.Persona != "" {
			persona[ss.Persona]++
		}
	}
	var last10 int64
	for _, e := range s.events {
		if target != "" && !strings.EqualFold(e.Target, target) {
			continue
		}
		if e.At.After(now.Add(-10 * time.Second)) {
			last10++
		}
	}
	pathSource := s.pathCounts
	if target != "" {
		pathSource = map[string]int64{}
		for _, e := range s.events {
			if strings.EqualFold(e.Target, target) {
				pathSource[normalizePath(e.Path)]++
			}
		}
	}
	top := make([]model.Count, 0, len(pathSource))
	for k, v := range pathSource {
		top = append(top, model.Count{Name: k, Count: v})
	}
	sort.Slice(top, func(i, j int) bool { return top[i].Count > top[j].Count })
	if len(top) > 8 {
		top = top[:8]
	}
	pc := make([]model.Count, 0, len(persona))
	for k, v := range persona {
		pc = append(pc, model.Count{Name: k, Count: v})
	}
	sort.Slice(pc, func(i, j int) bool { return pc[i].Count > pc[j].Count })
	avg := 0.0
	if depthN > 0 {
		avg = float64(depth) / float64(depthN)
	}
	return model.Overview{Now: now, UptimeSeconds: int64(now.Sub(s.started).Seconds()), ActiveSessions: benign + suspicious + hostile, Benign: benign, Suspicious: suspicious, Hostile: hostile, Human: human, Automated: auto, Unknown: unknown, RequestsTotal: s.requestsTotal, RequestsToday: s.dayCounts[dayKey(now)], RequestsPerSec: float64(last10) / 10, AvgDepth: avg, LoopsTotal: loops, TopPaths: top, PersonaCounts: pc, TopCountries: rankedCounts(countries, 8), TopReferrers: rankedCounts(referrers, 8), TopTargets: rankedCounts(s.targetCounts, 50), RiskBuckets: []model.Count{{Name: "0-29", Count: int64(benign)}, {Name: "30-59", Count: int64(suspicious)}, {Name: "60-100", Count: int64(hostile)}}}
}

func rankedCounts(in map[string]int64, limit int) []model.Count {
	out := make([]model.Count, 0, len(in))
	for k, v := range in {
		out = append(out, model.Count{Name: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Name < out[j].Name
		}
		return out[i].Count > out[j].Count
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
