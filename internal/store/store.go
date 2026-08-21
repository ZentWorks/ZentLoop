package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
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
	maxRing                         = 5000
	maxPathKeys                     = 5000
	maxSessions                     = 10000
	maxRealtimeSubscribers          = 24
	storagePressureWarnBytes        = 512 << 20
	storagePressureCritBytes        = 1 << 30
	storagePressureTargetTotalBytes = 768 << 20
)

type Store struct {
	mu                    sync.RWMutex
	sessions              map[string]*model.Session
	fingerprints          map[string]string
	events                []model.Event
	realtimeSubs          map[*realtimeSubscriber]struct{}
	pathCounts            map[string]int64
	dayCounts             map[string]int64
	httpHourCounts        map[int64]map[string]int64
	ipDailyActivity       map[string]map[int64]*model.IPActivityBucket
	targetCounts          map[string]int64
	requestHostStats      map[string]*rawHostStat
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
	sshUserCounts         map[string]int64
	sshCommandCounts      map[string]int64
	sshFamilyCounts       map[string]int64
	sshCountryCounts      map[string]int64
	sshClientCounts       map[string]int64
	sshDayConnections     map[string]int64
	sshDayAuth            map[string]int64
	sshDayShells          map[string]int64
	sshDayCommands        map[string]int64
	sshHourCounts         map[int64]int64
	sshHighlightStates    map[string]*sshHighlightState
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
	actorSSHUsers         map[string]map[string]struct{}
	intelEvents           []model.IntelSignal
	intelEventFile        *os.File
	health                model.HealthOverview
	integrationPeers      map[string]*model.IntegrationPeer
	integrationPersist    map[string]time.Time
	trustedManual         map[string]model.TrustedDomain
	retentionDays         int
	retentionStop         chan struct{}
	retentionDone         chan struct{}
}

func eventStorageBytes(dataDir string) int64 {
	return fileSize(filepath.Join(dataDir, "events.jsonl")) + fileSize(filepath.Join(dataDir, "ssh-events.jsonl")) + fileSize(filepath.Join(dataDir, "intel-events.jsonl"))
}

func New(dataDir string) (*Store, error) {
	return NewWithRetention(dataDir, 30)
}

func newStoreState(dataDir string, retentionDays int) *Store {
	return &Store{
		sessions: make(map[string]*model.Session), fingerprints: make(map[string]string),
		realtimeSubs: make(map[*realtimeSubscriber]struct{}), pathCounts: make(map[string]int64), dayCounts: make(map[string]int64), httpHourCounts: make(map[int64]map[string]int64), ipDailyActivity: make(map[string]map[int64]*model.IPActivityBucket), targetCounts: make(map[string]int64), requestHostStats: make(map[string]*rawHostStat), unknownPaths: make(map[string]*model.UnknownPath), probeStats: make(map[string]*model.ProbeStat), catchAllHosts: make(map[string]*model.CatchAllHost), integrationCounts: make(map[string]int64),
		actors: make(map[string]*model.ActorProfile), actorTimeline: make(map[string][]model.ActorActivity), actorSessionLast: make(map[string]time.Time), actorFingerprints: make(map[string]int64), sshActorLastCommand: make(map[string]string), sshActorLastCommandAt: make(map[string]time.Time), actorSSHUsers: make(map[string]map[string]struct{}),
		sshSessions: make(map[string]*model.SSHSession), sshUserCounts: make(map[string]int64), sshCommandCounts: make(map[string]int64), sshFamilyCounts: make(map[string]int64), sshCountryCounts: make(map[string]int64), sshClientCounts: make(map[string]int64), sshDayConnections: make(map[string]int64), sshDayAuth: make(map[string]int64), sshDayShells: make(map[string]int64), sshDayCommands: make(map[string]int64), sshHourCounts: make(map[int64]int64), sshHighlightStates: make(map[string]*sshHighlightState),
		integrationPeers: make(map[string]*model.IntegrationPeer), integrationPersist: make(map[string]time.Time),
		trustedManual: make(map[string]model.TrustedDomain),
		started:       time.Now(), dataDir: dataDir, retentionDays: retentionDays,
		retentionStop: make(chan struct{}), retentionDone: make(chan struct{}),
	}
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
	s := newStoreState(dataDir, retentionDays)
	if err := s.loadIntegrationPeers(); err != nil {
		return nil, err
	}
	if err := s.loadTrustedDomains(); err != nil {
		return nil, err
	}
	if err := pruneJSONLPaths(dataDir, retentionDays, time.Now()); err != nil {
		return nil, err
	}
	if eventStorageBytes(dataDir) >= storagePressureCritBytes {
		if err := compactJSONLStorageBudget(dataDir, storagePressureTargetTotalBytes, []jsonlPressureTarget{
			{name: "events.jsonl"},
			{name: "ssh-events.jsonl"},
			{name: "intel-events.jsonl"},
		}); err != nil {
			return nil, fmt.Errorf("startup storage pressure compact: %w", err)
		}
		s.health.StorageCompactions++
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

// LoadReadOnlySnapshot reconstructs the retained in-memory view from the data
// directory without opening writers, pruning files, or starting maintenance loops.
// It is intended for short-lived local tooling that must not interfere with the
// running ZentLoop process.
func LoadReadOnlySnapshot(dataDir string) (*Store, error) {
	s := newStoreState(dataDir, 30)
	if err := s.loadIntegrationPeers(); err != nil {
		return nil, err
	}
	if err := s.loadTrustedDomains(); err != nil {
		return nil, err
	}
	if err := s.load(filepath.Join(dataDir, "events.jsonl")); err != nil {
		return nil, err
	}
	if err := s.loadIntel(filepath.Join(dataDir, "intel-events.jsonl")); err != nil {
		return nil, err
	}
	if err := s.loadSSH(filepath.Join(dataDir, "ssh-events.jsonl")); err != nil {
		return nil, err
	}
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
		s.countHTTPActivityLocked(e)
		s.events = append(s.events, e)
		if len(s.events) > maxRing {
			s.events = s.events[len(s.events)-maxRing:]
		}
		s.requestsTotal++
		s.countPath(e.Path)
		s.dayCounts[dayKey(e.At)]++
		s.countTarget(e.Target)
		s.countRequestHost(e)
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
	if e.TargetTrust != "" {
		ss.TargetTrust = e.TargetTrust
	}
	if e.SelfOrigin {
		ss.SelfOrigin = true
	}
	if e.HostSweep {
		ss.HostSweep = true
		if e.HostSweepHosts > ss.HostSweepHosts {
			ss.HostSweepHosts = e.HostSweepHosts
		}
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
	visitChanged := false
	if !e.SessionVisitStarted.IsZero() {
		visitChanged = ss.VisitStarted.IsZero() || !ss.VisitStarted.Equal(e.SessionVisitStarted)
		ss.VisitStarted = e.SessionVisitStarted
	} else if ss.VisitStarted.IsZero() {
		ss.VisitStarted = ss.FirstSeen
		visitChanged = true
	}
	if e.SessionVisitRequests > 0 {
		ss.VisitRequestCount = e.SessionVisitRequests
	} else {
		// Older durable event logs do not carry a per-visit request counter.
		// Rebuild it while replaying the log and reset it whenever VisitStarted
		// changes so upgrades preserve the current-visit view correctly.
		if visitChanged {
			ss.VisitRequestCount = 0
		}
		ss.VisitRequestCount++
	}
	if e.SessionVisitFirstPath != "" {
		ss.VisitFirstPath = e.SessionVisitFirstPath
	} else if visitChanged || ss.VisitFirstPath == "" {
		ss.VisitFirstPath = e.Path
	}
	ss.RiskScore = e.RiskScore
	ss.AutomationScore = e.AutomationScore
	ss.Classification = e.Classification
	ss.Actor = e.Actor
	ss.Confidence = e.Confidence
	ss.AvgIntervalMS = e.AvgIntervalMS
	ss.IntervalVarMS = e.IntervalVarMS
	ss.Persona = e.Persona
	if e.WebStory != "" {
		ss.WebStory = e.WebStory
		ss.WebStoryConfidence = e.WebStoryConfidence
		ss.WebStoryLocked = e.WebStoryLocked
	}
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

func (s *Store) GetSessionView(id string) (*model.Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ss, ok := s.sessions[id]
	if !ok {
		return nil, false
	}
	cp := s.decorateSessionLocked(ss)
	cp.RecentTimes = nil
	return &cp, true
}
func (s *Store) SessionDetail(id string, limit int) (model.SessionDetail, bool) {
	return s.sessionDetail(id, limit, false)
}

// SessionDetailCurrentVisit returns the long-lived Web session metadata but
// restricts the retained request timeline to the currently active visit.
// Historical visits remain available through SessionDetail/WebSessionExport
// and IP Intelligence.
func (s *Store) SessionDetailCurrentVisit(id string, limit int) (model.SessionDetail, bool) {
	detail, ok := s.sessionDetail(id, limit, true)
	if !ok {
		return model.SessionDetail{}, false
	}
	expected := detail.Session.VisitRequestCount
	if expected <= 0 || len(detail.Events) >= minInt(expected, limit) {
		return detail, true
	}
	rows, err := s.currentVisitEventsFromDisk(id, detail.Session.VisitStarted, limit)
	if err != nil || len(rows) <= len(detail.Events) {
		return detail, true
	}
	s.mu.RLock()
	for i := range rows {
		rows[i] = s.decorateEventLocked(rows[i])
	}
	s.mu.RUnlock()
	detail.Events = rows
	return detail, true
}

// currentVisitEventsFromDisk is a durable fallback for the live/current-visit
// drawer. The global in-memory ring is intentionally bounded, so a busy trap
// must not make requests from the still-current visit disappear from its
// timeline while they are still present in events.jsonl.
func eventBelongsToVisit(e model.Event, started time.Time) bool {
	if started.IsZero() {
		return true
	}
	// Newer events carry the visit boundary explicitly. Prefer that durable
	// association over comparing Event.At with VisitStarted because the older
	// request path could stamp those two values a few microseconds apart.
	if !e.SessionVisitStarted.IsZero() {
		return e.SessionVisitStarted.Equal(started)
	}
	return !e.At.Before(started)
}

func (s *Store) currentVisitEventsFromDisk(id string, started time.Time, limit int) ([]model.Event, error) {
	if limit <= 0 {
		limit = 5000
	}
	f, err := os.Open(filepath.Join(s.dataDir, "events.jsonl"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rows := make([]model.Event, 0, minInt(limit, 128))
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for sc.Scan() {
		var e model.Event
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.SessionID != id {
			continue
		}
		if !eventBelongsToVisit(e, started) {
			continue
		}
		rows = append(rows, e)
		if len(rows) > limit {
			rows = rows[len(rows)-limit:]
		}
	}
	return rows, sc.Err()
}

func (s *Store) sessionDetail(id string, limit int, currentVisitOnly bool) (model.SessionDetail, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ss, ok := s.sessions[id]
	if !ok {
		return model.SessionDetail{}, false
	}
	if limit <= 0 {
		limit = len(s.events)
	}
	events := make([]model.Event, 0, minInt(limit, len(s.events)))
	for i := len(s.events) - 1; i >= 0 && len(events) < limit; i-- {
		e := s.events[i]
		if e.SessionID != id {
			continue
		}
		if currentVisitOnly && !eventBelongsToVisit(e, ss.VisitStarted) {
			continue
		}
		events = append(events, e)
	}
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
	cp := s.decorateSessionLocked(ss)
	cp.RecentTimes = nil
	for i := range events {
		events[i] = s.decorateEventLocked(events[i])
	}
	traces := s.attackTracesLocked(ss.IP)
	filtered := make([]model.AttackTrace, 0, len(traces))
	for _, trace := range traces {
		for _, step := range trace.Steps {
			if step.SessionID == id {
				filtered = append(filtered, trace)
				break
			}
		}
	}
	return model.SessionDetail{Session: cp, Events: events, AttackTrace: filtered}, true
}

func (s *Store) WebSessionExport(id, version string) (model.WebSessionExport, bool) {
	detail, ok := s.SessionDetail(id, 5000)
	if !ok {
		return model.WebSessionExport{}, false
	}
	traces := s.AttackTraces(detail.Session.IP)
	filtered := make([]model.AttackTrace, 0, len(traces))
	for _, trace := range traces {
		for _, step := range trace.Steps {
			if step.SessionID == id {
				filtered = append(filtered, trace)
				break
			}
		}
	}
	return model.WebSessionExport{
		ExportedAt:  time.Now().UTC(),
		Version:     version,
		Session:     detail.Session,
		Events:      detail.Events,
		AttackTrace: filtered,
	}, true
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
	s.countHTTPActivityLocked(e)
	s.events = append(s.events, e)
	if len(s.events) > maxRing {
		s.events = s.events[len(s.events)-maxRing:]
	}
	s.requestsTotal++
	s.countPath(e.Path)
	s.dayCounts[dayKey(e.At)]++
	s.countTarget(e.Target)
	s.countRequestHost(e)
	s.countUnknown(e)
	s.countProbe(e)
	s.countCatchAll(e)
	s.applyActorHTTPEventLocked(e)
	viewEvent := s.decorateEventLocked(e)
	var viewSession *model.Session
	if ss := s.sessions[e.SessionID]; ss != nil {
		cp := s.decorateSessionLocked(ss)
		cp.RecentTimes = nil
		viewSession = &cp
	}
	s.publishRealtimeLocked(model.RealtimeMessage{Type: "web", At: e.At, Event: &viewEvent, Session: viewSession})
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
		rawTarget := e.Target
		if rawTarget == "" {
			rawTarget = e.RequestHost
		}
		if wantTarget != "" && !s.targetFilterMatchesLocked(rawTarget, wantTarget) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func (s *Store) EventsView(limit int, target ...string) []model.Event {
	rows := s.Events(limit, target...)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range rows {
		rows[i] = s.decorateEventLocked(rows[i])
	}
	return rows
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
		rawTarget := ss.Target
		if rawTarget == "" {
			rawTarget = ss.RequestHost
		}
		if len(target) > 0 && target[0] != "" && !s.targetFilterMatchesLocked(rawTarget, target[0]) {
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

func (s *Store) SessionsView(activeWithin time.Duration, limit int, target ...string) []model.Session {
	rows := s.Sessions(activeWithin, limit, target...)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range rows {
		view := s.decorateSessionLocked(&rows[i])
		view.RecentTimes = nil
		rows[i] = view
	}
	return rows
}

func (s *Store) History(inactiveFor time.Duration, limit int, target ...string) []model.Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	out := make([]model.Session, 0, len(s.sessions))
	for _, ss := range s.sessions {
		rawTarget := ss.Target
		if rawTarget == "" {
			rawTarget = ss.RequestHost
		}
		if len(target) > 0 && target[0] != "" && !s.targetFilterMatchesLocked(rawTarget, target[0]) {
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

func (s *Store) HistoryView(inactiveFor time.Duration, limit int, target ...string) []model.Session {
	rows := s.History(inactiveFor, limit, target...)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range rows {
		view := s.decorateSessionLocked(&rows[i])
		view.RecentTimes = nil
		rows[i] = view
	}
	return rows
}

func inRange(t, from, to time.Time) bool {
	if !from.IsZero() && t.Before(from) {
		return false
	}
	if !to.IsZero() && !t.Before(to) {
		return false
	}
	return true
}

func (s *Store) OverviewRangeTarget(from, to time.Time, target string) model.Overview {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	var benign, suspicious, hostile, human, auto, unknown int
	var depth, depthN int
	var loops int64
	persona := map[string]int64{}
	countries := map[string]int64{}
	referrers := map[string]int64{}
	paths := map[string]int64{}
	targets := map[string]int64{}
	var requests int64
	durableRequests, durableRequestCount := s.durableHTTPCountRangeLocked(from, to, target)
	if durableRequestCount {
		requests = durableRequests
	}
	var last10 int64
	for _, ss := range s.sessions {
		rawTarget := ss.Target
		if rawTarget == "" {
			rawTarget = ss.RequestHost
		}
		if target != "" && !s.targetFilterMatchesLocked(rawTarget, target) {
			continue
		}
		if !inRange(ss.LastSeen, from, to) {
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
	}
	for _, e := range s.events {
		rawTarget := e.Target
		if rawTarget == "" {
			rawTarget = e.RequestHost
		}
		if target != "" && !s.targetFilterMatchesLocked(rawTarget, target) {
			continue
		}
		if !inRange(e.At, from, to) {
			continue
		}
		if !durableRequestCount {
			requests++
		}
		paths[normalizePath(e.Path)]++
		if root, _, ok := s.trustedTargetRootLocked(rawTarget); ok {
			targets[root]++
		}
		if e.At.After(now.Add(-10 * time.Second)) {
			last10++
		}
	}
	webBenign, webSuspicious, webHostile := benign, suspicious, hostile
	sshBenign, sshSuspicious, sshHostile := 0, 0, 0
	sshActive := 0
	if strings.TrimSpace(target) == "" {
		for _, ss := range s.sshSessions {
			if !inRange(ss.LastSeen, from, to) {
				continue
			}
			sshActive++
			switch ss.Classification {
			case model.ClassBenign:
				sshBenign++
			case model.ClassSuspicious:
				sshSuspicious++
			default:
				sshHostile++
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
		}
		benign += sshBenign
		suspicious += sshSuspicious
		hostile += sshHostile
	}
	avg := 0.0
	if depthN > 0 {
		avg = float64(depth) / float64(depthN)
	}
	return model.Overview{Now: now, UptimeSeconds: int64(now.Sub(s.started).Seconds()), ActiveSessions: benign + suspicious + hostile, Benign: benign, Suspicious: suspicious, Hostile: hostile, Human: human, Automated: auto, Unknown: unknown, RequestsTotal: requests, RequestsToday: requests, RequestsPerSec: float64(last10) / 10, AvgDepth: avg, LoopsTotal: loops, WebActiveSessions: webBenign + webSuspicious + webHostile, SSHActiveSessions: sshActive, WebHostile: webHostile, WebSuspicious: webSuspicious, WebBenign: webBenign, SSHHostile: sshHostile, SSHSuspicious: sshSuspicious, SSHBenign: sshBenign, TopPaths: rankedCounts(paths, 8), PersonaCounts: rankedCounts(persona, 10), TopCountries: rankedCounts(countries, 8), TopReferrers: rankedCounts(referrers, 8), TopTargets: rankedCounts(targets, 50), RiskBuckets: []model.Count{{Name: "0-29", Count: int64(benign)}, {Name: "30-59", Count: int64(suspicious)}, {Name: "60-100", Count: int64(hostile)}}}
}

func (s *Store) AvailableDays() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := map[string]struct{}{}
	for key := range s.httpHourCounts {
		seen[dayKey(time.Unix(key, 0))] = struct{}{}
	}
	for key := range s.sshHourCounts {
		seen[dayKey(time.Unix(key, 0))] = struct{}{}
	}
	for _, e := range s.intelEvents {
		seen[dayKey(e.At)] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out
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
		rawTarget := ss.Target
		if rawTarget == "" {
			rawTarget = ss.RequestHost
		}
		if target != "" && !s.targetFilterMatchesLocked(rawTarget, target) {
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
	for _, raw := range s.events {
		rawTarget := raw.Target
		if rawTarget == "" {
			rawTarget = raw.RequestHost
		}
		if target != "" && !s.targetFilterMatchesLocked(rawTarget, target) {
			continue
		}
		if raw.At.After(now.Add(-10 * time.Second)) {
			last10++
		}
	}
	pathSource := s.pathCounts
	if target != "" {
		pathSource = map[string]int64{}
		for _, raw := range s.events {
			rawTarget := raw.Target
			if rawTarget == "" {
				rawTarget = raw.RequestHost
			}
			if s.targetFilterMatchesLocked(rawTarget, target) {
				pathSource[normalizePath(raw.Path)]++
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
	webBenign, webSuspicious, webHostile := benign, suspicious, hostile
	sshBenign, sshSuspicious, sshHostile := 0, 0, 0
	sshActive := 0
	if strings.TrimSpace(target) == "" {
		for _, ss := range s.sshSessions {
			if !ss.Active || ss.LastSeen.Before(activeSince) {
				continue
			}
			sshActive++
			switch ss.Classification {
			case model.ClassBenign:
				sshBenign++
			case model.ClassSuspicious:
				sshSuspicious++
			default:
				sshHostile++
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
		}
		benign += sshBenign
		suspicious += sshSuspicious
		hostile += sshHostile
	}
	avg := 0.0
	if depthN > 0 {
		avg = float64(depth) / float64(depthN)
	}
	trustedTargetCounts := map[string]int64{}
	for raw, count := range s.targetCounts {
		if root, _, ok := s.trustedTargetRootLocked(raw); ok {
			trustedTargetCounts[root] += count
		}
	}
	return model.Overview{Now: now, UptimeSeconds: int64(now.Sub(s.started).Seconds()), ActiveSessions: benign + suspicious + hostile, Benign: benign, Suspicious: suspicious, Hostile: hostile, Human: human, Automated: auto, Unknown: unknown, RequestsTotal: s.requestsTotal, RequestsToday: s.dayCounts[dayKey(now)], RequestsPerSec: float64(last10) / 10, AvgDepth: avg, LoopsTotal: loops, WebActiveSessions: webBenign + webSuspicious + webHostile, SSHActiveSessions: sshActive, WebHostile: webHostile, WebSuspicious: webSuspicious, WebBenign: webBenign, SSHHostile: sshHostile, SSHSuspicious: sshSuspicious, SSHBenign: sshBenign, TopPaths: top, PersonaCounts: pc, TopCountries: rankedCounts(countries, 8), TopReferrers: rankedCounts(referrers, 8), TopTargets: rankedCounts(trustedTargetCounts, 50), RiskBuckets: []model.Count{{Name: "0-29", Count: int64(benign)}, {Name: "30-59", Count: int64(suspicious)}, {Name: "60-100", Count: int64(hostile)}}}
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
