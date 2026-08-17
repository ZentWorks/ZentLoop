package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"zentloop/internal/config"
	"zentloop/internal/model"
	"zentloop/internal/store"
)

//go:embed web/*
var webFS embed.FS

type adminAuthFailure struct {
	Count int
	Last  time.Time
}

type AdminServer struct {
	cfg   config.Config
	store *store.Store

	authMu       sync.Mutex
	authFailures map[string]adminAuthFailure
}

func NewAdmin(cfg config.Config, st *store.Store) *AdminServer {
	return &AdminServer{cfg: cfg, store: st, authFailures: make(map[string]adminAuthFailure)}
}

func (s *AdminServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/overview", s.overview)
	mux.HandleFunc("/api/available-days", s.availableDays)
	mux.HandleFunc("/api/sessions", s.sessions)
	mux.HandleFunc("/api/history", s.history)
	mux.HandleFunc("/api/sessions/", s.session)
	mux.HandleFunc("/api/events", s.events)
	mux.HandleFunc("/api/realtime", s.realtime)
	mux.HandleFunc("/api/info", s.info)
	mux.HandleFunc("/api/settings/trusted-domains", s.trustedDomains)
	mux.HandleFunc("/api/untrusted-hosts", s.untrustedHosts)
	mux.HandleFunc("/api/known-probes", s.knownProbes)
	mux.HandleFunc("/api/known-probes.csv", s.knownProbesCSV)
	mux.HandleFunc("/api/unknown-paths", s.unknownPaths)
	mux.HandleFunc("/api/unknown-paths.csv", s.unknownPathsCSV)
	mux.HandleFunc("/api/recent-paths", s.recentPaths)
	mux.HandleFunc("/api/catchall-hosts", s.catchAllHosts)
	mux.HandleFunc("/api/catchall-hosts.csv", s.catchAllHostsCSV)
	mux.HandleFunc("/api/integration", s.integrationCapabilities)
	mux.HandleFunc("/api/integration/peers", s.integrationPeers)
	mux.HandleFunc("/api/actors/overview", s.actorOverview)
	mux.HandleFunc("/api/bursts", s.scanBursts)
	mux.HandleFunc("/api/actors", s.actors)
	mux.HandleFunc("/api/actors/", s.actor)
	mux.HandleFunc("/api/intelligence", s.intelligence)
	mux.HandleFunc("/api/health", s.health)
	mux.HandleFunc("/api/ssh/overview", s.sshOverview)
	mux.HandleFunc("/api/ssh/sessions", s.sshSessions)
	mux.HandleFunc("/api/ssh/live-sessions", s.sshLiveSessions)
	mux.HandleFunc("/api/ssh/live-feed", s.sshLiveFeed)
	mux.HandleFunc("/api/ssh/history", s.sshHistory)
	mux.HandleFunc("/api/ssh/highlights", s.sshHighlights)
	mux.HandleFunc("/api/ssh/sessions/", s.sshSession)
	mux.HandleFunc("/api/ssh/events", s.sshEvents)

	sub, _ := fs.Sub(webFS, "web")
	mux.Handle("/", http.FileServer(http.FS(sub)))
	return s.securityHeaders(s.basicAuth(mux))
}

func (s *AdminServer) basicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		valid := ok && !subtleStringMismatch(u, s.cfg.AdminUser) && !subtleStringMismatch(p, s.cfg.AdminPassword)
		ip := remoteIP(r.RemoteAddr)
		if !valid {
			delay := s.recordAdminAuthFailure(ip, time.Now())
			if delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-r.Context().Done():
					return
				}
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="ZentLoop Admin", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		s.clearAdminAuthFailures(ip)
		next.ServeHTTP(w, r)
	})
}

func (s *AdminServer) recordAdminAuthFailure(ip string, now time.Time) time.Duration {
	if ip == "" {
		ip = "unknown"
	}
	s.authMu.Lock()
	defer s.authMu.Unlock()
	state := s.authFailures[ip]
	if !state.Last.IsZero() && now.Sub(state.Last) > 10*time.Minute {
		state.Count = 0
	}
	state.Count++
	state.Last = now
	s.authFailures[ip] = state
	if len(s.authFailures) > 2048 {
		for key, entry := range s.authFailures {
			if now.Sub(entry.Last) > 10*time.Minute {
				delete(s.authFailures, key)
			}
		}
		for len(s.authFailures) > 2048 {
			for key := range s.authFailures {
				if key != ip {
					delete(s.authFailures, key)
					break
				}
			}
		}
	}
	if state.Count <= 1 {
		return 0
	}
	shift := state.Count - 2
	if shift > 4 {
		shift = 4
	}
	return time.Duration(150*(1<<shift)) * time.Millisecond
}

func (s *AdminServer) clearAdminAuthFailures(ip string) {
	if ip == "" {
		ip = "unknown"
	}
	s.authMu.Lock()
	delete(s.authFailures, ip)
	s.authMu.Unlock()
}

func (s *AdminServer) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src "+adminConnectSources(r.Host)+"; img-src 'self' data:")
		next.ServeHTTP(w, r)
	})
}

func adminConnectSources(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return "'self'"
	}
	for _, r := range host {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune(".-_:[]", r) {
			continue
		}
		return "'self'"
	}
	return "'self' ws://" + host + " wss://" + host
}

func subtleStringMismatch(a, b string) bool {
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) != 1
}

func (s *AdminServer) overview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	tr := requestTimeRange(r)
	if tr.Set {
		writeJSON(w, s.store.OverviewRangeTarget(tr.From, tr.To, r.URL.Query().Get("target")))
		return
	}
	writeJSON(w, s.store.OverviewTarget(time.Duration(s.cfg.LiveSessionMinutes)*time.Minute, r.URL.Query().Get("target")))
}
func (s *AdminServer) sessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	limit := queryInt(r, "limit", 100, 1, 500)
	active := queryInt(r, "active_minutes", s.cfg.LiveSessionMinutes, 1, 10080)
	tr := requestTimeRange(r)
	if tr.Set {
		if tr.All || !tr.To.IsZero() {
			writeJSON(w, []model.Session{})
			return
		}
		writeJSON(w, limitSessions(s.store.SessionsView(time.Duration(active)*time.Minute, 0, r.URL.Query().Get("target")), tr, limit))
		return
	}
	writeJSON(w, s.store.SessionsView(time.Duration(active)*time.Minute, limit, r.URL.Query().Get("target")))
}
func (s *AdminServer) history(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	limit := queryInt(r, "limit", 300, 1, 1000)
	tr := requestTimeRange(r)
	if tr.Set {
		base := s.store.HistoryView(0, 0, r.URL.Query().Get("target"))
		if !tr.All && tr.To.IsZero() {
			base = s.store.HistoryView(time.Duration(s.cfg.LiveSessionMinutes)*time.Minute, 0, r.URL.Query().Get("target"))
		}
		writeJSON(w, limitSessions(base, tr, limit))
		return
	}
	writeJSON(w, s.store.HistoryView(time.Duration(s.cfg.LiveSessionMinutes)*time.Minute, limit, r.URL.Query().Get("target")))
}
func (s *AdminServer) session(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/sessions/")
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	if r.URL.Query().Get("event_limit") == "" {
		ss, ok := s.store.GetSessionView(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, ss)
		return
	}
	detail, ok := s.store.SessionDetail(id, queryInt(r, "event_limit", 500, 1, 5000))
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, detail)
}
func (s *AdminServer) events(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	limit := queryInt(r, "limit", 200, 1, 1000)
	tr := requestTimeRange(r)
	if tr.Set {
		writeJSON(w, limitEvents(s.store.EventsView(0, r.URL.Query().Get("target")), tr, limit))
		return
	}
	writeJSON(w, s.store.EventsView(limit, r.URL.Query().Get("target")))
}
func (s *AdminServer) trustedDomains(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.store.TrustedDomains())
	case http.MethodPut:
		var body struct {
			Domains []string `json:"domains"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024))
		if err := dec.Decode(&body); err != nil {
			http.Error(w, "invalid settings payload", http.StatusBadRequest)
			return
		}
		if err := s.store.SetManualTrustedDomains(body.Domains, time.Now()); err != nil {
			if errors.Is(err, store.ErrInvalidTrustedDomain) {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			http.Error(w, "failed to persist trusted domains", http.StatusInternalServerError)
			return
		}
		writeJSON(w, s.store.TrustedDomains())
	default:
		methodNotAllowed(w)
	}
}

func (s *AdminServer) untrustedHosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	limit := queryInt(r, "limit", 50, 1, 500)
	tr := requestTimeRange(r)
	if tr.Set {
		writeJSON(w, untrustedFromEvents(s.store.EventsView(0), tr, limit))
		return
	}
	writeJSON(w, s.store.UntrustedHosts(limit))
}

func (s *AdminServer) availableDays(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, s.store.AvailableDays())
}

func (s *AdminServer) info(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	_, geoErr := os.Stat(s.cfg.GeoIPDB)
	_, botCacheErr := os.Stat(s.cfg.OfficialBotsCache)
	writeJSON(w, map[string]any{
		"brand": s.cfg.Brand, "version": "0.2.16", "proxy_mode": s.cfg.ProxyMode, "proxy_rules": s.cfg.ProxyRules,
		"hostile_threshold": s.cfg.HostileThreshold, "suspicious_threshold": s.cfg.SuspiciousThreshold,
		"live_session_minutes": s.cfg.LiveSessionMinutes, "resume_window_hours": s.cfg.ResumeWindowHours,
		"geo_enrichment": true, "geoip_ready": geoErr == nil, "geoip_db": s.cfg.GeoIPDB, "integration_protocol": 1, "integration_secret_configured": s.cfg.IntegrationSecret != "", "telemetry": false,
		"ssh_trap_enabled": s.cfg.SSHEnabled, "ssh_trap_addr": s.cfg.SSHAddr, "admin_ssh_enabled": s.cfg.AdminSSHEnabled, "admin_ssh_addr": s.cfg.AdminSSHAddr,
		"official_bots_enabled": s.cfg.OfficialBotsEnabled, "official_bots_refresh_hours": s.cfg.OfficialBotsRefreshH, "official_bots_cache_ready": botCacheErr == nil,
	})
}
func (s *AdminServer) actorOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	tr := requestTimeRange(r)
	if tr.Set {
		writeJSON(w, actorOverviewFromRows(limitActors(s.store.Actors(0), tr, 0)))
		return
	}
	writeJSON(w, s.store.ActorOverview())
}

func (s *AdminServer) scanBursts(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 50, 1, 200)
	tr := requestTimeRange(r)
	if tr.Set {
		writeJSON(w, limitBursts(s.store.ScanBursts(0), tr, limit))
		return
	}
	writeJSON(w, s.store.ScanBursts(limit))
}

func (s *AdminServer) actors(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	limit := queryInt(r, "limit", 250, 1, 1000)
	tr := requestTimeRange(r)
	if tr.Set {
		writeJSON(w, limitActors(s.store.Actors(0), tr, limit))
		return
	}
	writeJSON(w, s.store.Actors(limit))
}

func (s *AdminServer) actor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/actors/")
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	detail, ok := s.store.ActorDetail(id, queryInt(r, "event_limit", 240, 1, 1000))
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, detail)
}

func (s *AdminServer) intelligence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	limit := queryInt(r, "limit", 250, 1, 1000)
	tr := requestTimeRange(r)
	rows := s.store.IntelEvents(0)
	if tr.Set {
		rows = limitIntel(rows, tr, 0)
	}
	if r.URL.Query().Get("aggregate") == "1" {
		writeJSON(w, aggregateIntel(rows, limit))
		return
	}
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	writeJSON(w, rows)
}

func (s *AdminServer) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, s.store.HealthOverview())
}

func (s *AdminServer) sshActiveWindow() time.Duration {
	seconds := s.cfg.SSHIdleSeconds + 30
	if seconds < 60 {
		seconds = 60
	}
	return time.Duration(seconds) * time.Second
}

func (s *AdminServer) sshOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	tr := requestTimeRange(r)
	if tr.Set {
		writeJSON(w, s.store.SSHOverviewRange(s.cfg.SSHEnabled, tr.From, tr.To))
		return
	}
	writeJSON(w, s.store.SSHOverview(s.cfg.SSHEnabled, s.sshActiveWindow()))
}

func (s *AdminServer) sshSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	limit := queryInt(r, "limit", 100, 1, 500)
	tr := requestTimeRange(r)
	if tr.Set {
		if tr.All || !tr.To.IsZero() {
			writeJSON(w, []model.SSHSession{})
			return
		}
		writeJSON(w, limitSSHSessions(s.store.SSHSessions(s.sshActiveWindow(), 0), tr, limit))
		return
	}
	writeJSON(w, s.store.SSHSessions(s.sshActiveWindow(), limit))
}

func (s *AdminServer) sshLiveSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	left := time.Duration(queryInt(r, "left_seconds", 10, 0, 60)) * time.Second
	writeJSON(w, s.store.SSHLiveSessions(s.sshActiveWindow(), left, queryInt(r, "limit", 100, 1, 500)))
}

func (s *AdminServer) sshLiveFeed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	left := time.Duration(queryInt(r, "left_seconds", 10, 0, 60)) * time.Second
	writeJSON(w, s.store.SSHLiveFeed(s.sshActiveWindow(), left, queryInt(r, "session_limit", 12, 1, 50), queryInt(r, "event_limit", 10, 1, 50)))
}

func (s *AdminServer) sshHighlights(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	limit := queryInt(r, "limit", 20, 1, 100)
	var before time.Time
	beforeID := ""
	if raw := strings.TrimSpace(r.URL.Query().Get("before")); raw != "" {
		ts := raw
		if i := strings.LastIndex(raw, "|"); i > 0 {
			ts, beforeID = raw[:i], raw[i+1:]
		}
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			before = t
		}
	}
	writeJSON(w, s.store.SSHHighlights(limit, before, beforeID, r.URL.Query().Get("rating")))
}

func (s *AdminServer) sshHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	limit := queryInt(r, "limit", 300, 1, 1000)
	tr := requestTimeRange(r)
	if tr.Set {
		base := s.store.SSHHistory(0, 0)
		if !tr.All && tr.To.IsZero() {
			base = s.store.SSHHistory(s.sshActiveWindow(), 0)
		}
		writeJSON(w, limitSSHSessions(base, tr, limit))
		return
	}
	writeJSON(w, s.store.SSHHistory(s.sshActiveWindow(), limit))
}

func (s *AdminServer) sshSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/ssh/sessions/")
	if rest == "" {
		http.NotFound(w, r)
		return
	}
	parts := strings.Split(rest, "/")
	id := parts[0]
	if id == "" {
		http.NotFound(w, r)
		return
	}
	if len(parts) == 1 {
		detail, ok := s.store.SSHSessionDetail(id, queryInt(r, "event_limit", 250, 1, 5000))
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, detail)
		return
	}
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	switch parts[1] {
	case "export.json":
		ex, ok := s.store.SSHSessionExport(id, "0.2.16")
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="zentloop-ssh-%s.json"`, safeFilename(id)))
		writeJSON(w, ex)
	case "export.txt":
		ex, ok := s.store.SSHSessionExport(id, "0.2.16")
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="zentloop-ssh-%s.txt"`, safeFilename(id)))
		writeSSHExportText(w, ex)
	default:
		http.NotFound(w, r)
	}
}

func safeFilename(v string) string {
	var b strings.Builder
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "session"
	}
	return b.String()
}

func writeSSHExportText(w http.ResponseWriter, ex model.SSHSessionExport) {
	ss := ex.Session
	fmt.Fprintf(w, "ZentLoop SSH Session Export\nVersion: %s\nExported: %s\nSession: %s\nSource: %s (%s)\nUser: %s\nClient: %s\nFirst seen: %s\nLast seen: %s\nCommands: %d\nDepth: %d\nRisk: %d/100\n", ex.Version, ex.ExportedAt.Format(time.RFC3339), ss.ID, ss.IP, ss.Country, ss.Username, ss.ClientVersion, ss.FirstSeen.Format(time.RFC3339), ss.LastSeen.Format(time.RFC3339), ss.CommandCount, ss.Depth, ss.RiskScore)
	if ex.Actor != nil {
		fmt.Fprintf(w, "Actor: %s\nFingerprints: %s\nEngagement: %ds\nCanary touches: %d\nPayload signals: %d\n", ex.Actor.ID, strings.Join(ex.Actor.Fingerprints, ", "), ex.Actor.EngagementSeconds, ex.Actor.CanaryTouches, ex.Actor.PayloadAttempts)
	}
	if len(ex.Intel) > 0 {
		fmt.Fprintln(w, "\nIntelligence:")
		for _, x := range ex.Intel {
			fmt.Fprintf(w, "%s  %s  %s\n", x.At.Format(time.RFC3339), x.Kind, x.Summary)
		}
	}
	fmt.Fprintln(w, "\nVirtual transcript:")
	for _, e := range ex.Events {
		fmt.Fprintf(w, "\n%s · %s", e.At.Format(time.RFC3339), strings.ToUpper(e.Type))
		if e.CommandFamily != "" {
			fmt.Fprintf(w, " · %s", e.CommandFamily)
		}
		fmt.Fprintln(w)
		if e.Command != "" {
			fmt.Fprintf(w, "%s@%s $ %s\n", firstPresent(e.Username, ss.Username, "user"), firstPresent(e.CWD, "/"), e.Command)
			if e.Output != "" {
				fmt.Fprintln(w, e.Output)
			}
		} else {
			fmt.Fprintln(w, firstPresent(e.Message, e.AuthMethod, e.Type))
		}
	}
}

func firstPresent(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func (s *AdminServer) sshEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	limit := queryInt(r, "limit", 250, 1, 1000)
	tr := requestTimeRange(r)
	if tr.Set {
		writeJSON(w, limitSSHEvents(s.store.SSHEvents(0), tr, limit))
		return
	}
	writeJSON(w, s.store.SSHEvents(limit))
}

func (s *AdminServer) knownProbes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	limit := queryInt(r, "limit", 250, 1, 5000)
	tr := requestTimeRange(r)
	if tr.Set {
		writeJSON(w, probesFromEvents(s.store.Events(0), tr, limit))
		return
	}
	writeJSON(w, s.knownProbeRows(limit))
}
func (s *AdminServer) knownProbesCSV(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="zentloop-known-probes.csv"`)
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"probe", "product", "cve", "count", "hostile_requests", "suspicious_requests", "first_seen", "last_seen"})
	for _, p := range s.knownProbeRows(5000) {
		_ = cw.Write([]string{p.Name, p.Product, p.CVE, strconv.FormatInt(p.Count, 10), strconv.FormatInt(p.HostileRequests, 10), strconv.FormatInt(p.SuspiciousRequests, 10), p.FirstSeen.Format(time.RFC3339), p.LastSeen.Format(time.RFC3339)})
	}
}

func (s *AdminServer) unknownPaths(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	limit := queryInt(r, "limit", 500, 1, 5000)
	tr := requestTimeRange(r)
	if tr.Set {
		writeJSON(w, unknownFromEvents(s.store.Events(0), tr, limit))
		return
	}
	writeJSON(w, s.currentUnknownRows(limit))
}
func (s *AdminServer) unknownPathsCSV(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="zentloop-unknown-paths.csv"`)
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"method", "path", "count", "first_seen", "last_seen", "example_ip", "example_user_agent"})
	for _, u := range s.currentUnknownRows(5000) {
		_ = cw.Write([]string{u.Method, u.Path, strconv.FormatInt(u.Count, 10), u.FirstSeen.Format(time.RFC3339), u.LastSeen.Format(time.RFC3339), u.ExampleIP, u.ExampleUserAgent})
	}
}

func (s *AdminServer) recentPaths(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	limit := queryInt(r, "limit", 250, 1, 1000)
	rows := make(map[string]*model.RecentPath)
	tr := requestTimeRange(r)
	events := s.store.Events(5000)
	if tr.Set {
		events = limitEvents(s.store.Events(0), tr, 0)
	}
	for _, e := range events {
		path := strings.TrimSpace(e.Path)
		if path == "" {
			continue
		}
		k := strings.ToUpper(e.Method) + "|" + path
		row := rows[k]
		if row == nil {
			row = &model.RecentPath{Path: path, Method: e.Method, FirstSeen: e.At, LastSeen: e.At, Status: e.Status, Classification: e.Classification}
			rows[k] = row
		}
		row.Count++
		if e.At.Before(row.FirstSeen) {
			row.FirstSeen = e.At
		}
		if e.At.After(row.LastSeen) {
			row.LastSeen = e.At
			row.Status = e.Status
			row.Classification = e.Classification
		}
		if info, ok := identifyProbe(path); ok {
			row.Kind = "known"
			row.ProbeName = info.Name
		} else if isBenignDiscovery(path) || isHistoricalActivityPubEvent(e) || path == "/" || path == "/favicon.ico" || path == "/robots.txt" || path == "/sitemap.xml" {
			row.Kind = "benign-known"
		} else {
			row.Kind = "unmapped"
		}
	}
	out := make([]model.RecentPath, 0, len(rows))
	for _, row := range rows {
		out = append(out, *row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if len(out) > limit {
		out = out[:limit]
	}
	writeJSON(w, out)
}

func (s *AdminServer) currentUnknownRows(limit int) []model.UnknownPath {
	rows := s.store.UnknownPaths(5000)
	out := make([]model.UnknownPath, 0, len(rows))
	for _, u := range rows {
		if _, known := identifyProbe(u.Path); known || isBenignDiscovery(u.Path) {
			continue
		}
		out = append(out, u)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

func isHistoricalActivityPubEvent(e model.Event) bool {
	if strings.ToUpper(strings.TrimSpace(e.Method)) != "POST" || normalizeProbePath(e.Path) != "/inbox" {
		return false
	}
	ua := strings.ToLower(e.UserAgent)
	return e.Message == "activitypub-relay" || strings.Contains(ua, "activity-relay") || strings.Contains(ua, "toot relay")
}

func (s *AdminServer) knownProbeRows(limit int) []model.ProbeStat {
	rows := s.store.ProbeStats(5000)
	byKey := make(map[string]*model.ProbeStat, len(rows))
	for i := range rows {
		p := rows[i]
		k := strings.ToLower(p.Name + "|" + p.Product + "|" + p.CVE)
		cp := p
		byKey[k] = &cp
	}
	// When the probe catalog learns a new path, historical events written by an older
	// ZentLoop version still carry KnownProbe=false. Promote their aggregated unknown
	// rows at read time so an upgrade immediately cleans the feedback list and preserves
	// the observed count without rewriting the append-only event log.
	for _, u := range s.store.UnknownPaths(5000) {
		info, ok := identifyProbe(u.Path)
		if !ok {
			continue
		}
		k := strings.ToLower(info.Name + "|" + info.Product + "|" + info.CVE)
		p := byKey[k]
		if p == nil {
			p = &model.ProbeStat{Name: info.Name, Product: info.Product, CVE: info.CVE, FirstSeen: u.FirstSeen}
			byKey[k] = p
		}
		p.Count += u.Count
		if p.FirstSeen.IsZero() || (!u.FirstSeen.IsZero() && u.FirstSeen.Before(p.FirstSeen)) {
			p.FirstSeen = u.FirstSeen
		}
		if u.LastSeen.After(p.LastSeen) {
			p.LastSeen = u.LastSeen
		}
	}
	rows = rows[:0]
	for _, p := range byKey {
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

func (s *AdminServer) catchAllHosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	limit := queryInt(r, "limit", 250, 1, 5000)
	tr := requestTimeRange(r)
	if tr.Set {
		writeJSON(w, catchAllFromEvents(s.store.Events(0), tr, limit))
		return
	}
	writeJSON(w, s.store.CatchAllOverview(limit))
}

func (s *AdminServer) catchAllHostsCSV(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="zentloop-catchall-hosts.csv"`)
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"host", "requests", "hostile_requests", "suspicious_requests", "first_seen", "last_seen", "last_integration"})
	for _, h := range s.store.CatchAllOverview(5000).Hosts {
		_ = cw.Write([]string{h.Host, strconv.FormatInt(h.Requests, 10), strconv.FormatInt(h.HostileRequests, 10), strconv.FormatInt(h.SuspiciousRequests, 10), h.FirstSeen.Format(time.RFC3339), h.LastSeen.Format(time.RFC3339), h.LastIntegration})
	}
}

func (s *AdminServer) integrationCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, map[string]any{
		"product":          "ZentLoop",
		"version":          "0.2.16",
		"protocol_version": 1,
		"capabilities": []string{
			"catch_all", "forwarded_ip", "target_host", "multi_target", "signed_ingress", "catch_all_statistics", "health_verification", "integration_peers",
		},
		"headers": []string{
			"X-ZentLoop-Integration", "X-ZentLoop-Target", "X-ZentLoop-Catch-All", "X-ZentLoop-Timestamp", "X-ZentLoop-Signature",
		},
		"response_headers": []string{"X-ZentLoop-Integration-Verified"},
		"signature": map[string]any{
			"algorithm":        "HMAC-SHA256",
			"format":           "sha256=<hex>",
			"canonical":        "v1\\n<timestamp>\\n<integration>\\n<target>\\n<catch_all:0|1>\\n<METHOD>\\n<request-uri>",
			"max_skew_seconds": s.cfg.IntegrationMaxSkew,
		},
		"secret_configured":        s.cfg.IntegrationSecret != "",
		"private_unsigned_allowed": s.cfg.IntegrationSecret == "",
		"health_check": map[string]any{
			"method": "GET", "path": integrationCheckPath, "success_status": http.StatusNoContent,
			"verified_header": "X-ZentLoop-Integration-Verified", "verified_value": "1",
			"stale_after_seconds": 45, "offline_after_seconds": 90,
		},
	})
}

func (s *AdminServer) integrationPeers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, s.store.IntegrationPeers(time.Now()))
}

func queryInt(r *http.Request, key string, d, lo, hi int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return d
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return d
	}
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}
func methodNotAllowed(w http.ResponseWriter) {
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}
