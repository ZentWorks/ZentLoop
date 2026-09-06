package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"zentloop/internal/model"
)

func (s *Store) initSSH() error {
	path := filepath.Join(s.dataDir, "ssh-events.jsonl")
	if err := s.loadSSH(path); err != nil {
		return err
	}
	// A process restart terminates every network connection. Durable sessions are
	// therefore history until a new TCP connection creates a new session.
	for _, ss := range s.sshSessions {
		ss.Active = false
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	s.sshEventFile = f
	return nil
}

func (s *Store) loadSSH(path string) error {
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
		var e model.SSHEvent
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		s.countSSHActivityLocked(e)
		s.updateSSHHighlightStateLocked(e)
		s.sshEvents = append(s.sshEvents, e)
		if len(s.sshEvents) > maxRing {
			s.sshEvents = s.sshEvents[len(s.sshEvents)-maxRing:]
		}
		s.applySSHEventLocked(e)
		if len(s.sshSessions) > maxSessions+1000 {
			s.pruneSSHSessionsLocked(maxSessions)
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if len(s.sshSessions) > maxSessions {
		s.pruneSSHSessionsLocked(maxSessions)
	}
	return nil
}

func (s *Store) AddSSHEvent(e model.SSHEvent) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sshEventFile != nil {
		if _, err = s.sshEventFile.Write(append(b, '\n')); err != nil {
			return err
		}
	}
	s.countSSHActivityLocked(e)
	s.updateSSHHighlightStateLocked(e)
	s.sshEvents = append(s.sshEvents, e)
	if len(s.sshEvents) > maxRing {
		s.sshEvents = s.sshEvents[len(s.sshEvents)-maxRing:]
	}
	s.applySSHEventLocked(e)
	if len(s.sshSessions) > maxSessions {
		s.pruneSSHSessionsLocked(maxSessions - 1000)
	}
	var viewSession *model.SSHSession
	if ss := s.sshSessions[e.SessionID]; ss != nil {
		cp := *ss
		viewSession = &cp
	}
	s.publishRealtimeLocked(model.RealtimeMessage{Type: "ssh", At: e.At, SSHEvent: &e, SSHSession: viewSession})
	return nil
}

func (s *Store) applySSHEventLocked(e model.SSHEvent) {
	ss := s.sshSessions[e.SessionID]
	if ss == nil {
		ss = &model.SSHSession{ID: e.SessionID, IP: e.IP, FirstSeen: e.At, LastSeen: e.At, CurrentDir: "/", Classification: model.ClassSuspicious, Actor: model.ActorUnknown}
		s.sshSessions[e.SessionID] = ss
	}
	wasClientKnown := ss.ClientVersion != ""
	wasShellOpen := ss.ShellOpened

	if e.IP != "" {
		ss.IP = e.IP
	}
	if e.Country != "" {
		ss.Country = e.Country
		ss.CountrySource = e.CountrySource
	}
	if e.ClientVersion != "" {
		ss.ClientVersion = e.ClientVersion
	}
	if e.Username != "" {
		ss.Username = e.Username
	}
	if e.At.Before(ss.FirstSeen) || ss.FirstSeen.IsZero() {
		ss.FirstSeen = e.At
	}
	if e.At.After(ss.LastSeen) || ss.LastSeen.IsZero() {
		ss.LastSeen = e.At
	}
	if e.Classification != "" {
		ss.Classification = e.Classification
	}
	if e.Actor != "" && e.Actor != model.ActorUnknown {
		if ss.Actor != model.ActorAutomated || e.Actor == model.ActorAutomated {
			ss.Actor = e.Actor
		}
	}
	if e.RiskScore > ss.RiskScore {
		ss.RiskScore = e.RiskScore
	}
	if e.Depth > ss.Depth {
		ss.Depth = e.Depth
	}
	if e.Loop > ss.Loop {
		ss.Loop = e.Loop
	}
	if e.Frustration > ss.Frustration {
		ss.Frustration = e.Frustration
	}
	if e.Persona != "" && (ss.Persona == "" || sshPersonaRank(e.Persona) >= sshPersonaRank(ss.Persona)) {
		ss.Persona = e.Persona
	}
	if e.CWD != "" {
		ss.CurrentDir = e.CWD
	}

	if action := sshEventAction(e); action != "" {
		ss.LastAction = action
	}

	day := dayKey(e.At)
	switch e.Type {
	case "connect":
		ss.Active = true
		ss.DisconnectedAt = time.Time{}
		s.sshConnections++
		s.sshDayConnections[day]++
		country := strings.TrimSpace(e.Country)
		if country == "" {
			country = "(unknown)"
		}
		s.sshCountryCounts[country]++
	case "auth":
		ss.AuthAttempts++
		if e.AuthAccepted {
			ss.AuthAccepted = true
		}
		s.sshAuthAttempts++
		s.sshDayAuth[day]++
		user := strings.TrimSpace(e.Username)
		if user == "" {
			user = "(empty)"
		}
		s.sshUserCounts[user]++
		if !wasClientKnown && e.ClientVersion != "" {
			s.sshClientCounts[normalizeSSHClient(e.ClientVersion)]++
		}
	case "shell":
		ss.ShellOpened = true
		ss.Active = true
		if !wasShellOpen {
			s.sshShells++
			s.sshDayShells[day]++
		}
	case "exec":
		ss.ExecRequests++
		if !ss.ShellOpened && ss.ExecRequests >= 3 && !ss.FirstSeen.IsZero() && e.At.Sub(ss.FirstSeen) >= 0 && e.At.Sub(ss.FirstSeen) <= 2*time.Second {
			ss.Actor = model.ActorAutomated
		}
		fallthrough
	case "command":
		ss.CommandCount++
		ss.CurrentCommand = e.Command
		s.sshCommands++
		s.sshDayCommands[day]++
		name := strings.TrimSpace(e.CommandName)
		if name == "" {
			name = "(unknown)"
		}
		s.sshCommandCounts[name]++
		family := strings.TrimSpace(e.CommandFamily)
		if family == "" {
			family = "other"
		}
		s.sshFamilyCounts[family]++
	case "disconnect", "limit", "handshake_error":
		ss.Active = false
		ss.DisconnectedAt = e.At
		ss.CurrentCommand = ""
	}
	if !ss.FirstSeen.IsZero() && !ss.LastSeen.IsZero() {
		ss.DurationSeconds = int64(ss.LastSeen.Sub(ss.FirstSeen).Seconds())
		if ss.DurationSeconds < 0 {
			ss.DurationSeconds = 0
		}
	}
	s.applyActorSSHEventLocked(e)
}

func sshPersonaRank(persona string) int {
	switch strings.TrimSpace(persona) {
	case "payload-execution":
		return 100
	case "resource-hijack-preparation":
		return 95
	case "payload-staging":
		return 90
	case "persistence", "privilege-escalation", "lateral-movement":
		return 80
	case "anti-fingerprint":
		return 75
	case "network-recon", "hosting-provider-discovery", "resource-discovery", "system-recon":
		return 50
	case "file-manipulation", "file-discovery":
		return 30
	case "interactive-shell":
		return 20
	default:
		return 40
	}
}

func normalizeSSHClient(v string) string {
	v = strings.TrimSpace(strings.TrimPrefix(v, "SSH-2.0-"))
	if v == "" {
		return "(unknown)"
	}
	if len(v) > 64 {
		v = v[:64]
	}
	return v
}

func cloneSSHSession(ss *model.SSHSession) model.SSHSession { return *ss }

func sshEventAction(e model.SSHEvent) string {
	if strings.TrimSpace(e.Command) != "" {
		return strings.TrimSpace(e.Command)
	}
	if strings.TrimSpace(e.Message) != "" {
		return strings.TrimSpace(e.Message)
	}
	switch e.Type {
	case "connect":
		return "SSH connection opened"
	case "auth":
		if e.AuthAccepted {
			return "authentication accepted"
		}
		return "authentication rejected"
	case "shell":
		return "virtual shell opened"
	case "disconnect":
		return "session ended via SSH"
	case "handshake_error":
		return "SSH handshake/authentication ended"
	case "limit":
		return "session ended by protection limit"
	}
	return e.Type
}

func (s *Store) GetSSHSession(id string) (model.SSHSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ss, ok := s.sshSessions[id]
	if !ok {
		return model.SSHSession{}, false
	}
	return cloneSSHSession(ss), true
}

func (s *Store) AllSSHSessions() []model.SSHSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.SSHSession, 0, len(s.sshSessions))
	for _, ss := range s.sshSessions {
		out = append(out, cloneSSHSession(ss))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

func (s *Store) SSHSessions(activeWithin time.Duration, limit int) []model.SSHSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	out := make([]model.SSHSession, 0, len(s.sshSessions))
	for _, ss := range s.sshSessions {
		if !ss.Active {
			continue
		}
		if activeWithin > 0 && now.Sub(ss.LastSeen) > activeWithin {
			continue
		}
		out = append(out, cloneSSHSession(ss))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (s *Store) SSHLiveSessions(activeWithin, leftGrace time.Duration, limit int) []model.SSHSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	out := make([]model.SSHSession, 0, len(s.sshSessions))
	for _, ss := range s.sshSessions {
		if ss.Active {
			if activeWithin > 0 && now.Sub(ss.LastSeen) > activeWithin {
				continue
			}
		} else {
			if leftGrace <= 0 || ss.DisconnectedAt.IsZero() || now.Sub(ss.DisconnectedAt) > leftGrace {
				continue
			}
		}
		out = append(out, cloneSSHSession(ss))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (s *Store) SSHLiveFeed(activeWithin, leftGrace time.Duration, sessionLimit, eventLimit int) []model.SSHLiveFeedItem {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	sessions := make([]model.SSHSession, 0, len(s.sshSessions))
	for _, ss := range s.sshSessions {
		if ss.Active {
			if activeWithin > 0 && now.Sub(ss.LastSeen) > activeWithin {
				continue
			}
		} else if leftGrace <= 0 || ss.DisconnectedAt.IsZero() || now.Sub(ss.DisconnectedAt) > leftGrace {
			continue
		}
		sessions = append(sessions, cloneSSHSession(ss))
	}
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].LastSeen.After(sessions[j].LastSeen) })
	if sessionLimit > 0 && len(sessions) > sessionLimit {
		sessions = sessions[:sessionLimit]
	}
	out := make([]model.SSHLiveFeedItem, 0, len(sessions))
	for _, ss := range sessions {
		events := make([]model.SSHEvent, 0, eventLimit)
		for i := len(s.sshEvents) - 1; i >= 0; i-- {
			if s.sshEvents[i].SessionID != ss.ID {
				continue
			}
			events = append(events, s.sshEvents[i])
			if eventLimit > 0 && len(events) >= eventLimit {
				break
			}
		}
		for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
			events[i], events[j] = events[j], events[i]
		}
		out = append(out, model.SSHLiveFeedItem{Session: ss, Events: events})
	}
	return out
}

func (s *Store) SSHHistory(activeWithin time.Duration, limit int) []model.SSHSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	out := make([]model.SSHSession, 0, len(s.sshSessions))
	for _, ss := range s.sshSessions {
		if ss.Active && (activeWithin <= 0 || now.Sub(ss.LastSeen) <= activeWithin) {
			continue
		}
		out = append(out, cloneSSHSession(ss))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (s *Store) SSHEvents(limit int) []model.SSHEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > len(s.sshEvents) {
		limit = len(s.sshEvents)
	}
	out := append([]model.SSHEvent(nil), s.sshEvents[len(s.sshEvents)-limit:]...)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func (s *Store) SSHSessionDetail(id string, limit int) (model.SSHSessionDetail, bool) {
	return s.sshSessionDetailRetained(id, limit)
}

func (s *Store) SSHSessionExport(id, version string) (model.SSHSessionExport, bool) {
	detail, actor, ok := s.sshSessionEvidence(id, 0)
	if !ok {
		return model.SSHSessionExport{}, false
	}
	return model.SSHSessionExport{
		ExportedAt:       time.Now().UTC(),
		Version:          version,
		Session:          detail.Session,
		Events:           detail.Events,
		Actor:            actor,
		Intel:            detail.Intel,
		AttackTrace:      detail.AttackTrace,
		Highlight:        detail.Highlight,
		TranscriptStatus: detail.TranscriptStatus,
	}, true
}

func (s *Store) SSHOverviewRange(enabled bool, from, to time.Time) model.SSHOverview {
	s.mu.RLock()
	defer s.mu.RUnlock()
	users := map[string]int64{}
	commands := map[string]int64{}
	families := map[string]int64{}
	countries := map[string]int64{}
	clients := map[string]int64{}
	var conn, auth, shells, cmds int64
	depth, depthN := 0, 0
	seenSessions := map[string]struct{}{}
	for _, e := range s.sshEvents {
		if !inRange(e.At, from, to) {
			continue
		}
		switch e.Type {
		case "connect":
			conn++
		case "auth":
			auth++
		case "shell":
			shells++
		case "exec":
			cmds++
		}
		if e.Username != "" {
			users[e.Username]++
		}
		if e.CommandName != "" {
			commands[e.CommandName]++
		}
		if e.CommandFamily != "" {
			families[e.CommandFamily]++
		}
		if e.Country != "" {
			countries[e.Country]++
		}
		if e.ClientVersion != "" {
			clients[e.ClientVersion]++
		}
		seenSessions[e.SessionID] = struct{}{}
	}
	active := 0
	for id := range seenSessions {
		if ss := s.sshSessions[id]; ss != nil {
			if ss.Depth > 0 {
				depth += ss.Depth
				depthN++
			}
			if ss.Active {
				active++
			}
		}
	}
	avg := 0.0
	if depthN > 0 {
		avg = float64(depth) / float64(depthN)
	}
	return model.SSHOverview{Enabled: enabled, ActiveSessions: active, ConnectionsTotal: conn, ConnectionsToday: conn, AuthAttemptsTotal: auth, AuthAttemptsToday: auth, ShellsTotal: shells, ShellsToday: shells, CommandsTotal: cmds, CommandsToday: cmds, AvgDepth: avg, TopUsers: rankedCounts(users, 10), TopCommands: rankedCounts(commands, 12), TopFamilies: rankedCounts(families, 10), TopCountries: rankedCounts(countries, 10), TopClients: rankedCounts(clients, 10)}
}

func (s *Store) SSHOverview(enabled bool, activeWithin time.Duration) model.SSHOverview {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	if activeWithin <= 0 {
		activeWithin = 5 * time.Minute
	}
	active := 0
	depth, depthN := 0, 0
	for _, ss := range s.sshSessions {
		if ss.Active && now.Sub(ss.LastSeen) <= activeWithin {
			active++
			if ss.Depth > 0 {
				depth += ss.Depth
				depthN++
			}
		}
	}
	avg := 0.0
	if depthN > 0 {
		avg = float64(depth) / float64(depthN)
	}
	day := dayKey(now)
	return model.SSHOverview{
		Enabled: enabled, ActiveSessions: active,
		ConnectionsTotal: s.sshConnections, ConnectionsToday: s.sshDayConnections[day],
		AuthAttemptsTotal: s.sshAuthAttempts, AuthAttemptsToday: s.sshDayAuth[day],
		ShellsTotal: s.sshShells, ShellsToday: s.sshDayShells[day],
		CommandsTotal: s.sshCommands, CommandsToday: s.sshDayCommands[day], AvgDepth: avg,
		TopUsers: rankedCounts(s.sshUserCounts, 10), TopCommands: rankedCounts(s.sshCommandCounts, 12),
		TopFamilies: rankedCounts(s.sshFamilyCounts, 10), TopCountries: rankedCounts(s.sshCountryCounts, 10),
		TopClients: rankedCounts(s.sshClientCounts, 10),
	}
}

func (s *Store) pruneSSHSessionsLocked(target int) {
	type pair struct {
		id string
		at time.Time
	}
	rows := make([]pair, 0, len(s.sshSessions))
	for id, ss := range s.sshSessions {
		rows = append(rows, pair{id: id, at: ss.LastSeen})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].at.Before(rows[j].at) })
	remove := len(rows) - target
	for i := 0; i < remove; i++ {
		id := rows[i].id
		if ss := s.sshSessions[id]; ss != nil {
			if h, ok := scoreSSHHighlightState(cloneSSHSession(ss), s.sshHighlightStates[id]); ok {
				s.sshHighlightHistory[id] = h
			}
		}
		delete(s.sshSessions, id)
		delete(s.sshHighlightStates, id)
	}
}

// SSHAuthProfile returns bounded actor/session context for the SSH deception
// acceptance policy. It intentionally exposes usernames and counters only;
// ZentLoop never retains plaintext passwords for this purpose.
type SSHAuthProfile struct {
	UniqueUsers         int
	AuthAccepted        int64
	AuthRejected        int64
	RecentAcceptedUsers []string
	ActiveAcceptedUsers []string
}

func (s *Store) SSHAuthProfile(ip string) SSHAuthProfile {
	ip = strings.TrimSpace(ip)
	out := SSHAuthProfile{}
	if ip == "" {
		return out
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if actor := s.actors[actorID(ip)]; actor != nil {
		out.UniqueUsers = actor.SSHUniqueUsers
		out.AuthAccepted = actor.SSHAuthAccepted
		out.AuthRejected = actor.SSHAuthRejected
	}
	type row struct {
		user string
		at   time.Time
	}
	var recent []row
	active := map[string]struct{}{}
	for _, ss := range s.sshSessions {
		if ss == nil || ss.IP != ip || !ss.AuthAccepted || strings.TrimSpace(ss.Username) == "" {
			continue
		}
		user := strings.ToLower(strings.TrimSpace(ss.Username))
		recent = append(recent, row{user: user, at: ss.LastSeen})
		if ss.Active {
			active[user] = struct{}{}
		}
	}
	sort.Slice(recent, func(i, j int) bool { return recent[i].at.After(recent[j].at) })
	seen := map[string]struct{}{}
	for _, r := range recent {
		if _, ok := seen[r.user]; ok {
			continue
		}
		seen[r.user] = struct{}{}
		out.RecentAcceptedUsers = append(out.RecentAcceptedUsers, r.user)
		if len(out.RecentAcceptedUsers) >= 8 {
			break
		}
	}
	for user := range active {
		out.ActiveAcceptedUsers = append(out.ActiveAcceptedUsers, user)
	}
	sort.Strings(out.ActiveAcceptedUsers)
	return out
}
