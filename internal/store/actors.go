package store

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"zentloop/internal/model"
)

const (
	maxActorTimeline = 240
	maxIntelRing     = 3000
)

func actorID(ip string) string {
	h := sha256.Sum256([]byte(strings.TrimSpace(ip)))
	return "actor-" + hex.EncodeToString(h[:6])
}

func (s *Store) ensureActorLocked(ip, country string, at time.Time) *model.ActorProfile {
	id := actorID(ip)
	a := s.actors[id]
	if a == nil {
		a = &model.ActorProfile{ID: id, IP: ip, Country: country, FirstSeen: at, LastSeen: at, Classification: model.ClassBenign, Actor: model.ActorUnknown}
		s.actors[id] = a
	}
	if a.IP == "" {
		a.IP = ip
	}
	if country != "" {
		a.Country = country
	}
	if a.FirstSeen.IsZero() || at.Before(a.FirstSeen) {
		a.FirstSeen = at
	}
	if a.LastSeen.IsZero() || at.After(a.LastSeen) {
		a.LastSeen = at
	}
	return a
}

func addProtocol(a *model.ActorProfile, protocol string) {
	for _, p := range a.Protocols {
		if p == protocol {
			return
		}
	}
	a.Protocols = append(a.Protocols, protocol)
	sort.Strings(a.Protocols)
}

func addFingerprint(a *model.ActorProfile, fingerprint string) bool {
	fingerprint = strings.TrimSpace(fingerprint)
	if fingerprint == "" {
		return false
	}
	for _, f := range a.Fingerprints {
		if f == fingerprint {
			return false
		}
	}
	a.Fingerprints = append(a.Fingerprints, fingerprint)
	sort.Strings(a.Fingerprints)
	return true
}

func strongerClassification(a, b model.Classification) model.Classification {
	rank := func(v model.Classification) int {
		switch v {
		case model.ClassHostile:
			return 3
		case model.ClassSuspicious:
			return 2
		case model.ClassBenign:
			return 1
		default:
			return 0
		}
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

func strongerActor(a, b model.ActorType) model.ActorType {
	// Automation evidence is stronger than a browser-looking/human-like hint.
	// A single spoofed UA must never downgrade an actor already observed automating.
	if a == model.ActorAutomated || b == model.ActorAutomated {
		return model.ActorAutomated
	}
	if a == model.ActorHuman || b == model.ActorHuman {
		return model.ActorHuman
	}
	return model.ActorUnknown
}

func (s *Store) addActorEngagementLocked(a *model.ActorProfile, protocol, sessionID string, at time.Time) {
	if sessionID == "" || at.IsZero() {
		return
	}
	key := a.ID + "|" + protocol + "|" + sessionID
	if last, ok := s.actorSessionLast[key]; ok && at.After(last) {
		d := at.Sub(last)
		// Do not count long idle gaps as attacker engagement. Five minutes is
		// intentionally generous for somebody reading output or editing a command.
		if d <= 5*time.Minute {
			a.EngagementSeconds += int64(d / time.Second)
		}
	}
	if last, ok := s.actorSessionLast[key]; !ok || at.After(last) {
		s.actorSessionLast[key] = at
	}
}

func (s *Store) appendActorActivityLocked(a *model.ActorProfile, item model.ActorActivity) {
	rows := append(s.actorTimeline[a.ID], item)
	if len(rows) > maxActorTimeline {
		rows = rows[len(rows)-maxActorTimeline:]
	}
	s.actorTimeline[a.ID] = rows
}

func fingerprintHTTP(e model.Event) string {
	if e.HostSweep {
		return "web:host-header-sweep"
	}
	ua := strings.ToLower(e.UserAgent)
	for _, p := range []struct{ needle, label string }{
		{"infrawatch", "http:internet-measurement"}, {"nuclei", "http:nuclei"}, {"sqlmap", "http:sqlmap"}, {"nikto", "http:nikto"}, {"masscan", "http:masscan"},
		{"zgrab", "http:zgrab"}, {"gobuster", "http:gobuster"}, {"ffuf", "http:ffuf"}, {"wpscan", "http:wpscan"},
		{"python-requests", "http:python-requests"}, {"go-http-client", "http:go-client"}, {"curl/", "http:curl"}, {"wget/", "http:wget"},
	} {
		if strings.Contains(ua, p.needle) {
			return p.label
		}
	}
	if e.AutomationScore >= 80 {
		return "http:high-rate-automation"
	}
	if e.Actor == model.ActorHuman {
		return "http:interactive-browser"
	}
	return ""
}

func (s *Store) applyActorHTTPEventLocked(e model.Event) {
	if strings.TrimSpace(e.IP) == "" {
		return
	}
	a := s.ensureActorLocked(e.IP, e.Country, e.At)
	addProtocol(a, "http")
	a.HTTPRequests++
	if e.RiskScore > a.RiskScore {
		a.RiskScore = e.RiskScore
	}
	if e.Depth > a.Depth {
		a.Depth = e.Depth
	}
	a.Classification = strongerClassification(a.Classification, e.Classification)
	a.Actor = strongerActor(a.Actor, e.Actor)
	s.addActorEngagementLocked(a, "http", e.SessionID, e.At)
	fp := fingerprintHTTP(e)
	if addFingerprint(a, fp) {
		s.actorFingerprints[fp]++
	}
	summary := e.Method + " " + e.Path
	if e.ProbeName != "" {
		summary += " · " + e.ProbeName
	}
	s.appendActorActivityLocked(a, model.ActorActivity{At: e.At, Protocol: "http", Kind: e.Category, SessionID: e.SessionID, Summary: summary, Path: e.Path, RiskScore: e.RiskScore, Depth: e.Depth, Fingerprint: fp})
}

func fingerprintSSH(e model.SSHEvent) string {
	if e.Fingerprint != "" {
		return e.Fingerprint
	}
	client := strings.ToLower(e.ClientVersion)
	for _, p := range []struct{ needle, label string }{
		{"paramiko", "ssh:paramiko"}, {"libssh", "ssh:libssh"}, {"ssh-2.0-go", "ssh:go-client"}, {"golang", "ssh:go-client"}, {"go-ssh", "ssh:go-client"}, {"openssh", "ssh:openssh"},
	} {
		if strings.Contains(client, p.needle) {
			return p.label
		}
	}
	return ""
}

func (s *Store) applyActorSSHEventLocked(e model.SSHEvent) {
	if strings.TrimSpace(e.IP) == "" {
		return
	}
	a := s.ensureActorLocked(e.IP, e.Country, e.At)
	addProtocol(a, "ssh")
	if e.Type == "connect" {
		a.SSHConnections++
		recur := s.sshRecurrenceLocked(e.IP, e.At)
		a.SSHMedianRevisitSeconds = recur.MedianSeconds
		a.SSHRevisitJitterSeconds = recur.JitterSeconds
		if recur.Rapid || recur.LowAndSlow {
			a.Actor = model.ActorAutomated
			label := "ssh:low-and-slow"
			if recur.Rapid {
				label = "ssh:rapid-recurrence"
			}
			if addFingerprint(a, label) {
				s.actorFingerprints[label]++
			}
			if addFingerprint(a, "ssh:recurring-credential-probe") {
				s.actorFingerprints["ssh:recurring-credential-probe"]++
			}
		}
	}
	if e.Type == "command" || e.Type == "exec" {
		a.SSHCommands++
		if e.Type == "exec" {
			if ss := s.sshSessions[e.SessionID]; ss != nil && !ss.ShellOpened && ss.ExecRequests >= 3 && ss.LastSeen.Sub(ss.FirstSeen) >= 0 && ss.LastSeen.Sub(ss.FirstSeen) <= 2*time.Second {
				a.Actor = model.ActorAutomated
				if addFingerprint(a, "ssh:rapid-exec-burst") {
					s.actorFingerprints["ssh:rapid-exec-burst"]++
				}
			}
		}
	}
	if e.RiskScore > a.RiskScore {
		a.RiskScore = e.RiskScore
	}
	if e.Depth > a.Depth {
		a.Depth = e.Depth
	}
	a.Classification = strongerClassification(a.Classification, e.Classification)
	a.Actor = strongerActor(a.Actor, e.Actor)
	s.addActorEngagementLocked(a, "ssh", e.SessionID, e.At)
	fp := fingerprintSSH(e)
	if addFingerprint(a, fp) {
		s.actorFingerprints[fp]++
	}
	if (e.Type == "exec" || e.Type == "command") && fp == "ssh:environment-fingerprint-probe" && strings.TrimSpace(e.Command) != "" {
		key := a.ID
		if previous, ok := s.sshActorLastCommand[key]; ok && previous == e.Command {
			if at := s.sshActorLastCommandAt[key]; !at.IsZero() && !e.At.Before(at) && e.At.Sub(at) <= 2*time.Second {
				if addFingerprint(a, "ssh:environment-fingerprint-burst") {
					s.actorFingerprints["ssh:environment-fingerprint-burst"]++
				}
			}
		}
		s.sshActorLastCommand[key] = e.Command
		s.sshActorLastCommandAt[key] = e.At
	}
	summary := e.Message
	if e.Command != "" {
		summary = e.Command
	}
	if summary == "" {
		summary = e.Type
	}
	canary := ""
	if len(e.CanaryTouches) > 0 {
		canary = strings.Join(e.CanaryTouches, ",")
	}
	s.appendActorActivityLocked(a, model.ActorActivity{At: e.At, Protocol: "ssh", Kind: e.Type, SessionID: e.SessionID, Summary: summary, Command: e.Command, Family: e.CommandFamily, RiskScore: e.RiskScore, Depth: e.Depth, Canary: canary, Fingerprint: fp})
}

func cloneActor(a *model.ActorProfile) model.ActorProfile {
	out := *a
	out.Protocols = append([]string(nil), a.Protocols...)
	out.Fingerprints = append([]string(nil), a.Fingerprints...)
	return out
}

func (s *Store) Actors(limit int) []model.ActorProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.ActorProfile, 0, len(s.actors))
	for _, a := range s.actors {
		out = append(out, cloneActor(a))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (s *Store) ActorDetail(id string, limit int) (model.ActorDetail, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.actors[id]
	if !ok {
		return model.ActorDetail{}, false
	}
	rows := append([]model.ActorActivity(nil), s.actorTimeline[id]...)
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].At.Before(rows[j].At) })
	if limit > 0 && len(rows) > limit {
		rows = rows[len(rows)-limit:]
	}
	return model.ActorDetail{Actor: cloneActor(a), Timeline: rows}, true
}

func (s *Store) ActorOverview() model.ActorOverview {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var o model.ActorOverview
	o.ActorsTotal = int64(len(s.actors))
	for _, a := range s.actors {
		if len(a.Protocols) > 1 {
			o.CrossProtocol++
		}
		o.EngagementSeconds += a.EngagementSeconds
		o.CanaryTouches += a.CanaryTouches
		o.PayloadAttempts += a.PayloadAttempts
	}
	o.TopFingerprints = rankedCounts(s.actorFingerprints, 12)
	return o
}

func (s *Store) initIntel() error {
	path := filepath.Join(s.dataDir, "intel-events.jsonl")
	if err := s.loadIntel(path); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	s.intelEventFile = f
	return nil
}

func (s *Store) loadIntel(path string) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var e model.IntelSignal
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		s.intelEvents = append(s.intelEvents, e)
		if len(s.intelEvents) > maxIntelRing {
			s.intelEvents = s.intelEvents[len(s.intelEvents)-maxIntelRing:]
		}
		s.applyIntelLocked(e)
	}
	return sc.Err()
}

func (s *Store) applyIntelLocked(e model.IntelSignal) {
	a := s.ensureActorLocked(e.IP, "", e.At)
	if e.Kind == "canary" {
		a.CanaryTouches++
	}
	if e.Kind == "payload" {
		a.PayloadAttempts++
	}
	s.appendActorActivityLocked(a, model.ActorActivity{At: e.At, Protocol: e.Protocol, Kind: e.Kind, SessionID: e.SessionID, Summary: e.Summary, Canary: e.Canary})
}

func (s *Store) AddIntelSignal(e model.IntelSignal) error {
	if e.ID == "" || e.At.IsZero() || e.IP == "" {
		return nil
	}
	if e.ActorID == "" {
		e.ActorID = actorID(e.IP)
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.intelEventFile != nil {
		if _, err := s.intelEventFile.Write(append(b, '\n')); err != nil {
			return err
		}
	}
	s.intelEvents = append(s.intelEvents, e)
	if len(s.intelEvents) > maxIntelRing {
		s.intelEvents = s.intelEvents[len(s.intelEvents)-maxIntelRing:]
	}
	s.applyIntelLocked(e)
	return nil
}

func (s *Store) IntelEvents(limit int) []model.IntelSignal {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > len(s.intelEvents) {
		limit = len(s.intelEvents)
	}
	out := append([]model.IntelSignal(nil), s.intelEvents[len(s.intelEvents)-limit:]...)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func (s *Store) RecordHealth(kind string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch kind {
	case "http_rejected":
		s.health.HTTPRejected++
	case "ssh_rejected_global":
		s.health.SSHRejectedGlobal++
	case "ssh_rejected_per_ip":
		s.health.SSHRejectedPerIP++
	case "ssh_command_budget":
		s.health.SSHCommandBudgetHits++
	case "ssh_virtual_storage":
		s.health.SSHVirtualStorageHits++
	case "ssh_recursion_guard":
		s.health.SSHRecursionGuardHits++
	}
}

func fileSize(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Size()
}

func (s *Store) HealthOverview() model.HealthOverview {
	s.mu.RLock()
	o := s.health
	o.HTTPEventsInMemory = len(s.events)
	o.SSHEventsInMemory = len(s.sshEvents)
	o.IntelEventsInMemory = len(s.intelEvents)
	o.HTTPSessionsInMemory = len(s.sessions)
	o.SSHSessionsInMemory = len(s.sshSessions)
	o.ActorsInMemory = len(s.actors)
	o.LiveSubscribers = len(s.subs)
	o.SSHLiveSubscribers = len(s.sshSubs)
	o.LiveSubscriberLimit = maxLiveSubscribers
	dataDir := s.dataDir
	s.mu.RUnlock()
	o.EventsBytes = fileSize(filepath.Join(dataDir, "events.jsonl"))
	o.SSHEventsBytes = fileSize(filepath.Join(dataDir, "ssh-events.jsonl"))
	o.IntelEventsBytes = fileSize(filepath.Join(dataDir, "intel-events.jsonl"))
	o.StorageTotalBytes = o.EventsBytes + o.SSHEventsBytes + o.IntelEventsBytes
	o.StorageWarnBytes = storagePressureWarnBytes
	o.StorageCriticalBytes = storagePressureCritBytes
	switch {
	case o.StorageTotalBytes >= storagePressureCritBytes:
		o.StoragePressure = "critical"
	case o.StorageTotalBytes >= storagePressureWarnBytes:
		o.StoragePressure = "warning"
	default:
		o.StoragePressure = "normal"
	}
	return o
}
