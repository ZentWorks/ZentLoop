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
			s.actorEngagementMS[a.ID] += d.Milliseconds()
			a.EngagementSeconds = s.actorEngagementMS[a.ID] / 1000
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

func normalizedHTTPSequencePath(raw string) string {
	p := strings.ToLower(strings.TrimSpace(raw))
	if p == "" {
		return "/"
	}
	parts := strings.Split(p, "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		if strings.HasPrefix(part, "exec-") && len(part) > 9 {
			parts[i] = "exec-<token>"
			continue
		}
		if isHTTPSequenceToken(part) {
			parts[i] = "<token>"
		}
	}
	out := strings.Join(parts, "/")
	if !strings.HasPrefix(out, "/") {
		out = "/" + out
	}
	return out
}

func isHTTPSequenceToken(v string) bool {
	if len(v) < 10 {
		return false
	}
	hexish := 0
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			hexish++
		case r == '-':
		default:
			return false
		}
	}
	return hexish >= 10
}

type httpSequenceSighting struct {
	IP     string
	Target string
	UA     string
	At     time.Time
}

func (s *Store) updateHTTPSequenceFingerprintLocked(a *model.ActorProfile, e model.Event) {
	if a == nil || e.SessionID == "" || e.SelfOrigin {
		return
	}
	if s.httpSessionSequences == nil {
		s.httpSessionSequences = make(map[string][]string)
	}
	seq := s.httpSessionSequences[e.SessionID]
	if len(seq) < 12 {
		seq = append(seq, strings.ToUpper(strings.TrimSpace(e.Method))+" "+normalizedHTTPSequencePath(e.Path))
		s.httpSessionSequences[e.SessionID] = seq
	}
	if len(seq) != 12 {
		return
	}
	h := sha256.Sum256([]byte(strings.Join(seq, "\n")))
	fp := "http:sequence:" + hex.EncodeToString(h[:8])
	if addFingerprint(a, fp) {
		s.actorFingerprints[fp]++
	}

	// Correlate parallel workers that run the same normalized probe program
	// against multiple targets while rotating browser identities. Keep only a
	// short bounded window; this is campaign affinity, never identity proof.
	rows := s.httpSequenceSightings[fp]
	cut := e.At.Add(-5 * time.Second)
	kept := rows[:0]
	worker := false
	for _, row := range rows {
		if row.At.Before(cut) {
			continue
		}
		kept = append(kept, row)
		if row.IP == e.IP && row.Target != "" && e.Target != "" && row.Target != e.Target && row.UA != "" && e.UserAgent != "" && row.UA != e.UserAgent {
			worker = true
		}
	}
	kept = append(kept, httpSequenceSighting{IP: e.IP, Target: e.Target, UA: e.UserAgent, At: e.At})
	if len(kept) > 64 {
		kept = kept[len(kept)-64:]
	}
	s.httpSequenceSightings[fp] = kept
	if worker {
		if addFingerprint(a, "http:parallel-target-worker-pool") {
			s.actorFingerprints["http:parallel-target-worker-pool"]++
		}
	}
}

func fingerprintHTTP(e model.Event) string {
	if e.HostSweep {
		return "web:host-header-sweep"
	}
	switch e.GraphQLOperation {
	case "introspection":
		return "http:graphql-introspection"
	case "mutation":
		return "http:graphql-mutation-probe"
	case "subscription":
		return "http:graphql-subscription-probe"
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
	if e.SelfOrigin {
		a.SelfOriginHTTPRequests++
		return
	}
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
	s.updateHTTPSequenceFingerprintLocked(a, e)
	if s.httpPHPUnitDockerExecChainLocked(e) {
		a.Actor = model.ActorAutomated
		if addFingerprint(a, "http:phpunit-docker-exec-chain") {
			s.actorFingerprints["http:phpunit-docker-exec-chain"]++
		}
	}
	if s.httpPeriodicAuthValidatorLocked(e) {
		a.Actor = model.ActorAutomated
		a.Classification = strongerClassification(a.Classification, model.ClassHostile)
		if a.RiskScore < 82 {
			a.RiskScore = 82
		}
		if addFingerprint(a, "http:periodic-auth-validator") {
			s.actorFingerprints["http:periodic-auth-validator"]++
		}
	}
	if e.AutomationScore >= 80 && strings.TrimSpace(e.UserAgent) != "" {
		uas := s.httpActorUAs[e.IP]
		if uas == nil {
			uas = map[string]time.Time{}
			s.httpActorUAs[e.IP] = uas
		}
		cut := e.At.Add(-15 * time.Minute)
		for ua, at := range uas {
			if at.Before(cut) {
				delete(uas, ua)
			}
		}
		uas[e.UserAgent] = e.At
		if len(uas) >= 3 {
			if addFingerprint(a, "http:user-agent-rotation") {
				s.actorFingerprints["http:user-agent-rotation"]++
			}
		}
	}
	if e.BotClaimed || botClaimLabel(e.UserAgent) != "" {
		claim := strings.ToLower(strings.TrimSpace(e.BotProvider))
		if claim == "" {
			claim = botClaimLabel(e.UserAgent)
		}
		if claim == "" {
			claim = strings.ToLower(strings.TrimSpace(e.BotName))
		}
		if claim != "" {
			claims := s.httpActorBotClaims[e.IP]
			if claims == nil {
				claims = map[string]struct{}{}
				s.httpActorBotClaims[e.IP] = claims
			}
			claims[claim] = struct{}{}
			if len(claims) >= 2 {
				if addFingerprint(a, "http:bot-identity-rotation") {
					s.actorFingerprints["http:bot-identity-rotation"]++
				}
			}
		}
	}
	summary := e.Method + " " + e.Path
	if e.ProbeName != "" {
		summary += " · " + e.ProbeName
	}
	s.appendActorActivityLocked(a, model.ActorActivity{At: e.At, Protocol: "http", Kind: e.Category, SessionID: e.SessionID, Summary: summary, Path: e.Path, RiskScore: e.RiskScore, Depth: e.Depth, Fingerprint: fp})
}

func (s *Store) httpPeriodicAuthValidatorLocked(e model.Event) bool {
	if e.SessionID == "" || strings.ToUpper(strings.TrimSpace(e.Method)) != "POST" || !isHTTPLoginPath(e.Path) || e.AutomationScore < 80 {
		return false
	}
	cut := e.At.Add(-2 * time.Hour)
	times := make([]time.Time, 0, 12)
	for i := len(s.events) - 1; i >= 0; i-- {
		row := s.events[i]
		if row.At.Before(cut) {
			break
		}
		if row.IP != e.IP || strings.ToUpper(strings.TrimSpace(row.Method)) != "POST" || !isHTTPLoginPath(row.Path) {
			continue
		}
		times = append(times, row.At)
	}
	if len(times) < 3 {
		return false
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	gaps := make([]time.Duration, 0, len(times)-1)
	for i := 1; i < len(times); i++ {
		gap := times[i].Sub(times[i-1])
		if gap >= 5*time.Minute && gap <= 30*time.Minute {
			gaps = append(gaps, gap)
		}
	}
	if len(gaps) < 2 {
		return false
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i] < gaps[j] })
	median := gaps[len(gaps)/2]
	return gaps[len(gaps)-1]-gaps[0] <= 4*time.Minute && median >= 5*time.Minute && median <= 30*time.Minute
}

func isHTTPLoginPath(p string) bool {
	p = strings.ToLower(strings.TrimSpace(p))
	return p == "/login" || p == "/login.html" || p == "/login.htm" || p == "/login.jsp" || p == "/manage/account/login"
}

func (s *Store) httpPHPUnitDockerExecChainLocked(e model.Event) bool {
	if e.SessionID == "" || e.Message != "fake-docker-api-exec-start" {
		return false
	}
	cut := e.At.Add(-2 * time.Minute)
	phpunit := false
	containers := false
	creates := 0
	starts := 0
	for i := len(s.events) - 1; i >= 0; i-- {
		row := s.events[i]
		if row.At.Before(cut) {
			break
		}
		if row.SessionID != e.SessionID {
			continue
		}
		switch row.Message {
		case "fake-phpunit-eval":
			phpunit = true
		case "fake-docker-api-containers":
			containers = true
		case "fake-docker-api-exec-create":
			creates++
		case "fake-docker-api-exec-start":
			starts++
		}
	}
	return phpunit && containers && creates >= 3 && starts >= 3
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

func (s *Store) sshScriptedReconSequenceLocked(e model.SSHEvent) bool {
	if e.SessionID == "" || (e.Type != "exec" && e.Type != "command") {
		return false
	}
	cut := e.At.Add(-30 * time.Second)
	times := make([]time.Time, 0, 32)
	families := map[string]struct{}{}
	for i := len(s.sshEvents) - 1; i >= 0; i-- {
		row := s.sshEvents[i]
		if row.At.Before(cut) {
			break
		}
		if row.SessionID != e.SessionID || (row.Type != "exec" && row.Type != "command") {
			continue
		}
		times = append(times, row.At)
		if fam := strings.ToLower(strings.TrimSpace(row.CommandFamily)); fam != "" && fam != "other" {
			families[fam] = struct{}{}
		}
	}
	if len(times) < 10 || len(families) < 3 {
		return false
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	gaps := make([]time.Duration, 0, len(times)-1)
	for i := 1; i < len(times); i++ {
		gap := times[i].Sub(times[i-1])
		if gap >= 0 {
			gaps = append(gaps, gap)
		}
	}
	if len(gaps) == 0 {
		return false
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i] < gaps[j] })
	return gaps[len(gaps)/2] <= time.Second
}

func sshPayloadHashFingerprint(e model.SSHEvent) string {
	h := strings.ToLower(strings.TrimSpace(e.StdinSHA256))
	if len(h) < 16 {
		return ""
	}
	for _, r := range h[:16] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return ""
		}
	}
	kind := strings.ToLower(strings.TrimSpace(e.StdinKind))
	if kind == "script" || strings.Contains(kind, "elf") {
		return "ssh:payload-sha256:" + h[:16]
	}
	low := strings.ToLower(e.Command)
	if kind == "text" && strings.Contains(low, "systemctl --user") && strings.Contains(low, ".service") {
		return "ssh:service-unit-sha256:" + h[:16]
	}
	return ""
}

func (s *Store) sshPersistenceKitFingerprintLocked(e model.SSHEvent) string {
	if e.SessionID == "" {
		return ""
	}
	current := sshPayloadHashFingerprint(e)
	var payload, unit string
	if strings.HasPrefix(current, "ssh:payload-sha256:") {
		payload = strings.TrimPrefix(current, "ssh:payload-sha256:")
	}
	if strings.HasPrefix(current, "ssh:service-unit-sha256:") {
		unit = strings.TrimPrefix(current, "ssh:service-unit-sha256:")
	}
	cut := e.At.Add(-3 * time.Minute)
	for i := len(s.sshEvents) - 1; i >= 0; i-- {
		row := s.sshEvents[i]
		if row.At.Before(cut) {
			break
		}
		if row.SessionID != e.SessionID {
			continue
		}
		fp := sshPayloadHashFingerprint(row)
		if payload == "" && strings.HasPrefix(fp, "ssh:payload-sha256:") {
			payload = strings.TrimPrefix(fp, "ssh:payload-sha256:")
		}
		if unit == "" && strings.HasPrefix(fp, "ssh:service-unit-sha256:") {
			unit = strings.TrimPrefix(fp, "ssh:service-unit-sha256:")
		}
		if payload != "" && unit != "" {
			break
		}
	}
	if payload == "" || unit == "" {
		return ""
	}
	return "ssh:persistence-kit:" + payload + ":" + unit
}

func (s *Store) applyActorSSHEventLocked(e model.SSHEvent) {
	if strings.TrimSpace(e.IP) == "" {
		return
	}
	a := s.ensureActorLocked(e.IP, e.Country, e.At)
	addProtocol(a, "ssh")
	if e.Type == "connect" {
		a.SSHConnections++
		concurrent := 0
		for _, ss := range s.sshSessions {
			if ss.IP == e.IP && ss.Active {
				concurrent++
			}
		}
		if concurrent > a.SSHPeakConcurrent {
			a.SSHPeakConcurrent = concurrent
		}
		if concurrent >= 3 {
			if addFingerprint(a, "ssh:parallel-session-burst") {
				s.actorFingerprints["ssh:parallel-session-burst"]++
			}
		}
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
	if e.Type == "auth" {
		if e.AuthAccepted {
			a.SSHAuthAccepted++
		} else {
			a.SSHAuthRejected++
		}
		user := strings.TrimSpace(e.Username)
		if user != "" {
			users := s.actorSSHUsers[a.ID]
			if users == nil {
				users = make(map[string]struct{})
				s.actorSSHUsers[a.ID] = users
			}
			users[user] = struct{}{}
			a.SSHUniqueUsers = len(users)
		}

		windowStart := e.At.Add(-time.Minute)
		attempts := 0
		sprayUsers := map[string]struct{}{}
		sprayRejected := 0
		sprayStart := e.At.Add(-2 * time.Minute)
		for i := len(s.sshEvents) - 1; i >= 0; i-- {
			row := s.sshEvents[i]
			if row.At.Before(sprayStart) {
				break
			}
			if row.IP != e.IP || row.Type != "auth" {
				continue
			}
			if !row.At.Before(windowStart) {
				attempts++
			}
			if !row.AuthAccepted {
				sprayRejected++
				if u := strings.TrimSpace(row.Username); u != "" {
					sprayUsers[u] = struct{}{}
				}
			}
		}
		if attempts > a.SSHPeakAttemptsPerMin {
			a.SSHPeakAttemptsPerMin = attempts
		}
		if len(sprayUsers) >= 5 && sprayRejected >= 6 {
			a.Actor = model.ActorAutomated
			if addFingerprint(a, "ssh:credential-spray") {
				s.actorFingerprints["ssh:credential-spray"]++
			}
		}
		if e.AuthAccepted {
			activeUsers := map[string]struct{}{}
			for _, ss := range s.sshSessions {
				if ss == nil || ss.IP != e.IP || !ss.Active || !ss.AuthAccepted {
					continue
				}
				if u := strings.ToLower(strings.TrimSpace(ss.Username)); u != "" {
					activeUsers[u] = struct{}{}
				}
			}
			if len(activeUsers) >= 2 {
				a.Actor = model.ActorAutomated
				if addFingerprint(a, "ssh:parallel-account-validation") {
					s.actorFingerprints["ssh:parallel-account-validation"]++
				}
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
		if s.sshScriptedReconSequenceLocked(e) {
			a.Actor = model.ActorAutomated
			if addFingerprint(a, "ssh:scripted-recon-sequence") {
				s.actorFingerprints["ssh:scripted-recon-sequence"]++
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
	for _, sideFP := range e.SecondaryFingerprints {
		sideFP = strings.TrimSpace(sideFP)
		if sideFP == "" || sideFP == fp {
			continue
		}
		if addFingerprint(a, sideFP) {
			s.actorFingerprints[sideFP]++
		}
	}
	if payloadFP := sshPayloadHashFingerprint(e); payloadFP != "" {
		if addFingerprint(a, payloadFP) {
			s.actorFingerprints[payloadFP]++
		}
	}
	if kitFP := s.sshPersistenceKitFingerprintLocked(e); kitFP != "" {
		a.Actor = model.ActorAutomated
		if addFingerprint(a, kitFP) {
			s.actorFingerprints[kitFP]++
		}
	}
	if (e.Type == "exec" || e.Type == "command") && fp == "ssh:environment-fingerprint-probe" && strings.TrimSpace(e.Command) != "" {
		seenSessions := map[string]struct{}{}
		for i := len(s.sshEvents) - 1; i >= 0; i-- {
			row := s.sshEvents[i]
			if e.At.Sub(row.At) > 30*time.Minute {
				break
			}
			if row.IP == e.IP && row.Fingerprint == "ssh:environment-fingerprint-probe" {
				seenSessions[row.SessionID] = struct{}{}
			}
		}
		if len(seenSessions) >= 3 {
			a.Actor = model.ActorAutomated
			if addFingerprint(a, "ssh:repeating-post-auth-probe") {
				s.actorFingerprints["ssh:repeating-post-auth-probe"]++
			}
		}
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
	case "ssh_tarpit":
		s.health.SSHTarpitApplied++
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
	o.RealtimeSubscribers = len(s.realtimeSubs)
	o.RealtimeSubscriberLimit = maxRealtimeSubscribers
	dataDir := s.dataDir
	s.mu.RUnlock()
	o.EventsBytes = fileSize(filepath.Join(dataDir, "events.jsonl"))
	o.SSHEventsBytes = fileSize(filepath.Join(dataDir, "ssh-events.jsonl"))
	o.IntelEventsBytes = fileSize(filepath.Join(dataDir, "intel-events.jsonl"))
	o.StorageTotalBytes = o.EventsBytes + o.SSHEventsBytes + o.IntelEventsBytes
	o.StorageWarnBytes = storagePressureWarnBytes
	o.StorageCriticalBytes = storagePressureCritBytes
	o.StorageCleanupTargetBytes = storagePressureTargetTotalBytes
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
