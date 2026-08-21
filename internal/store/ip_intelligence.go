package store

import (
	"sort"
	"strings"
	"time"

	"zentloop/internal/model"
)

type ipSweepPoint struct {
	at    time.Time
	delta int
}

func topIPValues(counts map[string]int64, limit int) []model.IPTopValue {
	rows := make([]model.IPTopValue, 0, len(counts))
	for value, count := range counts {
		value = strings.TrimSpace(value)
		if value == "" || count <= 0 {
			continue
		}
		rows = append(rows, model.IPTopValue{Value: value, Count: count})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count == rows[j].Count {
			return rows[i].Value < rows[j].Value
		}
		return rows[i].Count > rows[j].Count
	})
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

func setIntersectionSize(a, b map[string]struct{}) int {
	if len(a) > len(b) {
		a, b = b, a
	}
	n := 0
	for k := range a {
		if _, ok := b[k]; ok {
			n++
		}
	}
	return n
}

func stringSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out[value] = struct{}{}
		}
	}
	return out
}

func (s *Store) campaignPeersLocked(ip string, target *model.ActorProfile, targetUsers, targetClients map[string]struct{}) []model.IPCampaignPeer {
	if target == nil {
		return nil
	}
	targetFP := stringSet(target.Fingerprints)
	rows := make([]model.IPCampaignPeer, 0, 8)

	// Build SSH evidence once for this intelligence request. The previous form
	// rescanned every retained SSH session once per candidate actor.
	usersByIP := make(map[string]map[string]struct{})
	clientsByIP := make(map[string]map[string]struct{})
	for _, ss := range s.sshSessions {
		if ss.IP == "" {
			continue
		}
		if u := strings.TrimSpace(ss.Username); u != "" {
			if usersByIP[ss.IP] == nil {
				usersByIP[ss.IP] = map[string]struct{}{}
			}
			usersByIP[ss.IP][u] = struct{}{}
		}
		if c := strings.TrimSpace(ss.ClientVersion); c != "" {
			if clientsByIP[ss.IP] == nil {
				clientsByIP[ss.IP] = map[string]struct{}{}
			}
			clientsByIP[ss.IP][normalizeSSHClient(c)] = struct{}{}
		}
	}

	for _, peer := range s.actors {
		if peer == nil || peer.IP == ip || peer.IP == "" {
			continue
		}
		// A clearly human/manual actor and a clearly automated actor are not
		// promoted into the same campaign by weak infrastructure similarities.
		// This is negative evidence, not just absence of positive evidence.
		if (target.Actor == model.ActorHuman && peer.Actor == model.ActorAutomated) || (target.Actor == model.ActorAutomated && peer.Actor == model.ActorHuman) {
			continue
		}
		score := 0
		strongSignals := 0
		strongReasons := make([]string, 0, 5)
		contextReasons := make([]string, 0, 2)
		if target.Country != "" && peer.Country == target.Country {
			score += 8
			contextReasons = append(contextReasons, "same country")
		}
		if target.LastSeen.Sub(peer.LastSeen) <= 15*time.Minute && peer.LastSeen.Sub(target.LastSeen) <= 15*time.Minute {
			score += 15
			contextReasons = append(contextReasons, "overlapping activity window")
		} else if target.LastSeen.Sub(peer.LastSeen) <= time.Hour && peer.LastSeen.Sub(target.LastSeen) <= time.Hour {
			score += 7
			contextReasons = append(contextReasons, "nearby activity window")
		}
		peerFP := stringSet(peer.Fingerprints)
		sharedFP := setIntersectionSize(targetFP, peerFP)
		if sharedFP >= 2 {
			bonus := sharedFP * 10
			if bonus > 30 {
				bonus = 30
			}
			score += bonus
			strongSignals++
			strongReasons = append(strongReasons, "multiple shared behavior fingerprints")
		}
		if target.SSHMedianRevisitSeconds > 0 && peer.SSHMedianRevisitSeconds > 0 {
			diff := target.SSHMedianRevisitSeconds - peer.SSHMedianRevisitSeconds
			if diff < 0 {
				diff = -diff
			}
			tolerance := target.SSHMedianRevisitSeconds / 4
			if tolerance < 5 {
				tolerance = 5
			}
			if diff <= tolerance {
				score += 15
				strongSignals++
				strongReasons = append(strongReasons, "similar SSH revisit cadence")
			}
		}
		peerUsers := usersByIP[peer.IP]
		peerClients := clientsByIP[peer.IP]
		sharedUsers := setIntersectionSize(targetUsers, peerUsers)
		if sharedUsers >= 3 {
			score += 15
			strongSignals++
			strongReasons = append(strongReasons, "shared username spray set")
		} else if sharedUsers > 0 {
			score += 6
			contextReasons = append(contextReasons, "shared usernames")
		}
		if setIntersectionSize(targetClients, peerClients) > 0 {
			score += 16
			strongSignals++
			strongReasons = append(strongReasons, "same SSH client family")
		}
		if target.Actor == model.ActorAutomated && peer.Actor == model.ActorAutomated {
			score += 5
		}
		// Country, timing and small username overlap are context only. Require at
		// least two independent behavioral signals before surfacing a peer.
		if score < 55 || strongSignals < 2 {
			continue
		}
		if score > 99 {
			score = 99
		}
		reasons := append(strongReasons, contextReasons...)
		rows = append(rows, model.IPCampaignPeer{IP: peer.IP, Country: peer.Country, Confidence: score, RiskScore: peer.RiskScore, LastSeen: peer.LastSeen, Reasons: reasons})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Confidence == rows[j].Confidence {
			return rows[i].LastSeen.After(rows[j].LastSeen)
		}
		return rows[i].Confidence > rows[j].Confidence
	})
	if len(rows) > 12 {
		rows = rows[:12]
	}
	return rows
}

// IPIntelligence returns one correlated, all-in-one retained view for a source IP.
// It deliberately uses only data ZentLoop already observed; campaign peers are
// heuristic correlations, not identity claims.
func (s *Store) IPIntelligence(ip, version string) (model.IPIntelligence, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	actor := s.actors[actorID(ip)]
	if actor == nil {
		return model.IPIntelligence{}, false
	}
	out := model.IPIntelligence{ExportedAt: time.Now(), Version: version, IP: ip, Actor: cloneActor(actor)}
	out.Summary = model.IPIntelligenceSummary{
		FirstSeen: actor.FirstSeen, LastSeen: actor.LastSeen, RiskScore: actor.RiskScore,
		Classification: string(actor.Classification), Actor: string(actor.Actor),
		HTTPRequests: actor.HTTPRequests + actor.SelfOriginHTTPRequests, SelfOriginHTTPRequests: actor.SelfOriginHTTPRequests, SelfOriginOnly: actor.SelfOriginHTTPRequests > 0 && actor.HTTPRequests == 0 && actor.SSHConnections == 0, SSHConnections: actor.SSHConnections, SSHCommands: actor.SSHCommands,
		SSHAuthAccepted: actor.SSHAuthAccepted, SSHAuthRejected: actor.SSHAuthRejected,
		SSHUniqueUsers: actor.SSHUniqueUsers, SSHPeakConcurrent: actor.SSHPeakConcurrent,
		SSHPeakAttemptsPerMinute: actor.SSHPeakAttemptsPerMin, SSHMedianRevisitSeconds: actor.SSHMedianRevisitSeconds,
		SSHRevisitJitterSeconds: actor.SSHRevisitJitterSeconds, PayloadSignals: actor.PayloadAttempts,
		CanaryTouches: actor.CanaryTouches, EngagementSeconds: actor.EngagementSeconds, Depth: actor.Depth,
	}

	pathCounts := map[string]int64{}
	targetCounts := map[string]int64{}
	userCounts := map[string]int64{}
	clientCounts := map[string]int64{}
	commandCounts := map[string]int64{}
	familyCounts := map[string]int64{}
	targetUsers := map[string]struct{}{}
	targetClients := map[string]struct{}{}
	httpMinute := map[int64]int{}
	sshAuthMinute := map[int64]int{}
	for _, ss := range s.sessions {
		if ss.IP != ip {
			continue
		}
		cp := *cloneSession(ss)
		cp.RecentTimes = nil
		out.HTTPSessions = append(out.HTTPSessions, cp)
	}
	for _, e := range s.events {
		if e.IP != ip {
			continue
		}
		out.HTTPEvents = append(out.HTTPEvents, e)
		httpMinute[e.At.Truncate(time.Minute).Unix()]++
		if p := strings.TrimSpace(e.Path); p != "" {
			pathCounts[p]++
		}
		target := strings.TrimSpace(e.Target)
		if target == "" {
			target = strings.TrimSpace(e.RequestHost)
		}
		if target != "" {
			targetCounts[target]++
		}
	}

	points := make([]ipSweepPoint, 0, 2*len(s.sshSessions))
	for _, ss := range s.sshSessions {
		if ss.IP != ip {
			continue
		}
		out.SSHSessions = append(out.SSHSessions, cloneSSHSession(ss))
		if u := strings.TrimSpace(ss.Username); u != "" {
			targetUsers[u] = struct{}{}
		}
		if c := strings.TrimSpace(ss.ClientVersion); c != "" {
			targetClients[normalizeSSHClient(c)] = struct{}{}
		}
		points = append(points, ipSweepPoint{at: ss.FirstSeen, delta: 1})
		end := ss.DisconnectedAt
		if end.IsZero() {
			end = ss.LastSeen
		}
		if !end.IsZero() {
			points = append(points, ipSweepPoint{at: end, delta: -1})
		}
	}
	for _, e := range s.sshEvents {
		if e.IP != ip {
			continue
		}
		out.SSHEvents = append(out.SSHEvents, e)
		if e.Type == "auth" {
			sshAuthMinute[e.At.Truncate(time.Minute).Unix()]++
			if u := strings.TrimSpace(e.Username); u != "" {
				userCounts[u]++
				targetUsers[u] = struct{}{}
			}
		}
		if c := strings.TrimSpace(e.ClientVersion); c != "" {
			clientCounts[normalizeSSHClient(c)]++
			targetClients[normalizeSSHClient(c)] = struct{}{}
		}
		if e.Type == "exec" || e.Type == "command" {
			if n := strings.TrimSpace(e.CommandName); n != "" {
				commandCounts[n]++
			}
			if f := strings.TrimSpace(e.CommandFamily); f != "" {
				familyCounts[f]++
			}
		}
	}
	for _, e := range s.intelEvents {
		if e.IP == ip {
			out.Intelligence = append(out.Intelligence, e)
		}
	}

	out.Summary.HTTPUniquePaths = len(pathCounts)
	out.Summary.HTTPUniqueTargets = len(targetCounts)
	out.Summary.SSHUniqueUsers = len(targetUsers)
	out.Summary.SSHUniqueClients = len(targetClients)
	for _, n := range httpMinute {
		if n > out.Summary.HTTPPeakRequestsPerMinute {
			out.Summary.HTTPPeakRequestsPerMinute = n
		}
	}
	for _, n := range sshAuthMinute {
		if n > out.Summary.SSHPeakAttemptsPerMinute {
			out.Summary.SSHPeakAttemptsPerMinute = n
		}
	}
	sort.Slice(points, func(i, j int) bool {
		if points[i].at.Equal(points[j].at) {
			return points[i].delta < points[j].delta
		}
		return points[i].at.Before(points[j].at)
	})
	active, peak := 0, 0
	for _, p := range points {
		active += p.delta
		if active > peak {
			peak = active
		}
	}
	if peak > out.Summary.SSHPeakConcurrent {
		out.Summary.SSHPeakConcurrent = peak
	}

	out.TopUsernames = topIPValues(userCounts, 20)
	out.TopSSHClients = topIPValues(clientCounts, 12)
	out.TopCommands = topIPValues(commandCounts, 20)
	out.TopFamilies = topIPValues(familyCounts, 16)
	out.TopPaths = topIPValues(pathCounts, 20)
	out.TopTargets = topIPValues(targetCounts, 20)
	out.Timeline = s.ipDailyTimelineLocked(ip, time.Now())

	reasons := make([]string, 0, len(actor.Fingerprints)+5)
	if actor.SelfOriginHTTPRequests > 0 {
		reasons = append(reasons, "self-origin / hairpin Web traffic observed")
	}
	if actor.SSHPeakAttemptsPerMin >= 10 {
		reasons = append(reasons, "high SSH authentication rate")
	}
	if actor.SSHUniqueUsers >= 5 {
		reasons = append(reasons, "multiple SSH usernames observed")
	}
	if actor.SSHPeakConcurrent >= 3 {
		reasons = append(reasons, "parallel SSH sessions observed")
	}
	if actor.PayloadAttempts > 0 {
		reasons = append(reasons, "payload indicators observed")
	}
	for _, fp := range actor.Fingerprints {
		reasons = append(reasons, fp)
	}
	out.Summary.Reasons = reasons
	out.CampaignPeers = s.campaignPeersLocked(ip, actor, targetUsers, targetClients)
	out.AttackTrace = s.attackTracesLocked(ip)

	sort.Slice(out.HTTPSessions, func(i, j int) bool { return out.HTTPSessions[i].FirstSeen.Before(out.HTTPSessions[j].FirstSeen) })
	sort.Slice(out.SSHSessions, func(i, j int) bool { return out.SSHSessions[i].FirstSeen.Before(out.SSHSessions[j].FirstSeen) })
	sort.Slice(out.HTTPEvents, func(i, j int) bool { return out.HTTPEvents[i].At.Before(out.HTTPEvents[j].At) })
	sort.Slice(out.SSHEvents, func(i, j int) bool { return out.SSHEvents[i].At.Before(out.SSHEvents[j].At) })
	sort.Slice(out.Intelligence, func(i, j int) bool { return out.Intelligence[i].At.Before(out.Intelligence[j].At) })
	return out, true
}

// SSHTarpitDelay returns a small bounded banner delay only for clearly aggressive
// repeat sources. It never changes authentication policy or accepted credentials.
func (s *Store) SSHTarpitDelay(ip string, now time.Time) time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if ip == "" {
		return 0
	}
	window := now.Add(-time.Minute)
	connections := 0
	for _, ss := range s.sshSessions {
		if ss.IP == ip && !ss.FirstSeen.Before(window) && !ss.FirstSeen.After(now) {
			connections++
		}
	}
	var base time.Duration
	switch {
	case connections >= 30:
		base = 2500 * time.Millisecond
	case connections >= 16:
		base = 1200 * time.Millisecond
	case connections >= 8:
		base = 400 * time.Millisecond
	default:
		return 0
	}
	// Deterministic per-second jitter avoids an obvious fixed delay while keeping
	// tests and resource usage bounded. Range is 85-115 percent of base.
	var h uint32 = 2166136261
	for _, b := range []byte(ip + now.Format("150405")) {
		h ^= uint32(b)
		h *= 16777619
	}
	pct := 85 + int(h%31)
	delay := time.Duration(int64(base) * int64(pct) / 100)
	if delay > 3*time.Second {
		delay = 3 * time.Second
	}
	return delay
}
