package store

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"zentloop/internal/model"
)

type ipSweepPoint struct {
	at    time.Time
	delta int
}

func positiveDurationUnits(ns int64, unit time.Duration) int64 {
	if ns <= 0 || unit <= 0 {
		return 0
	}
	u := int64(unit)
	return (ns + u - 1) / u
}

func ipFirstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
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

func sharedFingerprintPrefix(a, b map[string]struct{}, prefix string) int {
	n := 0
	for value := range a {
		if !strings.HasPrefix(value, prefix) {
			continue
		}
		if _, ok := b[value]; ok {
			n++
		}
	}
	return n
}

func canonicalCampaignFingerprint(fp string) string {
	fp = strings.TrimSpace(fp)
	if fp == "http:interactive-browser" {
		return "http:browser-like-client"
	}
	return fp
}

func campaignFingerprintWeight(fp string) int {
	fp = canonicalCampaignFingerprint(fp)
	switch {
	case strings.HasPrefix(fp, "ssh:persistence-kit:"), strings.HasPrefix(fp, "ssh:authorized-key-sha256:"), strings.HasPrefix(fp, "ssh:payload-sha256:"):
		return 18
	case strings.HasPrefix(fp, "ssh:recon-playbook:"):
		return 14
	case fp == "http:phpunit-docker-exec-chain":
		return 16
	case fp == "http:periodic-auth-validator", fp == "http:graphql-introspection", fp == "http:wordpress-webshell-scanner":
		return 8
	case fp == "http:bot-identity-rotation", fp == "http:spoofed-crawler-rotation", fp == "http:ssrf-prober", fp == "http:dev-file-reader":
		return 6
	case fp == "http:cloud-credential-hunter", fp == "http:php-backdoor-hunter", fp == "http:user-agent-rotation", fp == "http:parallel-target-worker-pool":
		return 5
	case fp == "http:config-hunter", fp == "http:parallel-prober", fp == "http:low-and-slow-prober":
		return 3
	case fp == "http:burst-automation", fp == "http:high-rate-automation", fp == "http:browser-like-client":
		return 1
	case strings.HasPrefix(fp, "http:sequence:"):
		return 0
	default:
		return 2
	}
}

func canonicalFingerprintSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = canonicalCampaignFingerprint(value)
		if value != "" {
			out[value] = struct{}{}
		}
	}
	return out
}

func sharedCanonicalBehavior(a, b map[string]struct{}) (count, weight int) {
	if len(a) > len(b) {
		a, b = b, a
	}
	for fp := range a {
		if _, ok := b[fp]; !ok || strings.HasPrefix(fp, "http:sequence:") {
			continue
		}
		w := campaignFingerprintWeight(fp)
		if w <= 0 {
			continue
		}
		count++
		weight += w
	}
	return count, weight
}

func behaviorSummarySet(rows []model.ActorBehaviorStat) map[string]struct{} {
	out := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		if row.Count <= 0 {
			continue
		}
		name := strings.TrimSpace(strings.ToLower(row.Name))
		// Fingerprint rows are already scored independently; keeping them out of
		// the summary-overlap signal prevents the same evidence being counted twice.
		if name != "" && !strings.HasPrefix(name, "fingerprint:") {
			out[name] = struct{}{}
		}
	}
	return out
}

func (s *Store) campaignPeersLocked(ip string, target *model.ActorProfile, targetUsers, targetClients map[string]struct{}) []model.IPCampaignPeer {
	if target == nil {
		return nil
	}
	targetFP := canonicalFingerprintSet(target.Fingerprints)
	targetBehavior := behaviorSummarySet(target.BehaviorSummary)
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
		peerFP := canonicalFingerprintSet(peer.Fingerprints)
		sharedFP := setIntersectionSize(targetFP, peerFP)
		if sharedFP >= 2 {
			bonus := sharedFP * 6
			if bonus > 24 {
				bonus = 24
			}
			score += bonus
			strongSignals++
			strongReasons = append(strongReasons, "multiple shared behavior fingerprints")
		}
		canonicalCount, canonicalWeight := sharedCanonicalBehavior(targetFP, peerFP)
		if canonicalCount >= 5 && canonicalWeight >= 24 {
			bonus := 18 + canonicalWeight/2
			if bonus > 50 {
				bonus = 50
			}
			score += bonus
			strongSignals += 2
			strongReasons = append(strongReasons, fmt.Sprintf("shared canonical behavior profile (%d signals)", canonicalCount))
		}
		peerBehavior := behaviorSummarySet(peer.BehaviorSummary)
		if shared := setIntersectionSize(targetBehavior, peerBehavior); shared >= 6 {
			denom := len(targetBehavior) + len(peerBehavior) - shared
			if denom > 0 && shared*100/denom >= 60 {
				score += 24
				strongSignals++
				strongReasons = append(strongReasons, "similar bounded behavior summary")
			}
		}
		if sharedFingerprintPrefix(targetFP, peerFP, "http:sequence:") > 0 {
			score += 45
			// A 12-request normalized sequence is substantially stronger than a
			// generic UA/country match, so treat it as two behavioral signals.
			strongSignals += 2
			strongReasons = append(strongReasons, "identical normalized HTTP request sequence")
		}
		if sharedFingerprintPrefix(targetFP, peerFP, "ssh:payload-sha256:") > 0 {
			score += 30
			strongSignals++
			strongReasons = append(strongReasons, "identical staged payload hash")
		}
		if sharedFingerprintPrefix(targetFP, peerFP, "ssh:service-unit-sha256:") > 0 {
			score += 18
			strongSignals++
			strongReasons = append(strongReasons, "identical persistence service payload")
		}
		if sharedFingerprintPrefix(targetFP, peerFP, "ssh:persistence-kit:") > 0 {
			score += 45
			strongSignals += 2
			strongReasons = append(strongReasons, "identical SSH persistence kit")
		}
		if sharedFingerprintPrefix(targetFP, peerFP, "ssh:recon-playbook:") > 0 {
			score += 38
			strongSignals += 2
			strongReasons = append(strongReasons, "matching SSH reconnaissance playbook")
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
	retainedTargetCounts := map[string]int64{}
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
		targetName := strings.TrimSpace(ss.Target)
		if targetName == "" {
			targetName = strings.TrimSpace(ss.RequestHost)
		}
		if targetName != "" {
			targetCounts[targetName] += int64(ss.RequestCount)
		}
		last := strings.TrimSpace(ss.CurrentPath)
		if last == "" {
			last = strings.TrimSpace(ss.FirstPath)
		}
		if last == "" {
			last = "/"
		}
		method := strings.TrimSpace(ss.LastMethod)
		if method == "" {
			method = "HTTP"
		}
		summary := fmt.Sprintf("%d requests · %d visits · last %s %s", ss.RequestCount, ss.VisitCount, method, last)
		out.Observations = append(out.Observations, model.IPObservation{At: ss.LastSeen, Protocol: "WEB", Kind: "SESSION", Summary: summary, RiskScore: ss.RiskScore, Source: "history", SessionID: ss.ID})
	}
	for _, e := range s.events {
		if e.IP != ip {
			continue
		}
		out.HTTPEvents = append(out.HTTPEvents, e)
		summary := strings.TrimSpace(strings.TrimSpace(e.Method) + " " + strings.TrimSpace(e.Path))
		if summary == "" {
			summary = strings.TrimSpace(e.Message)
		}
		out.Observations = append(out.Observations, model.IPObservation{At: e.At, Protocol: "WEB", Kind: ipFirstNonEmpty(strings.TrimSpace(e.Method), strings.TrimSpace(e.Category), "HTTP"), Summary: summary, RiskScore: e.RiskScore, Source: "retained", SessionID: e.SessionID})
		httpMinute[e.At.Truncate(time.Minute).Unix()]++
		if p := strings.TrimSpace(e.Path); p != "" {
			pathCounts[p]++
		}
		target := strings.TrimSpace(e.Target)
		if target == "" {
			target = strings.TrimSpace(e.RequestHost)
		}
		if target != "" {
			retainedTargetCounts[target]++
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
			userCounts[u]++
		}
		if c := strings.TrimSpace(ss.ClientVersion); c != "" {
			normalized := normalizeSSHClient(c)
			targetClients[normalized] = struct{}{}
			clientCounts[normalized]++
		}
		auth := "auth not accepted"
		if ss.AuthAccepted {
			auth = "authenticated"
		}
		user := strings.TrimSpace(ss.Username)
		if user == "" {
			user = "unknown user"
		}
		summary := fmt.Sprintf("%s · %s · %d auth · %d commands", user, auth, ss.AuthAttempts, ss.CommandCount)
		out.Observations = append(out.Observations, model.IPObservation{At: ss.LastSeen, Protocol: "SSH", Kind: "SESSION", Summary: summary, RiskScore: ss.RiskScore, Source: "history", SessionID: ss.ID})
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
		sshSummary := strings.TrimSpace(e.Command)
		if sshSummary == "" {
			sshSummary = strings.TrimSpace(e.Message)
		}
		if sshSummary == "" {
			sshSummary = strings.TrimSpace(e.Type)
		}
		out.Observations = append(out.Observations, model.IPObservation{At: e.At, Protocol: "SSH", Kind: strings.ToUpper(ipFirstNonEmpty(strings.TrimSpace(e.Type), "SSH")), Summary: sshSummary, RiskScore: e.RiskScore, Source: "retained", SessionID: e.SessionID})
		if e.Type == "auth" {
			sshAuthMinute[e.At.Truncate(time.Minute).Unix()]++
			if u := strings.TrimSpace(e.Username); u != "" {
				targetUsers[u] = struct{}{}
			}
		}
		if c := strings.TrimSpace(e.ClientVersion); c != "" {
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
			summary := ipFirstNonEmpty(strings.TrimSpace(e.Summary), strings.TrimSpace(e.URL), strings.TrimSpace(e.Host), "intelligence")
			out.Observations = append(out.Observations, model.IPObservation{At: e.At, Protocol: strings.ToUpper(ipFirstNonEmpty(strings.TrimSpace(e.Protocol), "INTEL")), Kind: strings.ToUpper(ipFirstNonEmpty(strings.TrimSpace(e.Kind), "INTEL")), Summary: summary, Source: "retained"})
		}
	}

	out.Summary.HTTPUniquePaths = len(pathCounts)
	out.Summary.HTTPUniqueTargets = len(targetCounts)

	observationNS := actor.LastSeen.Sub(actor.FirstSeen).Nanoseconds()
	if actor.FirstSeen.IsZero() || actor.LastSeen.IsZero() || observationNS < 0 {
		observationNS = 0
	}
	httpTotalNS := maxInt64(0, actor.HTTPActivityTotalNS)
	httpWallNS := maxInt64(0, actor.HTTPActiveWallNS)
	sshTotalNS := maxInt64(0, actor.SSHActivityTotalNS)
	sshWallNS := maxInt64(0, actor.SSHActiveWallNS)
	// Mathematical invariants are enforced before presentation rounding. This
	// also protects old/replayed state from ever exporting impossible metrics.
	if httpWallNS > httpTotalNS {
		httpWallNS = httpTotalNS
	}
	if sshWallNS > sshTotalNS {
		sshWallNS = sshTotalNS
	}
	if observationNS > 0 {
		if httpWallNS > observationNS {
			httpWallNS = observationNS
		}
		if sshWallNS > observationNS {
			sshWallNS = observationNS
		}
	}
	out.Summary.ObservationSpanMilliseconds = positiveDurationUnits(observationNS, time.Millisecond)
	out.Summary.ObservationSpanSeconds = positiveDurationUnits(observationNS, time.Second)
	out.Summary.HTTPRequestMillisecondsTotal = positiveDurationUnits(httpTotalNS, time.Millisecond)
	out.Summary.HTTPRequestSecondsTotal = positiveDurationUnits(httpTotalNS, time.Second)
	out.Summary.HTTPActiveWallMilliseconds = positiveDurationUnits(httpWallNS, time.Millisecond)
	out.Summary.HTTPActiveWallSeconds = positiveDurationUnits(httpWallNS, time.Second)
	out.Summary.SSHSessionMillisecondsTotal = positiveDurationUnits(sshTotalNS, time.Millisecond)
	out.Summary.SSHSessionSecondsTotal = positiveDurationUnits(sshTotalNS, time.Second)
	out.Summary.SSHActiveWallMilliseconds = positiveDurationUnits(sshWallNS, time.Millisecond)
	out.Summary.SSHActiveWallSeconds = positiveDurationUnits(sshWallNS, time.Second)
	// Legacy field retained for API compatibility, but it now means HTTP wall-clock
	// activity only. Pure SSH actors therefore correctly report zero here.
	out.Summary.ActiveRequestSeconds = out.Summary.HTTPActiveWallSeconds
	out.Summary.HTTPRetainedRequests = int64(len(out.HTTPEvents))
	out.Summary.SSHRetainedConnections = int64(len(out.SSHSessions))
	out.Summary.HTTPDetailRetentionComplete = actor.HTTPRequests <= out.Summary.HTTPRetainedRequests
	out.Summary.SSHDetailRetentionComplete = actor.SSHConnections <= out.Summary.SSHRetainedConnections
	out.Summary.HTTPRetainedUniqueTargets = len(retainedTargetCounts)
	// Actor counters are durable/all-observed. The retained detail window can be
	// smaller after pruning, so do not overwrite the durable semantic with a
	// window-local count under the same field name.
	out.Summary.SSHUniqueUsers = actor.SSHUniqueUsers
	out.Summary.SSHRetainedUniqueUsers = len(targetUsers)
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
	sort.Slice(out.Observations, func(i, j int) bool {
		if out.Observations[i].At.Equal(out.Observations[j].At) {
			return out.Observations[i].Source < out.Observations[j].Source
		}
		return out.Observations[i].At.Before(out.Observations[j].At)
	})
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

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
