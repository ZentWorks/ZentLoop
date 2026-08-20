package store

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"zentloop/internal/model"
)

func traceID(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "trace-" + hex.EncodeToString(h[:6])
}

func referrerURL(raw string) (*url.URL, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil || u.EscapedPath() == "" {
		return nil, false
	}
	return u, true
}

func traceHost(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		return strings.Trim(strings.ToLower(host), "[]")
	}
	return strings.Trim(raw, "[]")
}

func sameReferrerTarget(u *url.URL, e model.Event) bool {
	if u == nil {
		return false
	}
	refHost := traceHost(u.Hostname())
	targetHost := traceHost(e.RequestHost)
	if targetHost == "" {
		targetHost = traceHost(e.Target)
	}
	// Browser Referer headers are normally absolute. When ZentLoop knows the
	// requested target, require the referrer to point at that exact host so an
	// unrelated site's same path cannot manufacture a deception trace.
	if targetHost != "" {
		return refHost != "" && refHost == targetHost
	}
	return refHost != ""
}

func traceableWebCause(e model.Event) bool {
	if e.Status < 200 || e.Status >= 400 {
		return false
	}
	msg := strings.TrimSpace(strings.ToLower(e.Message))
	if msg == "" || msg == "benign" || msg == "plausible-404" || strings.HasPrefix(msg, "transient-") {
		return false
	}
	// A visible attack trace should originate in an actual ZentLoop deception
	// surface, not ordinary browser navigation through a successful page.
	return e.Depth > 0 || strings.HasPrefix(msg, "fake-") || strings.Contains(msg, "bait")
}

func eventCanaryLabels(e model.Event) map[string]bool {
	if e.Status < 200 || e.Status >= 400 {
		return nil
	}
	labels := map[string]bool{}
	switch e.Message {
	case "fake-env", "fake-env-family", "fake-config-export", "fake-netrc", "fake-cloud-service-account", "fake-terraform-state":
		labels["backup"] = true
		labels["internal-api"] = true
	case "fake-internal-inventory", "fake-degraded", "fake-aws-credentials", "fake-s3-config", "fake-rclone-config", "fake-s3fs-credentials", "fake-ssh-private-key", "fake-terraform-vars":
		labels["backup"] = true
	case "fake-internal-api", "fake-azure-credentials", "fake-ai-tool-credentials", "fake-ssrf-internal-api", "fake-database-dump":
		labels["internal-api"] = true
	case "fake-container-registry", "fake-ssrf-internal-registry", "fake-npm-credentials", "fake-docker-credentials":
		labels["registry"] = true
	}
	if len(labels) == 0 {
		return nil
	}
	return labels
}

func hasCanary(values []string, label string) bool {
	for _, v := range values {
		if strings.EqualFold(strings.TrimSpace(v), label) {
			return true
		}
	}
	return false
}

func (s *Store) attackTracesLocked(ip string) []model.AttackTrace {
	if strings.TrimSpace(ip) == "" {
		return nil
	}
	httpEvents := make([]model.Event, 0, 64)
	sshEvents := make([]model.SSHEvent, 0, 64)
	intel := make([]model.IntelSignal, 0, 16)
	for _, e := range s.events {
		if e.IP == ip {
			httpEvents = append(httpEvents, e)
		}
	}
	for _, e := range s.sshEvents {
		if e.IP == ip {
			sshEvents = append(sshEvents, e)
		}
	}
	for _, e := range s.intelEvents {
		if e.IP == ip && strings.EqualFold(e.Protocol, "ssh") && e.Kind == "canary" && strings.TrimSpace(e.Canary) != "" {
			intel = append(intel, e)
		}
	}
	sort.Slice(httpEvents, func(i, j int) bool { return httpEvents[i].At.Before(httpEvents[j].At) })
	sort.Slice(sshEvents, func(i, j int) bool { return sshEvents[i].At.Before(sshEvents[j].At) })
	sort.Slice(intel, func(i, j int) bool { return intel[i].At.Before(intel[j].At) })

	traces := make([]model.AttackTrace, 0, 8)
	seen := map[string]bool{}

	// A browser-supplied referrer that exactly names a previously served path is
	// direct evidence that the client navigated from that ZentLoop response. This
	// is intentionally stricter than temporal/path similarity.
	for i := 1; i < len(httpEvents); i++ {
		effect := httpEvents[i]
		ru, ok := referrerURL(effect.Referrer)
		if !ok || !sameReferrerTarget(ru, effect) {
			continue
		}
		rp := ru.EscapedPath()
		for j := i - 1; j >= 0; j-- {
			cause := httpEvents[j]
			if effect.At.Sub(cause.At) > 10*time.Minute {
				break
			}
			if cause.SessionID != effect.SessionID || cause.Path != rp || !traceableWebCause(cause) {
				continue
			}
			id := traceID(ip, cause.ID, effect.ID, "referrer-follow")
			if seen[id] {
				break
			}
			seen[id] = true
			traces = append(traces, model.AttackTrace{
				ID: id, IP: ip, Confidence: "likely", Relation: "referrer-follow",
				Evidence:  "request referrer exactly matches a previously served ZentLoop path",
				FirstSeen: cause.At, LastSeen: effect.At,
				Steps: []model.AttackTraceStep{
					{At: cause.At, Protocol: "web", SessionID: cause.SessionID, EventID: cause.ID, Kind: "cause", Path: cause.Path, Summary: cause.Message},
					{At: effect.At, Protocol: "web", SessionID: effect.SessionID, EventID: effect.ID, Kind: "effect", Path: effect.Path, Summary: effect.Message},
				},
			})
			break
		}
	}

	// Canary tokens are deterministic per observed source and never represent real
	// credentials. Reuse of one over SSH after ZentLoop served that exact canary
	// label over Web is therefore strong cross-protocol evidence, not coincidence.
	for _, sig := range intel {
		label := strings.TrimSpace(sig.Canary)
		var cause *model.Event
		for i := len(httpEvents) - 1; i >= 0; i-- {
			e := httpEvents[i]
			if e.At.After(sig.At) {
				continue
			}
			if sig.At.Sub(e.At) > 24*time.Hour {
				break
			}
			if eventCanaryLabels(e)[label] {
				cp := e
				cause = &cp
				break
			}
		}
		if cause == nil {
			continue
		}
		var effect *model.SSHEvent
		for i := len(sshEvents) - 1; i >= 0; i-- {
			e := sshEvents[i]
			if e.SessionID != sig.SessionID || e.At.After(sig.At.Add(2*time.Second)) {
				continue
			}
			if sig.At.Sub(e.At) > 5*time.Second {
				break
			}
			if hasCanary(e.CanaryTouches, label) {
				cp := e
				effect = &cp
				break
			}
		}
		id := traceID(ip, cause.ID, sig.ID, "canary-reuse", label)
		if seen[id] {
			continue
		}
		seen[id] = true
		effectStep := model.AttackTraceStep{At: sig.At, Protocol: "ssh", SessionID: sig.SessionID, EventID: sig.ID, Kind: "effect", Summary: sig.Summary}
		if effect != nil {
			effectStep.At = effect.At
			effectStep.EventID = effect.ID
			effectStep.Command = effect.Command
			effectStep.Username = effect.Username
			effectStep.Summary = effect.Message
		}
		traces = append(traces, model.AttackTrace{
			ID: id, IP: ip, Confidence: "confirmed", Relation: "canary-reuse", CrossProtocol: true,
			Evidence:  "synthetic ZentLoop canary exposed over Web was reused verbatim over SSH (" + label + ")",
			FirstSeen: cause.At, LastSeen: effectStep.At,
			Steps: []model.AttackTraceStep{
				{At: cause.At, Protocol: "web", SessionID: cause.SessionID, EventID: cause.ID, Kind: "cause", Path: cause.Path, Summary: cause.Message + " exposed canary " + label},
				effectStep,
			},
		})
	}

	sort.Slice(traces, func(i, j int) bool { return traces[i].LastSeen.Before(traces[j].LastSeen) })
	return traces
}

func (s *Store) AttackTraces(ip string) []model.AttackTrace {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]model.AttackTrace(nil), s.attackTracesLocked(ip)...)
}

func (s *Store) CrossProtocolObservations(limit int) []model.CrossProtocolObservation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows := make([]model.CrossProtocolObservation, 0, 32)
	for _, a := range s.actors {
		if a == nil || len(a.Protocols) < 2 {
			continue
		}
		rows = append(rows, model.CrossProtocolObservation{IP: a.IP, Country: a.Country, RiskScore: a.RiskScore, LastSeen: a.LastSeen, HTTP: a.HTTPRequests, SSH: a.SSHConnections})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].LastSeen.After(rows[j].LastSeen) })
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	// Trace derivation scans retained Web/SSH evidence. Do that only for the
	// bounded rows the Admin UI will actually render instead of once per actor.
	for i := range rows {
		traces := s.attackTracesLocked(rows[i].IP)
		for j := range traces {
			if traces[j].CrossProtocol {
				rows[i].TraceCount++
				cp := traces[j]
				rows[i].Trace = &cp
			}
		}
	}
	return rows
}
