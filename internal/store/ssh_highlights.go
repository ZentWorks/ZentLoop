package store

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"zentloop/internal/model"
)

const sshHighlightMinScore = 50

type sshHighlightState struct {
	acceptedAt    time.Time
	commandEvents int
	families      map[string]bool
	signals       map[string]bool
}

func newSSHHighlightState() *sshHighlightState {
	return &sshHighlightState{families: make(map[string]bool), signals: make(map[string]bool)}
}

func (s *Store) updateSSHHighlightStateLocked(e model.SSHEvent) {
	if s.sshHighlightStates == nil {
		s.sshHighlightStates = make(map[string]*sshHighlightState)
	}
	state := s.sshHighlightStates[e.SessionID]
	if state == nil {
		state = newSSHHighlightState()
		s.sshHighlightStates[e.SessionID] = state
	}
	state.apply(e)
}

func (state *sshHighlightState) apply(e model.SSHEvent) {
	if e.Type == "auth" && e.AuthAccepted && state.acceptedAt.IsZero() {
		state.acceptedAt = e.At
	}
	if state.acceptedAt.IsZero() || e.At.Before(state.acceptedAt) {
		return
	}
	if e.Type == "command" || e.Type == "exec" {
		state.commandEvents++
		if e.CommandFamily != "" {
			state.families[e.CommandFamily] = true
		}
	}
	fp := strings.ToLower(e.Fingerprint)
	cmd := strings.ToLower(e.Command)
	fam := strings.ToLower(e.CommandFamily)
	if strings.Contains(fp, "privilege") || fam == "privilege" || strings.Contains(cmd, "sudo -l") {
		state.signals["privilege"] = true
	}
	if strings.Contains(fp, "resource-hijack") {
		state.signals["resource-hijack"] = true
	}
	if strings.Contains(fp, "persistence") || fam == "persistence" || (strings.Contains(cmd, "crontab") && !strings.Contains(cmd, "crontab -r")) {
		state.signals["persistence"] = true
	}
	if e.StdinBytes > 0 || strings.Contains(fp, "staged-payload") || strings.Contains(cmd, "cat >") || strings.Contains(cmd, "cat  >") {
		state.signals["payload-staging"] = true
	}
	if strings.Contains(fp, "process-killer") || strings.HasPrefix(strings.TrimSpace(cmd), "kill ") || strings.Contains(cmd, "pkill ") || strings.Contains(cmd, "killall ") {
		state.signals["process-control"] = true
	}
	if strings.Contains(fp, "shell-control-flow") || strings.Contains(cmd, "if ") || strings.Contains(cmd, "for ") {
		state.signals["control-flow"] = true
	}
	if fam == "credentials" || strings.Contains(e.Persona, "credential") || len(e.CanaryTouches) > 0 {
		state.signals["credentials"] = true
	}
	if len(e.CanaryTouches) > 0 {
		state.signals["canary"] = true
	}
	if strings.Contains(fp, "cryptominer") || strings.Contains(cmd, "xmrig") || strings.Contains(cmd, "cnrig") {
		state.signals["miner"] = true
	}
}

func (s *Store) SSHHighlights(limit int, before time.Time, beforeID, rating string) model.SSHHighlightPage {
	return s.SSHHighlightsRange(limit, before, beforeID, rating, time.Time{}, time.Time{})
}

func (s *Store) SSHHighlightsRange(limit int, before time.Time, beforeID, rating string, from, to time.Time) model.SSHHighlightPage {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	rating = strings.ToLower(strings.TrimSpace(rating))

	rows := make([]model.SSHHighlight, 0, 64)
	for id, ss := range s.sshSessions {
		if !ss.AuthAccepted {
			continue
		}
		state := s.sshHighlightStates[id]
		if state == nil {
			state = newSSHHighlightState()
			for _, e := range s.sshEvents {
				if e.SessionID == id {
					state.apply(e)
				}
			}
		}
		h, ok := scoreSSHHighlightState(cloneSSHSession(ss), state)
		if !ok {
			continue
		}
		if !before.IsZero() {
			if h.At.After(before) || (h.At.Equal(before) && (beforeID == "" || h.SessionID >= beforeID)) {
				continue
			}
		}
		if !from.IsZero() && h.At.Before(from) {
			continue
		}
		if !to.IsZero() && !h.At.Before(to) {
			continue
		}
		if rating != "" && rating != "all" && h.Rating != rating {
			continue
		}
		rows = append(rows, h)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].At.Equal(rows[j].At) {
			return rows[i].SessionID > rows[j].SessionID
		}
		return rows[i].At.After(rows[j].At)
	})
	page := model.SSHHighlightPage{}
	if len(rows) > limit {
		rows = rows[:limit]
	}
	page.Items = rows
	if len(rows) == limit {
		last := rows[len(rows)-1]
		page.NextBefore = last.At.Format(time.RFC3339Nano) + "|" + last.SessionID
	}
	return page
}

func scoreSSHHighlight(ss model.SSHSession, events []model.SSHEvent) (model.SSHHighlight, bool) {
	state := newSSHHighlightState()
	for _, e := range events {
		state.apply(e)
	}
	return scoreSSHHighlightState(ss, state)
}

func scoreSSHHighlightState(ss model.SSHSession, state *sshHighlightState) (model.SSHHighlight, bool) {
	if !ss.AuthAccepted || state == nil || state.acceptedAt.IsZero() {
		return model.SSHHighlight{}, false
	}
	families := state.families
	signals := state.signals
	commandEvents := state.commandEvents
	if commandEvents < 2 {
		return model.SSHHighlight{}, false
	}
	highSignal := signals["privilege"] || signals["persistence"] || signals["payload-staging"] || signals["canary"] || signals["miner"] || signals["resource-hijack"]
	if !highSignal && !(commandEvents >= 4 && len(families) >= 2) {
		return model.SSHHighlight{}, false
	}

	score := 20
	if commandEvents > 10 {
		score += 18
	} else {
		score += commandEvents * 2
	}
	if ss.Depth > 5 {
		score += 15
	} else {
		score += ss.Depth * 2
	}
	if signals["privilege"] {
		score += 14
	}
	if signals["persistence"] {
		score += 18
	}
	if signals["payload-staging"] {
		score += 20
	}
	if signals["process-control"] {
		score += 10
	}
	if signals["control-flow"] {
		score += 7
	}
	if signals["credentials"] {
		score += 10
	}
	if signals["canary"] {
		score += 20
	}
	if signals["miner"] {
		score += 18
	}
	if signals["resource-hijack"] {
		score += 20
	}
	if len(families) >= 3 {
		score += 7
	}
	if score > 100 {
		score = 100
	}
	if score < sshHighlightMinScore {
		return model.SSHHighlight{}, false
	}

	order := []string{"canary", "payload-staging", "resource-hijack", "persistence", "privilege", "miner", "process-control", "credentials", "control-flow"}
	labels := map[string]string{"canary": "Canary touch", "payload-staging": "Payload staging", "resource-hijack": "Resource hijack prep", "persistence": "Persistence", "privilege": "Privilege discovery", "miner": "Miner behavior", "process-control": "Process control", "credentials": "Credential hunting", "control-flow": "Shell control flow"}
	outSignals := make([]string, 0, len(signals))
	for _, k := range order {
		if signals[k] {
			outSignals = append(outSignals, labels[k])
		}
	}
	if len(outSignals) == 0 {
		outSignals = append(outSignals, "Multi-stage command activity")
	}
	title := outSignals[0]
	if len(outSignals) > 1 {
		title += " + " + outSignals[1]
	}
	tagLabels := map[string]string{
		"Canary touch": "CANARY", "Payload staging": "PAYLOAD", "Persistence": "PERSISTENCE",
		"Privilege discovery": "PRIVILEGE", "Miner behavior": "MINER", "Resource hijack prep": "RESOURCE", "Process control": "PROCESS",
		"Credential hunting": "CREDENTIALS", "Shell control flow": "CONTROL-FLOW", "Multi-stage command activity": "MULTI-STAGE",
	}
	tags := make([]string, 0, len(outSignals))
	for _, label := range outSignals {
		if tag := tagLabels[label]; tag != "" {
			tags = append(tags, tag)
		}
	}
	reasonParts := []string{fmt.Sprintf("authenticated session executed %d commands and reached depth %d", ss.CommandCount, ss.Depth)}
	if len(outSignals) > 0 {
		reasonParts = append(reasonParts, "signals: "+strings.Join(outSignals, ", "))
	}
	reason := strings.Join(reasonParts, "; ")
	rating := "notable"
	if score >= 90 {
		rating = "critical"
	} else if score >= 70 {
		rating = "high"
	}
	at := ss.LastSeen
	if !ss.DisconnectedAt.IsZero() {
		at = ss.DisconnectedAt
	}
	return model.SSHHighlight{SessionID: ss.ID, At: at, LastSeen: ss.LastSeen, IP: ss.IP, Country: ss.Country, Username: ss.Username, Score: score, Rating: rating, Title: title, Reason: reason, Tags: tags, Commands: ss.CommandCount, DurationSeconds: ss.DurationSeconds, Depth: ss.Depth, Signals: outSignals}, true
}
