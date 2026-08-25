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

func sshTranscriptComplete(ss model.SSHSession, events []model.SSHEvent) bool {
	if len(events) == 0 {
		return ss.AuthAttempts == 0 && ss.CommandCount == 0 && ss.ExecRequests == 0 && !ss.ShellOpened
	}
	auth, commands, execs, shells := 0, 0, 0, 0
	var first, last time.Time
	for _, e := range events {
		if first.IsZero() || e.At.Before(first) {
			first = e.At
		}
		if last.IsZero() || e.At.After(last) {
			last = e.At
		}
		switch e.Type {
		case "auth":
			auth++
		case "exec":
			execs++
			commands++
		case "command":
			commands++
		case "shell":
			shells++
		}
	}
	if auth < ss.AuthAttempts || commands < ss.CommandCount || execs < ss.ExecRequests || (ss.ShellOpened && shells == 0) {
		return false
	}
	// A completed session should retain evidence spanning its observed lifetime.
	if !ss.FirstSeen.IsZero() && first.After(ss.FirstSeen.Add(time.Millisecond)) {
		return false
	}
	if !ss.LastSeen.IsZero() && last.Before(ss.LastSeen.Add(-time.Millisecond)) {
		return false
	}
	return true
}

func limitSSHTail(events []model.SSHEvent, limit int) []model.SSHEvent {
	if limit > 0 && len(events) > limit {
		return append([]model.SSHEvent(nil), events[len(events)-limit:]...)
	}
	return append([]model.SSHEvent(nil), events...)
}

func (s *Store) scanRetainedSSHSession(id string) ([]model.SSHEvent, *model.SSHSession, error) {
	f, err := os.Open(filepath.Join(s.dataDir, "ssh-events.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	rows := make([]model.SSHEvent, 0, 64)
	tmp := newStoreState("", s.retentionDays)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for sc.Scan() {
		var e model.SSHEvent
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.SessionID != id {
			continue
		}
		rows = append(rows, e)
		tmp.applySSHEventLocked(e)
		tmp.updateSSHHighlightStateLocked(e)
	}
	if err := sc.Err(); err != nil {
		return nil, nil, err
	}
	if ss := tmp.sshSessions[id]; ss != nil {
		cp := cloneSSHSession(ss)
		return rows, &cp, nil
	}
	return rows, nil, nil
}

func (s *Store) scanRetainedIntel(ip string) ([]model.IntelSignal, error) {
	f, err := os.Open(filepath.Join(s.dataDir, "intel-events.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rows := make([]model.IntelSignal, 0, 32)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for sc.Scan() {
		var e model.IntelSignal
		if json.Unmarshal(sc.Bytes(), &e) == nil && e.IP == ip {
			rows = append(rows, e)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].At.Before(rows[j].At) })
	return rows, nil
}

func stagedPayloadTracesFromIntel(ip string, intel []model.IntelSignal) []model.AttackTrace {
	out := make([]model.AttackTrace, 0, 4)
	seen := map[string]bool{}
	for _, effect := range intel {
		if effect.Kind != "payload" || effect.Technique != "staged-payload-execution" {
			continue
		}
		filename := strings.TrimSpace(effect.Filename)
		if filename == "" {
			continue
		}
		var cause *model.IntelSignal
		for i := len(intel) - 1; i >= 0; i-- {
			sig := intel[i]
			if sig.At.After(effect.At) || sig.Kind != "payload" || strings.TrimSpace(sig.Filename) != filename {
				continue
			}
			if effect.At.Sub(sig.At) > 24*time.Hour {
				break
			}
			if sig.Technique != "scp-upload-staging" && sig.Technique != "exec-stdin-staging" {
				continue
			}
			if !strings.Contains(strings.ToLower(sig.Summary), "completed") {
				continue
			}
			cp := sig
			cause = &cp
			break
		}
		if cause == nil {
			continue
		}
		id := traceID(ip, cause.ID, effect.ID, "staged-payload-execution", filename)
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, model.AttackTrace{ID: id, IP: ip, Confidence: "confirmed", Relation: "staged-payload-execution", Evidence: "source-bound virtual file accepted over SSH was later executed at the exact same path", FirstSeen: cause.At, LastSeen: effect.At, Steps: []model.AttackTraceStep{{At: cause.At, Protocol: "ssh", SessionID: cause.SessionID, EventID: cause.ID, Kind: "cause", Summary: cause.Summary}, {At: effect.At, Protocol: "ssh", SessionID: effect.SessionID, EventID: effect.ID, Kind: "effect", Summary: effect.Summary}}})
	}
	return out
}

func filterSessionTraces(traces []model.AttackTrace, id string) []model.AttackTrace {
	out := make([]model.AttackTrace, 0, len(traces))
	seen := map[string]bool{}
	for _, tr := range traces {
		hit := false
		for _, st := range tr.Steps {
			if st.SessionID == id {
				hit = true
				break
			}
		}
		if hit && !seen[tr.ID] {
			seen[tr.ID] = true
			out = append(out, tr)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.Before(out[j].LastSeen) })
	return out
}

func (s *Store) sshSessionEvidence(id string, limit int) (model.SSHSessionDetail, *model.ActorProfile, bool) {
	s.mu.RLock()
	var ss *model.SSHSession
	if cur := s.sshSessions[id]; cur != nil {
		cp := cloneSSHSession(cur)
		ss = &cp
	}
	memEvents := make([]model.SSHEvent, 0, 64)
	for _, e := range s.sshEvents {
		if e.SessionID == id {
			memEvents = append(memEvents, e)
		}
	}
	var actor *model.ActorProfile
	if ss != nil {
		if a := s.actors[actorID(ss.IP)]; a != nil {
			cp := cloneActor(a)
			actor = &cp
		}
	}
	var highlight *model.SSHHighlight
	if ss != nil {
		if h, ok := scoreSSHHighlightState(*ss, s.sshHighlightStates[id]); ok {
			cp := h
			highlight = &cp
		}
	}
	if highlight == nil {
		if h, ok := s.sshHighlightHistory[id]; ok {
			cp := h
			highlight = &cp
		}
	}
	var currentTraces []model.AttackTrace
	if ss != nil {
		currentTraces = filterSessionTraces(s.attackTracesLocked(ss.IP), id)
	}
	s.mu.RUnlock()

	fullEvents := memEvents
	status := "memory"
	if ss == nil || !sshTranscriptComplete(*ss, memEvents) {
		diskEvents, diskSS, err := s.scanRetainedSSHSession(id)
		if err == nil && diskSS != nil {
			ss = diskSS
			fullEvents = diskEvents
			status = "retained"
		}
	}
	if ss == nil {
		return model.SSHSessionDetail{}, actor, false
	}
	if len(fullEvents) == 0 {
		status = "expired"
	} else if !sshTranscriptComplete(*ss, fullEvents) {
		status = "partial"
	}

	intelAll, _ := s.scanRetainedIntel(ss.IP)
	intel := make([]model.IntelSignal, 0, 8)
	for _, e := range intelAll {
		if e.SessionID == id {
			intel = append(intel, e)
		}
	}
	traces := append([]model.AttackTrace(nil), currentTraces...)
	traces = append(traces, stagedPayloadTracesFromIntel(ss.IP, intelAll)...)
	traces = filterSessionTraces(traces, id)

	if highlight == nil && len(fullEvents) > 0 {
		if h, ok := scoreSSHHighlight(*ss, fullEvents); ok {
			cp := h
			highlight = &cp
		}
	}
	if actor == nil {
		s.mu.RLock()
		if a := s.actors[actorID(ss.IP)]; a != nil {
			cp := cloneActor(a)
			actor = &cp
		}
		s.mu.RUnlock()
	}
	detail := model.SSHSessionDetail{Session: *ss, Events: limitSSHTail(fullEvents, limit), Intel: intel, AttackTrace: traces, Highlight: highlight, TranscriptStatus: status}
	return detail, actor, true
}

func (s *Store) sshSessionDetailRetained(id string, limit int) (model.SSHSessionDetail, bool) {
	d, _, ok := s.sshSessionEvidence(id, limit)
	return d, ok
}
