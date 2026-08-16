package store

import (
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
	integrationStaleAfter   = 45 * time.Second
	integrationOfflineAfter = 90 * time.Second
)

func (s *Store) loadIntegrationPeers() error {
	path := filepath.Join(s.dataDir, "integration-peers.json")
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var rows []model.IntegrationPeer
	if err := json.Unmarshal(b, &rows); err != nil {
		return err
	}
	for i := range rows {
		row := rows[i]
		row.Name = strings.TrimSpace(strings.ToLower(row.Name))
		if row.Name == "" {
			continue
		}
		row.Status = ""
		cp := row
		s.integrationPeers[row.Name] = &cp
	}
	return nil
}

func (s *Store) persistIntegrationPeersLocked() error {
	rows := make([]model.IntegrationPeer, 0, len(s.integrationPeers))
	for _, p := range s.integrationPeers {
		cp := *p
		cp.Status = ""
		rows = append(rows, cp)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	b, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	path := filepath.Join(s.dataDir, "integration-peers.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Store) RecordIntegrationVerified(name, sourceIP, trust string, now time.Time) {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.integrationPeers[name]
	changed := false
	if p == nil {
		p = &model.IntegrationPeer{Name: name, FirstSeen: now}
		s.integrationPeers[name] = p
		changed = true
	}
	if p.SourceIP != sourceIP || p.Trust != trust {
		changed = true
	}
	p.SourceIP = sourceIP
	p.Trust = trust
	p.LastVerified = now
	p.Checks++
	p.LastError = ""
	last := s.integrationPersist[name]
	if changed || last.IsZero() || now.Sub(last) >= 5*time.Minute {
		if s.persistIntegrationPeersLocked() == nil {
			s.integrationPersist[name] = now
		}
	}
}

func (s *Store) RecordIntegrationFailure(name, sourceIP, message string, now time.Time, allowCreate bool) {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.integrationPeers[name]
	if p == nil {
		p = &model.IntegrationPeer{Name: name, FirstSeen: now}
		s.integrationPeers[name] = p
	}
	p.SourceIP = sourceIP
	p.LastFailure = now
	p.Failures++
	p.LastError = strings.TrimSpace(message)
	_ = s.persistIntegrationPeersLocked()
	s.integrationPersist[name] = now
}

func (s *Store) IntegrationPeers(now time.Time) []model.IntegrationPeer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows := make([]model.IntegrationPeer, 0, len(s.integrationPeers))
	for _, p := range s.integrationPeers {
		cp := *p
		age := now.Sub(cp.LastVerified)
		switch {
		case cp.LastVerified.IsZero() || age > integrationOfflineAfter:
			cp.Status = "offline"
		case age > integrationStaleAfter:
			cp.Status = "stale"
		default:
			cp.Status = "verified"
		}
		rows = append(rows, cp)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].LastVerified.After(rows[j].LastVerified) })
	return rows
}
