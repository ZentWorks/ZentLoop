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

func integrationPeerKey(name, sourceIP, keyID string) string {
	return strings.Join([]string{
		strings.TrimSpace(strings.ToLower(name)),
		strings.TrimSpace(sourceIP),
		strings.TrimSpace(strings.ToLower(keyID)),
	}, "\x00")
}

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
		row.SourceIP = strings.TrimSpace(row.SourceIP)
		row.KeyID = strings.TrimSpace(strings.ToLower(row.KeyID))
		if row.Name == "" {
			continue
		}
		row.Status = ""
		cp := row
		s.integrationPeers[integrationPeerKey(row.Name, row.SourceIP, row.KeyID)] = &cp
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
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Name != rows[j].Name {
			return rows[i].Name < rows[j].Name
		}
		if rows[i].SourceIP != rows[j].SourceIP {
			return rows[i].SourceIP < rows[j].SourceIP
		}
		return rows[i].KeyID < rows[j].KeyID
	})
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

func (s *Store) RecordIntegrationVerified(name, sourceIP, trust, keyID string, now time.Time) {
	name = strings.TrimSpace(strings.ToLower(name))
	sourceIP = strings.TrimSpace(sourceIP)
	keyID = strings.TrimSpace(strings.ToLower(keyID))
	if name == "" {
		return
	}
	key := integrationPeerKey(name, sourceIP, keyID)
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.integrationPeers[key]
	changed := false
	if p == nil && keyID != "" {
		// Older persisted peers did not carry a key id. Promote a matching
		// name/source peer on its next successful signed verification instead
		// of leaving a duplicate offline legacy row behind.
		legacyKey := integrationPeerKey(name, sourceIP, "")
		if legacy := s.integrationPeers[legacyKey]; legacy != nil && legacy.Trust == "signed" {
			delete(s.integrationPeers, legacyKey)
			delete(s.integrationPersist, legacyKey)
			p = legacy
			p.KeyID = keyID
			s.integrationPeers[key] = p
			changed = true
		}
	}
	if p == nil {
		p = &model.IntegrationPeer{Name: name, SourceIP: sourceIP, KeyID: keyID, FirstSeen: now}
		s.integrationPeers[key] = p
		changed = true
	}
	if p.SourceIP != sourceIP || p.Trust != trust || p.KeyID != keyID {
		changed = true
	}
	p.SourceIP = sourceIP
	p.Trust = trust
	p.KeyID = keyID
	p.LastVerified = now
	p.Checks++
	p.LastError = ""
	last := s.integrationPersist[key]
	if changed || last.IsZero() || now.Sub(last) >= 5*time.Minute {
		if s.persistIntegrationPeersLocked() == nil {
			s.integrationPersist[key] = now
		}
	}
}

func (s *Store) RecordIntegrationFailure(name, sourceIP, message string, now time.Time, allowCreate bool) {
	name = strings.TrimSpace(strings.ToLower(name))
	sourceIP = strings.TrimSpace(sourceIP)
	if name == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// A failed request cannot prove which configured signing key was intended.
	// Prefer an already-known peer with the same integration name/source so a
	// transient bad signature increments that peer instead of creating noise.
	var key string
	var p *model.IntegrationPeer
	for candidateKey, candidate := range s.integrationPeers {
		if candidate.Name == name && candidate.SourceIP == sourceIP {
			key, p = candidateKey, candidate
			break
		}
	}
	if p == nil {
		if !allowCreate {
			return
		}
		key = integrationPeerKey(name, sourceIP, "")
		p = &model.IntegrationPeer{Name: name, SourceIP: sourceIP, FirstSeen: now}
		s.integrationPeers[key] = p
	}
	p.SourceIP = sourceIP
	p.LastFailure = now
	p.Failures++
	p.LastError = strings.TrimSpace(message)
	_ = s.persistIntegrationPeersLocked()
	s.integrationPersist[key] = now
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
