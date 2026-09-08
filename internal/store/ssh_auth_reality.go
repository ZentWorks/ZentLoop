package store

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	sshCredentialKeyFile     = ".ssh-auth-reality-key"
	sshCredentialStateFile   = "ssh-auth-reality.json"
	sshCredentialPoolSize    = 8
	sshCredentialRotateAfter = 45 * time.Minute
)

type sshCredentialSlot struct {
	Fingerprint string    `json:"fingerprint"`
	FirstSeen   time.Time `json:"first_seen,omitempty"`
	LastSeen    time.Time `json:"last_seen,omitempty"`
}

type sshCredentialRealityDisk struct {
	// Fingerprints is the 0.3.17 single-slot format. It remains read-only here so
	// existing installations migrate without losing their established decoy.
	Fingerprints map[string]string              `json:"fingerprints,omitempty"`
	Pools        map[string][]sshCredentialSlot `json:"pools,omitempty"`
}

func (s *Store) initSSHCredentialReality(create bool) error {
	keyPath := filepath.Join(s.dataDir, sshCredentialKeyFile)
	key, err := os.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) && create {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return err
		}
		if err := os.WriteFile(keyPath, key, 0o600); err != nil {
			return err
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(key) > 0 {
		s.sshCredentialKey = append([]byte(nil), key...)
	}

	statePath := filepath.Join(s.dataDir, sshCredentialStateFile)
	b, err := os.ReadFile(statePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var disk sshCredentialRealityDisk
	if err := json.Unmarshal(b, &disk); err != nil {
		return err
	}
	for user, slots := range disk.Pools {
		user = strings.ToLower(strings.TrimSpace(user))
		if user == "" {
			continue
		}
		for _, slot := range slots {
			fp := strings.ToLower(strings.TrimSpace(slot.Fingerprint))
			if len(fp) != 64 {
				continue
			}
			s.sshCredentialPools[user] = append(s.sshCredentialPools[user], sshCredentialSlot{Fingerprint: fp, FirstSeen: slot.FirstSeen, LastSeen: slot.LastSeen})
			if len(s.sshCredentialPools[user]) >= sshCredentialPoolSize {
				break
			}
		}
	}
	for user, fp := range disk.Fingerprints {
		user = strings.ToLower(strings.TrimSpace(user))
		fp = strings.ToLower(strings.TrimSpace(fp))
		if user == "" || len(fp) != 64 || len(s.sshCredentialPools[user]) > 0 {
			continue
		}
		s.sshCredentialPools[user] = []sshCredentialSlot{{Fingerprint: fp}}
	}
	return nil
}

func (s *Store) sshCredentialFingerprintLocked(user string, password []byte) string {
	if len(s.sshCredentialKey) == 0 || user == "" || len(password) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, s.sshCredentialKey)
	_, _ = mac.Write([]byte(strings.ToLower(strings.TrimSpace(user))))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(password)
	return hex.EncodeToString(mac.Sum(nil))
}

// SSHCredentialStatus reports whether the virtual host has any credential slot
// for this account and whether the supplied credential matches one of them.
func (s *Store) SSHCredentialStatus(user string, password []byte) (established, matches bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user = strings.ToLower(strings.TrimSpace(user))
	slots := s.sshCredentialPools[user]
	if len(slots) == 0 {
		return false, false
	}
	got := s.sshCredentialFingerprintLocked(user, password)
	if got == "" {
		return true, false
	}
	now := time.Now()
	for i := range slots {
		if hmac.Equal([]byte(slots[i].Fingerprint), []byte(got)) {
			slots[i].LastSeen = now
			s.sshCredentialPools[user] = slots
			_ = s.persistSSHCredentialRealityLocked()
			return true, true
		}
	}
	return true, false
}

// EstablishSSHCredential adds a bounded synthetic compromise slot. When a pool
// is full, only a slot that has been idle long enough may rotate out. This keeps
// recent actor continuity while preventing a single historical password from
// starving the trap forever. No plaintext password is persisted.
func (s *Store) EstablishSSHCredential(user string, password []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	user = strings.ToLower(strings.TrimSpace(user))
	if user == "" || len(password) == 0 || len(password) > 256 {
		return false
	}
	fp := s.sshCredentialFingerprintLocked(user, password)
	if fp == "" {
		return false
	}
	now := time.Now()
	slots := append([]sshCredentialSlot(nil), s.sshCredentialPools[user]...)
	for i := range slots {
		if hmac.Equal([]byte(slots[i].Fingerprint), []byte(fp)) {
			slots[i].LastSeen = now
			s.sshCredentialPools[user] = slots
			return s.persistSSHCredentialRealityLocked()
		}
	}
	if len(slots) < sshCredentialPoolSize {
		slots = append(slots, sshCredentialSlot{Fingerprint: fp, FirstSeen: now, LastSeen: now})
		s.sshCredentialPools[user] = slots
		return s.persistSSHCredentialRealityLocked()
	}
	sort.Slice(slots, func(i, j int) bool { return slots[i].LastSeen.Before(slots[j].LastSeen) })
	oldest := slots[0].LastSeen
	if oldest.IsZero() || now.Sub(oldest) >= sshCredentialRotateAfter {
		slots[0] = sshCredentialSlot{Fingerprint: fp, FirstSeen: now, LastSeen: now}
		s.sshCredentialPools[user] = slots
		return s.persistSSHCredentialRealityLocked()
	}
	return false
}

func (s *Store) SSHCredentialPoolSize(user string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sshCredentialPools[strings.ToLower(strings.TrimSpace(user))])
}

func (s *Store) persistSSHCredentialRealityLocked() bool {
	disk := sshCredentialRealityDisk{Pools: map[string][]sshCredentialSlot{}}
	for user, slots := range s.sshCredentialPools {
		disk.Pools[user] = append([]sshCredentialSlot(nil), slots...)
	}
	b, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return false
	}
	b = append(b, '\n')
	path := filepath.Join(s.dataDir, sshCredentialStateFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return false
	}
	if err := os.Rename(tmp, path); err != nil {
		return false
	}
	return true
}
