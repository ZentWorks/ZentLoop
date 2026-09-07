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
	"strings"
)

const (
	sshCredentialKeyFile   = ".ssh-auth-reality-key"
	sshCredentialStateFile = "ssh-auth-reality.json"
)

type sshCredentialRealityDisk struct {
	Fingerprints map[string]string `json:"fingerprints"`
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
	for user, fp := range disk.Fingerprints {
		user = strings.ToLower(strings.TrimSpace(user))
		if user != "" && len(fp) == 64 {
			s.sshCredentialFingerprints[user] = strings.ToLower(fp)
		}
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

// SSHCredentialStatus reports whether the virtual host already has a credential
// fingerprint for this account and, if so, whether the supplied credential is
// the same one. No plaintext password is persisted.
func (s *Store) SSHCredentialStatus(user string, password []byte) (established, matches bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user = strings.ToLower(strings.TrimSpace(user))
	want, ok := s.sshCredentialFingerprints[user]
	if !ok {
		return false, false
	}
	got := s.sshCredentialFingerprintLocked(user, password)
	return true, got != "" && hmac.Equal([]byte(want), []byte(got))
}

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
	if existing, ok := s.sshCredentialFingerprints[user]; ok {
		return hmac.Equal([]byte(existing), []byte(fp))
	}
	s.sshCredentialFingerprints[user] = fp
	disk := sshCredentialRealityDisk{Fingerprints: map[string]string{}}
	for k, v := range s.sshCredentialFingerprints {
		disk.Fingerprints[k] = v
	}
	b, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		delete(s.sshCredentialFingerprints, user)
		return false
	}
	b = append(b, '\n')
	path := filepath.Join(s.dataDir, sshCredentialStateFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		delete(s.sshCredentialFingerprints, user)
		return false
	}
	if err := os.Rename(tmp, path); err != nil {
		delete(s.sshCredentialFingerprints, user)
		return false
	}
	return true
}
