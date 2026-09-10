package store

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// ResolveWebLoginOutcome derives a stable per-target outcome from an
// installation-local HMAC. Credentials are never persisted or logged.
func (s *Store) ResolveWebLoginOutcome(target, username string, credential []byte) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.sshCredentialKey) == 0 || len(credential) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, s.sshCredentialKey)
	_, _ = mac.Write([]byte("web-login-v1\x00"))
	_, _ = mac.Write([]byte(strings.ToLower(strings.TrimSpace(target))))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(strings.ToLower(strings.TrimSpace(username))))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(credential)
	sum := mac.Sum(nil)
	// Roughly one third remain rejected while the rest reach the MFA lure.
	// The same target+username+credential always receives the same outcome.
	if sum[0]%3 == 0 {
		return "reject:" + hex.EncodeToString(sum[:6])
	}
	return "mfa:" + hex.EncodeToString(sum[:6])
}
