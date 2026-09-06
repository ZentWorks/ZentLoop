package server

import (
	"hash/fnv"
	"strings"
	"time"

	"zentloop/internal/store"
)

func shouldAcceptTrapPassword(remote, user string, password []byte, attempt, maxTries int) bool {
	if user == "" || len(password) == 0 || len(password) > 256 {
		return false
	}
	threshold := 2 + int(stableSSHHash(remote+"|"+user)%2)
	if maxTries > 0 && threshold > maxTries {
		threshold = maxTries
	}
	return attempt >= threshold
}

func shouldAcceptRecurringProbe(recur store.SSHRecurrence, remote, user string, password []byte, attempt int) bool {
	if attempt != 1 || !recur.LowAndSlow || recur.Connections < 6 || user == "" || len(password) == 0 || len(password) > 256 {
		return false
	}
	// Deterministic occasional success for a persistent low-and-slow prober.
	// No password value is retained or compared against real credentials.
	return (uint32(recur.Connections)+stableSSHHash(remote+"|"+user))%3 == 0
}

func (s *TrapSSH) shouldAcceptTrapCredential(remote, user string, password []byte, attempt int) bool {
	user = strings.ToLower(strings.TrimSpace(user))
	if !virtualSSHAccountExists(user) || len(password) == 0 || len(password) > 256 {
		return false
	}
	profile := s.store.SSHAuthProfile(remote)
	compromised := s.system.compromisedAccountForSource(remote)
	established := false
	// Preserve continuity across a rollout: if this source previously reached a
	// believable host account, keep that account sticky instead of silently
	// moving the compromise to another username.
	for _, accepted := range profile.RecentAcceptedUsers {
		if virtualSSHAccountExists(accepted) {
			compromised = accepted
			established = true
			break
		}
	}
	if user != compromised {
		return false
	}
	// Multiple sessions using the same compromised account are believable; a
	// second simultaneously successful username is not.
	for _, active := range profile.ActiveAcceptedUsers {
		if active != user {
			return false
		}
	}
	pass := string(password)
	common := map[string]string{"root": "root", "admin": "admin", "svc-web": "web", "svc-backup": "backup"}
	if expected := common[user]; expected != "" && pass == expected {
		return true
	}
	if !established && attempt == 1 && profile.UniqueUsers < 15 && stableSSHHash(remote+"|"+user+"|"+pass)%8 == 0 {
		return true
	}
	// Username spraying progressively removes new lucky successes. Once a
	// source has tested thirty identities, only an already-established account
	// can continue to authenticate.
	if profile.UniqueUsers >= 30 && !established {
		return false
	}
	if shouldAcceptTrapPassword(remote, user, password, attempt, s.cfg.SSHMaxAuthTries) {
		return true
	}
	return shouldAcceptRecurringProbe(s.store.SSHRecurrence(remote, time.Now()), remote, user, password, attempt)
}

func stableSSHHash(v string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(v))
	return h.Sum32()
}
