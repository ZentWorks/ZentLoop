package server

import (
	"hash/fnv"
	"strings"
	"time"

	"zentloop/internal/store"
)

const (
	sshAuthAcceptedExisting     = "accepted-existing-credential"
	sshAuthAcceptedNewSlot      = "accepted-new-credential-slot"
	sshAuthAcceptedLegacySticky = "accepted-legacy-sticky"
	sshAuthRejectInvalid        = "reject-invalid-credential"
	sshAuthRejectUnknownAccount = "reject-unknown-account"
	sshAuthRejectSourceConflict = "reject-source-account-conflict"
	sshAuthRejectConcurrent     = "reject-concurrent-identity"
	sshAuthRejectSpray          = "reject-spray-hardening"
	sshAuthRejectCredential     = "reject-credential-mismatch"
	sshAuthRejectPolicy         = "reject-policy"
	sshAuthRejectPoolBusy       = "reject-credential-pool-busy"
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
	return (uint32(recur.Connections)+stableSSHHash(remote+"|"+user))%3 == 0
}

// shouldAcceptFirstKnownAccount gives single-shot scanners a bounded way into
// the trap. It only applies to accounts that actually exist in Host Reality;
// arbitrary dictionary usernames remain hard failures.
func shouldAcceptFirstKnownAccount(remote, user string, password []byte, attempt int) bool {
	if attempt != 1 || user == "" || len(password) == 0 || len(password) > 256 {
		return false
	}
	return stableSSHHash(remote+"|"+user+"|"+string(password))%5 == 0
}

func (s *TrapSSH) shouldAcceptTrapCredential(remote, user string, password []byte, attempt int) bool {
	ok, _ := s.trapCredentialDecision(remote, user, password, attempt)
	return ok
}

func (s *TrapSSH) trapCredentialDecision(remote, user string, password []byte, attempt int) (bool, string) {
	user = strings.ToLower(strings.TrimSpace(user))
	if user == "" || len(password) == 0 || len(password) > 256 {
		return false, sshAuthRejectInvalid
	}
	if !virtualSSHAccountExists(user) {
		return false, sshAuthRejectUnknownAccount
	}

	profile := s.store.SSHAuthProfile(remote)
	stickyUser := ""
	for _, accepted := range profile.RecentAcceptedUsers {
		if virtualSSHAccountExists(accepted) {
			stickyUser = accepted
			break
		}
	}
	if stickyUser != "" && user != stickyUser {
		return false, sshAuthRejectSourceConflict
	}
	for _, active := range profile.ActiveAcceptedUsers {
		if active != user {
			return false, sshAuthRejectConcurrent
		}
	}

	credentialEstablished, credentialMatches := s.store.SSHCredentialStatus(user, password)
	if credentialMatches {
		return true, sshAuthAcceptedExisting
	}

	// 0.3.16/0.3.17 continuity: a source that had already reached this believable
	// account may establish the first pool slot after upgrade.
	if stickyUser == user && !credentialEstablished {
		if s.store.EstablishSSHCredential(user, password) {
			return true, sshAuthAcceptedLegacySticky
		}
		return false, sshAuthRejectPoolBusy
	}

	// Heavy username spraying may keep using an already known credential, but it
	// must not create fresh successful identities or password slots.
	if profile.UniqueUsers >= 30 {
		return false, sshAuthRejectSpray
	}

	candidate := shouldAcceptFirstKnownAccount(remote, user, password, attempt) ||
		shouldAcceptTrapPassword(remote, user, password, attempt, s.cfg.SSHMaxAuthTries) ||
		shouldAcceptRecurringProbe(s.store.SSHRecurrence(remote, time.Now()), remote, user, password, attempt)
	if !candidate {
		if credentialEstablished {
			return false, sshAuthRejectCredential
		}
		return false, sshAuthRejectPolicy
	}
	if s.store.EstablishSSHCredential(user, password) {
		return true, sshAuthAcceptedNewSlot
	}
	return false, sshAuthRejectPoolBusy
}

func stableSSHHash(v string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(v))
	return h.Sum32()
}
