package server

import (
	"hash/fnv"
	"strings"

	"zentloop/internal/store"
)

func shouldAcceptTrapPassword(remote, user string, password []byte, attempt, maxTries int) bool {
	if user == "" || len(password) == 0 || len(password) > 256 {
		return false
	}
	pass := string(password)
	common := map[string]string{"root": "root", "admin": "admin", "ubuntu": "ubuntu", "pi": "raspberry", "oracle": "oracle", "test": "test"}
	if expected, ok := common[strings.ToLower(user)]; ok && pass == expected {
		return true
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

func stableSSHHash(v string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(v))
	return h.Sum32()
}
