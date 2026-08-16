package server

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode/utf8"
)

func annotateVirtualExecStdin(result *virtualSSHResult, data []byte, truncated bool) {
	if result == nil || len(data) == 0 {
		return
	}
	sum := sha256.Sum256(data)
	result.StdinBytes = len(data)
	result.StdinSHA256 = hex.EncodeToString(sum[:])
	result.StdinKind = virtualStdinKind(data)
	if truncated {
		result.StdinKind += "/truncated"
	}
}

func virtualStdinKind(data []byte) string {
	switch {
	case len(data) >= 4 && string(data[:4]) == "\x7fELF":
		return "elf"
	case strings.HasPrefix(string(data), "#!"):
		return "script"
	case utf8.Valid(data):
		for _, b := range data {
			if b == 0 {
				return "binary"
			}
		}
		return "text"
	default:
		return "binary"
	}
}

func virtualCommandConsumesInput(command string) bool {
	low := strings.ToLower(command)
	return strings.Contains(low, "cat >") || strings.Contains(low, "cat  >") || strings.Contains(low, "crontab -") || strings.Contains(low, "bash -s") || strings.Contains(low, "sh -s")
}
