package server

import "strings"

func looksLikeAuthorizedKeyPersistence(low string) bool {
	if !strings.Contains(low, "authorized_keys") {
		return false
	}
	write := strings.Contains(low, "> ~/.ssh/authorized_keys") || strings.Contains(low, ">~/.ssh/authorized_keys") ||
		strings.Contains(low, "> /root/.ssh/authorized_keys") || strings.Contains(low, ">/root/.ssh/authorized_keys") ||
		strings.Contains(low, "tee ") && strings.Contains(low, "authorized_keys")
	keyMaterial := strings.Contains(low, "ssh-rsa ") || strings.Contains(low, "ssh-ed25519 ") || strings.Contains(low, "ecdsa-sha2-")
	return write && keyMaterial
}

func looksLikeImmutableAuthorizedKeyPersistence(low string) bool {
	if !looksLikeAuthorizedKeyPersistence(low) {
		return false
	}
	return strings.Contains(low, "chattr +ai") || strings.Contains(low, "chattr +ia") || strings.Contains(low, "chattr +i")
}

func looksLikeScriptBootstrap(low string) bool {
	// Observed installer pattern: execute staged helper scripts, remove them, then
	// continue with persistence/deployment. Keep this deliberately bounded so an
	// ordinary `sh script.sh` is not overclassified.
	exec := strings.Contains(low, "sh clean.sh") || strings.Contains(low, "./clean.sh") ||
		strings.Contains(low, "sh setup.sh") || strings.Contains(low, "./setup.sh")
	cleanup := strings.Contains(low, "rm -rf clean.sh") || strings.Contains(low, "rm -f clean.sh") ||
		strings.Contains(low, "rm -rf setup.sh") || strings.Contains(low, "rm -f setup.sh")
	return exec && cleanup
}

func looksLikeFilesystemPermissionProbe(low string, shape sshShellShape) bool {
	if !(strings.Contains(low, "touch ") && (strings.Contains(low, "[ -f ") || strings.Contains(low, "test -f "))) {
		return false
	}
	return strings.Contains(low, "sudo -s") || strings.Contains(low, "sudo ") || shape.OrCount >= 2
}

func looksLikeGPUCapacityProfiling(low string) bool {
	gpuQueries := 0
	for _, needle := range []string{"nvidia-smi", "lspci", "3d controller", "grep vga", "product name"} {
		if strings.Contains(low, needle) {
			gpuQueries++
		}
	}
	countProbe := strings.Contains(low, " -c") || strings.Contains(low, "wc -l") || strings.Contains(low, "grep . -c")
	return gpuQueries >= 2 && countProbe
}

func looksLikeEncodedExecutionMarker(low string) bool {
	if !(strings.Contains(low, "echo -e") || strings.Contains(low, "printf")) {
		return false
	}
	// Common success markers observed in automation. The bytes spell auth_ok or
	// success while still preserving the original command in the event log.
	return strings.Contains(low, `\x61\x75\x74\x68\x5f\x6f\x6b`) ||
		strings.Contains(low, `\x73\x75\x63\x63\x65\x73\x73`)
}

func looksLikeDownloadExecuteCleanup(low string) bool {
	download := strings.Contains(low, "curl ") || strings.Contains(low, "wget ")
	exec := strings.Contains(low, "chmod +x") && (strings.Contains(low, "./") || strings.Contains(low, " sh ") || strings.Contains(low, " bash "))
	cleanup := strings.Contains(low, "rm -rf") || strings.Contains(low, "rm -f")
	return download && exec && cleanup
}

func isStealthPayloadPath(p string) bool {
	p = strings.TrimSpace(p)
	if p == "" {
		return false
	}
	base := p
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	return strings.HasPrefix(base, ".") && base != "." && base != ".."
}
