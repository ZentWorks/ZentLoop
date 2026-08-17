package server

import (
	"path"
	"strings"
)

const virtualProviderOrg = "AS16276 OVH SAS"

func isVirtualProviderLookup(raw string) bool {
	low := strings.ToLower(strings.TrimSpace(raw))
	low = strings.TrimSuffix(low, "/")
	return low == "http://ipinfo.io/org" || low == "https://ipinfo.io/org" || low == "ipinfo.io/org"
}

// executeKnownResourceCleanup models the observed competitor-miner cleanup as a
// bounded state transition in the virtual machine. It never touches host/container processes.
func (w *virtualSSHWorld) executeKnownResourceCleanup(line string) (virtualSSHResult, bool) {
	low := strings.ToLower(line)
	if !looksLikeObservedResourceCleanup(low) {
		return virtualSSHResult{}, false
	}

	w.crontabExists = false
	w.crontabContent = ""
	w.system.setPeerCrontab(w.peerKey, false, "")
	w.deleteVirtualFile("/var/spool/cron/crontabs/" + safeVirtualName(w.user))

	// The observed routine removes temporary payloads and known miner names.
	for f := range w.files {
		clean := path.Clean(f)
		if clean == "/tmp" || clean == "/var/tmp" || clean == "/dev/shm" {
			continue
		}
		if strings.HasPrefix(clean, "/tmp/") || strings.HasPrefix(clean, "/var/tmp/") {
			w.deleteVirtualFile(clean)
			continue
		}
		base := strings.ToLower(path.Base(clean))
		switch base {
		case "xmrig", "cpuminer", "minerd", "ccminer", "cache":
			w.deleteVirtualFile(clean)
		}
	}
	for _, proc := range w.processes {
		if proc == nil || !proc.Alive {
			continue
		}
		name := strings.ToLower(path.Base(strings.Fields(proc.Command)[0]))
		if proc.CPU > 40.0 || proc.Mem > 60.0 || name == "cache" || name == "xmrig" || name == "cpuminer" || name == "minerd" || name == "ccminer" {
			proc.Alive = false
		}
	}

	return virtualSSHResult{
		CommandName: "for",
		Family:      "execution",
		Depth:       7,
		Risk:        99,
		Persona:     "resource-hijack-preparation",
		Message:     "virtual competitor/resource cleanup",
		Status:      0,
		LoopInc:     2,
	}, true
}

func looksLikeObservedResourceCleanup(low string) bool {
	markers := 0
	for _, needle := range []string{
		"crontab -r",
		"ps aux",
		"readlink -f /proc/$pid/exe",
		"kill -9 $pid",
		"xmrig cpuminer minerd ccminer",
		"pkill -9 $proc",
		"rm -rf /tmp",
		"rm -rf /var/tmp",
	} {
		if strings.Contains(low, needle) {
			markers++
		}
	}
	return markers >= 5
}

func normalizeVirtualResourceIntent(result *virtualSSHResult, command string) {
	if result == nil {
		return
	}
	low := strings.ToLower(command)
	if strings.Contains(low, "nvidia-smi") || strings.Contains(low, "lspci") || strings.Contains(low, "lscpu") || strings.Contains(low, "nproc") {
		result.Family = "recon"
		result.Persona = "resource-discovery"
		result.Message = "hardware/resource discovery"
		if result.Depth < 4 {
			result.Depth = 4
		}
		if result.Risk < 89 {
			result.Risk = 89
		}
	}
}
