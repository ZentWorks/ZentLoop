package server

import (
	"fmt"
	"path"
	"strings"
)

const defaultVirtualProviderOrg = "AS16276 OVH SAS"

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
		fields := strings.Fields(proc.Command)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(path.Base(fields[0]))
		if proc.CPU > 40.0 || proc.Mem > 60.0 || name == "cache" || name == "xmrig" || name == "cpuminer" || name == "minerd" || name == "ccminer" {
			proc.Alive = false
		}
	}

	result := virtualSSHResult{
		CommandName: "crontab",
		Family:      "execution",
		Depth:       7,
		Risk:        99,
		Persona:     "resource-hijack-preparation",
		Message:     "virtual competitor/resource cleanup",
		Status:      0,
		LoopInc:     2,
	}

	// Some observed miner families append chmod/execute/disown/history cleanup to
	// the same giant command. The fast-path above must still apply those later
	// side effects or a follow-up ps/stat/history probe would reveal a fake shell.
	for _, target := range w.virtualLocalExecutionTargets(line) {
		if _, exists := w.files[target]; !exists {
			_ = w.setVirtualFile(target, "\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00GLIBC_2.34\x00worker\n")
		}
		base := path.Base(target)
		if strings.Contains(low, "chmod 777 "+strings.ToLower(base)) || strings.Contains(low, "chmod +x "+strings.ToLower(base)) {
			w.fileModes[target] = 0o777
		}
		proc := w.ensureVirtualPayloadProcess(target)
		if proc != nil {
			proc.Disowned = strings.Contains(low, "disown")
			if strings.Contains(low, "&") {
				proc.JobID = w.nextJob
				w.nextJob++
				if !proc.Disowned {
					w.jobs[proc.JobID] = proc.PID
				}
				result.Output = fmt.Sprintf("[%d] %d", proc.JobID, proc.PID)
			}
		}
		result.PayloadStage = "executed"
		result.PayloadPath = target
		result.Risk = 100
		result.Persona = "payload-execution"
		result.Message = "virtual competitor cleanup and payload execution"
		result.LoopInc++
		break
	}
	if strings.Contains(low, "history -c") {
		w.history = nil
		w.historyCleared = true
	}
	if strings.Contains(low, ".bash_history") {
		w.deleteVirtualFile(path.Join(w.homeDir(), ".bash_history"))
	}
	return result, true
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
