package server

import (
	"strings"
	"time"

	"zentloop/internal/model"
	"zentloop/internal/store"
)

func sshBehaviorFingerprint(result virtualSSHResult, command string) string {
	low := strings.ToLower(command)
	switch {
	case looksLikeObservedResourceCleanup(low):
		return "ssh:resource-hijack-preparation"
	case strings.Contains(low, "ipinfo.io/org"):
		return "ssh:hosting-provider-discovery"
	case ((strings.Contains(low, "===shell_behavior===") || (strings.Contains(low, "path_err=") && strings.Contains(low, "cmd_err="))) && strings.Contains(low, "xxxxxx")) || environmentFingerprintCollectorScore(low) >= 5:
		return "ssh:environment-fingerprint-probe"
	case strings.Contains(low, "ps ") && strings.Contains(low, "grep") && !strings.Contains(low, "grep -v grep"):
		return "ssh:process-discovery"
	case strings.Contains(low, "ps ") && strings.Contains(low, "grep"):
		return "ssh:payload-presence-check"
	case strings.Contains(low, "ps ") && (strings.Contains(low, "pcpu") || strings.Contains(low, "%cpu") || strings.Contains(low, "--sort=-pcpu")):
		return "ssh:resource-recon"
	case strings.Contains(low, "/proc/cpuinfo") || strings.Contains(low, "nvidia-smi") || strings.Contains(low, "lspci") || strings.Contains(low, "lscpu") || strings.Contains(low, "nproc"):
		return "ssh:hardware-recon"
	case looksLikeMinerCleanupSequence(low) && (strings.Contains(low, "chmod 777") || strings.Contains(low, "history -c")):
		return "ssh:cryptominer-behavior"
	case result.PayloadStage == "completed" || (result.StdinBytes > 0 && (strings.Contains(low, "cat >") || strings.Contains(low, "cat  >"))):
		return "ssh:staged-payload"
	case result.PayloadStage == "retry":
		return "ssh:payload-staging-retry"
	case result.PayloadStage == "intent":
		return "ssh:payload-staging-intent"
	case result.PayloadStage == "executed":
		return "ssh:staged-payload-execution"
	case strings.Contains(low, "crontab -r"):
		return "ssh:scheduled-task-removal"
	case (strings.Contains(low, "crontab -") && !strings.Contains(low, "crontab -r")) || (strings.Contains(low, "crontab") && strings.Contains(low, "@reboot")):
		return "ssh:cron-persistence"
	case strings.Contains(low, "kill -9") || strings.Contains(low, "pkill ") || strings.Contains(low, "killall "):
		return "ssh:process-killer"
	case (strings.Contains(low, "for ") && strings.Contains(low, "; do ")) || (strings.Contains(low, "if ") && strings.Contains(low, "; then ")):
		return "ssh:shell-control-flow"
	case strings.Contains(low, "history -c") || strings.Contains(low, "unset histfile") || strings.Contains(low, "histfile=/dev/null") || (strings.Contains(low, ".bash_history") && (strings.Contains(low, "rm ") || strings.Contains(low, "truncate ") || strings.Contains(low, "shred ") || strings.Contains(low, "> /dev/null"))):
		return "ssh:history-evasion"
	case strings.Contains(low, ".bash_history") || strings.HasPrefix(strings.TrimSpace(low), "history"):
		return "ssh:history-discovery"
	case isHoneypotProbeCommand(command) || result.Persona == "anti-fingerprint":
		return "ssh:honeypot-probe"
	case result.Family == "lateral" || strings.HasPrefix(low, "ssh "):
		return "ssh:lateral-movement"
	case result.Family == "containers":
		return "ssh:container-recon"
	case result.Family == "credentials":
		return "ssh:credential-hunter"
	case result.Family == "privilege":
		return "ssh:privilege-enumeration"
	case result.Family == "persistence":
		return "ssh:persistence-attempt"
	case strings.Contains(low, "curl ") || strings.Contains(low, "wget "):
		if strings.Contains(low, "| bash") || strings.Contains(low, "| sh") {
			return "ssh:download-execute"
		}
		return "ssh:downloader"
	case result.Family == "network":
		return "ssh:network-recon"
	}
	return ""
}

func (w *virtualSSHWorld) sshInstallerSequenceFingerprint(result virtualSSHResult, command string) string {
	if w == nil {
		return ""
	}
	if w.installerSignals == nil {
		w.installerSignals = make(map[string]bool)
	}
	low := strings.ToLower(command)
	if strings.Contains(low, "for d in /dev/shm") || (strings.Contains(low, "cd /dev/shm") && strings.Contains(low, "cd /tmp")) {
		w.installerSignals["writable-dir"] = true
	}
	if result.PayloadStage != "" || strings.Contains(low, "cat >") || strings.Contains(low, "cat  >") {
		w.installerSignals["staging"] = true
	}
	if strings.Contains(low, "crontab") || strings.Contains(low, "@reboot") {
		w.installerSignals["persistence"] = true
	}
	currentProcessCheck := strings.Contains(low, "ps ") || strings.Contains(low, "pgrep ") || strings.Contains(low, "pidof ")
	if currentProcessCheck {
		w.installerSignals["process-check"] = true
	}
	if result.PayloadStage == "executed" || strings.Contains(low, "chmod +x") {
		w.installerSignals["execution"] = true
	}
	if strings.Contains(low, "nproc") || strings.Contains(low, "/proc/cpuinfo") || strings.Contains(low, "lscpu") {
		w.installerSignals["cpu-recon"] = true
	}
	if len(w.installerSignals) >= 4 && (result.PayloadStage == "retry" || result.PayloadStage == "executed" || currentProcessCheck) {
		return "ssh:automated-installer"
	}
	return ""
}

func recordSSHIntelligence(st *store.Store, base model.SSHEvent, command string, canaries []string) {
	tool, technique := commandTechnique(command)
	urls := intelURLPattern.FindAllString(command, 12)
	seenURLs := make(map[string]struct{})
	for _, raw := range urls {
		raw = strings.TrimRight(raw, ").,;]")
		safeURL, host, filename, ok := sanitizeIntelURL(raw)
		if !ok {
			continue
		}
		if _, exists := seenURLs[safeURL]; exists {
			continue
		}
		seenURLs[safeURL] = struct{}{}
		kind := "payload"
		if technique == "" {
			technique = "remote-resource"
		}
		_ = st.AddIntelSignal(model.IntelSignal{ID: newID(6), At: time.Now(), IP: base.IP, Protocol: "ssh", SessionID: base.SessionID, Kind: kind, Tool: tool, Technique: technique, URL: safeURL, Host: host, Filename: filename, Summary: "SSH remote resource: " + host})
	}
	for _, label := range canaries {
		_ = st.AddIntelSignal(model.IntelSignal{ID: newID(6), At: time.Now(), IP: base.IP, Protocol: "ssh", SessionID: base.SessionID, Kind: "canary", Canary: label, Summary: "decoy token reused in SSH command: " + label})
	}
}
