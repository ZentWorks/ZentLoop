package server

import (
	"encoding/hex"
	"path"
	"regexp"
	"strings"
	"time"

	"zentloop/internal/model"
	"zentloop/internal/store"
)

var sshPayloadRedirectRE = regexp.MustCompile(`(?i)\bcat\s*>\s*["']?([^"'\s;&|]+)`)

func (w *virtualSSHWorld) applySSHPayloadEvidence(command string, result *virtualSSHResult) (recovered any) {
	defer func() {
		recovered = recover()
	}()
	w.observeImplicitPayloadStage(command, result)
	w.confirmPreviouslyStagedExecution(command, result)
	return nil
}

func (w *virtualSSHWorld) classifyVirtualPayloadStage(target string, sum [32]byte) (stage, relation, message string) {
	if w == nil {
		return "completed", "new-payload", "virtual payload staging completed"
	}
	target = path.Clean(target)
	if w.sessionPayloadHash == nil {
		w.sessionPayloadHash = make(map[string][32]byte)
	}
	if previous, ok := w.sessionPayloadHash[target]; ok {
		w.sessionPayloadHash[target] = sum
		if previous == sum {
			return "retry", "same-path-retry", "identical virtual payload staging retry"
		}
		return "completed", "payload-replacement", "virtual payload replaced at previously staged path"
	}
	for other, previous := range w.sessionPayloadHash {
		if other == target {
			continue
		}
		if previous == sum {
			w.sessionPayloadHash[target] = sum
			return "completed", "payload-relocation", "identical payload staged at a second virtual path"
		}
	}
	if len(w.sessionPayloadHash) > 0 {
		w.sessionPayloadHash[target] = sum
		return "completed", "companion-payload", "additional companion payload staged in the same SSH session"
	}
	if previous, ok := w.stagingPayloadHash[target]; ok && previous == sum {
		w.sessionPayloadHash[target] = sum
		return "completed", "recurring-campaign-payload", "previously observed payload staged again in a new SSH session"
	}
	for other, previous := range w.stagingPayloadHash {
		if other != target && previous == sum {
			w.sessionPayloadHash[target] = sum
			return "completed", "recurring-payload-relocation", "previously observed payload staged again at a different virtual path"
		}
	}
	w.sessionPayloadHash[target] = sum
	return "completed", "new-payload", "virtual payload staging completed"
}

func (w *virtualSSHWorld) observeImplicitPayloadStage(command string, result *virtualSSHResult) {
	if w == nil || result == nil || result.PayloadStage != "" || result.StdinBytes <= 0 || result.StdinSHA256 == "" {
		return
	}
	kind := strings.ToLower(strings.TrimSpace(result.StdinKind))
	if kind != "script" && !strings.Contains(kind, "elf") {
		return
	}
	m := sshPayloadRedirectRE.FindStringSubmatch(command)
	if len(m) != 2 {
		return
	}
	target := w.resolve(strings.TrimSpace(m[1]))
	if !w.isVirtualPayloadStagingPath(target) {
		return
	}
	raw, err := hex.DecodeString(result.StdinSHA256)
	if err != nil || len(raw) != 32 {
		return
	}
	var sum [32]byte
	copy(sum[:], raw)
	stage, relation, message := w.classifyVirtualPayloadStage(target, sum)
	w.stagingAttempts[target]++
	w.stagingPayloadHash[target] = sum
	result.PayloadPath = target
	result.PayloadStage = stage
	result.PayloadRelation = relation
	result.Family = "execution"
	result.Depth = maxInt(result.Depth, 6)
	result.Risk = maxInt(result.Risk, 97)
	result.Persona = "payload-staging"
	result.Message = message
	if stage == "retry" {
		result.LoopInc++
		result.Risk = maxInt(result.Risk, 98)
	}
}

func (w *virtualSSHWorld) confirmPreviouslyStagedExecution(command string, result *virtualSSHResult) {
	if w == nil || result == nil || result.PayloadStage != "" {
		return
	}
	// Only exact local execution paths that already carry a source-bound staging
	// hash qualify. Random filenames and timing alone never create trace evidence.
	for _, target := range w.virtualLocalExecutionTargets(command) {
		target = w.resolve(target)
		if _, ok := w.stagingPayloadHash[target]; !ok {
			continue
		}
		result.PayloadStage = "executed"
		result.PayloadPath = target
		result.PayloadRelation = "staged-payload-execution"
		if sum, ok := w.stagingPayloadHash[target]; ok {
			result.StdinSHA256 = hex.EncodeToString(sum[:])
		}
		result.Depth = maxInt(result.Depth, 7)
		result.Risk = maxInt(result.Risk, 100)
		result.Persona = "payload-execution"
		return
	}
}

func sshBehaviorFingerprint(result virtualSSHResult, command string) string {
	low := strings.ToLower(command)
	switch {
	case strings.TrimSpace(command) == "ssh -V" || strings.TrimSpace(command) == "ssh --version":
		return "ssh:ssh-client-discovery"
	case strings.HasPrefix(strings.TrimSpace(low), "mount"):
		return "ssh:filesystem-discovery"
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
	case looksLikeGPUCapacityProfiling(low):
		return "ssh:gpu-capacity-profiling"
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

func selectSSHCommandFingerprint(w *virtualSSHWorld, result virtualSSHResult, command string, analysis sshCommandAnalysis) string {
	fingerprint := sshBehaviorFingerprint(result, command)
	if analysis.Fingerprint != "" {
		fingerprint = analysis.Fingerprint
	}
	if w == nil {
		return fingerprint
	}
	// Always feed the aggregate sequence detector so a process-presence probe can
	// be correlated with a later matching staged filename. The precise
	// presence->install relationship may override the generic per-command staging
	// label; ordinary automated-installer remains subordinate to stronger evidence.
	installer := w.sshInstallerSequenceFingerprint(result, command)
	if installer == "ssh:payload-presence-to-install" {
		return installer
	}
	if installer != "" && analysis.Fingerprint == "" && (fingerprint == "" || result.PayloadStage == "retry") {
		fingerprint = installer
	}
	return fingerprint
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
	if result.CommandName == "sftp" && (result.PayloadStage == "completed" || result.PayloadStage == "retry") {
		w.installerSignals["sftp-staging"] = true
	}
	if strings.Contains(low, "crontab") || strings.Contains(low, "@reboot") {
		w.installerSignals["persistence"] = true
	}
	currentProcessCheck := strings.Contains(low, "ps ") || strings.Contains(low, "pgrep ") || strings.Contains(low, "pidof ")
	if currentProcessCheck {
		w.installerSignals["process-check"] = true
		if target := sshProcessProbeTarget(command); target != "" {
			w.installerSignals["process-target:"+strings.ToLower(pathBaseSafe(target))] = true
		}
	}
	if result.PayloadPath != "" && (result.PayloadStage == "completed" || result.PayloadStage == "retry") {
		base := strings.ToLower(pathBaseSafe(result.PayloadPath))
		if base != "" && w.installerSignals["process-target:"+base] {
			return "ssh:payload-presence-to-install"
		}
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

func pathBaseSafe(v string) string {
	v = strings.TrimSpace(strings.ReplaceAll(v, "\\", "/"))
	if i := strings.LastIndex(v, "/"); i >= 0 {
		v = v[i+1:]
	}
	return strings.Trim(v, "'\" ")
}
