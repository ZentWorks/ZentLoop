package server

import (
	"path"
	"regexp"
	"strings"
)

type sshCommandAnalysis struct {
	Stages      []string
	Primary     string
	Family      string
	Intent      string
	Target      string
	Message     string
	Fingerprint string
	Depth       int
	Risk        int
	Persona     string
}

var (
	sshGrepTargetRE = regexp.MustCompile(`(?i)\bgrep\s+(?:-[^\s]+\s+)*(?:--\s+)?['"]?([a-z0-9._-]{2,64})['"]?`)
	sshStageNameRE  = regexp.MustCompile(`^[A-Za-z0-9._+:-]+$`)
)

func analyzeSSHCommand(command string, result virtualSSHResult) sshCommandAnalysis {
	low := strings.ToLower(strings.TrimSpace(command))
	a := sshCommandAnalysis{Stages: collectSSHCommandStages(command)}
	a.Primary = primarySSHCommand(a.Stages, result.CommandName)

	switch {
	case looksLikeObservedResourceCleanup(low) && hasSSHLocalPayloadExecution(low):
		a.Primary, a.Family, a.Intent, a.Message = primarySSHCommand(a.Stages, "crontab"), "execution", "resource-hijack-payload-execution", "competitor cleanup followed by local payload execution"
		a.Fingerprint, a.Depth, a.Risk, a.Persona = "ssh:resource-hijack-execution", 7, 100, "payload-execution"
	case looksLikeObservedResourceCleanup(low):
		a.Primary, a.Family, a.Intent, a.Message = primarySSHCommand(a.Stages, "crontab"), "execution", "competitor-resource-cleanup", "virtual competitor/resource cleanup"
		a.Fingerprint, a.Depth, a.Risk, a.Persona = "ssh:resource-hijack-preparation", 7, 99, "resource-hijack-preparation"
	case strings.Contains(low, "/proc/cpuinfo") && (strings.Contains(low, "processor") || strings.Contains(low, "model name")):
		a.Primary, a.Family, a.Intent, a.Message = firstStageOr(a.Stages, "cat"), "recon", "cpu-topology-discovery", "CPU topology discovery"
		a.Fingerprint, a.Depth, a.Risk, a.Persona = "ssh:hardware-recon", 4, 88, "system-recon"
	case strings.Contains(low, "ps ") || strings.HasPrefix(low, "ps\t"):
		a.Primary, a.Family = "ps", "recon"
		a.Depth, a.Risk, a.Persona = 4, 88, "system-recon"
		if target := sshProcessProbeTarget(command); target != "" {
			a.Intent, a.Target, a.Message = "payload-process-discovery", target, "payload/process presence discovery"
			a.Fingerprint, a.Risk = "ssh:payload-presence-check", 91
		} else if strings.Contains(low, "pcpu") || strings.Contains(low, "%cpu") || strings.Contains(low, "--sort=-pcpu") || strings.Contains(low, "--sort=-%cpu") {
			a.Intent, a.Message = "high-cpu-process-discovery", "high CPU process discovery"
			a.Fingerprint, a.Risk = "ssh:resource-recon", 90
		} else {
			a.Intent, a.Message = "process-discovery", "process discovery"
			a.Fingerprint = "ssh:process-discovery"
		}
	case strings.Contains(low, "crontab"):
		a.Primary, a.Family, a.Depth, a.Risk, a.Persona = "crontab", "persistence", 5, 92, "persistence"
		switch {
		case strings.Contains(low, "crontab -r") && !strings.Contains(low, "@reboot") && !strings.Contains(low, "| crontab") && !strings.Contains(low, "crontab - "):
			a.Intent, a.Message, a.Fingerprint, a.Depth, a.Risk = "scheduled-task-removal", "scheduled task removal", "ssh:scheduled-task-removal", 5, 93
		case strings.Contains(low, "@reboot") || strings.Contains(low, "| crontab") || (strings.Contains(low, "crontab -") && !strings.Contains(low, "crontab -l")):
			a.Intent, a.Message, a.Fingerprint, a.Depth, a.Risk = "scheduled-task-modification", "scheduled task discovery or modification", "ssh:cron-persistence", 6, 97
		default:
			a.Intent, a.Message, a.Fingerprint = "scheduled-task-discovery", "scheduled task discovery", "ssh:scheduled-task-discovery"
		}
	case strings.Contains(low, "> /tmp/d.log") || strings.Contains(low, ">/tmp/d.log"):
		a.Primary, a.Family, a.Intent, a.Message = primarySSHCommand(a.Stages, "echo"), "filesystem", "execution-marker-write", "execution/campaign marker written"
		a.Fingerprint, a.Depth, a.Risk, a.Persona = "ssh:execution-marker", 5, 91, result.Persona
	case strings.Contains(low, "nproc") || strings.Contains(low, "lscpu") || strings.Contains(low, "getconf _nprocessors"):
		a.Family, a.Intent, a.Message = "recon", "cpu-resource-discovery", "CPU resource discovery"
		a.Fingerprint, a.Depth, a.Risk, a.Persona = "ssh:hardware-recon", 4, 87, "system-recon"
	case strings.Contains(low, "uname"):
		a.Primary, a.Family, a.Depth, a.Risk, a.Persona = "uname", "recon", 3, 84, "system-recon"
		switch {
		case strings.Contains(low, "uname -a") || strings.Contains(low, "uname -s -v") || (strings.Contains(low, "uname -m") && (strings.Contains(low, " -n") || strings.Contains(low, " -r") || strings.Contains(low, " -v"))):
			a.Intent, a.Message = "system-identity-discovery", "system identity discovery"
		case strings.Contains(low, "uname -m"):
			a.Intent, a.Message = "architecture-discovery", "architecture discovery"
		case strings.Contains(low, "uname -n"):
			a.Intent, a.Message = "hostname-discovery", "hostname discovery"
		case strings.Contains(low, "uname -r"):
			a.Intent, a.Message = "kernel-release-discovery", "kernel release discovery"
		default:
			a.Intent, a.Message = "system-identity-discovery", "system identity discovery"
		}
	case strings.Contains(low, "uptime"):
		a.Primary, a.Family, a.Intent, a.Message = "uptime", "recon", "uptime-discovery", "system uptime discovery"
		a.Depth, a.Risk, a.Persona = 3, 84, "system-recon"
	case strings.Contains(low, "ip addr") || strings.Contains(low, "ip route") || strings.Contains(low, "ifconfig") || strings.Contains(low, "netstat") || strings.Contains(low, "ss -"):
		a.Family, a.Intent, a.Message = "network", "network-discovery", "network configuration/service discovery"
		a.Fingerprint, a.Depth, a.Risk, a.Persona = "ssh:network-recon", 4, 90, "network-recon"
	}

	return a
}

func hasSSHLocalPayloadExecution(low string) bool {
	if !strings.Contains(low, "./") {
		return false
	}
	return strings.Contains(low, "chmod ") || strings.Contains(low, " disown") || strings.Contains(low, "&")
}

func applySSHCommandAnalysis(result *virtualSSHResult, a sshCommandAnalysis) {
	if result == nil {
		return
	}
	if a.Primary != "" {
		result.CommandName = a.Primary
	}
	if a.Family != "" {
		result.Family = a.Family
	}
	if a.Message != "" {
		result.Message = a.Message
	}
	if a.Depth > result.Depth {
		result.Depth = a.Depth
	}
	if a.Risk > result.Risk {
		result.Risk = a.Risk
	}
	if a.Persona != "" && (a.Risk >= result.Risk || sshAnalysisOwnsReconPersona(a.Intent)) {
		result.Persona = a.Persona
	}
}

func sshAnalysisOwnsReconPersona(intent string) bool {
	switch intent {
	case "system-identity-discovery", "architecture-discovery", "hostname-discovery", "kernel-release-discovery", "uptime-discovery", "cpu-topology-discovery", "cpu-resource-discovery":
		return true
	}
	return false
}

func collectSSHCommandStages(command string) []string {
	seen := make(map[string]bool)
	var out []string
	var addLine func(string, int)
	add := func(name string) {
		name = path.Base(strings.TrimSpace(name))
		if name == "" || strings.HasPrefix(name, "-") || !sshStageNameRE.MatchString(name) || isShellSyntaxWord(name) || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, name)
	}
	addLine = func(line string, depth int) {
		if depth > 4 {
			return
		}
		// Walk the parsed shell structure first so stages retain their actual
		// first-occurrence order. The flat scan remains a fallback for commands
		// hidden inside substitutions/groups that the lightweight parser cannot
		// fully unwrap.
		for _, chain := range splitVirtualChain(strings.TrimSpace(line)) {
			for _, pipeStage := range splitOutsideQuotes(chain.command, '|') {
				stage := strings.TrimSpace(pipeStage)
				if inner, ok := unwrapVirtualGroup(stage); ok {
					addLine(inner, depth+1)
					continue
				}
				clean, _ := parseVirtualRedirection(stage)
				words := virtualWords(clean)
				if len(words) == 0 {
					continue
				}
				idx := 0
				for idx < len(words) {
					if _, _, ok := strings.Cut(words[idx], "="); ok && validVirtualEnvName(strings.SplitN(words[idx], "=", 2)[0]) {
						idx++
						continue
					}
					break
				}
				if idx >= len(words) {
					continue
				}
				cmd := path.Base(words[idx])
				add(cmd)
				if (cmd == "sh" || cmd == "bash" || cmd == "dash") && idx+2 < len(words) && words[idx+1] == "-c" {
					addLine(strings.Join(words[idx+2:], " "), depth+1)
				}
			}
		}
		for _, name := range collectSSHFlatStages(line) {
			add(name)
		}
	}
	addLine(command, 0)
	return out
}

func collectSSHFlatStages(line string) []string {
	var segments []string
	var b strings.Builder
	var quote byte
	escaped := false
	flush := func() {
		if v := strings.TrimSpace(b.String()); v != "" {
			segments = append(segments, v)
		}
		b.Reset()
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		if escaped {
			b.WriteByte(c)
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			b.WriteByte(c)
			continue
		}
		if quote != 0 {
			b.WriteByte(c)
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			b.WriteByte(c)
			continue
		}
		if c == ';' || c == '|' || c == '&' {
			flush()
			if i+1 < len(line) && line[i+1] == c {
				i++
			}
			continue
		}
		b.WriteByte(c)
	}
	flush()
	var out []string
	for _, seg := range segments {
		words := virtualWords(seg)
		for i := 0; i < len(words); i++ {
			w := path.Base(words[i])
			if isShellSyntaxWord(w) || w == "!" {
				continue
			}
			if name, _, ok := strings.Cut(words[i], "="); ok && validVirtualEnvName(name) {
				continue
			}
			if virtualCommandExists(w) || virtualBuiltin(w) {
				out = append(out, w)
			}
			break
		}
	}
	return out
}

func primarySSHCommand(stages []string, fallback string) string {
	aux := map[string]bool{"grep": true, "egrep": true, "fgrep": true, "wc": true, "head": true, "tail": true, "sort": true, "uniq": true, "cut": true, "tr": true, "tee": true, "xargs": true, "sh": true, "bash": true, "dash": true}
	for _, s := range stages {
		if !aux[s] && !isShellSyntaxWord(s) {
			return s
		}
	}
	for _, s := range stages {
		if !isShellSyntaxWord(s) {
			return s
		}
	}
	fallback = path.Base(strings.TrimSpace(fallback))
	if fallback == "" || isShellSyntaxWord(fallback) {
		return ""
	}
	return fallback
}

func firstStageOr(stages []string, fallback string) string {
	if len(stages) > 0 {
		return stages[0]
	}
	return fallback
}

func sshProcessProbeTarget(command string) string {
	low := strings.ToLower(command)
	if !strings.Contains(low, "grep") {
		return ""
	}
	matches := sshGrepTargetRE.FindAllStringSubmatch(command, -1)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		target := strings.Trim(m[1], "'\"")
		if target == "" || target == "grep" || target == "-v" || target == "root" {
			continue
		}
		return target
	}
	return ""
}

func isShellSyntaxWord(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "if", "then", "elif", "else", "fi", "for", "while", "until", "do", "done", "case", "esac", "in", "function", "time":
		return true
	}
	return false
}
