package server

import "strings"

// sshShellShape is a bounded, quote-aware structural summary of a shell line.
// It is intentionally not a Bash parser and never executes attacker input. The
// goal is to preserve top-level intent when useful discovery commands are nested
// inside fallback/download/control-flow chains.
type sshShellShape struct {
	AndCount        int
	OrCount         int
	SequenceCount   int
	PipeCount       int
	Substitutions   int
	Groups          int
	HasSudo         bool
	HasShell        bool
	HasCurl         bool
	HasWget         bool
	HasChmod        bool
	HasCleanup      bool
	HasLocalExec    bool
	HasAntiForensic bool
	HasReconBundle  bool
	HasShellProbe   bool
}

func inspectSSHShellShape(line string) sshShellShape {
	var s sshShellShape
	var quote byte
	escaped := false
	parenDepth := 0
	low := strings.ToLower(line)
	for i := 0; i < len(line); i++ {
		c := line[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if c == '$' && i+1 < len(line) && line[i+1] == '(' {
			s.Substitutions++
			continue
		}
		switch c {
		case '(':
			parenDepth++
			s.Groups++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case ';':
			if parenDepth == 0 {
				s.SequenceCount++
			}
		case '&':
			if i+1 < len(line) && line[i+1] == '&' {
				if parenDepth == 0 {
					s.AndCount++
				}
				i++
			}
		case '|':
			if i+1 < len(line) && line[i+1] == '|' {
				if parenDepth == 0 {
					s.OrCount++
				}
				i++
			} else {
				s.PipeCount++
			}
		}
	}

	s.HasSudo = shellWordPresent(low, "sudo")
	s.HasShell = shellWordPresent(low, "sh") || shellWordPresent(low, "bash") || shellWordPresent(low, "dash") || strings.Contains(low, "busybox sh")
	s.HasCurl = shellWordPresent(low, "curl")
	s.HasWget = shellWordPresent(low, "wget")
	s.HasChmod = shellWordPresent(low, "chmod")
	s.HasCleanup = strings.Contains(low, "rm -f") || strings.Contains(low, "rm -rf") || strings.Contains(low, "unlink ")
	s.HasLocalExec = hasSSHLocalPayloadExecution(low) || strings.Contains(low, "sh ") && (s.HasCurl || s.HasWget)
	s.HasAntiForensic = strings.Contains(low, "history -c") || strings.Contains(low, ".bash_history") || strings.Contains(low, "unset histfile")
	reconSignals := 0
	for _, needle := range []string{"uname", "nproc", "lscpu", "lspci", "nvidia-smi", "/proc/cpuinfo", "/proc/uptime", "last ", "ipinfo.io/org"} {
		if strings.Contains(low, needle) {
			reconSignals++
		}
	}
	s.HasReconBundle = reconSignals >= 4
	s.HasShellProbe = strings.Contains(low, "shell_behavior") || (strings.Contains(low, "command not found") && strings.Contains(low, "no such file")) || (strings.Contains(low, "./xxxxxx") && strings.Contains(low, "xxxxxx"))
	return s
}

func shellWordPresent(low, word string) bool {
	for _, stage := range collectSSHCommandStages(low) {
		if stage == word {
			return true
		}
	}
	return false
}

func looksLikeArchitectureAwareDownloadExecute(low string, shape sshShellShape) bool {
	if !(shape.HasCurl || shape.HasWget) || !shape.HasChmod || !shape.HasCleanup {
		return false
	}
	if !shape.HasLocalExec && !strings.Contains(low, "| sh") && !strings.Contains(low, "| bash") {
		return false
	}
	return strings.Contains(low, "uname -m") || strings.Contains(low, "arch") || shape.Substitutions > 0
}

func looksLikeCompoundEnvironmentFingerprint(low string, shape sshShellShape) bool {
	if !shape.HasReconBundle {
		return false
	}
	assignments := 0
	for _, name := range []string{"uname=", "arch=", "uptime=", "cpus=", "cpu_model=", "gpu_info=", "last_output=", "filter_output="} {
		if strings.Contains(low, name) {
			assignments++
		}
	}
	return assignments >= 4 || shape.HasShellProbe
}

func looksLikePrivilegeFallbackChain(low string, shape sshShellShape) bool {
	if !shape.HasSudo || shape.OrCount < 2 {
		return false
	}
	// Observed installers try sudo-shell, sudo-direct, shell and direct forms.
	return strings.Contains(low, "sudo -s") || strings.Contains(low, "sudo -s ") || (strings.Contains(low, "sudo ") && shape.HasShell)
}
