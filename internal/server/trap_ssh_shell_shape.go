package server

import "strings"

// sshShellShape is deliberately a bounded structural summary, not a Bash parser.
// It recognizes top-level control operators while respecting basic quotes and escapes.
type sshShellShape struct {
	AndCount, OrCount, SequenceCount, PipelineCount int
	SubstitutionCount, GroupCount                   int
}

func inspectSSHShellShape(command string) sshShellShape {
	var s sshShellShape
	if len(command) > 32768 {
		command = command[:32768]
	}
	var quote byte
	escaped := false
	depth := 0
	for i := 0; i < len(command); i++ {
		c := command[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' || c == '`' {
			quote = c
			if c == '`' {
				s.SubstitutionCount++
			}
			continue
		}
		if c == '$' && i+1 < len(command) && command[i+1] == '(' {
			s.SubstitutionCount++
			depth++
			i++
			continue
		}
		if c == '(' || c == '{' {
			depth++
			s.GroupCount++
			continue
		}
		if c == ')' || c == '}' {
			if depth > 0 {
				depth--
			}
			continue
		}
		if depth != 0 {
			continue
		}
		switch c {
		case '&':
			if i+1 < len(command) && command[i+1] == '&' {
				s.AndCount++
				i++
			}
		case '|':
			if i+1 < len(command) && command[i+1] == '|' {
				s.OrCount++
				i++
			} else {
				s.PipelineCount++
			}
		case ';':
			s.SequenceCount++
		}
	}
	return s
}

func looksLikeArchitectureAwareDownloadExecute(low string, shape sshShellShape) bool {
	download := strings.Contains(low, "curl ") || strings.Contains(low, "wget ")
	arch := strings.Contains(low, "uname -m") || strings.Contains(low, "$(uname") || strings.Contains(low, "${arch") || strings.Contains(low, "$arch") || strings.Contains(low, " aarch64") || strings.Contains(low, "x86_64")
	exec := strings.Contains(low, "chmod +x") && (strings.Contains(low, "./") || strings.Contains(low, "sh "))
	cleanup := strings.Contains(low, "rm ") || strings.Contains(low, "rm -")
	return download && arch && exec && cleanup && (shape.AndCount+shape.OrCount+shape.SequenceCount >= 2)
}

func looksLikeCompoundEnvironmentFingerprint(low string, shape sshShellShape) bool {
	signals := 0
	for _, n := range []string{"uname", "/proc/uptime", "nproc", "/proc/cpuinfo", "lscpu", "lspci", "nvidia", "/etc/os-release", "last ", "shell_behavior", "xxxxxx"} {
		if strings.Contains(low, n) {
			signals++
		}
	}
	return signals >= 4 && (shape.SubstitutionCount >= 2 || shape.SequenceCount >= 2 || shape.OrCount >= 2)
}

func looksLikePrivilegeFallbackChain(low string, shape sshShellShape) bool {
	return strings.Contains(low, "sudo") && (shape.OrCount >= 2 || strings.Contains(low, "|| sh -c") || strings.Contains(low, "|| nproc") || strings.Contains(low, "|| /usr/bin/"))
}
