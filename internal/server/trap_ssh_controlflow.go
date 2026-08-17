package server

import (
	"path/filepath"
	"strconv"
	"strings"
)

// executeVirtualControlFlow handles a deliberately small, bounded subset of
// POSIX shell control flow commonly used by reconnaissance/dropper scripts.
// It never delegates to a real shell.
func (w *virtualSSHWorld) executeVirtualControlFlow(line, input string) (virtualSSHResult, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return virtualSSHResult{}, false
	}
	if strings.HasPrefix(trimmed, "case ") && strings.Contains(trimmed, " in") && strings.Contains(trimmed, "esac") {
		return w.executeVirtualCase(trimmed, input)
	}
	if strings.HasPrefix(trimmed, "for ") && (strings.HasSuffix(trimmed, " done") || strings.HasSuffix(trimmed, "; done")) {
		if r, ok := w.executeVirtualFor(trimmed); ok {
			return r, true
		}
	}
	if strings.HasPrefix(trimmed, "if ") && strings.Contains(trimmed, "; then ") && strings.Contains(trimmed, " fi") {
		if r, ok := w.executeVirtualIf(trimmed, input); ok {
			return r, true
		}
	}
	return virtualSSHResult{}, false
}

func (w *virtualSSHWorld) executeVirtualFor(line string) (virtualSSHResult, bool) {
	bodyStart := strings.Index(line, "; do ")
	if bodyStart < 0 {
		return virtualSSHResult{}, false
	}
	header := strings.TrimSpace(strings.TrimPrefix(line[:bodyStart], "for "))
	body := strings.TrimSpace(line[bodyStart+5:])
	body = strings.TrimSpace(strings.TrimSuffix(body, "done"))
	body = strings.TrimSpace(strings.TrimSuffix(body, ";"))
	varName, valuesText, ok := strings.Cut(header, " in ")
	varName = strings.TrimSpace(varName)
	if !ok || !validVirtualEnvName(varName) {
		return virtualSSHResult{}, false
	}
	values := virtualWords(w.expandVirtualLine(valuesText))
	if len(values) > 64 {
		values = values[:64]
	}
	combined := virtualSSHResult{Status: 0, Family: "execution", CommandName: "for", Depth: 5, Risk: 94, Persona: "shell-control-flow", Message: "simulated shell loop"}
	var outputs []string
	for _, value := range values {
		w.env[varName] = value
		r := w.Execute(body)
		if r.Output != "" {
			outputs = append(outputs, r.Output)
		}
		if r.Depth >= combined.Depth {
			combined.Depth, combined.Risk, combined.Persona, combined.Message = r.Depth, r.Risk, r.Persona, r.Message
		}
		combined.Status = r.Status
		if r.TerminalAction == "break" {
			combined.Status = 0
			break
		}
		if r.Exit {
			combined.Exit = true
			break
		}
	}
	combined.Output = strings.Join(outputs, "\n")
	combined.TerminalAction = ""
	return combined, true
}

func splitVirtualIfBody(rest string) (thenBody, elseBody, suffix string) {
	// Find the first top-level ; fi and preserve commands that follow it.
	fi := strings.Index(rest, "; fi")
	if fi < 0 {
		fi = strings.Index(rest, " fi")
	}
	body := rest
	if fi >= 0 {
		body = strings.TrimSpace(rest[:fi])
		rem := strings.TrimSpace(rest[fi:])
		if strings.HasPrefix(rem, "; fi") {
			rem = strings.TrimSpace(strings.TrimPrefix(rem, "; fi"))
		} else {
			rem = strings.TrimSpace(strings.TrimPrefix(rem, "fi"))
		}
		rem = strings.TrimPrefix(rem, ";")
		suffix = strings.TrimSpace(rem)
	}
	thenBody = body
	if pos := strings.Index(body, "; else "); pos >= 0 {
		thenBody = strings.TrimSpace(body[:pos])
		elseBody = strings.TrimSpace(body[pos+7:])
	}
	return
}

func (w *virtualSSHWorld) executeVirtualIf(line, input string) (virtualSSHResult, bool) {
	thenPos := strings.Index(line, "; then ")
	if thenPos < 0 {
		return virtualSSHResult{}, false
	}
	condition := strings.TrimSpace(strings.TrimPrefix(line[:thenPos], "if "))
	rest := strings.TrimSpace(line[thenPos+7:])
	thenBody, elseBody, suffix := splitVirtualIfBody(rest)
	negate := false
	if strings.HasPrefix(condition, "! ") {
		negate = true
		condition = strings.TrimSpace(strings.TrimPrefix(condition, "! "))
	}
	cond := w.executePipeline(w.expandVirtualLine(condition), input)
	ok := cond.Status == 0
	if negate {
		ok = !ok
	}
	body := elseBody
	if ok {
		body = thenBody
	}
	r := virtualSSHResult{Status: 0, Family: "execution", CommandName: "if", Depth: 5, Risk: 94, Persona: "shell-control-flow", Message: "simulated shell conditional"}
	if body != "" {
		r = w.Execute(body)
		r.CommandName = "if"
		r.Family = "execution"
		r.Depth = maxInt(r.Depth, 5)
		r.Risk = maxInt(r.Risk, 94)
		r.Persona = "shell-control-flow"
		r.Message = "simulated shell conditional"
	}
	if suffix != "" && !r.Exit {
		tail := w.Execute(suffix)
		if r.Output != "" && tail.Output != "" {
			r.Output += "\n" + tail.Output
		} else if r.Output == "" {
			r.Output = tail.Output
		}
		r.Status = tail.Status
		r.Exit = tail.Exit
		if tail.Depth > r.Depth {
			r.Depth = tail.Depth
			r.Risk = maxInt(r.Risk, tail.Risk)
		}
	}
	return r, true
}

func (w *virtualSSHWorld) executeVirtualCase(line, input string) (virtualSSHResult, bool) {
	bodyStart := strings.Index(line, " in")
	if bodyStart < 0 {
		return virtualSSHResult{}, false
	}
	expr := strings.TrimSpace(strings.TrimPrefix(line[:bodyStart], "case "))
	rest := strings.TrimSpace(line[bodyStart+3:])
	if i := strings.LastIndex(rest, "esac"); i >= 0 {
		rest = strings.TrimSpace(rest[:i])
	}
	value := strings.TrimSpace(w.expandVirtualLine(expr))
	value = strings.Trim(value, "'\"")
	clauses := strings.Split(rest, ";;")
	for _, cl := range clauses {
		cl = strings.TrimSpace(cl)
		pos := strings.Index(cl, ")")
		if pos < 0 {
			continue
		}
		patterns := strings.Split(strings.TrimSpace(cl[:pos]), "|")
		command := strings.TrimSpace(cl[pos+1:])
		for _, pat := range patterns {
			pat = strings.Trim(strings.TrimSpace(pat), "'\"")
			matched, _ := filepath.Match(pat, value)
			if pat == "*" {
				matched = true
			}
			if matched {
				r := w.Execute(command)
				r.CommandName = "case"
				r.Family = "execution"
				r.Depth = maxInt(r.Depth, 4)
				r.Risk = maxInt(r.Risk, 88)
				r.Persona = "shell-control-flow"
				r.Message = "simulated shell case branch"
				return r, true
			}
		}
	}
	return virtualSSHResult{Status: 0, Family: "execution", CommandName: "case", Depth: 4, Risk: 88, Persona: "shell-control-flow", Message: "simulated shell case branch"}, true
}

func (w *virtualSSHWorld) virtualTest(args []string) virtualSSHResult {
	r := virtualBaseResult("test", "filesystem", 3, 82, "file-discovery", "shell condition test")
	negate := false
	if len(args) > 0 && args[0] == "!" {
		negate = true
		args = args[1:]
	}
	ok := false
	if len(args) >= 3 {
		left, op, right := args[0], args[1], args[2]
		switch op {
		case "=", "==":
			ok = left == right
		case "!=":
			ok = left != right
		case "-eq", "-ne", "-gt", "-ge", "-lt", "-le":
			a, ea := strconv.ParseInt(left, 10, 64)
			b, eb := strconv.ParseInt(right, 10, 64)
			if ea == nil && eb == nil {
				switch op {
				case "-eq":
					ok = a == b
				case "-ne":
					ok = a != b
				case "-gt":
					ok = a > b
				case "-ge":
					ok = a >= b
				case "-lt":
					ok = a < b
				case "-le":
					ok = a <= b
				}
			}
		}
	} else if len(args) >= 2 {
		op, value := args[0], args[1]
		switch op {
		case "-f":
			resolved := w.resolve(value)
			_, fileOK := w.virtualReadFile(resolved)
			ok = fileOK && !w.dirs[resolved]
		case "-d":
			ok = w.dirs[w.resolve(value)]
		case "-e":
			resolved := w.resolve(value)
			_, fileOK := w.virtualReadFile(resolved)
			ok = fileOK || w.dirs[resolved]
		case "-x":
			resolved := w.resolve(value)
			_, exists := w.fileMeta[resolved]
			ok = exists && w.virtualFileMode(resolved)&0o111 != 0
		case "-n":
			ok = value != ""
		case "-z":
			ok = value == ""
		}
	} else if len(args) == 1 {
		ok = args[0] != ""
	}
	if negate {
		ok = !ok
	}
	if !ok {
		r.Status = 1
	}
	return r
}

func parseVirtualPIDArg(v string) (int, bool) {
	pid, err := strconv.Atoi(strings.TrimSpace(v))
	return pid, err == nil && pid > 0
}

func (w *virtualSSHWorld) executeEmbeddedVirtualIf(line, input string) (virtualSSHResult, bool) {
	markers := []struct{ text, op string }{{"&& if ", "&&"}, {"; if ", ";"}}
	best := -1
	var marker struct{ text, op string }
	for _, m := range markers {
		if i := strings.Index(line, m.text); i >= 0 && (best < 0 || i < best) {
			best = i
			marker = m
		}
	}
	if best < 0 {
		return virtualSSHResult{}, false
	}
	prefix := strings.TrimSpace(line[:best])
	ifLine := "if " + strings.TrimSpace(line[best+len(marker.text):])
	pre := w.executeWithInput(prefix, "")
	if marker.op == "&&" && pre.Status != 0 {
		return pre, true
	}
	cond, ok := w.executeVirtualIf(ifLine, input)
	if !ok {
		return virtualSSHResult{}, false
	}
	if pre.Output != "" && cond.Output != "" {
		cond.Output = pre.Output + "\n" + cond.Output
	} else if cond.Output == "" {
		cond.Output = pre.Output
	}
	return cond, true
}
