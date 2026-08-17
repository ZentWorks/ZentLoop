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
	if (strings.HasPrefix(trimmed, "while ") || strings.HasPrefix(trimmed, "until ")) && (strings.HasSuffix(trimmed, " done") || strings.HasSuffix(trimmed, "; done")) {
		if r, ok := w.executeVirtualWhile(trimmed); ok {
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
		if r.TerminalAction == "continue" {
			combined.Status = 0
			continue
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

func (w *virtualSSHWorld) executeVirtualWhile(line string) (virtualSSHResult, bool) {
	until := strings.HasPrefix(line, "until ")
	prefix := "while "
	if until {
		prefix = "until "
	}
	bodyStart := strings.Index(line, "; do ")
	if bodyStart < 0 {
		return virtualSSHResult{}, false
	}
	condition := strings.TrimSpace(strings.TrimPrefix(line[:bodyStart], prefix))
	body := strings.TrimSpace(line[bodyStart+5:])
	body = strings.TrimSpace(strings.TrimSuffix(body, "done"))
	body = strings.TrimSpace(strings.TrimSuffix(body, ";"))
	if condition == "" {
		return virtualSSHResult{}, false
	}
	combined := virtualSSHResult{Status: 0, Family: "execution", CommandName: strings.TrimSpace(prefix), Depth: 5, Risk: 94, Persona: "shell-control-flow", Message: "simulated bounded shell loop"}
	var outputs []string
	for iteration := 0; iteration < 32; iteration++ {
		cond := w.executePipeline(w.expandVirtualLine(condition))
		run := cond.Status == 0
		if until {
			run = !run
		}
		if !run {
			combined.Status = 0
			break
		}
		r := w.Execute(body)
		if r.Output != "" {
			outputs = append(outputs, r.Output)
		}
		if r.Depth > combined.Depth {
			combined.Depth, combined.Risk, combined.Persona = r.Depth, maxInt(combined.Risk, r.Risk), r.Persona
		}
		combined.Status = r.Status
		if r.Exit {
			combined.Exit = true
			break
		}
		if r.TerminalAction == "break" {
			combined.Status = 0
			break
		}
		if r.TerminalAction == "continue" {
			combined.Status = 0
			continue
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
	if pos := strings.Index(body, "; elif "); pos >= 0 {
		thenBody = strings.TrimSpace(body[:pos])
		elseBody = "if " + strings.TrimSpace(body[pos+8:]) + "; fi"
	} else if pos := strings.Index(body, "; else "); pos >= 0 {
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
	r := virtualBaseResult("test", "shell", 3, 80, "shell-control-flow", "shell condition test")
	ok := w.evalVirtualTest(args)
	if !ok {
		r.Status = 1
	}
	return r
}

func (w *virtualSSHWorld) evalVirtualTest(args []string) bool {
	if len(args) == 0 {
		return false
	}
	if args[0] == "!" {
		return !w.evalVirtualTest(args[1:])
	}
	// The legacy `test` -a/-o operators still appear in compact installer
	// scripts. Keep evaluation bounded and left-associative for the simple forms
	// used by automation.
	for i := 1; i < len(args)-1; i++ {
		if args[i] == "-o" {
			return w.evalVirtualTest(args[:i]) || w.evalVirtualTest(args[i+1:])
		}
	}
	for i := 1; i < len(args)-1; i++ {
		if args[i] == "-a" {
			return w.evalVirtualTest(args[:i]) && w.evalVirtualTest(args[i+1:])
		}
	}
	if len(args) >= 3 {
		left, op, right := args[0], args[1], args[2]
		switch op {
		case "=", "==":
			return left == right
		case "!=":
			return left != right
		case "-eq", "-ne", "-gt", "-ge", "-lt", "-le":
			a, ea := strconv.ParseInt(left, 10, 64)
			b, eb := strconv.ParseInt(right, 10, 64)
			if ea != nil || eb != nil {
				return false
			}
			switch op {
			case "-eq":
				return a == b
			case "-ne":
				return a != b
			case "-gt":
				return a > b
			case "-ge":
				return a >= b
			case "-lt":
				return a < b
			case "-le":
				return a <= b
			}
		case "-nt", "-ot":
			lm, lok := w.fileMeta[w.resolve(left)]
			rm, rok := w.fileMeta[w.resolve(right)]
			if !lok || !rok {
				return false
			}
			if op == "-nt" {
				return lm.ModTime.After(rm.ModTime)
			}
			return lm.ModTime.Before(rm.ModTime)
		}
	}
	if len(args) >= 2 {
		op, value := args[0], args[1]
		resolved := w.resolve(value)
		content, fileOK := w.virtualReadFile(resolved)
		switch op {
		case "-f":
			return fileOK && !w.dirs[resolved]
		case "-d":
			return w.dirs[resolved]
		case "-e":
			return fileOK || w.dirs[resolved]
		case "-x":
			return fileOK && w.virtualFileMode(resolved)&0o111 != 0
		case "-r":
			return w.virtualFileReadable(value)
		case "-w":
			return w.virtualFileWritable(value)
		case "-s":
			return fileOK && len(content) > 0
		case "-L", "-h":
			// The current virtual filesystem does not advertise symlinks as such;
			// a copied virtual file must not falsely claim to be one.
			return false
		case "-n":
			return value != ""
		case "-z":
			return value == ""
		}
	}
	return len(args) == 1 && args[0] != ""
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
