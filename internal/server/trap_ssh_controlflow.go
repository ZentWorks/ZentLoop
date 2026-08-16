package server

import (
	"path"
	"strconv"
	"strings"
)

// executeVirtualControlFlow handles a deliberately small, bounded subset of
// POSIX shell control flow commonly used by automated reconnaissance and
// dropper scripts. It never delegates to a real shell.
func (w *virtualSSHWorld) executeVirtualControlFlow(line, input string) (virtualSSHResult, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return virtualSSHResult{}, false
	}
	if strings.HasPrefix(trimmed, "for ") && strings.HasSuffix(trimmed, " done") || strings.HasSuffix(trimmed, "; done") {
		if r, ok := w.executeVirtualFor(trimmed); ok {
			return r, true
		}
	}
	if strings.HasPrefix(trimmed, "if ") && strings.Contains(trimmed, "; then ") && (strings.HasSuffix(trimmed, " fi") || strings.HasSuffix(trimmed, "; fi")) {
		if r, ok := w.executeVirtualIf(trimmed, input); ok {
			return r, true
		}
	}
	return virtualSSHResult{}, false
}

func (w *virtualSSHWorld) executeVirtualFor(line string) (virtualSSHResult, bool) {
	// Supported form: for name in words...; do commands...; done
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
	if len(values) > 64 { // hard bound; this is a simulator, not a shell runtime.
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

func (w *virtualSSHWorld) executeVirtualIf(line, input string) (virtualSSHResult, bool) {
	thenPos := strings.Index(line, "; then ")
	if thenPos < 0 {
		return virtualSSHResult{}, false
	}
	condition := strings.TrimSpace(strings.TrimPrefix(line[:thenPos], "if "))
	rest := strings.TrimSpace(line[thenPos+7:])
	rest = strings.TrimSpace(strings.TrimSuffix(rest, "fi"))
	rest = strings.TrimSpace(strings.TrimSuffix(rest, ";"))
	thenBody, elseBody := rest, ""
	if pos := strings.Index(rest, "; else "); pos >= 0 {
		thenBody = strings.TrimSpace(rest[:pos])
		elseBody = strings.TrimSpace(rest[pos+7:])
	}
	negate := false
	if strings.HasPrefix(condition, "! ") {
		negate = true
		condition = strings.TrimSpace(strings.TrimPrefix(condition, "! "))
	}
	cond := w.executePipeline(w.expandVirtualLine(condition))
	ok := cond.Status == 0
	if negate {
		ok = !ok
	}
	body := elseBody
	if ok {
		body = thenBody
	}
	if body == "" {
		return virtualSSHResult{Status: 0, Family: "execution", CommandName: "if", Depth: 5, Risk: 94, Persona: "shell-control-flow", Message: "simulated shell conditional"}, true
	}
	r := w.Execute(body)
	r.CommandName = "if"
	r.Family = "execution"
	r.Depth = maxInt(r.Depth, 5)
	r.Risk = maxInt(r.Risk, 94)
	r.Persona = "shell-control-flow"
	r.Message = "simulated shell conditional"
	return r, true
}

func (w *virtualSSHWorld) virtualTest(args []string) virtualSSHResult {
	r := virtualBaseResult("test", "filesystem", 3, 82, "file-discovery", "shell condition test")
	negate := false
	if len(args) > 0 && args[0] == "!" {
		negate = true
		args = args[1:]
	}
	ok := false
	if len(args) >= 2 {
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
			meta, exists := w.fileMeta[resolved]
			ok = exists && (meta.Kind == "elf" || strings.HasPrefix(w.files[resolved], "#!") || w.looksLikeStagedPayload(path.Base(resolved)))
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
	markers := []struct {
		text string
		op   string
	}{{"&& if ", "&&"}, {"; if ", ";"}}
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
