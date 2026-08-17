package server

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
	"regexp"
	"strconv"
	"strings"
)

func virtualGNUUname(host string, args []string) string {
	if len(args) == 0 {
		return "Linux"
	}
	selected := map[rune]bool{}
	for _, a := range args {
		if a == "--all" || a == "-a" {
			for _, f := range "snrvmpio" {
				selected[f] = true
			}
			continue
		}
		if !strings.HasPrefix(a, "-") {
			continue
		}
		for _, f := range strings.TrimLeft(a, "-") {
			selected[f] = true
		}
	}
	// GNU coreutils emits fields in this canonical order, regardless of option order.
	order := []rune{'s', 'n', 'r', 'v', 'm', 'p', 'i', 'o'}
	values := map[rune]string{
		's': "Linux", 'n': host, 'r': virtualKernelRelease, 'v': virtualKernelVersion,
		'm': virtualMachineArch, 'p': virtualMachineArch, 'i': virtualMachineArch, 'o': "GNU/Linux",
	}
	var out []string
	for _, f := range order {
		if selected[f] {
			out = append(out, values[f])
		}
	}
	if len(out) == 0 {
		return "Linux"
	}
	return strings.Join(out, " ")
}

func virtualEchoOutput(cmd string, args []string) string {
	if cmd == "printf" {
		if len(args) == 0 {
			return ""
		}
		format := decodeVirtualEscapes(args[0])
		// Small bounded printf subset used by collectors: %s plus literal text.
		for _, a := range args[1:] {
			if strings.Contains(format, "%s") {
				format = strings.Replace(format, "%s", a, 1)
			}
		}
		return strings.ReplaceAll(format, "%%", "%")
	}
	interpret := false
	newline := true
	var vals []string
	for _, a := range args {
		if len(vals) == 0 && strings.HasPrefix(a, "-") && len(a) > 1 {
			known := true
			for _, c := range a[1:] {
				switch c {
				case 'e':
					interpret = true
				case 'E':
					interpret = false
				case 'n':
					newline = false
				default:
					known = false
				}
			}
			if known {
				continue
			}
		}
		vals = append(vals, a)
	}
	out := strings.Join(vals, " ")
	if interpret {
		out = decodeVirtualEscapes(out)
	}
	if newline {
		// Command output representation omits the terminal newline; pipeline code
		// re-adds it when needed, matching the rest of the virtual command model.
		out = strings.TrimSuffix(out, "\n")
	}
	return out
}

func decodeVirtualEscapes(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] != '\\' || i+1 >= len(v) {
			b.WriteByte(v[i])
			continue
		}
		i++
		switch v[i] {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case '\\':
			b.WriteByte('\\')
		case 'x':
			if i+2 < len(v) {
				if n, err := strconv.ParseUint(v[i+1:i+3], 16, 8); err == nil {
					b.WriteByte(byte(n))
					i += 2
					continue
				}
			}
			b.WriteString("\\x")
		case '0':
			j := i + 1
			for j < len(v) && j < i+4 && v[j] >= '0' && v[j] <= '7' {
				j++
			}
			if j > i+1 {
				if n, err := strconv.ParseUint(v[i+1:j], 8, 8); err == nil {
					b.WriteByte(byte(n))
					i = j - 1
					continue
				}
			}
			b.WriteByte(0)
		default:
			b.WriteByte('\\')
			b.WriteByte(v[i])
		}
	}
	return b.String()
}

func virtualSudoCommandArgs(args []string) ([]string, bool) {
	stdinPassword := false
	for len(args) > 0 {
		a := args[0]
		if a == "--" {
			return args[1:], stdinPassword
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			break
		}
		switch a {
		case "-S", "--stdin":
			stdinPassword = true
			args = args[1:]
		case "-n", "--non-interactive", "-H", "-E", "-k", "-K", "-b":
			args = args[1:]
		case "-u", "-g", "-h", "-p", "-C", "-T", "--user", "--group", "--host", "--prompt":
			if len(args) >= 2 {
				args = args[2:]
			} else {
				return nil, stdinPassword
			}
		default:
			// combined short options such as -Sn are common.
			if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") {
				if strings.Contains(a, "S") {
					stdinPassword = true
				}
				args = args[1:]
			} else {
				return args, stdinPassword
			}
		}
	}
	return args, stdinPassword
}

func (w *virtualSSHWorld) virtualGrep(args []string, input string) virtualSSHResult {
	r := virtualBaseResult("grep", "filesystem", 4, 87, "file-discovery", "text search")
	ignoreCase, invert, quiet, countOnly, onlyMatch, fixed := false, false, false, false, false, false
	maxMatches := 0
	var patterns, files []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			files = append(files, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "--") {
			switch a {
			case "--ignore-case":
				ignoreCase = true
			case "--invert-match":
				invert = true
			case "--quiet", "--silent":
				quiet = true
			case "--count":
				countOnly = true
			case "--only-matching":
				onlyMatch = true
			case "--fixed-strings":
				fixed = true
			}
			continue
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			if a == "-e" && i+1 < len(args) {
				patterns = append(patterns, args[i+1])
				i++
				continue
			}
			if a == "-m" && i+1 < len(args) {
				maxMatches, _ = strconv.Atoi(args[i+1])
				i++
				continue
			}
			if strings.HasPrefix(a, "-m") && len(a) > 2 {
				maxMatches, _ = strconv.Atoi(a[2:])
				continue
			}
			for _, f := range a[1:] {
				switch f {
				case 'i':
					ignoreCase = true
				case 'v':
					invert = true
				case 'q':
					quiet = true
				case 'c':
					countOnly = true
				case 'o':
					onlyMatch = true
				case 'F':
					fixed = true
				case 'E': /* Go regexp already extended */
				case 'h': /* omit filename */
				case 'e': /* value may be next token below */
				}
			}
			if strings.Contains(a, "e") && i+1 < len(args) {
				patterns = append(patterns, args[i+1])
				i++
			}
			continue
		}
		if len(patterns) == 0 {
			patterns = append(patterns, a)
		} else {
			files = append(files, a)
		}
	}
	if len(patterns) == 0 {
		r.Status = 2
		return r
	}
	data := input
	if data == "" && len(files) > 0 {
		var chunks []string
		for _, f := range files {
			if c, ok := w.virtualReadFile(f); ok {
				chunks = append(chunks, c)
			}
		}
		data = strings.Join(chunks, "\n")
	}
	var matchers []func(string) []string
	for _, pat := range patterns {
		p := pat
		if fixed {
			matchers = append(matchers, func(line string) []string {
				l, q := line, p
				if ignoreCase {
					l = strings.ToLower(l)
					q = strings.ToLower(q)
				}
				if strings.Contains(l, q) {
					return []string{p}
				}
				return nil
			})
			continue
		}
		prefix := ""
		if ignoreCase {
			prefix = "(?i)"
		}
		re, err := regexp.Compile(prefix + p)
		if err != nil {
			continue
		}
		matchers = append(matchers, func(line string) []string { return re.FindAllString(line, -1) })
	}
	var out []string
	matches := 0
	for _, line := range strings.Split(strings.TrimSuffix(data, "\n"), "\n") {
		var got []string
		for _, m := range matchers {
			if x := m(line); len(x) > 0 {
				got = x
				break
			}
		}
		ok := len(got) > 0
		if invert {
			ok = !ok
		}
		if !ok {
			continue
		}
		matches++
		if quiet {
			r.Status = 0
			return r
		}
		if onlyMatch && !invert {
			out = append(out, got...)
		} else {
			out = append(out, line)
		}
		if maxMatches > 0 && matches >= maxMatches {
			break
		}
	}
	if matches == 0 {
		r.Status = 1
		return r
	}
	if countOnly {
		r.Output = strconv.Itoa(matches)
	} else {
		r.Output = strings.Join(out, "\n")
	}
	return r
}

func parseVirtualSedSub(expr string) (pattern, replacement, flags string, ok bool) {
	if len(expr) < 4 || expr[0] != 's' {
		return
	}
	d := expr[1]
	var parts []string
	var b strings.Builder
	esc := false
	for i := 2; i < len(expr); i++ {
		c := expr[i]
		if esc {
			b.WriteByte('\\')
			b.WriteByte(c)
			esc = false
			continue
		}
		if c == '\\' {
			esc = true
			continue
		}
		if c == d {
			parts = append(parts, b.String())
			b.Reset()
			if len(parts) == 2 {
				flags = expr[i+1:]
				break
			}
			continue
		}
		b.WriteByte(c)
	}
	if len(parts) < 2 {
		return "", "", "", false
	}
	return parts[0], parts[1], flags, true
}

func simpleVirtualSed(data, expr string) string {
	// Support deletion address regexes and substitutions used by common collectors.
	var lines = []string{}
	for _, line := range strings.Split(strings.TrimSuffix(data, "\n"), "\n") {
		keep := true
		cur := line
		for _, raw := range strings.Split(expr, ";") {
			x := strings.TrimSpace(raw)
			if x == "" {
				continue
			}
			if strings.HasPrefix(x, "/") && strings.HasSuffix(x, "/d") {
				pat := strings.TrimSuffix(strings.TrimPrefix(x, "/"), "/d")
				if re, err := regexp.Compile(pat); err == nil && re.MatchString(cur) {
					keep = false
					break
				}
				continue
			}
			pat, repl, flags, ok := parseVirtualSedSub(x)
			if !ok {
				continue
			}
			re, err := regexp.Compile(pat)
			if err != nil {
				continue
			}
			if strings.Contains(flags, "g") {
				cur = re.ReplaceAllString(cur, repl)
			} else {
				loc := re.FindStringIndex(cur)
				if loc != nil {
					cur = cur[:loc[0]] + re.ReplaceAllString(cur[loc[0]:loc[1]], repl) + cur[loc[1]:]
				}
			}
		}
		if keep {
			lines = append(lines, cur)
		}
	}
	return strings.Join(lines, "\n")
}

func evalVirtualAwkExpr(expr string, fields []string) string {
	expr = strings.TrimSpace(expr)
	// Concatenation used by observed probes: $2" "$3 and comma-separated fields.
	var out strings.Builder
	for i := 0; i < len(expr); {
		if expr[i] == '$' {
			j := i + 1
			for j < len(expr) && expr[j] >= '0' && expr[j] <= '9' {
				j++
			}
			n, _ := strconv.Atoi(expr[i+1 : j])
			if n > 0 && n <= len(fields) {
				out.WriteString(fields[n-1])
			}
			i = j
			continue
		}
		if expr[i] == '"' {
			j := i + 1
			for j < len(expr) && expr[j] != '"' {
				j++
			}
			if j < len(expr) {
				out.WriteString(decodeVirtualEscapes(expr[i+1 : j]))
				i = j + 1
				continue
			}
		}
		if expr[i] == ',' {
			out.WriteByte(' ')
			i++
			continue
		}
		if expr[i] == ' ' || expr[i] == '\t' {
			i++
			continue
		}
		i++
	}
	return out.String()
}

func simpleVirtualAwk(data, program string, fieldSeparators ...string) string {
	program = strings.TrimSpace(program)
	fieldSep := ""
	if len(fieldSeparators) > 0 {
		fieldSep = strings.Trim(fieldSeparators[0], "'\"")
	}
	if fieldSep == "" && strings.Contains(program, "Model name") {
		fieldSep = ":"
	}
	selector := ""
	if a := strings.Index(program, "/"); a >= 0 {
		if b := strings.Index(program[a+1:], "/"); b >= 0 {
			selector = program[a+1 : a+1+b]
		}
	}
	body := program
	if i := strings.Index(body, "{"); i >= 0 {
		if j := strings.LastIndex(body, "}"); j > i {
			body = body[i+1 : j]
		}
	}
	printExpr := ""
	if i := strings.Index(body, "printf "); i >= 0 {
		printExpr = strings.TrimSpace(body[i+7:])
		if j := strings.Index(printExpr, ";"); j >= 0 {
			printExpr = printExpr[:j]
		}
	} else if i := strings.Index(body, "print "); i >= 0 {
		printExpr = strings.TrimSpace(body[i+6:])
		if j := strings.Index(printExpr, ";"); j >= 0 {
			printExpr = printExpr[:j]
		}
	}
	var out []string
	for _, row := range strings.Split(strings.TrimSuffix(data, "\n"), "\n") {
		if selector != "" {
			re, err := regexp.Compile(selector)
			if err != nil || !re.MatchString(row) {
				continue
			}
		}
		fields := strings.Fields(row)
		if fieldSep != "" {
			parts := []string(nil)
			if re, err := regexp.Compile(fieldSep); err == nil {
				parts = re.Split(row, -1)
			} else {
				parts = strings.Split(row, fieldSep)
			}
			fields = make([]string, len(parts))
			for i, p := range parts {
				// Common collector gsub() calls trim the selected field; keeping
				// split fields trimmed provides the same observable result without
				// implementing a general awk interpreter.
				fields[i] = strings.TrimSpace(p)
			}
		}
		if printExpr != "" {
			out = append(out, evalVirtualAwkExpr(printExpr, fields))
		} else {
			out = append(out, row)
		}
		if strings.Contains(body, "exit") {
			break
		}
	}
	return strings.Join(out, "\n")
}

func (w *virtualSSHWorld) virtualFileMode(target string) uint32 {
	target = path.Clean(target)
	if m := w.fileModes[target]; m != 0 {
		return m
	}
	base := path.Base(target)
	switch {
	case target == "/etc/shadow":
		return 0o640
	case strings.Contains(target, "/.ssh/") && (strings.HasPrefix(base, "id_") || base == "authorized_keys" || base == "config"):
		return 0o600
	case base == ".bash_history":
		return 0o600
	case base == ".env" || strings.HasSuffix(base, ".env.production") || strings.Contains(target, "/credentials"):
		return 0o640
	default:
		return 0o644
	}
}

func virtualDirMode(target string) uint32 {
	target = path.Clean(target)
	switch {
	case target == "/tmp" || target == "/var/tmp" || target == "/dev/shm":
		return 0o1777
	case target == "/root" || strings.HasSuffix(target, "/.ssh"):
		return 0o700
	case strings.HasPrefix(target, "/home/") && strings.Count(strings.TrimPrefix(target, "/home/"), "/") == 0:
		return 0o750
	default:
		return 0o755
	}
}

func (w *virtualSSHWorld) virtualFileImmutable(target string) bool {
	return strings.Contains(w.fileAttrs[path.Clean(target)], "i")
}

func (w *virtualSSHWorld) virtualWriteFailure(target string) string {
	if w.virtualFileImmutable(target) {
		return "Operation not permitted"
	}
	return "No space left on device"
}

func (w *virtualSSHWorld) packageInstalled(name string) bool {
	return w.installedPackages[strings.ToLower(path.Base(name))]
}

func virtualUserID(user string) int {
	switch strings.TrimSpace(user) {
	case "root":
		return 0
	case "svc-web":
		return 997
	case "svc-backup":
		return 998
	case "admin":
		return 1000
	default:
		return 1001 + int(stableSSHHash(strings.TrimSpace(user))%3000)
	}
}

func virtualUserPasswdEntry(user string) string {
	user = safeVirtualName(user)
	if user == "root" {
		return "root:x:0:0:root:/root:/bin/bash"
	}
	uid := virtualUserID(user)
	home := "/home/" + user
	return user + ":x:" + strconv.Itoa(uid) + ":" + strconv.Itoa(uid) + ":" + user + ":" + home + ":/bin/bash"
}

func virtualUserGroupEntry(user string) string {
	user = safeVirtualName(user)
	if user == "root" {
		return "root:x:0:"
	}
	uid := virtualUserID(user)
	return user + ":x:" + strconv.Itoa(uid) + ":"
}

func (w *virtualSSHWorld) virtualUserExists(user string) bool {
	user = safeVirtualName(user)
	prefix := user + ":"
	for _, row := range strings.Split(w.files["/etc/passwd"], "\n") {
		if strings.HasPrefix(row, prefix) {
			return true
		}
	}
	return false
}

func (w *virtualSSHWorld) updateVirtualShadowPassword(user, secret string) {
	user = safeVirtualName(user)
	sum := sha256.Sum256([]byte(w.peerKey + "|" + user + "|" + secret))
	token := hex.EncodeToString(sum[:12])
	day := w.system.snapshot().Now.Unix() / 86400
	rows := strings.Split(strings.TrimSuffix(w.files["/etc/shadow"], "\n"), "\n")
	for i, row := range rows {
		if strings.HasPrefix(row, user+":") {
			rows[i] = user + ":$y$j9T$" + token[:8] + "$" + token[8:] + ":" + strconv.FormatInt(day, 10) + ":0:99999:7:::"
			w.files["/etc/shadow"] = strings.Join(rows, "\n") + "\n"
			meta := w.fileMeta["/etc/shadow"]
			meta.ModTime = w.system.snapshot().Now
			meta.Size = int64(len(w.files["/etc/shadow"]))
			w.fileMeta["/etc/shadow"] = meta
			return
		}
	}
}
