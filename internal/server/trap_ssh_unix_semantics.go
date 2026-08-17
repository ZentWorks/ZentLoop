package server

import (
	"fmt"
	"path"
	"strconv"
	"strings"
)

type virtualEnvAssignment struct {
	name  string
	value string
}

// virtualCommandEnvPrefix peels only leading NAME=value words and returns the
// untouched command suffix. Keeping the original suffix is important: joining
// tokenized words would destroy quotes in commands such as LC_ALL=C awk '{...}'.
func virtualCommandEnvPrefix(raw string) (string, []virtualEnvAssignment) {
	pos := 0
	var assigns []virtualEnvAssignment
	for {
		word, start, end, ok := nextVirtualShellWord(raw, pos)
		if !ok {
			if len(assigns) > 0 {
				return "", assigns
			}
			return raw, nil
		}
		name, value, assignment := strings.Cut(word, "=")
		if !assignment || !validVirtualEnvName(name) {
			if len(assigns) == 0 {
				return raw, nil
			}
			return strings.TrimSpace(raw[start:]), assigns
		}
		assigns = append(assigns, virtualEnvAssignment{name: name, value: value})
		pos = end
	}
}

func nextVirtualShellWord(raw string, pos int) (word string, start, end int, ok bool) {
	for pos < len(raw) && (raw[pos] == ' ' || raw[pos] == '\t' || raw[pos] == '\r' || raw[pos] == '\n') {
		pos++
	}
	if pos >= len(raw) {
		return "", 0, 0, false
	}
	start = pos
	var b strings.Builder
	var quote byte
	for pos < len(raw) {
		c := raw[pos]
		if quote == '\'' {
			if c == '\'' {
				quote = 0
			} else {
				b.WriteByte(c)
			}
			pos++
			continue
		}
		if quote == '"' {
			if c == '"' {
				quote = 0
				pos++
				continue
			}
			if c == '\\' && pos+1 < len(raw) {
				n := raw[pos+1]
				if n == '$' || n == '`' || n == '"' || n == '\\' || n == '\n' {
					b.WriteByte(n)
					pos += 2
					continue
				}
			}
			b.WriteByte(c)
			pos++
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			pos++
			continue
		}
		if c == '\\' && pos+1 < len(raw) {
			b.WriteByte(raw[pos+1])
			pos += 2
			continue
		}
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			break
		}
		b.WriteByte(c)
		pos++
	}
	return b.String(), start, pos, true
}

func (w *virtualSSHWorld) applyTemporaryEnv(assigns []virtualEnvAssignment) func() {
	type oldValue struct {
		value string
		set   bool
	}
	old := make(map[string]oldValue, len(assigns))
	for _, a := range assigns {
		if _, seen := old[a.name]; !seen {
			v, ok := w.env[a.name]
			old[a.name] = oldValue{value: v, set: ok}
		}
		w.env[a.name] = w.expandVirtualLine(a.value)
	}
	return func() {
		for name, before := range old {
			if before.set {
				w.env[name] = before.value
			} else {
				delete(w.env, name)
			}
		}
	}
}

func (w *virtualSSHWorld) executeVirtualEnv(args []string, input string) (virtualSSHResult, bool) {
	r := virtualBaseResult("env", "recon", 3, 82, "environment-discovery", "environment inspection")
	ignoreEnvironment := false
	var assigns []virtualEnvAssignment
	i := 0
	for i < len(args) {
		if args[i] == "-i" || args[i] == "--ignore-environment" {
			ignoreEnvironment = true
			i++
			continue
		}
		name, value, ok := strings.Cut(args[i], "=")
		if !ok || !validVirtualEnvName(name) {
			break
		}
		assigns = append(assigns, virtualEnvAssignment{name: name, value: value})
		i++
	}

	// `env -i` is intentionally scoped to this invocation. Copy/restore the map
	// rather than mutating the virtual machine's persistent environment.
	original := make(map[string]string, len(w.env))
	for k, v := range w.env {
		original[k] = v
	}
	if ignoreEnvironment {
		for k := range w.env {
			delete(w.env, k)
		}
	}
	restoreAssigns := w.applyTemporaryEnv(assigns)
	defer func() {
		restoreAssigns()
		if ignoreEnvironment {
			for k := range w.env {
				delete(w.env, k)
			}
			for k, v := range original {
				w.env[k] = v
			}
		}
	}()

	if i == len(args) {
		r.Output = w.virtualEnvOutput(nil)
		return r, true
	}
	inner := strings.Join(args[i:], " ")
	res := w.executeOne(inner, input)
	return res, true
}

func virtualFormatPrintf(format string, args []string) string {
	format = decodeVirtualEscapes(format)
	arg := 0
	var out strings.Builder
	for pass := 0; pass < 64; pass++ {
		usedConversion := false
		for i := 0; i < len(format); {
			if format[i] != '%' {
				out.WriteByte(format[i])
				i++
				continue
			}
			if i+1 < len(format) && format[i+1] == '%' {
				out.WriteByte('%')
				i += 2
				continue
			}
			j := i + 1
			zeroPad := false
			if j < len(format) && format[j] == '0' {
				zeroPad = true
				j++
			}
			widthStart := j
			for j < len(format) && format[j] >= '0' && format[j] <= '9' {
				j++
			}
			width := 0
			if j > widthStart {
				width, _ = strconv.Atoi(format[widthStart:j])
			}
			if j >= len(format) {
				out.WriteString(format[i:])
				i = len(format)
				continue
			}
			conv := format[j]
			value := ""
			if arg < len(args) {
				value = args[arg]
			}
			arg++
			usedConversion = true
			formatted := value
			switch conv {
			case 's':
			case 'b':
				formatted = decodeVirtualEscapes(value)
			case 'c':
				if value != "" {
					formatted = value[:1]
				}
			case 'd', 'i', 'u', 'x', 'X', 'o':
				n, _ := strconv.ParseInt(strings.TrimSpace(value), 0, 64)
				base := 10
				if conv == 'x' || conv == 'X' {
					base = 16
				} else if conv == 'o' {
					base = 8
				}
				formatted = strconv.FormatInt(n, base)
				if conv == 'X' {
					formatted = strings.ToUpper(formatted)
				}
			default:
				out.WriteByte('%')
				out.WriteByte(conv)
				i = j + 1
				continue
			}
			if width > len(formatted) {
				pad := " "
				if zeroPad {
					pad = "0"
				}
				formatted = strings.Repeat(pad, width-len(formatted)) + formatted
			}
			out.WriteString(formatted)
			i = j + 1
		}
		if arg >= len(args) || !usedConversion {
			break
		}
	}
	return out.String()
}

func (w *virtualSSHWorld) virtualReadBuiltin(args []string, input string) virtualSSHResult {
	r := virtualBaseResult("read", "shell", 2, 74, "interactive-shell", "shell input read")
	var names []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		names = append(names, a)
	}
	if len(names) == 0 {
		names = []string{"REPLY"}
	}
	if input == "" || input == "\x00ZL_EMPTY_STDIN\x00" {
		r.Status = 1
		return r
	}
	line := strings.SplitN(input, "\n", 2)[0]
	fields := strings.Fields(line)
	for i, name := range names {
		if !validVirtualEnvName(name) {
			continue
		}
		if len(names) == 1 {
			w.env[name] = line
			continue
		}
		if i == len(names)-1 {
			if i < len(fields) {
				w.env[name] = strings.Join(fields[i:], " ")
			} else {
				w.env[name] = ""
			}
		} else if i < len(fields) {
			w.env[name] = fields[i]
		} else {
			w.env[name] = ""
		}
	}
	return r
}

func virtualSeq(args []string) (string, int) {
	var nums []int64
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		n, err := strconv.ParseInt(a, 10, 64)
		if err != nil {
			return "seq: invalid floating point argument: ‘" + a + "’", 1
		}
		nums = append(nums, n)
	}
	start, step, end := int64(1), int64(1), int64(0)
	switch len(nums) {
	case 1:
		end = nums[0]
	case 2:
		start, end = nums[0], nums[1]
	case 3:
		start, step, end = nums[0], nums[1], nums[2]
	default:
		return "seq: missing operand", 1
	}
	if step == 0 {
		return "seq: invalid Zero increment value: ‘0’", 1
	}
	var rows []string
	for n, count := start, 0; count < 4096 && ((step > 0 && n <= end) || (step < 0 && n >= end)); n, count = n+step, count+1 {
		rows = append(rows, strconv.FormatInt(n, 10))
	}
	return strings.Join(rows, "\n"), 0
}

func virtualExpr(args []string) (string, int) {
	if len(args) == 0 {
		return "expr: missing operand", 2
	}
	if len(args) == 1 {
		if args[0] == "" || args[0] == "0" {
			return args[0], 1
		}
		return args[0], 0
	}
	if len(args) >= 3 {
		left, op, right := args[0], args[1], args[2]
		a, ea := strconv.ParseInt(left, 10, 64)
		b, eb := strconv.ParseInt(right, 10, 64)
		if ea == nil && eb == nil {
			switch op {
			case "+":
				return strconv.FormatInt(a+b, 10), 0
			case "-":
				return strconv.FormatInt(a-b, 10), 0
			case "*":
				return strconv.FormatInt(a*b, 10), 0
			case "/":
				if b == 0 {
					return "expr: division by zero", 2
				}
				return strconv.FormatInt(a/b, 10), 0
			case "%":
				if b == 0 {
					return "expr: division by zero", 2
				}
				return strconv.FormatInt(a%b, 10), 0
			case "=", "==":
				if a == b {
					return "1", 0
				}
				return "0", 1
			case "!=":
				if a != b {
					return "1", 0
				}
				return "0", 1
			case ">":
				if a > b {
					return "1", 0
				}
				return "0", 1
			case "<":
				if a < b {
					return "1", 0
				}
				return "0", 1
			}
		}
		switch op {
		case "=", "==":
			if left == right {
				return "1", 0
			}
			return "0", 1
		case "!=":
			if left != right {
				return "1", 0
			}
			return "0", 1
		}
	}
	return strings.Join(args, " "), 0
}

func (w *virtualSSHWorld) virtualGetconf(args []string) virtualSSHResult {
	r := virtualBaseResult("getconf", "recon", 3, 80, "system-recon", "system configuration discovery")
	key := ""
	if len(args) > 0 {
		key = args[len(args)-1]
	}
	values := map[string]string{
		"_NPROCESSORS_ONLN": strconv.Itoa(virtualCPUCount),
		"NPROCESSORS_ONLN":  strconv.Itoa(virtualCPUCount),
		"PAGESIZE":          "4096",
		"PAGE_SIZE":         "4096",
		"LONG_BIT":          "64",
		"GNU_LIBC_VERSION":  "glibc 2.39",
	}
	if value, ok := values[key]; ok {
		r.Output = value
		return r
	}
	r.Output = fmt.Sprintf("getconf: Unrecognized variable `%s'", key)
	r.Status = 2
	return r
}

func (w *virtualSSHWorld) virtualFileReadable(target string) bool {
	resolved := w.resolve(target)
	if _, ok := w.virtualReadFile(resolved); !ok {
		return false
	}
	mode := w.virtualFileMode(resolved)
	if w.user == "root" {
		return true
	}
	return mode&0o444 != 0
}

func (w *virtualSSHWorld) virtualFileWritable(target string) bool {
	resolved := w.resolve(target)
	if w.virtualFileImmutable(resolved) {
		return false
	}
	if _, ok := w.virtualReadFile(resolved); ok {
		if w.user == "root" {
			return true
		}
		return w.virtualFileMode(resolved)&0o222 != 0
	}
	parent := path.Dir(resolved)
	return w.dirs[parent] && (w.user == "root" || virtualDirMode(parent)&0o002 != 0)
}

type virtualArithmeticParser struct {
	s string
	i int
	w *virtualSSHWorld
}

func (p *virtualArithmeticParser) skip() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
}

func (p *virtualArithmeticParser) parseExpr() (int64, bool) {
	left, ok := p.parseTerm()
	if !ok {
		return 0, false
	}
	for {
		p.skip()
		if p.i >= len(p.s) || (p.s[p.i] != '+' && p.s[p.i] != '-') {
			return left, true
		}
		op := p.s[p.i]
		p.i++
		right, ok := p.parseTerm()
		if !ok {
			return 0, false
		}
		if op == '+' {
			left += right
		} else {
			left -= right
		}
	}
}

func (p *virtualArithmeticParser) parseTerm() (int64, bool) {
	left, ok := p.parseFactor()
	if !ok {
		return 0, false
	}
	for {
		p.skip()
		if p.i >= len(p.s) || (p.s[p.i] != '*' && p.s[p.i] != '/' && p.s[p.i] != '%') {
			return left, true
		}
		op := p.s[p.i]
		p.i++
		right, ok := p.parseFactor()
		if !ok {
			return 0, false
		}
		if (op == '/' || op == '%') && right == 0 {
			return 0, false
		}
		switch op {
		case '*':
			left *= right
		case '/':
			left /= right
		case '%':
			left %= right
		}
	}
}

func (p *virtualArithmeticParser) parseFactor() (int64, bool) {
	p.skip()
	if p.i >= len(p.s) {
		return 0, false
	}
	if p.s[p.i] == '+' || p.s[p.i] == '-' {
		op := p.s[p.i]
		p.i++
		v, ok := p.parseFactor()
		if !ok {
			return 0, false
		}
		if op == '-' {
			v = -v
		}
		return v, true
	}
	if p.s[p.i] == '(' {
		p.i++
		v, ok := p.parseExpr()
		if !ok {
			return 0, false
		}
		p.skip()
		if p.i >= len(p.s) || p.s[p.i] != ')' {
			return 0, false
		}
		p.i++
		return v, true
	}
	start := p.i
	if p.s[p.i] >= '0' && p.s[p.i] <= '9' {
		p.i++
		if p.i < len(p.s) && p.s[start] == '0' && (p.s[p.i] == 'x' || p.s[p.i] == 'X') {
			p.i++
			for p.i < len(p.s) {
				c := p.s[p.i]
				if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
					p.i++
					continue
				}
				break
			}
		} else {
			for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
				p.i++
			}
		}
		v, err := strconv.ParseInt(p.s[start:p.i], 0, 64)
		return v, err == nil
	}
	for p.i < len(p.s) {
		c := p.s[p.i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			p.i++
			continue
		}
		break
	}
	if p.i == start {
		return 0, false
	}
	name := p.s[start:p.i]
	v, _ := strconv.ParseInt(strings.TrimSpace(p.w.virtualVariable(name)), 0, 64)
	return v, true
}

func (w *virtualSSHWorld) evalVirtualArithmetic(expr string) (int64, bool) {
	if len(expr) > 256 {
		return 0, false
	}
	p := &virtualArithmeticParser{s: expr, w: w}
	v, ok := p.parseExpr()
	p.skip()
	return v, ok && p.i == len(p.s)
}

func (w *virtualSSHWorld) expandVirtualArithmetic(line string) string {
	for pass := 0; pass < 12; pass++ {
		start := -1
		var quote byte
		for i := 0; i+2 < len(line); i++ {
			c := line[i]
			if c == '\\' {
				i++
				continue
			}
			if quote == '\'' {
				if c == '\'' {
					quote = 0
				}
				continue
			}
			if c == '\'' {
				quote = '\''
				continue
			}
			if c == '"' {
				if quote == '"' {
					quote = 0
				} else if quote == 0 {
					quote = '"'
				}
				continue
			}
			if c == '$' && line[i+1] == '(' && line[i+2] == '(' {
				start = i
			}
		}
		if start < 0 {
			break
		}
		depth := 1
		end := -1
		for i := start + 3; i+1 < len(line); i++ {
			if line[i] == '(' {
				depth++
				continue
			}
			if line[i] == ')' {
				if depth > 1 {
					depth--
					continue
				}
				if line[i+1] == ')' {
					end = i
					break
				}
			}
		}
		if end < 0 {
			break
		}
		expr := line[start+3 : end]
		value, ok := w.evalVirtualArithmetic(expr)
		if !ok {
			value = 0
		}
		line = line[:start] + strconv.FormatInt(value, 10) + line[end+2:]
	}
	return line
}

func (w *virtualSSHWorld) expandVirtualBackticks(line string) string {
	for pass := 0; pass < 12; pass++ {
		start, end := -1, -1
		var quote byte
		for i := 0; i < len(line); i++ {
			c := line[i]
			if c == '\\' {
				i++
				continue
			}
			if quote == '\'' {
				if c == '\'' {
					quote = 0
				}
				continue
			}
			if c == '\'' {
				quote = '\''
				continue
			}
			if c == '"' {
				if quote == '"' {
					quote = 0
				} else if quote == 0 {
					quote = '"'
				}
				continue
			}
			if c == '`' {
				if start < 0 {
					start = i
				} else {
					end = i
					break
				}
			}
		}
		if start < 0 || end < 0 {
			break
		}
		w.substDepth++
		res := w.executeGrouped(line[start+1 : end])
		w.substDepth--
		value := strings.TrimRight(res.Output, "\r\n")
		line = line[:start] + value + line[end+1:]
	}
	return line
}
