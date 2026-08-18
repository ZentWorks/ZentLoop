package server

import (
	"bufio"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"unicode"
)

const maxVirtualHistory = 100

// virtualSSHLineReader implements a small, deterministic readline-style editor.
// It never delegates input to a host shell or terminal library. All editing and
// completion stays inside the SSH session's virtual world.
type virtualSSHLineReader struct {
	r         *bufio.Reader
	discardLF bool
	world     *virtualSSHWorld
	onRead    func()
}

func newVirtualSSHLineReader(in io.Reader, world *virtualSSHWorld) *virtualSSHLineReader {
	return &virtualSSHLineReader{r: bufio.NewReader(in), world: world}
}

func (r *virtualSSHLineReader) SetReadActivity(fn func()) { r.onRead = fn }

func (r *virtualSSHLineReader) readByte() (byte, error) {
	for {
		b, err := r.r.ReadByte()
		if err != nil {
			return 0, err
		}
		if r.onRead != nil {
			r.onRead()
		}
		if r.discardLF {
			r.discardLF = false
			if b == '\n' {
				continue
			}
		}
		return b, nil
	}
}

func (r *virtualSSHLineReader) ReadLine(out io.Writer, prompt string, max int) (string, error) {
	buf := make([]rune, 0, 128)
	cursor := 0
	historyIndex := len(r.world.history)
	var draft []rune
	var killBuffer []rune
	reverseIndex := len(r.world.history)
	reverseQuery := ""
	reverseActive := false

	redraw := func() {
		_, _ = io.WriteString(out, "\r\x1b[2K"+prompt+string(buf))
		if n := len(buf) - cursor; n > 0 {
			_, _ = fmt.Fprintf(out, "\x1b[%dD", n)
		}
	}

	setBuffer := func(v string) {
		buf = []rune(v)
		if len(buf) > max {
			buf = buf[:max]
		}
		cursor = len(buf)
		redraw()
	}

	for {
		b, err := r.readByte()
		if err != nil {
			return "", err
		}

		if b != 18 { // Ctrl+R keeps a repeated reverse-history search active.
			reverseActive = false
		}

		switch b {
		case '\r':
			r.discardLF = true
			_, _ = io.WriteString(out, "\r\n")
			return string(buf), nil
		case '\n':
			_, _ = io.WriteString(out, "\r\n")
			return string(buf), nil
		case 1: // Ctrl+A
			cursor = 0
			redraw()
		case 2: // Ctrl+B
			if cursor > 0 {
				cursor--
				redraw()
			}
		case 3: // Ctrl+C
			_, _ = io.WriteString(out, "^C\r\n")
			return "", nil
		case 4: // Ctrl+D
			if len(buf) == 0 {
				return "", io.EOF
			}
			if cursor < len(buf) {
				buf = append(buf[:cursor], buf[cursor+1:]...)
				redraw()
			}
		case 5: // Ctrl+E
			cursor = len(buf)
			redraw()
		case 6: // Ctrl+F
			if cursor < len(buf) {
				cursor++
				redraw()
			}
		case 11: // Ctrl+K
			if cursor < len(buf) {
				killBuffer = append([]rune(nil), buf[cursor:]...)
				buf = buf[:cursor]
				redraw()
			}
		case 12: // Ctrl+L
			_, _ = io.WriteString(out, "\x1b[2J\x1b[H")
			_, _ = io.WriteString(out, prompt+string(buf))
			if n := len(buf) - cursor; n > 0 {
				_, _ = fmt.Fprintf(out, "\x1b[%dD", n)
			}
		case 14: // Ctrl+N, history next
			if historyIndex < len(r.world.history)-1 {
				historyIndex++
				setBuffer(r.world.history[historyIndex])
			} else if historyIndex == len(r.world.history)-1 {
				historyIndex = len(r.world.history)
				buf = append([]rune(nil), draft...)
				cursor = len(buf)
				redraw()
			}
		case 16: // Ctrl+P, history previous
			if len(r.world.history) > 0 {
				if historyIndex == len(r.world.history) {
					draft = append([]rune(nil), buf...)
				}
				if historyIndex > 0 {
					historyIndex--
					setBuffer(r.world.history[historyIndex])
				}
			}
		case 18: // Ctrl+R, bounded reverse history search
			if !reverseActive {
				reverseQuery = string(buf)
				reverseIndex = len(r.world.history)
				reverseActive = true
			}
			found := -1
			for i := reverseIndex - 1; i >= 0; i-- {
				if reverseQuery == "" || strings.Contains(r.world.history[i], reverseQuery) {
					found = i
					break
				}
			}
			if found >= 0 {
				reverseIndex = found
				historyIndex = found
				setBuffer(r.world.history[found])
			} else {
				_, _ = io.WriteString(out, "\a")
			}
		case 21: // Ctrl+U
			if cursor > 0 {
				killBuffer = append([]rune(nil), buf[:cursor]...)
				buf = append([]rune(nil), buf[cursor:]...)
				cursor = 0
				redraw()
			}
		case 23: // Ctrl+W
			if cursor > 0 {
				start := cursor
				for start > 0 && unicode.IsSpace(buf[start-1]) {
					start--
				}
				for start > 0 && !unicode.IsSpace(buf[start-1]) {
					start--
				}
				killBuffer = append([]rune(nil), buf[start:cursor]...)
				buf = append(buf[:start], buf[cursor:]...)
				cursor = start
				redraw()
			}
		case 25: // Ctrl+Y, yank last killed text
			if len(killBuffer) > 0 && len(buf)+len(killBuffer) <= max {
				left := append([]rune(nil), buf[:cursor]...)
				right := append([]rune(nil), buf[cursor:]...)
				buf = append(left, killBuffer...)
				cursor = len(buf)
				buf = append(buf, right...)
				redraw()
			}
		case 8, 127: // Backspace
			if cursor > 0 {
				buf = append(buf[:cursor-1], buf[cursor:]...)
				cursor--
				redraw()
			}
		case '\t':
			line := string(buf)
			start, end, matches := r.world.completeVirtualLine(line, cursor)
			if len(matches) == 0 {
				_, _ = io.WriteString(out, "\a")
				continue
			}
			if len(matches) == 1 {
				repl := []rune(matches[0])
				left := append([]rune(nil), buf[:start]...)
				right := append([]rune(nil), buf[end:]...)
				buf = append(left, repl...)
				cursor = len(left) + len(repl)
				buf = append(buf, right...)
				if cursor == len(buf) && !strings.HasSuffix(matches[0], "/") {
					buf = append(buf, ' ')
					cursor++
				}
				redraw()
				continue
			}
			prefix := commonStringPrefix(matches)
			current := string(buf[start:end])
			if len(prefix) > len(current) {
				repl := []rune(prefix)
				left := append([]rune(nil), buf[:start]...)
				right := append([]rune(nil), buf[end:]...)
				buf = append(left, repl...)
				cursor = len(left) + len(repl)
				buf = append(buf, right...)
				redraw()
				continue
			}
			_, _ = io.WriteString(out, "\r\n"+strings.Join(matches, "  ")+"\r\n")
			redraw()
		case 0x1b:
			seq, err := r.readEscapeSequence()
			if err != nil {
				return "", err
			}
			switch seq {
			case "[A": // Up
				if len(r.world.history) == 0 {
					continue
				}
				if historyIndex == len(r.world.history) {
					draft = append([]rune(nil), buf...)
				}
				if historyIndex > 0 {
					historyIndex--
					setBuffer(r.world.history[historyIndex])
				}
			case "[B": // Down
				if historyIndex < len(r.world.history)-1 {
					historyIndex++
					setBuffer(r.world.history[historyIndex])
				} else if historyIndex == len(r.world.history)-1 {
					historyIndex = len(r.world.history)
					buf = append([]rune(nil), draft...)
					cursor = len(buf)
					redraw()
				}
			case "[C": // Right
				if cursor < len(buf) {
					cursor++
					redraw()
				}
			case "[D": // Left
				if cursor > 0 {
					cursor--
					redraw()
				}
			case "[H", "[1~", "[7~", "OH": // Home
				cursor = 0
				redraw()
			case "[F", "[4~", "[8~", "OF": // End
				cursor = len(buf)
				redraw()
			case "[3~": // Delete
				if cursor < len(buf) {
					buf = append(buf[:cursor], buf[cursor+1:]...)
					redraw()
				}
			case "b": // Alt+B
				cursor = previousWordBoundary(buf, cursor)
				redraw()
			case "f": // Alt+F
				cursor = nextWordBoundary(buf, cursor)
				redraw()
			case "d": // Alt+D, kill next word
				end := nextWordBoundary(buf, cursor)
				if end > cursor {
					killBuffer = append([]rune(nil), buf[cursor:end]...)
					buf = append(buf[:cursor], buf[end:]...)
					redraw()
				}
			}
		default:
			if b < 0x20 || len(buf) >= max {
				continue
			}
			// SSH command input is normally UTF-8. For ASCII fast-path, insert the
			// byte directly. Multi-byte sequences are decoded by unread + ReadRune.
			if b < 0x80 {
				buf = insertRune(buf, cursor, rune(b))
				cursor++
				if cursor == len(buf) {
					_, _ = out.Write([]byte{b})
				} else {
					redraw()
				}
				continue
			}
			_ = r.r.UnreadByte()
			ru, _, err := r.r.ReadRune()
			if err != nil {
				return "", err
			}
			buf = insertRune(buf, cursor, ru)
			cursor++
			redraw()
		}
	}
}

func (r *virtualSSHLineReader) ReadSecretLine(out io.Writer, max int) (string, error) {
	buf := make([]byte, 0, 64)
	for {
		b, err := r.readByte()
		if err != nil {
			return "", err
		}
		switch b {
		case 13: // CR
			r.discardLF = true
			_, _ = io.WriteString(out, "\r\n")
			return string(buf), nil
		case 10: // LF
			_, _ = io.WriteString(out, "\r\n")
			return string(buf), nil
		case 3: // Ctrl+C
			_, _ = io.WriteString(out, "\r\n")
			return "", io.EOF
		case 8, 127:
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
			}
		default:
			if b >= 0x20 && len(buf) < max {
				buf = append(buf, b)
			}
		}
	}
}

func (r *virtualSSHLineReader) readEscapeSequence() (string, error) {
	b, err := r.readByte()
	if err != nil {
		return "", err
	}
	if b != '[' && b != 'O' {
		return string([]byte{b}), nil
	}
	seq := []byte{b}
	for len(seq) < 12 {
		c, err := r.readByte()
		if err != nil {
			return string(seq), err
		}
		seq = append(seq, c)
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '~' {
			break
		}
	}
	return string(seq), nil
}

func insertRune(buf []rune, at int, r rune) []rune {
	buf = append(buf, 0)
	copy(buf[at+1:], buf[at:])
	buf[at] = r
	return buf
}

func previousWordBoundary(buf []rune, cursor int) int {
	for cursor > 0 && unicode.IsSpace(buf[cursor-1]) {
		cursor--
	}
	for cursor > 0 && !unicode.IsSpace(buf[cursor-1]) {
		cursor--
	}
	return cursor
}

func nextWordBoundary(buf []rune, cursor int) int {
	for cursor < len(buf) && !unicode.IsSpace(buf[cursor]) {
		cursor++
	}
	for cursor < len(buf) && unicode.IsSpace(buf[cursor]) {
		cursor++
	}
	return cursor
}

func (w *virtualSSHWorld) addHistory(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	w.history = append(w.history, line)
	if len(w.history) > maxVirtualHistory {
		w.history = append([]string(nil), w.history[len(w.history)-maxVirtualHistory:]...)
	}
}

var virtualSSHCommands = []string{
	"alias", "apt", "apt-get", "arch", "arp", "awk", "base64", "basename", "bash", "blkid", "capsh", "cat", "cd",
	"chattr", "chmod", "chown", "clear", "command", "continue", "cp", "crontab", "curl", "cut", "date", "df", "dirname",
	"dmesg", "docker", "dpkg", "du", "echo", "env", "exit", "export", "false", "file", "find", "free", "getcap", "getconf", "getent",
	"gcc", "cc", "git", "go", "grep", "groups", "gunzip", "gzip", "head", "help", "history", "jobs", "disown", "hostname", "hostnamectl", "id", "ifconfig", "iptables",
	"ip", "journalctl", "kill", "killall", "kubectl", "last", "less", "ln", "logout", "ls", "lsattr", "lsblk", "lscpu",
	"lsb_release", "lsmod", "lsof", "make", "man", "mariadb", "mysql", "md5sum", "mkdir", "mktemp", "more", "mount", "mv", "nano", "nc", "ncat", "netcat", "nft", "node", "npm",
	"netstat", "nproc", "nvidia-smi", "nohup", "openssl", "passwd", "perl", "php", "pgrep", "pidof", "ping", "pkill", "printenv", "printf", "ps", "psql", "readelf", "redis-cli", "rsync",
	"pwd", "python", "python3", "read", "readlink", "realpath", "reset", "rm", "route", "scp", "sftp", "socat", "screen", "sed", "seq", "service", "set", "source",
	"sha256sum", "sh", "shutdown", "reboot", "poweroff", "halt", "sleep", "sort", "ss", "ssh", "stat", "strace", "strings", "su", "sudo", "sysctl", "systemctl", "systemd-detect-virt", "virt-what", "dmidecode", "stty", "tty", "tail", "tar", "tracepath", "traceroute",
	"tee", "telnet", "tmux", "top", "touch", "tr", "true", "type", "ulimit", "umask", "uname", "ufw", "uniq", "unzip", "unset", "expr",
	"timedatectl", "uptime", "vi", "vim", "w", "wc", "wget", "whereis", "which", "who", "dig", "host", "nslookup", "ldd", "objdump", "whoami", "xargs", "xxd", "zcat", "zip",
}

func (w *virtualSSHWorld) completeVirtualLine(line string, cursor int) (int, int, []string) {
	runes := []rune(line)
	if cursor > len(runes) {
		cursor = len(runes)
	}
	start := cursor
	for start > 0 && !unicode.IsSpace(runes[start-1]) {
		start--
	}
	end := cursor
	for end < len(runes) && !unicode.IsSpace(runes[end]) {
		end++
	}
	token := string(runes[start:cursor])
	first := strings.TrimSpace(string(runes[:start])) == ""
	if first && !strings.Contains(token, "/") {
		var matches []string
		for _, cmd := range virtualSSHCommands {
			if strings.HasPrefix(cmd, token) {
				matches = append(matches, cmd)
			}
		}
		return start, end, matches
	}

	return start, end, w.completeVirtualPath(token)
}

func (w *virtualSSHWorld) completeVirtualPath(token string) []string {
	displayDir := ""
	base := token
	if i := strings.LastIndex(token, "/"); i >= 0 {
		displayDir, base = token[:i+1], token[i+1:]
	}
	lookupDir := w.cwd
	if displayDir != "" {
		lookupDir = w.resolve(strings.TrimSuffix(displayDir, "/"))
	}
	seen := map[string]bool{}
	for d := range w.dirs {
		if d != lookupDir && path.Dir(d) == lookupDir {
			name := path.Base(d)
			if strings.HasPrefix(name, base) {
				seen[displayDir+name+"/"] = true
			}
		}
	}
	for f := range w.files {
		if path.Dir(f) == lookupDir {
			name := path.Base(f)
			if strings.HasPrefix(name, base) {
				seen[displayDir+name] = true
			}
		}
	}
	matches := make([]string, 0, len(seen))
	for m := range seen {
		matches = append(matches, m)
	}
	sort.Strings(matches)
	return matches
}

func commonStringPrefix(values []string) string {
	if len(values) == 0 {
		return ""
	}
	prefix := values[0]
	for _, v := range values[1:] {
		for !strings.HasPrefix(v, prefix) && prefix != "" {
			prefix = prefix[:len(prefix)-1]
		}
	}
	return prefix
}

func (r *virtualSSHLineReader) readEscapeSequenceMaybe() (string, error) {
	// A standalone ESC (notably Vim's insert->normal transition) must not wait
	// for another keystroke. Arrow/function-key sequences normally arrive in
	// the same SSH data chunk and are already buffered after the ESC byte.
	if r.r.Buffered() == 0 {
		return "", nil
	}
	b, err := r.readByte()
	if err != nil {
		return "", err
	}
	if b != '[' && b != 'O' {
		if err := r.r.UnreadByte(); err != nil {
			return "", err
		}
		return "", nil
	}
	seq := []byte{b}
	for len(seq) < 12 {
		c, err := r.readByte()
		if err != nil {
			return string(seq), err
		}
		seq = append(seq, c)
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '~' {
			break
		}
	}
	return string(seq), nil
}
