package server

import (
	"fmt"
	"io"
	"path"
	"strings"
	"unicode/utf8"
)

type virtualTextBuffer struct {
	lines    []string
	row      int
	col      int
	modified bool
	yank     string
	undo     []string
}

func newVirtualTextBuffer(content string) *virtualTextBuffer {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")
	lines := strings.Split(content, "\n")
	if len(lines) > 1 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) == 0 {
		lines = []string{""}
	}
	return &virtualTextBuffer{lines: lines}
}

func (b *virtualTextBuffer) snapshot() {
	b.undo = append([]string(nil), b.lines...)
}

func (b *virtualTextBuffer) restoreUndo() {
	if b.undo == nil {
		return
	}
	b.lines, b.undo = b.undo, append([]string(nil), b.lines...)
	b.clamp()
	b.modified = true
}

func (b *virtualTextBuffer) clamp() {
	if len(b.lines) == 0 {
		b.lines = []string{""}
	}
	if b.row < 0 {
		b.row = 0
	}
	if b.row >= len(b.lines) {
		b.row = len(b.lines) - 1
	}
	max := utf8.RuneCountInString(b.lines[b.row])
	if b.col < 0 {
		b.col = 0
	}
	if b.col > max {
		b.col = max
	}
}

func (b *virtualTextBuffer) insertRune(r rune) {
	b.snapshot()
	line := []rune(b.lines[b.row])
	line = insertRune(line, b.col, r)
	b.lines[b.row] = string(line)
	b.col++
	b.modified = true
}

func (b *virtualTextBuffer) newline() {
	b.snapshot()
	line := []rune(b.lines[b.row])
	left, right := string(line[:b.col]), string(line[b.col:])
	b.lines[b.row] = left
	b.lines = append(b.lines, "")
	copy(b.lines[b.row+2:], b.lines[b.row+1:])
	b.lines[b.row+1] = right
	b.row++
	b.col = 0
	b.modified = true
}

func (b *virtualTextBuffer) backspace() {
	if b.col > 0 {
		b.snapshot()
		line := []rune(b.lines[b.row])
		line = append(line[:b.col-1], line[b.col:]...)
		b.lines[b.row] = string(line)
		b.col--
		b.modified = true
		return
	}
	if b.row > 0 {
		b.snapshot()
		prev := []rune(b.lines[b.row-1])
		b.col = len(prev)
		b.lines[b.row-1] += b.lines[b.row]
		b.lines = append(b.lines[:b.row], b.lines[b.row+1:]...)
		b.row--
		b.modified = true
	}
}

func (b *virtualTextBuffer) deleteAt() {
	line := []rune(b.lines[b.row])
	if b.col < len(line) {
		b.snapshot()
		line = append(line[:b.col], line[b.col+1:]...)
		b.lines[b.row] = string(line)
		b.modified = true
	}
}

func (b *virtualTextBuffer) deleteLine() {
	b.snapshot()
	b.yank = b.lines[b.row]
	if len(b.lines) == 1 {
		b.lines[0] = ""
	} else {
		b.lines = append(b.lines[:b.row], b.lines[b.row+1:]...)
	}
	b.col = 0
	b.modified = true
	b.clamp()
}

func (b *virtualTextBuffer) pasteLine() {
	if b.yank == "" {
		return
	}
	b.snapshot()
	idx := b.row + 1
	b.lines = append(b.lines, "")
	copy(b.lines[idx+1:], b.lines[idx:])
	b.lines[idx] = b.yank
	b.row = idx
	b.col = 0
	b.modified = true
}

func (b *virtualTextBuffer) content() string {
	return strings.Join(b.lines, "\n") + "\n"
}

func (w *virtualSSHWorld) runVirtualVim(reader *virtualSSHLineReader, out io.Writer, target string) {
	name := target
	content := ""
	if name != "" {
		content = w.files[name]
	}
	buf := newVirtualTextBuffer(content)
	mode := "normal"
	status := ""
	showNumbers := false
	pending := byte(0)

	render := func() {
		cols, rows := w.virtualTTYSize()
		if cols < 40 {
			cols = 80
		}
		if rows < 8 {
			rows = 24
		}
		_, _ = io.WriteString(out, "\x1b[H\x1b[2J")
		visible := rows - 2
		start := 0
		if buf.row >= visible {
			start = buf.row - visible + 1
		}
		for screenRow := 0; screenRow < visible; screenRow++ {
			idx := start + screenRow
			line := "~"
			if idx < len(buf.lines) {
				line = buf.lines[idx]
				if showNumbers {
					line = fmt.Sprintf("%6d  %s", idx+1, line)
				}
			}
			line = truncateVirtualRunes(line, cols)
			_, _ = fmt.Fprintf(out, "%s\x1b[K\r\n", line)
		}
		fileLabel := "[No Name]"
		if name != "" {
			fileLabel = path.Base(name)
		}
		mod := ""
		if buf.modified {
			mod = " [+]"
		}
		left := fmt.Sprintf("\"%s\"%s %dL, %dB", fileLabel, mod, len(buf.lines), len(buf.content()))
		_, _ = fmt.Fprintf(out, "%-*s\x1b[K\r\n", cols, truncateVirtualRunes(left, cols))
		bottom := status
		if mode == "insert" {
			bottom = "-- INSERT --"
		}
		_, _ = fmt.Fprintf(out, "%-*s\x1b[K", cols, truncateVirtualRunes(bottom, cols))
		cursorRow := buf.row - start + 1
		cursorCol := buf.col + 1
		if showNumbers {
			cursorCol += 8
		}
		_, _ = fmt.Fprintf(out, "\x1b[%d;%dH", cursorRow, cursorCol)
	}

	writeFile := func(dst string) bool {
		if dst == "" {
			status = "E32: No file name"
			return false
		}
		if !w.setVirtualFile(dst, buf.content()) {
			status = "E514: write error (file system full?)"
			return false
		}
		name = dst
		buf.modified = false
		status = fmt.Sprintf("\"%s\" %dL, %dB written", path.Base(name), len(buf.lines), len(buf.content()))
		return true
	}

	render()
	for {
		b, err := reader.readByte()
		if err != nil {
			return
		}
		status = ""
		if mode == "insert" {
			switch b {
			case 0x1b:
				seq, err := reader.readEscapeSequenceMaybe()
				if err != nil {
					return
				}
				if seq == "" {
					mode = "normal"
					pending = 0
				} else {
					switch seq {
					case "[A":
						buf.row--
					case "[B":
						buf.row++
					case "[C":
						buf.col++
					case "[D":
						buf.col--
					case "[H", "[1~", "[7~", "OH":
						buf.col = 0
					case "[F", "[4~", "[8~", "OF":
						buf.col = utf8.RuneCountInString(buf.lines[buf.row])
					case "[3~":
						buf.deleteAt()
					}
					buf.clamp()
				}
			case '\r', '\n':
				if b == '\r' {
					reader.discardLF = true
				}
				buf.newline()
			case 8, 127:
				buf.backspace()
			default:
				if b >= 0x20 && b < 0x7f {
					buf.insertRune(rune(b))
				} else if b >= 0x80 {
					_ = reader.r.UnreadByte()
					ru, _, err := reader.r.ReadRune()
					if err == nil {
						buf.insertRune(ru)
					}
				}
			}
			render()
			continue
		}

		if b == 0x1b {
			seq, err := reader.readEscapeSequenceMaybe()
			if err != nil {
				return
			}
			switch seq {
			case "[A":
				buf.row--
			case "[B":
				buf.row++
			case "[C":
				buf.col++
			case "[D":
				buf.col--
			case "[H", "[1~", "[7~", "OH":
				buf.col = 0
			case "[F", "[4~", "[8~", "OF":
				buf.col = utf8.RuneCountInString(buf.lines[buf.row])
			case "[3~":
				buf.deleteAt()
			}
			buf.clamp()
			render()
			continue
		}

		switch b {
		case 'i':
			mode = "insert"
		case 'a':
			if buf.col < utf8.RuneCountInString(buf.lines[buf.row]) {
				buf.col++
			}
			mode = "insert"
		case 'o':
			buf.col = utf8.RuneCountInString(buf.lines[buf.row])
			buf.newline()
			mode = "insert"
		case 'O':
			buf.snapshot()
			idx := buf.row
			buf.lines = append(buf.lines, "")
			copy(buf.lines[idx+1:], buf.lines[idx:])
			buf.lines[idx] = ""
			buf.col = 0
			buf.modified = true
			mode = "insert"
		case 'h':
			buf.col--
		case 'j':
			buf.row++
		case 'k':
			buf.row--
		case 'l':
			buf.col++
		case '0':
			buf.col = 0
		case '$':
			buf.col = utf8.RuneCountInString(buf.lines[buf.row])
		case 'x':
			buf.deleteAt()
		case 'u':
			buf.restoreUndo()
		case 'p':
			buf.pasteLine()
		case 'd':
			if pending == 'd' {
				buf.deleteLine()
				pending = 0
			} else {
				pending = 'd'
			}
		case 'y':
			if pending == 'y' {
				buf.yank = buf.lines[buf.row]
				pending = 0
			} else {
				pending = 'y'
			}
		case 'g':
			if pending == 'g' {
				buf.row, buf.col, pending = 0, 0, 0
			} else {
				pending = 'g'
			}
		case 'G':
			buf.row = len(buf.lines) - 1
			buf.col = 0
		case ':':
			cmd, ok := readVirtualEditorCommand(reader, out, ":")
			if !ok {
				render()
				continue
			}
			cmd = strings.TrimSpace(cmd)
			switch {
			case cmd == "q":
				if buf.modified {
					status = "E37: No write since last change (add ! to override)"
				} else {
					_, _ = io.WriteString(out, "\x1b[2J\x1b[H")
					return
				}
			case cmd == "q!":
				_, _ = io.WriteString(out, "\x1b[2J\x1b[H")
				return
			case cmd == "w" || cmd == "w!":
				writeFile(name)
			case strings.HasPrefix(cmd, "w "):
				writeFile(w.resolve(strings.TrimSpace(strings.TrimPrefix(cmd, "w "))))
			case cmd == "wq" || cmd == "wq!" || cmd == "x":
				if !buf.modified || writeFile(name) {
					_, _ = io.WriteString(out, "\x1b[2J\x1b[H")
					return
				}
			case cmd == "set number" || cmd == "set nu":
				showNumbers = true
			case cmd == "set nonumber" || cmd == "set nonu":
				showNumbers = false
			case strings.HasPrefix(cmd, "!"):
				inner := strings.TrimSpace(strings.TrimPrefix(cmd, "!"))
				res := w.Execute(inner)
				_, _ = io.WriteString(out, "\x1b[2J\x1b[H")
				if res.Output != "" {
					_, _ = io.WriteString(out, normalizeSSHOutput(res.Output))
				}
				_, _ = io.WriteString(out, "\r\nPress ENTER or type command to continue")
				_, _ = reader.readByte()
			case cmd == "%d":
				buf.snapshot()
				buf.lines = []string{""}
				buf.row, buf.col, buf.modified = 0, 0, true
			default:
				status = "E492: Not an editor command: " + cmd
			}
		case '/':
			query, ok := readVirtualEditorCommand(reader, out, "/")
			if ok && query != "" {
				found := false
				for i := buf.row; i < len(buf.lines); i++ {
					if col := strings.Index(buf.lines[i], query); col >= 0 {
						buf.row = i
						buf.col = utf8.RuneCountInString(buf.lines[i][:col])
						found = true
						break
					}
				}
				if !found {
					status = "Pattern not found: " + query
				}
			}
		default:
			pending = 0
		}
		buf.clamp()
		render()
	}
}

func readVirtualEditorCommand(reader *virtualSSHLineReader, out io.Writer, prefix string) (string, bool) {
	buf := []rune{}
	_, _ = io.WriteString(out, "\r\x1b[K"+prefix)
	for {
		b, err := reader.readByte()
		if err != nil {
			return "", false
		}
		switch b {
		case '\r', '\n':
			if b == '\r' {
				reader.discardLF = true
			}
			return string(buf), true
		case 0x1b, 3:
			return "", false
		case 8, 127:
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
				_, _ = io.WriteString(out, "\b \b")
			}
		default:
			if b >= 0x20 && b < 0x7f {
				buf = append(buf, rune(b))
				_, _ = out.Write([]byte{b})
			}
		}
	}
}

func (w *virtualSSHWorld) runVirtualNano(reader *virtualSSHLineReader, out io.Writer, target string) {
	name := target
	content := ""
	if name != "" {
		content = w.files[name]
	}
	buf := newVirtualTextBuffer(content)
	status := ""

	render := func() {
		cols, rows := w.virtualTTYSize()
		if cols < 40 {
			cols = 80
		}
		if rows < 8 {
			rows = 24
		}
		_, _ = io.WriteString(out, "\x1b[H\x1b[2J")
		title := "  GNU nano 7.2"
		file := "New Buffer"
		if name != "" {
			file = path.Base(name)
		}
		_, _ = fmt.Fprintf(out, "%-*s\x1b[K\r\n", cols, truncateVirtualRunes(title+"                      "+file, cols))
		visible := rows - 4
		start := 0
		if buf.row >= visible {
			start = buf.row - visible + 1
		}
		for i := 0; i < visible; i++ {
			idx := start + i
			line := ""
			if idx < len(buf.lines) {
				line = buf.lines[idx]
			}
			_, _ = fmt.Fprintf(out, "%s\x1b[K\r\n", truncateVirtualRunes(line, cols))
		}
		_, _ = fmt.Fprintf(out, "%-*s\x1b[K\r\n", cols, truncateVirtualRunes(status, cols))
		shortcuts := "^G Help  ^O Write Out  ^W Where Is  ^K Cut  ^U Paste  ^X Exit"
		_, _ = fmt.Fprintf(out, "%-*s\x1b[K", cols, truncateVirtualRunes(shortcuts, cols))
		_, _ = fmt.Fprintf(out, "\x1b[%d;%dH", buf.row-start+2, buf.col+1)
	}

	write := func() bool {
		if name == "" {
			status = "File Name to Write: /tmp/nano-buffer"
			name = "/tmp/nano-buffer"
		}
		if !w.setVirtualFile(name, buf.content()) {
			status = "Error writing file"
			return false
		}
		buf.modified = false
		status = fmt.Sprintf("[ Wrote %d lines ]", len(buf.lines))
		return true
	}

	render()
	for {
		b, err := reader.readByte()
		if err != nil {
			return
		}
		status = ""
		switch b {
		case 24: // Ctrl+X
			if buf.modified {
				_, _ = io.WriteString(out, "\r\nSave modified buffer?  Y Yes  N No  ^C Cancel")
				answer, err := reader.readByte()
				if err != nil {
					return
				}
				if answer == 'y' || answer == 'Y' {
					if !write() {
						render()
						continue
					}
				} else if answer != 'n' && answer != 'N' {
					render()
					continue
				}
			}
			_, _ = io.WriteString(out, "\x1b[2J\x1b[H")
			return
		case 15: // Ctrl+O
			write()
		case 11: // Ctrl+K
			buf.yank = buf.lines[buf.row]
			buf.deleteLine()
		case 21: // Ctrl+U
			buf.pasteLine()
		case 23: // Ctrl+W
			query, ok := readVirtualEditorCommand(reader, out, "Search: ")
			if ok && query != "" {
				for i := buf.row; i < len(buf.lines); i++ {
					if col := strings.Index(buf.lines[i], query); col >= 0 {
						buf.row = i
						buf.col = utf8.RuneCountInString(buf.lines[i][:col])
						break
					}
				}
			}
		case 8, 127:
			buf.backspace()
		case '\r', '\n':
			if b == '\r' {
				reader.discardLF = true
			}
			buf.newline()
		case 0x1b:
			seq, err := reader.readEscapeSequenceMaybe()
			if err != nil {
				return
			}
			switch seq {
			case "[A":
				buf.row--
			case "[B":
				buf.row++
			case "[C":
				buf.col++
			case "[D":
				buf.col--
			case "[H", "[1~", "[7~", "OH":
				buf.col = 0
			case "[F", "[4~", "[8~", "OF":
				buf.col = utf8.RuneCountInString(buf.lines[buf.row])
			case "[3~":
				buf.deleteAt()
			}
		default:
			if b >= 0x20 && b < 0x7f {
				buf.insertRune(rune(b))
			} else if b >= 0x80 {
				_ = reader.r.UnreadByte()
				ru, _, err := reader.r.ReadRune()
				if err == nil {
					buf.insertRune(ru)
				}
			}
		}
		buf.clamp()
		render()
	}
}

func (w *virtualSSHWorld) runVirtualTop(reader *virtualSSHLineReader, out io.Writer) {
	render := func(message string) {
		cols, _ := w.virtualTTYSize()
		_, _ = io.WriteString(out, "\x1b[H\x1b[2J")
		for _, line := range strings.Split(w.virtualTopOutput(), "\n") {
			_, _ = io.WriteString(out, truncateVirtualRunes(line, cols)+"\x1b[K\r\n")
		}
		if message != "" {
			_, _ = io.WriteString(out, message+"\x1b[K")
		}
	}
	render("")
	for {
		b, err := reader.readByte()
		if err != nil {
			return
		}
		switch b {
		case 'q', 'Q', 3:
			_, _ = io.WriteString(out, "\x1b[2J\x1b[H")
			return
		case 'h', '?':
			render("Help for Interactive Commands - press q to quit, space to refresh")
		case ' ', '\r', '\n':
			render("")
		case 0x1b:
			_, _ = reader.readEscapeSequenceMaybe()
		default:
			// top accepts many single-key commands. Unknown keys are ignored like a
			// harmless refresh rather than reflected to the host terminal.
		}
	}
}

func (w *virtualSSHWorld) virtualTTYSize() (int, int) {
	w.ttyMu.RLock()
	defer w.ttyMu.RUnlock()
	cols, rows := w.ttyCols, w.ttyRows
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}
	return cols, rows
}

func truncateVirtualRunes(v string, max int) string {
	if max <= 0 {
		return ""
	}
	r := []rune(v)
	if len(r) > max {
		r = r[:max]
	}
	return string(r)
}
