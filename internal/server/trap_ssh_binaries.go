package server

import (
	"fmt"
	"path"
	"strings"
	"time"
)

type virtualSystemBinary struct {
	Path    string
	Size    int64
	Strings []string
}

var virtualSystemBinaries = []virtualSystemBinary{
	{"/usr/bin/true", 35664, []string{"GNU coreutils 9.4", "true", "--help", "--version"}},
	{"/usr/bin/false", 35664, []string{"GNU coreutils 9.4", "false", "--help", "--version"}},
	{"/usr/bin/test", 60368, []string{"GNU coreutils 9.4", "test", "missing argument", "unary operator expected"}},
	{"/usr/bin/[", 60368, []string{"GNU coreutils 9.4", "[", "missing ]", "unary operator expected"}},
	{"/usr/bin/echo", 43856, []string{"GNU coreutils 9.4", "echo", "write error", "--help", "--version"}},
	{"/usr/bin/printf", 64432, []string{"GNU coreutils 9.4", "printf", "usage: printf", "write error"}},
	{"/usr/bin/cat", 44016, []string{"GNU coreutils 9.4", "cat", "standard output", "write error"}},
	{"/usr/bin/ls", 151344, []string{"GNU coreutils 9.4", "ls", "invalid option", "--color=auto"}},
	{"/usr/bin/pwd", 43952, []string{"GNU coreutils 9.4", "pwd", "ignoring non-option arguments"}},
	{"/usr/bin/date", 121904, []string{"GNU coreutils 9.4", "date", "invalid date", "UTC"}},
	{"/usr/bin/uname", 43888, []string{"GNU coreutils 9.4", "uname", "GNU/Linux", "x86_64"}},
	{"/usr/bin/grep", 203152, []string{"grep (GNU grep) 3.11", "Usage: grep", "binary file matches"}},
	{"/usr/bin/sed", 126424, []string{"sed (GNU sed) 4.9", "Usage: sed", "invalid command code"}},
	{"/usr/bin/awk", 71448, []string{"mawk 1.3.4 20240123", "Usage: mawk", "awk"}},
	{"/usr/bin/env", 48536, []string{"GNU coreutils 9.4", "env", "SHELL", "PATH"}},
	{"/usr/bin/nproc", 39760, []string{"GNU coreutils 9.4", "nproc", "--all", "--ignore"}},
	{"/usr/bin/curl", 280800, []string{"curl 8.5.0", "libcurl/8.5.0", "Usage: curl", "https://curl.se/"}},
	{"/usr/bin/wget", 540016, []string{"GNU Wget 1.21.4", "Usage: wget", "HTTP request sent"}},
	{"/usr/bin/ssh", 1123792, []string{"OpenSSH_9.6p1", "usage: ssh", "known_hosts", "ssh-ed25519"}},
	{"/usr/bin/bash", 1446024, []string{"GNU bash, version 5.2.21", "bash", "SHELL", "BASH_VERSION"}},
	{"/usr/bin/sh", 125640, []string{"dash", "Debian Almquist Shell", "SHELL"}},
}

func (w *virtualSSHWorld) seedSystemBinaries() {
	now := w.system.snapshot().BootTime.Add(5 * time.Minute)
	for _, b := range virtualSystemBinaries {
		w.seedVirtualCommandBinary(b.Path, b.Size, virtualELFContent(b), now)
	}
	// Keep command discovery and filesystem discovery aligned. The virtual shell
	// intentionally implements a bounded command surface; every non-builtin it
	// advertises also has a small synthetic ELF surface for ls/file/stat/strings.
	for _, name := range virtualSSHCommands {
		if virtualBuiltin(name) {
			continue
		}
		cmdPath := "/usr/bin/" + path.Base(name)
		if _, exists := w.files[cmdPath]; exists {
			continue
		}
		w.ensureVirtualCommandBinary(name)
	}
}

func (w *virtualSSHWorld) seedVirtualCommandBinary(cmdPath string, size int64, content string, base time.Time) {
	cmdPath = path.Clean(cmdPath)
	w.files[cmdPath] = content
	w.fileMeta[cmdPath] = virtualFileMeta{Size: size, ModTime: base.Add(-time.Duration(stableSSHHash(cmdPath)%3000) * time.Hour), Kind: "elf"}
	w.fileModes[cmdPath] = 0o755
	if strings.HasPrefix(cmdPath, "/usr/bin/") {
		alias := "/bin/" + path.Base(cmdPath)
		w.files[alias] = content
		w.fileMeta[alias] = w.fileMeta[cmdPath]
		w.fileModes[alias] = 0o755
	}
}

func (w *virtualSSHWorld) ensureVirtualCommandBinary(name string) {
	name = path.Base(strings.TrimSpace(name))
	if name == "" || virtualBuiltin(name) {
		return
	}
	cmdPath := "/usr/bin/" + name
	if _, exists := w.files[cmdPath]; exists {
		return
	}
	h := stableSSHHash("bin|" + name)
	size := int64(32*1024 + h%(896*1024))
	b := virtualSystemBinary{Path: cmdPath, Size: size, Strings: []string{name, "GLIBC_2.34", "libc.so.6", "Usage: " + name}}
	w.seedVirtualCommandBinary(cmdPath, size, virtualELFContent(b), w.system.snapshot().BootTime.Add(5*time.Minute))
}

func (w *virtualSSHWorld) removeVirtualCommandBinary(name string) {
	name = path.Base(strings.TrimSpace(name))
	for _, p := range []string{"/usr/bin/" + name, "/bin/" + name} {
		w.deleteVirtualFile(p)
	}
}

func virtualELFContent(b virtualSystemBinary) string {
	// Deliberately synthetic and non-executable. It only gives file-inspection
	// commands consistent ELF-like bytes and printable strings.
	header := "\x7fELF\x02\x01\x01\x00" + strings.Repeat("\x00", 8)
	body := "\x03\x00>\x00\x01\x00\x00\x00" + strings.Repeat("\x00", 24)
	markers := strings.Join(b.Strings, "\x00") + "\x00"
	return header + body + fmt.Sprintf("%s\x00", path.Base(b.Path)) + markers
}

func virtualBuiltin(name string) bool {
	switch name {
	case "echo", "printf", "cd", "pwd", "type", "command", "alias", "export", "unset", "set", "history", "read", "test", "[", "true", "false", "umask", "ulimit", "jobs", "disown", "source", ".", "exit", "logout", "break", "continue":
		return true
	}
	return false
}

func virtualCommandPath(name string) string {
	name = path.Base(strings.TrimSpace(name))
	if name == "" {
		return ""
	}
	for _, b := range virtualSystemBinaries {
		if path.Base(b.Path) == name {
			return b.Path
		}
	}
	if virtualCommandExists(name) {
		return "/usr/bin/" + name
	}
	return ""
}
