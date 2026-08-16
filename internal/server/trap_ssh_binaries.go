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
	{"/usr/bin/echo", 43856, []string{"GNU coreutils 9.4", "echo", "write error", "--help", "--version"}},
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
		content := virtualELFContent(b)
		w.files[b.Path] = content
		w.fileMeta[b.Path] = virtualFileMeta{Size: b.Size, ModTime: now.Add(-time.Duration(stableSSHHash(b.Path)%3000) * time.Hour), Kind: "elf"}
		// Ubuntu usrmerge: /bin and /sbin tools resolve to the same userspace tools.
		if strings.HasPrefix(b.Path, "/usr/bin/") {
			alias := "/bin/" + path.Base(b.Path)
			w.files[alias] = content
			w.fileMeta[alias] = virtualFileMeta{Size: b.Size, ModTime: w.fileMeta[b.Path].ModTime, Kind: "elf"}
		}
	}
}

func virtualELFContent(b virtualSystemBinary) string {
	// Deliberately synthetic and non-executable. It only gives file-inspection
	// commands consistent ELF-like bytes and printable strings.
	header := "\x7fELF\x02\x01\x01\x00" + strings.Repeat("\x00", 8)
	body := "\x03\x00>\x00\x01\x00\x00\x00" + strings.Repeat("\x00", 24)
	markers := strings.Join(b.Strings, "\x00") + "\x00"
	return header + body + fmt.Sprintf("VIRTUAL:%s\x00", b.Path) + markers
}

func virtualBuiltin(name string) bool {
	switch name {
	case "echo", "cd", "pwd", "type", "command", "alias", "export", "unset", "history", "read", "source", ".", "exit", "logout":
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
