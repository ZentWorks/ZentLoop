package server

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"zentloop/internal/lures"
)

func virtualBaseResult(cmd, family string, depth, risk int, persona, message string) virtualSSHResult {
	return virtualSSHResult{CommandName: cmd, Family: family, Depth: depth, Risk: risk, Persona: persona, Message: message}
}

func (w *virtualSSHWorld) virtualEnvOutput(args []string) string {
	if len(args) == 1 && !strings.HasPrefix(args[0], "-") {
		return w.env[args[0]]
	}
	keys := make([]string, 0, len(w.env))
	for k := range w.env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s\n", k, w.env[k])
	}
	return strings.TrimSuffix(b.String(), "\n")
}

func (w *virtualSSHWorld) setVirtualUser(user string) {
	user = safeVirtualName(user)
	if user == "" {
		user = "root"
	}
	w.user = user
	w.cwd = w.homeDir()
	w.env["USER"] = user
	w.env["LOGNAME"] = user
	w.env["HOME"] = w.homeDir()
	w.env["PWD"] = w.cwd
}

func (w *virtualSSHWorld) executeExtraCommand(cmd string, args []string, raw, input string) (virtualSSHResult, bool) {
	if r, ok := w.deepRealityCommand(cmd, args); ok {
		return r, true
	}
	base := func(family string, depth, risk int, persona, message string) virtualSSHResult {
		return virtualBaseResult(cmd, family, depth, risk, persona, message)
	}

	switch cmd {
	case "busybox":
		r := base("recon", 3, 84, "tool-discovery", "busybox applet use")
		if len(args) == 0 {
			r.Output = "BusyBox v1.36.1 (Ubuntu 1:1.36.1-6ubuntu3.1) multi-call binary.\nCurrently defined functions: cat, cut, echo, grep, head, sed, tail, tr, uname, wc"
			return r, true
		}
		allowed := map[string]bool{"cat": true, "cut": true, "echo": true, "grep": true, "head": true, "sed": true, "tail": true, "tr": true, "uname": true, "wc": true}
		if !allowed[args[0]] {
			r.Output = "busybox: applet not found"
			r.Status = 127
			return r, true
		}
		inner := args[0]
		if len(args) > 1 {
			inner += " " + strings.Join(args[1:], " ")
		}
		return w.executeOne(inner, input), true
	case "lspci":
		r := base("recon", 3, 82, "system-recon", "PCI device discovery")
		r.Output = "00:00.0 Host bridge: Intel Corporation 440FX - 82441FX PMC [Natoma]\n00:01.0 ISA bridge: Intel Corporation 82371SB PIIX3 ISA [Natoma/Triton II]\n00:03.0 Ethernet controller: Red Hat, Inc. Virtio network device\n00:04.0 VGA compatible controller: Red Hat, Inc. Virtio GPU"
		return r, true
	case "which", "whereis", "type":
		r := base("recon", 3, 82, "tool-discovery", "binary/tool discovery")
		if len(args) == 0 {
			r.Status = 1
			return r, true
		}
		name := path.Base(args[len(args)-1])
		binPath := virtualCommandPath(name)
		if virtualBuiltin(name) && cmd == "type" {
			r.Output = name + " is a shell builtin"
		} else if binPath != "" {
			if cmd == "whereis" {
				r.Output = name + ": " + binPath + " /usr/share/man/man1/" + name + ".1.gz"
			} else if cmd == "type" {
				r.Output = name + " is " + binPath
			} else {
				r.Output = binPath
			}
		} else {
			r.Status = 1
			if cmd == "type" {
				r.Output = "bash: type: " + name + ": not found"
			}
		}
		return r, true
	case "command":
		r := base("recon", 3, 82, "tool-discovery", "shell command discovery")
		if len(args) >= 2 && args[0] == "-v" {
			name := path.Base(args[1])
			if virtualBuiltin(name) {
				r.Output = name
			} else if binPath := virtualCommandPath(name); binPath != "" {
				r.Output = binPath
			} else {
				r.Status = 1
			}
			return r, true
		}
		return r, true
	case "alias":
		r := base("shell", 2, 75, "interactive-shell", "shell alias inspection/modification")
		if len(args) == 0 {
			keys := make([]string, 0, len(w.aliases))
			for k := range w.aliases {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				r.Output += "alias " + k + "='" + w.aliases[k] + "'\n"
			}
			r.Output = strings.TrimSuffix(r.Output, "\n")
			return r, true
		}
		for _, a := range args {
			if name, value, ok := strings.Cut(a, "="); ok {
				w.aliases[name] = strings.Trim(value, "'\"")
			} else if value, ok := w.aliases[a]; ok {
				r.Output = "alias " + a + "='" + value + "'"
			} else {
				r.Output, r.Status = "bash: alias: "+a+": not found", 1
			}
		}
		return r, true
	case "unset":
		r := base("shell", 2, 76, "interactive-shell", "environment modification")
		for _, k := range args {
			delete(w.env, k)
		}
		return r, true
	case "export":
		r := base("credentials", 4, 88, "environment-modification", "environment variable modification")
		if len(args) == 0 {
			r.Output = w.virtualEnvOutput(nil)
			return r, true
		}
		for _, a := range args {
			if k, v, ok := strings.Cut(a, "="); ok && validVirtualEnvName(k) {
				w.env[k] = strings.Trim(v, "'\"")
			}
		}
		return r, true
	case "umask":
		r := base("shell", 2, 74, "interactive-shell", "umask inspection")
		if len(args) == 0 {
			r.Output = "0022"
		}
		return r, true
	case "ulimit":
		r := base("recon", 3, 80, "system-recon", "resource limit discovery")
		if containsArg(args, "-a") {
			r.Output = "real-time non-blocking time  (microseconds, -R) unlimited\ncore file size              (blocks, -c) 0\ndata seg size               (kbytes, -d) unlimited\nopen files                          (-n) 1024\nmax user processes                  (-u) 30576"
		} else {
			r.Output = "unlimited"
		}
		return r, true
	case "groups":
		r := base("recon", 3, 83, "account-discovery", "group membership discovery")
		if w.user == "root" {
			r.Output = "root"
		} else {
			r.Output = w.user + " sudo docker"
		}
		return r, true
	case "getent":
		r := base("recon", 4, 88, "account-discovery", "name service database discovery")
		if len(args) == 0 {
			r.Status = 2
			return r, true
		}
		switch args[0] {
		case "passwd":
			r.Output = strings.TrimSuffix(w.files["/etc/passwd"], "\n")
		case "hosts", "ahosts":
			name := "backup-01"
			if len(args) > 1 {
				name = args[1]
			}
			if h, ok := lures.Resolve(name); ok {
				r.Output = h.IP + "    " + h.Name + " " + strings.Join(h.Aliases, " ")
			} else {
				r.Status = 2
			}
		default:
			r.Status = 2
		}
		return r, true
	case "lsb_release":
		r := base("recon", 3, 82, "system-recon", "distribution discovery")
		r.Output = "Distributor ID:\tUbuntu\nDescription:\tUbuntu 24.04.3 LTS\nRelease:\t24.04\nCodename:\tnoble"
		return r, true
	case "hostnamectl":
		r := base("recon", 3, 83, "system-recon", "host metadata discovery")
		r.Output = " Static hostname: " + w.hostname + "\n       Icon name: computer-vm\n         Chassis: vm\n      Machine ID: " + w.system.machineID() + "\n         Boot ID: " + w.system.bootID() + "\n  Virtualization: kvm\nOperating System: Ubuntu 24.04.3 LTS\n          Kernel: Linux 6.8.0-64-generic\n    Architecture: x86-64"
		return r, true
	case "arch":
		r := base("recon", 3, 80, "system-recon", "architecture discovery")
		r.Output = "x86_64"
		return r, true
	case "nproc":
		r := base("recon", 3, 80, "system-recon", "CPU discovery")
		r.Output = "4"
		return r, true
	case "nvidia-smi":
		r := base("recon", 3, 82, "system-recon", "GPU discovery")
		if containsArg(args, "--version") {
			r.Output = "NVIDIA-SMI 550.120"
		} else {
			r.Output = "==============NVSMI LOG==============\n\nTimestamp                                 : Sat Aug 15 20:26:04 2026\nDriver Version                            : 550.120\nCUDA Version                              : 12.4\nAttached GPUs                             : 0"
		}
		return r, true
	case "lscpu":
		r := base("recon", 3, 84, "system-recon", "CPU discovery")
		r.Output = "Architecture:                         x86_64\nCPU(s):                               4\nVendor ID:                            GenuineIntel\nModel name:                           Intel(R) Xeon(R) CPU E-2288G @ 3.70GHz\nVirtualization:                       VT-x\nHypervisor vendor:                    KVM"
		return r, true
	case "lsblk":
		r := base("recon", 4, 86, "system-recon", "block device discovery")
		r.Output = "NAME   MAJ:MIN RM   SIZE RO TYPE MOUNTPOINTS\nvda    252:0    0   100G  0 disk\n├─vda1 252:1    0     1G  0 part /boot\n└─vda2 252:2    0    99G  0 part /\nvdb    252:16   0   500G  0 disk\n└─vdb1 252:17   0   500G  0 part /srv/archive"
		return r, true
	case "blkid":
		r := base("recon", 4, 86, "system-recon", "block device discovery")
		r.Output = "/dev/vda2: UUID=\"4e2a-91bf\" BLOCK_SIZE=\"4096\" TYPE=\"ext4\" PARTUUID=\"82adf4b1-02\"\n/dev/vdb1: UUID=\"3ac1-c98d\" BLOCK_SIZE=\"4096\" TYPE=\"ext4\""
		return r, true
	case "lsof":
		r := base("network", 5, 92, "network-recon", "open file/socket discovery")
		r.Output = "COMMAND   PID     USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\nsshd      612     root    3u  IPv4  23141      0t0  TCP *:ssh (LISTEN)\nweb       844  svc-web    7u  IPv4  24421      0t0  TCP *:tproxy (LISTEN)\npostgres  901 postgres    5u  IPv4  24912      0t0  TCP localhost:postgresql (LISTEN)"
		return r, true
	case "dmesg":
		r := base("recon", 4, 87, "system-recon", "kernel log discovery")
		r.Output = "[    0.000000] Linux version 6.8.0-64-generic\n[    0.881214] virtio_net virtio0 eth0: renamed from ens3\n[    1.201044] EXT4-fs (vda2): mounted filesystem with ordered data mode\n[    4.321881] systemd[1]: Reached target multi-user.target"
		return r, true
	case "lsmod":
		r := base("recon", 4, 85, "system-recon", "kernel module discovery")
		r.Output = "Module                  Size  Used by\nnf_conntrack          196608  2\nbr_netfilter           32768  0\noverlay                212992  3\nvirtio_net              73728  0"
		return r, true
	case "sysctl":
		r := base("recon", 4, 88, "system-recon", "kernel parameter discovery")
		key := lastNonOption(args)
		values := map[string]string{"kernel.hostname": w.hostname, "kernel.randomize_va_space": "2", "net.ipv4.ip_forward": "0", "fs.protected_hardlinks": "1", "fs.protected_symlinks": "1"}
		if containsArg(args, "-a") || key == "" {
			keys := make([]string, 0, len(values))
			for k := range values {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				r.Output += k + " = " + values[k] + "\n"
			}
			r.Output = strings.TrimSuffix(r.Output, "\n")
		} else if v, ok := values[key]; ok {
			r.Output = key + " = " + v
		} else {
			r.Output, r.Status = "sysctl: cannot stat /proc/sys/"+strings.ReplaceAll(key, ".", "/")+": No such file or directory", 1
		}
		return r, true
	case "getcap":
		r := base("privilege", 5, 94, "privilege-escalation", "Linux capabilities discovery")
		r.Output = "/usr/local/bin/backupctl cap_dac_read_search,cap_setuid+ep"
		return r, true
	case "capsh":
		r := base("privilege", 5, 94, "privilege-escalation", "process capabilities discovery")
		r.Output = "Current: cap_chown,cap_dac_override,cap_fowner,cap_setgid,cap_setuid+ep\nBounding set =cap_chown,cap_dac_override,cap_fowner,cap_setgid,cap_setuid,cap_net_bind_service\nuid=0(root) euid=0(root)"
		return r, true
	case "lsattr":
		r := base("filesystem", 4, 87, "file-discovery", "extended attribute discovery")
		file := lastNonOption(args)
		if file == "" {
			file = "."
		}
		resolved := w.resolve(file)
		if _, ok := w.virtualReadFile(resolved); !ok {
			r.Output, r.Status = "lsattr: No such file or directory while trying to stat "+file, 1
			return r, true
		}
		attrs := w.fileAttrs[resolved]
		if attrs == "" {
			attrs = "--------------e-------"
		}
		r.Output = attrs + " " + file
		return r, true
	case "chattr":
		r := base("persistence", 6, 98, "persistence", "immutable/extended attribute modification")
		file := lastNonOption(args)
		if file != "" {
			resolved := w.resolve(file)
			if _, ok := w.virtualReadFile(resolved); !ok {
				// Malware cleanup commands routinely target optional remnants; errors are often redirected.
				r.Output, r.Status = "chattr: No such file or directory while trying to stat "+file, 1
			} else {
				w.fileAttrs[resolved] = "--------------e-------"
			}
		}
		r.LoopInc = 1
		return r, true
	case "readlink", "realpath":
		r := base("filesystem", 3, 82, "file-discovery", "path resolution")
		target := lastNonOption(args)
		if target == "" {
			r.Status = 1
			return r, true
		}
		resolved := w.resolve(target)
		if strings.HasPrefix(resolved, "/proc/") && strings.HasSuffix(resolved, "/exe") {
			parts := strings.Split(strings.Trim(resolved, "/"), "/")
			if len(parts) == 3 {
				pid, ok := parseVirtualPIDArg(parts[1])
				if !ok {
					r.Status = 1
					return r, true
				}
				if exe, ok := w.virtualProcExe(pid); ok {
					r.Output = exe
					return r, true
				}
				r.Status = 1
				return r, true
			}
		}
		r.Output = resolved
		return r, true
	case "dirname":
		r := base("filesystem", 2, 75, "interactive-shell", "path manipulation")
		if len(args) > 0 {
			r.Output = path.Dir(args[len(args)-1])
		}
		return r, true
	case "basename":
		r := base("filesystem", 2, 75, "interactive-shell", "path manipulation")
		if len(args) > 0 {
			r.Output = path.Base(args[len(args)-1])
		}
		return r, true
	case "mktemp":
		r := base("filesystem", 4, 89, "file-manipulation", "temporary file creation")
		name := "/tmp/tmp." + fmt.Sprintf("%06x", stableSSHHash(fmt.Sprintf("%d|%s", w.ops, raw))&0xffffff)
		if !w.setVirtualFile(name, "") {
			r.Output, r.Status = "mktemp: failed to create file: No space left on device", 1
		} else {
			r.Output = name
		}
		return r, true
	case "ln":
		r := base("filesystem", 5, 91, "file-manipulation", "virtual link creation")
		if len(args) < 2 {
			r.Output, r.Status = "ln: missing file operand", 1
			return r, true
		}
		src, dst := w.resolve(args[len(args)-2]), w.resolve(args[len(args)-1])
		content, ok := w.virtualReadFile(src)
		if !ok {
			r.Output, r.Status = "ln: failed to access '"+args[len(args)-2]+"': No such file or directory", 1
		} else if !w.setVirtualFile(dst, content) {
			r.Output, r.Status = "ln: failed to create link: No space left on device", 1
		}
		return r, true
	case "sha256sum", "md5sum":
		r := base("filesystem", 4, 87, "file-discovery", "file hashing")
		file := lastNonOption(args)
		data := input
		if file != "" && file != "-" {
			var ok bool
			data, ok = w.virtualReadFile(file)
			if !ok {
				r.Output, r.Status = cmd+": "+file+": No such file or directory", 1
				return r, true
			}
		}
		if cmd == "sha256sum" {
			sum := sha256.Sum256([]byte(data))
			r.Output = hex.EncodeToString(sum[:]) + "  " + firstNonEmpty(file, "-")
		} else {
			sum := md5.Sum([]byte(data))
			r.Output = hex.EncodeToString(sum[:]) + "  " + firstNonEmpty(file, "-")
		}
		return r, true
	case "base64":
		r := base("execution", 5, 92, "payload-preparation", "base64 encode/decode")
		data := input
		file := lastNonOption(args)
		if data == "" && file != "" && !strings.HasPrefix(file, "-") {
			data, _ = w.virtualReadFile(file)
		}
		if containsArg(args, "-d") || containsArg(args, "--decode") {
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(data))
			if err != nil {
				r.Output, r.Status = "base64: invalid input", 1
			} else {
				r.Output = string(decoded)
			}
		} else {
			r.Output = base64.StdEncoding.EncodeToString([]byte(data))
		}
		return r, true
	case "xxd":
		r := base("execution", 5, 91, "payload-analysis", "hex encoding/decoding")
		data := input
		file := lastNonOption(args)
		if data == "" && file != "" {
			data, _ = w.virtualReadFile(file)
		}
		if containsArg(args, "-r") {
			clean := strings.Map(func(r rune) rune {
				if strings.ContainsRune("0123456789abcdefABCDEF", r) {
					return r
				}
				return -1
			}, data)
			decoded, err := hex.DecodeString(clean)
			if err != nil {
				r.Status = 1
			} else {
				r.Output = string(decoded)
			}
		} else {
			b := []byte(data)
			for i := 0; i < len(b) && i < 256; i += 16 {
				end := i + 16
				if end > len(b) {
					end = len(b)
				}
				r.Output += fmt.Sprintf("%08x: %-47s  %s\n", i, spacedHex(b[i:end]), printableASCII(b[i:end]))
			}
			r.Output = strings.TrimSuffix(r.Output, "\n")
		}
		return r, true
	case "strings":
		r := base("filesystem", 4, 87, "file-discovery", "printable string extraction")
		data := input
		if data == "" {
			data, _ = w.virtualReadFile(lastNonOption(args))
		}
		r.Output = virtualPrintableStrings(data)
		return r, true
	case "wc":
		r := base("filesystem", 3, 82, "file-discovery", "text measurement")
		data := virtualTextInput(w, args, input)
		lines := strings.Count(data, "\n")
		if data != "" && !strings.HasSuffix(data, "\n") {
			lines++
		}
		words := len(strings.Fields(data))
		bytes := len([]byte(data))
		switch {
		case containsArg(args, "-l"):
			r.Output = strconv.Itoa(lines)
		case containsArg(args, "-w"):
			r.Output = strconv.Itoa(words)
		case containsArg(args, "-c"):
			r.Output = strconv.Itoa(bytes)
		default:
			r.Output = fmt.Sprintf("%d %d %d", lines, words, bytes)
		}
		return r, true
	case "sort":
		r := base("filesystem", 3, 82, "file-discovery", "text sorting")
		rows := strings.Split(strings.TrimSuffix(virtualTextInput(w, args, input), "\n"), "\n")
		sort.Strings(rows)
		if containsArg(args, "-r") {
			for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
				rows[i], rows[j] = rows[j], rows[i]
			}
		}
		r.Output = strings.Join(rows, "\n")
		return r, true
	case "uniq":
		r := base("filesystem", 3, 82, "file-discovery", "text de-duplication")
		rows := strings.Split(strings.TrimSuffix(virtualTextInput(w, args, input), "\n"), "\n")
		var out []string
		for _, row := range rows {
			if len(out) == 0 || out[len(out)-1] != row {
				out = append(out, row)
			}
		}
		r.Output = strings.Join(out, "\n")
		return r, true
	case "cut":
		r := base("filesystem", 3, 83, "file-discovery", "text field extraction")
		data := virtualTextInput(w, args, input)
		delim := "\t"
		field := 1
		for i, a := range args {
			switch {
			case a == "-d" && i+1 < len(args):
				delim = args[i+1]
			case strings.HasPrefix(a, "-d") && len(a) > 2:
				delim = strings.TrimPrefix(a, "-d")
			case a == "-f" && i+1 < len(args):
				field, _ = strconv.Atoi(strings.Split(args[i+1], ",")[0])
			case strings.HasPrefix(a, "-f") && len(a) > 2:
				field, _ = strconv.Atoi(strings.Split(strings.TrimPrefix(a, "-f"), ",")[0])
			}
		}
		if delim == "" {
			delim = "\t"
		}
		for _, row := range strings.Split(strings.TrimSuffix(data, "\n"), "\n") {
			parts := strings.Split(row, delim)
			if field > 0 && field <= len(parts) {
				r.Output += parts[field-1] + "\n"
			}
		}
		r.Output = strings.TrimSuffix(r.Output, "\n")
		return r, true
	case "tr":
		r := base("filesystem", 3, 82, "file-discovery", "text transformation")
		data := input
		if len(args) >= 2 && args[0] == "-d" {
			chars := strings.ReplaceAll(args[1], `\n`, "\n")
			chars = strings.ReplaceAll(chars, `\r`, "\r")
			chars = strings.ReplaceAll(chars, `\t`, "\t")
			r.Output = strings.Map(func(ch rune) rune {
				if strings.ContainsRune(chars, ch) {
					return -1
				}
				return ch
			}, data)
		} else if len(args) >= 2 {
			from, to := args[len(args)-2], args[len(args)-1]
			if from == "[:lower:]" && to == "[:upper:]" {
				r.Output = strings.ToUpper(data)
			} else if from == "[:upper:]" && to == "[:lower:]" {
				r.Output = strings.ToLower(data)
			} else {
				r.Output = strings.NewReplacer(from, to).Replace(data)
			}
		} else {
			r.Output = data
		}
		return r, true
	case "sed":
		r := base("filesystem", 4, 87, "file-discovery", "stream editing")
		data := virtualTextInput(w, args, input)
		expr := firstNonOption(args)
		r.Output = simpleVirtualSed(data, expr)
		return r, true
	case "awk":
		r := base("filesystem", 4, 88, "file-discovery", "text processing")
		data := virtualTextInput(w, args, input)
		program := firstNonOption(args)
		r.Output = simpleVirtualAwk(data, program)
		return r, true
	case "tee":
		r := base("filesystem", 5, 91, "file-manipulation", "pipeline output written to virtual file")
		target := lastNonOption(args)
		if target != "" {
			ok := false
			if containsArg(args, "-a") {
				ok = w.appendVirtualFile(w.resolve(target), input)
			} else {
				ok = w.setVirtualFile(w.resolve(target), input)
			}
			if !ok {
				r.Output, r.Status = "tee: "+target+": No space left on device", 1
				return r, true
			}
		}
		r.Output = input
		return r, true
	case "xargs":
		r := base("execution", 5, 93, "command-execution", "pipeline command construction")
		if len(args) == 0 {
			r.Output = strings.Join(strings.Fields(input), " ")
			return r, true
		}
		constructed := strings.Join(args, " ") + " " + strings.Join(strings.Fields(input), " ")
		inner := w.executeOne(constructed, "")
		if inner.Depth < r.Depth {
			inner.Depth = r.Depth
		}
		return inner, true
	case "tar":
		r := base("archive", 5, 93, "collection", "archive inspection/manipulation")
		archive := virtualTarArchive(args)
		if containsCombinedFlag(args, 't') {
			if archive == "" {
				r.Output, r.Status = "tar: Cowardly refusing to create an empty archive", 2
			} else {
				r.Output = "app/.env\napp/current/config.yaml\nbackup/backup.conf\nroot/.ssh/id_ed25519_backup"
			}
			return r, true
		}
		if containsCombinedFlag(args, 'x') {
			_ = w.setVirtualDir(w.resolve("app"))
			_ = w.setVirtualFile(w.resolve("app/.env"), w.files["/opt/app/.env"])
			r.LoopInc = 1
			return r, true
		}
		if containsCombinedFlag(args, 'c') {
			if archive == "" {
				archive = "archive.tar.gz"
			}
			if !w.setVirtualFile(w.resolve(archive), "\x1f\x8bFAKE-VIRTUAL-TAR-ARCHIVE\n") {
				r.Output, r.Status = "tar: "+archive+": Cannot write: No space left on device", 2
			}
			return r, true
		}
		r.Output, r.Status = "tar: You must specify one of the '-Acdtrux', '--delete' or '--test-label' options", 2
		return r, true
	case "gzip", "gunzip", "zcat":
		r := base("archive", 4, 89, "collection", "compression/decompression")
		file := lastNonOption(args)
		decompress := cmd == "gunzip" || cmd == "zcat" || containsArg(args, "-d") || containsCombinedFlag(args, 'd')
		stdout := cmd == "zcat" || containsArg(args, "-c") || containsCombinedFlag(args, 'c')
		if file == "" {
			if decompress {
				plain := strings.TrimPrefix(input, "\x1f\x8b")
				if strings.Contains(plain, "virtual-gzip-country-database") {
					plain = "network,continent,country\n1.0.0.0/24,OC,AU\n1.0.1.0/24,AS,CN\n1.0.2.0/23,AS,CN\n"
				}
				r.Output = plain
				return r, true
			}
			if stdout && input != "" {
				r.Output = "\x1f\x8b" + input
			} else {
				r.Output = input
			}
			return r, true
		}
		p := w.resolve(file)
		content, ok := w.virtualReadFile(p)
		if !ok {
			r.Output, r.Status = cmd+": "+file+": No such file or directory", 1
			return r, true
		}
		if decompress {
			plain := strings.TrimPrefix(content, "\x1f\x8b")
			if meta := w.fileMeta[p]; meta.Kind == "gzip" && strings.Contains(strings.ToLower(file), "dbip-country-lite") {
				plain = "network,continent,country\n1.0.0.0/24,OC,AU\n1.0.1.0/24,AS,CN\n1.0.2.0/23,AS,CN\n"
			}
			if stdout {
				r.Output = plain
				return r, true
			}
			dst := strings.TrimSuffix(p, ".gz")
			_ = w.setVirtualFile(dst, plain)
			w.deleteVirtualFile(p)
			return r, true
		}
		if stdout {
			r.Output = "\x1f\x8b" + content
			return r, true
		}
		_ = w.setVirtualFile(p+".gz", "\x1f\x8b"+content)
		w.deleteVirtualFile(p)
		return r, true
	case "zip", "unzip":
		r := base("archive", 5, 91, "collection", "archive manipulation")
		if cmd == "unzip" {
			r.Output = "Archive:  " + firstNonEmpty(lastNonOption(args), "archive.zip") + "\n  inflating: config/.env\n  inflating: config/backup.conf"
			_ = w.setVirtualDir(w.resolve("config"))
			_ = w.setVirtualFile(w.resolve("config/.env"), w.files["/opt/app/.env"])
		} else if len(args) > 0 {
			_ = w.setVirtualFile(w.resolve(args[0]), "PK\x03\x04FAKE-VIRTUAL-ZIP\n")
			r.Output = "  adding: " + strings.Join(args[1:], " ") + " (deflated 42%)"
		}
		return r, true
	case "git":
		return w.fakeGit(args), true
	case "apt", "apt-get":
		return w.fakeApt(cmd, args), true
	case "dpkg":
		r := base("recon", 4, 86, "tool-discovery", "package inventory discovery")
		if containsArg(args, "-l") {
			r.Output = "Desired=Unknown/Install/Remove/Purge/Hold\n||/ Name           Version              Architecture Description\nii  curl           8.5.0-2ubuntu10.6   amd64        command line tool for transferring data\nii  openssh-server 1:9.6p1-3ubuntu13.13 amd64        secure shell server\nii  docker-ce      5:27.5.1-1~ubuntu.24 amd64        Docker container engine\nii  vim            2:9.1.0016-1ubuntu7  amd64        Vi IMproved"
		}
		return r, true
	case "openssl":
		r := base("credentials", 5, 93, "credential-hunter", "cryptographic material inspection")
		if len(args) > 0 && args[0] == "version" {
			r.Output = "OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)"
		} else if strings.Contains(raw, "x509") {
			r.Output = "subject=CN = api.prod.internal\nissuer=CN = prod-internal-ca\nnotBefore=Jul 19 05:00:00 2026 GMT\nnotAfter=Jul 19 05:00:00 2027 GMT"
		} else {
			r.Output = "OpenSSL>"
		}
		return r, true
	case "source", ".":
		r := base("execution", 6, 96, "script-execution", "virtual shell script sourced")
		if w.sourceDepth >= 8 {
			r.Output, r.Status = "bash: source: maximum virtual source depth exceeded", 1
			r.Persona, r.Message = "resource-abuse", "virtual source recursion bounded"
			return r, true
		}
		file := lastNonOption(args)
		content, ok := w.virtualReadFile(file)
		if !ok {
			r.Output, r.Status = "bash: "+file+": No such file or directory", 1
			return r, true
		}
		w.sourceDepth++
		defer func() { w.sourceDepth-- }()
		var outputs []string
		lines := strings.Split(content, "\n")
		if len(lines) > 24 {
			lines = lines[:24]
		}
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			res := w.Execute(line)
			if res.Output != "" {
				outputs = append(outputs, res.Output)
			}
			r.Status = res.Status
			if res.Exit {
				break
			}
		}
		r.Output = strings.Join(outputs, "\n")
		r.LoopInc = 1
		return r, true
	case "sleep":
		r := base("shell", 2, 74, "interactive-shell", "sleep requested")
		if len(args) > 0 {
			seconds, _ := strconv.ParseFloat(strings.TrimSuffix(args[0], "s"), 64)
			if seconds > 0 {
				if seconds > 2.0 {
					seconds = 2.0
				}
				r.Delay = time.Duration(seconds * float64(time.Second))
			}
		}
		return r, true
	case "kill", "pkill", "killall":
		r := base("execution", 5, 92, "process-control", "process termination attempt")
		matched := false
		if cmd == "kill" {
			for _, a := range args {
				if strings.HasPrefix(a, "-") {
					continue
				}
				pid, ok := parseVirtualPIDArg(a)
				if !ok {
					r.Output = "bash: kill: " + a + ": arguments must be process or job IDs"
					r.Status = 2
					return r, true
				}
				if p := w.processes[pid]; p != nil && p.Alive {
					p.Alive = false
					matched = true
				} else if virtualStaticPID(pid) {
					matched = true
				}
			}
		} else {
			name := lastNonOption(args)
			matched = w.killVirtualProcesses(name)
		}
		if !matched {
			r.Status = 1
		}
		r.LoopInc = 1
		return r, true
	case "nohup":
		r := base("persistence", 6, 97, "persistence", "detached process execution")
		_ = w.appendVirtualFile(w.resolve("nohup.out"), "worker started\n")
		r.Output = "nohup: ignoring input and appending output to 'nohup.out'"
		r.LoopInc = 1
		return r, true
	case "tmux":
		r := base("persistence", 5, 91, "session-management", "terminal multiplexer use")
		created := w.system.snapshot().Now.Add(-2*time.Hour - 5*time.Minute)
		if containsArg(args, "ls") || containsArg(args, "list-sessions") {
			r.Output = "ops: 1 windows (created " + created.Format("Mon Jan _2 15:04:05 2006") + ")"
		} else {
			r.Output = "[detached (from session ops)]"
		}
		return r, true
	case "screen":
		r := base("persistence", 5, 91, "session-management", "terminal multiplexer use")
		created := w.system.snapshot().Now.Add(-2*time.Hour - 5*time.Minute)
		if containsArg(args, "-ls") {
			r.Output = "There is a screen on:\n\t1842.ops\t(" + created.Format("01/02/06 15:04:05") + ")\t(Detached)\n1 Socket in /run/screen/S-root."
		}
		return r, true
	case "man":
		r := base("shell", 2, 74, "interactive-shell", "manual page requested")
		name := lastNonOption(args)
		if name == "" {
			r.Output, r.Status = "What manual page do you want?", 1
		} else {
			r.Output = strings.ToUpper(name) + "(1)                    User Commands                   " + strings.ToUpper(name) + "(1)\n\nNAME\n       " + name + " - standard Ubuntu command\n\nSYNOPSIS\n       " + name + " [OPTION]...\n\nDESCRIPTION\n       This is the system manual page for " + name + "."
		}
		return r, true
	case "psql":
		r := base("credentials", 6, 97, "database-access", "database client use")
		if containsArg(args, "--version") || containsArg(args, "-V") {
			r.Output = "psql (PostgreSQL) 16.9 (Ubuntu 16.9-0ubuntu0.24.04.1)"
		} else {
			r.Output = "psql (16.9 (Ubuntu 16.9-0ubuntu0.24.04.1))\nType \"help\" for help.\n\nplatform=>"
			r.LoopInc = 1
		}
		return r, true
	case "dig", "nslookup", "host":
		r := base("network", 4, 89, "network-recon", "DNS discovery")
		name := lastNonOption(args)
		if name == "" {
			name = "db-internal"
		}
		ip := "203.0.113.42"
		if h, ok := lures.Resolve(name); ok {
			ip = h.IP
		}
		if cmd == "dig" {
			r.Output = "; <<>> DiG 9.18.30-0ubuntu0.24.04.2-Ubuntu <<>> " + name + "\n;; global options: +cmd\n;; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 18421\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\n;; ANSWER SECTION:\n" + name + ".\t60\tIN\tA\t" + ip + "\n\n;; Query time: 2 msec\n;; SERVER: 10.10.30.1#53(10.10.30.1) (UDP)"
		} else if cmd == "nslookup" {
			r.Output = "Server:\t\t10.10.30.1\nAddress:\t10.10.30.1#53\n\nName:\t" + name + "\nAddress: " + ip
		} else {
			r.Output = name + " has address " + ip
		}
		return r, true
	case "arp":
		r := base("network", 4, 88, "network-recon", "ARP neighbor discovery")
		r.Output = "Address                  HWtype  HWaddress           Flags Mask            Iface\n_gateway                  ether   52:54:00:12:34:01   C                     eth0\nbackup-01                 ether   52:54:00:3a:91:0c   C                     eth0\ndb-primary                ether   52:54:00:51:10:14   C                     eth0\ncache-01                  ether   52:54:00:7b:22:18   C                     eth0\nregistry-01               ether   52:54:00:2c:81:25   C                     eth0\nops-gw-01                 ether   52:54:00:18:70:30   C                     eth0"
		return r, true
	case "iptables", "nft", "ufw":
		r := base("network", 5, 93, "network-recon", "firewall discovery or modification")
		if cmd == "ufw" {
			r.Output = "Status: inactive"
		} else if cmd == "nft" {
			r.Output = "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t}\n}"
		} else {
			r.Output = "Chain INPUT (policy ACCEPT)\ntarget     prot opt source               destination\nChain FORWARD (policy DROP)\ntarget     prot opt source               destination\nDOCKER-USER  all  --  anywhere             anywhere"
		}
		return r, true
	case "traceroute", "tracepath":
		r := base("network", 5, 92, "network-recon", "network path discovery")
		host := lastNonOption(args)
		if host == "" {
			host = "backup-01"
		}
		ip := host
		if h, ok := lures.Resolve(host); ok {
			ip = h.IP
		}
		r.Output = "traceroute to " + host + " (" + ip + "), 30 hops max, 60 byte packets"
		r.Interactive = "traceroute"
		r.Target = host
		return r, true
	case "rsync":
		r := base("file-transfer", 6, 97, "lateral-movement", "simulated rsync transfer")
		r.Output = "sending incremental file list\nconfig-prod.tar.gz\n\nsent 1,184 bytes  received 42 bytes  2,452.00 bytes/sec\ntotal size is 4,842,112  speedup is 3,949.52"
		r.LoopInc = 1
		return r, true
	case "sftp":
		r := base("file-transfer", 6, 97, "lateral-movement", "simulated SFTP client use")
		target := lastNonOption(args)
		if target == "" {
			target = "svc-backup@10.10.30.12"
		}
		r.Output = "Connected to " + strings.TrimPrefix(target, "svc-backup@") + ".\nsftp>"
		r.LoopInc = 1
		return r, true
	case "socat":
		r := base("network", 6, 98, "tunneling", "simulated socket relay/tunnel attempt")
		if containsArg(args, "-V") || containsArg(args, "-h") {
			r.Output = "socat version 1.7.4.4 on Linux"
		} else {
			r.Output = "2026/08/15 13:44:18 socat[28411] N listening on AF=2 0.0.0.0:4444"
			r.LoopInc = 1
		}
		return r, true
	case "redis-cli":
		r := base("credentials", 6, 97, "database-access", "Redis client use")
		if containsArg(args, "--version") {
			r.Output = "redis-cli 7.0.15"
		} else if len(args) > 0 && strings.EqualFold(args[len(args)-1], "ping") {
			r.Output = "PONG"
		} else {
			r.Output = "10.10.30.18:6379>"
			r.LoopInc = 1
		}
		return r, true
	case "mysql", "mariadb":
		r := base("credentials", 6, 97, "database-access", "SQL client use")
		if containsArg(args, "--version") || containsArg(args, "-V") {
			r.Output = "mysql  Ver 8.0.42-0ubuntu0.24.04.1 for Linux on x86_64 ((Ubuntu))"
		} else {
			r.Output = "Welcome to the MySQL monitor.  Commands end with ; or \\g.\nYour MySQL connection id is 1842\nServer version: 8.0.42-0ubuntu0.24.04.1 (Ubuntu)\n\nmysql>"
			r.LoopInc = 1
		}
		return r, true
	case "node", "npm":
		r := base("recon", 3, 82, "tool-discovery", "runtime discovery")
		if cmd == "node" {
			r.Output = "v20.19.2"
		} else {
			r.Output = "10.8.2"
		}
		return r, true
	case "go":
		r := base("recon", 3, 82, "tool-discovery", "compiler/runtime discovery")
		r.Output = "go version go1.23.12 linux/amd64"
		return r, true
	case "gcc", "cc":
		r := base("execution", 5, 93, "payload-preparation", "compiler use")
		if containsArg(args, "--version") {
			r.Output = "gcc (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0"
		} else {
			out := optionValue(args, "-o")
			if out == "" {
				out = "a.out"
			}
			_ = w.setVirtualFile(w.resolve(out), "\x7fELF\x02\x01\x01virtual-compiled-binary\n")
			r.LoopInc = 1
		}
		return r, true
	case "make":
		r := base("execution", 5, 92, "payload-preparation", "build tool use")
		r.Output = "cc -O2 -Wall -o worker worker.c\nstrip worker"
		_ = w.setVirtualFile(w.resolve("worker"), "\x7fELF\x02\x01\x01virtual-worker\n")
		return r, true
	case "ldd":
		r := base("recon", 4, 87, "binary-analysis", "shared library discovery")
		r.Output = "linux-vdso.so.1 (0x00007ffd7fbf9000)\nlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f13b1200000)\n/lib64/ld-linux-x86-64.so.2 (0x00007f13b1480000)"
		return r, true
	case "readelf", "objdump":
		r := base("recon", 4, 88, "binary-analysis", "binary metadata inspection")
		r.Output = "ELF Header:\n  Class:                             ELF64\n  Data:                              2's complement, little endian\n  Machine:                           Advanced Micro Devices X86-64\n  Type:                              DYN (Position-Independent Executable file)"
		return r, true
	case "strace":
		r := base("execution", 5, 93, "process-analysis", "system call tracing")
		r.Output = "execve(\"/usr/bin/id\", [\"id\"], 0x7ffd1a2c0 /* 18 vars */) = 0\nwrite(1, \"uid=1000(admin) gid=1000(admin)\\n\", 33) = 33\nexit_group(0) = ?\n+++ exited with 0 +++"
		return r, true
	case "passwd":
		r := base("credentials", 6, 98, "credential-manipulation", "password modification attempt")
		r.Output = "passwd: password updated successfully"
		r.LoopInc = 1
		return r, true
	}
	return virtualSSHResult{}, false
}

func virtualCommandExists(name string) bool {
	name = path.Base(name)
	for _, cmd := range virtualSSHCommands {
		if cmd == name {
			return true
		}
	}
	return false
}

func virtualCommandNotFound(cmd string) string {
	packages := map[string]string{"jq": "jq", "nmap": "nmap", "htop": "htop", "dig": "dnsutils", "nslookup": "dnsutils", "socat": "socat", "rsync": "rsync"}
	if pkg, ok := packages[cmd]; ok {
		return "Command '" + cmd + "' not found, but can be installed with:\napt install " + pkg
	}
	return "bash: " + cmd + ": command not found"
}

func validVirtualEnvName(v string) bool {
	if v == "" {
		return false
	}
	for i, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' || (i > 0 && r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

func firstNonOption(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return ""
}

func virtualTextInput(w *virtualSSHWorld, args []string, input string) string {
	if input != "" {
		return input
	}
	for i := len(args) - 1; i >= 0; i-- {
		if strings.HasPrefix(args[i], "-") || strings.ContainsAny(args[i], "{}$;") {
			continue
		}
		if content, ok := w.virtualReadFile(args[i]); ok {
			return content
		}
	}
	return ""
}

func spacedHex(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02x", v)
	}
	return strings.Join(parts, " ")
}

func printableASCII(b []byte) string {
	var out strings.Builder
	for _, v := range b {
		if v >= 32 && v <= 126 {
			out.WriteByte(v)
		} else {
			out.WriteByte('.')
		}
	}
	return out.String()
}

func virtualPrintableStrings(v string) string {
	var out []string
	var b strings.Builder
	flush := func() {
		if b.Len() >= 4 {
			out = append(out, b.String())
		}
		b.Reset()
	}
	for _, r := range v {
		if r >= 32 && r <= 126 {
			b.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	return strings.Join(out, "\n")
}

func simpleVirtualSed(data, expr string) string {
	if !strings.HasPrefix(expr, "s") || len(expr) < 4 {
		return data
	}
	delim := expr[1]
	parts := strings.Split(expr[2:], string(delim))
	if len(parts) < 2 {
		return data
	}
	old, new := parts[0], parts[1]
	if len(parts) >= 3 && strings.Contains(parts[2], "g") {
		return strings.ReplaceAll(data, old, new)
	}
	return strings.Replace(data, old, new, 1)
}

func simpleVirtualAwk(data, program string) string {
	program = strings.TrimSpace(program)
	// Observed collector pattern: uptime | awk -F'( up |,|load)' '{... print $2}'
	if strings.Contains(program, "print $2") && strings.Contains(data, " up ") && strings.Contains(data, "load average") {
		if _, after, ok := strings.Cut(data, " up "); ok {
			if before, _, ok := strings.Cut(after, ","); ok {
				return strings.TrimSpace(before)
			}
		}
	}
	if strings.Contains(program, "Model name") && (strings.Contains(program, "print $2") || strings.Contains(program, "print $ 2")) {
		for _, row := range strings.Split(strings.TrimSuffix(data, "\n"), "\n") {
			if !strings.Contains(strings.ToLower(row), "model name") {
				continue
			}
			if _, value, ok := strings.Cut(row, ":"); ok {
				return strings.TrimSpace(value)
			}
		}
		return ""
	}
	// Small but useful subset for collector pipelines such as awk '{print $4}'.
	for field := 1; field <= 16; field++ {
		needle1 := fmt.Sprintf("print $%d", field)
		needle2 := fmt.Sprintf("printf $%d", field)
		if !strings.Contains(program, needle1) && !strings.Contains(program, needle2) {
			continue
		}
		var out []string
		for _, row := range strings.Split(strings.TrimSuffix(data, "\n"), "\n") {
			fields := strings.Fields(row)
			if len(fields) >= field {
				out = append(out, fields[field-1])
			}
			if strings.Contains(program, "exit") && len(out) > 0 {
				break
			}
		}
		return strings.Join(out, "\n")
	}
	return data
}

func containsCombinedFlag(args []string, flag byte) bool {
	for _, a := range args {
		if strings.HasPrefix(a, "-") && strings.ContainsRune(a, rune(flag)) {
			return true
		}
	}
	return false
}

func virtualTarArchive(args []string) string {
	for i, a := range args {
		if (a == "-f" || a == "--file") && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(a, "-") && strings.ContainsRune(a, 'f') && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func (w *virtualSSHWorld) fakeGit(args []string) virtualSSHResult {
	r := virtualBaseResult("git", "source-control", 5, 92, "source-discovery", "source repository discovery/manipulation")
	if len(args) == 0 {
		r.Output, r.Status = "usage: git [-v | --version] [-h | --help] [-C <path>] <command> [<args>]", 1
		return r
	}
	switch args[0] {
	case "status":
		r.Output = "On branch release/2026.08\nYour branch is up to date with 'origin/release/2026.08'.\n\nnothing to commit, working tree clean"
	case "branch":
		r.Output = "* release/2026.08\n  main\n  hotfix/legacy-backup"
	case "remote":
		if containsArg(args, "-v") {
			r.Output = "origin\tssh://git@git.prod.internal/platform/web.git (fetch)\norigin\tssh://git@git.prod.internal/platform/web.git (push)"
		}
	case "log":
		r.Output = "commit 7e4ab12d5f8f52b4be14cf86d8e9031f2a9d2b11 (HEAD -> release/2026.08)\nAuthor: deploy-bot <deploy@prod.internal>\nDate:   Fri Aug 14 02:08:31 2026 +0200\n\n    release 2026.08\n\ncommit a18c20f519faad1b0d1e2813314d6e12f9460ca4\nAuthor: ops <ops@prod.internal>\nDate:   Thu Aug 13 18:42:10 2026 +0200\n\n    keep legacy backup until migration closes"
	case "config":
		if len(args) >= 2 && args[1] == "--list" {
			r.Output = "core.repositoryformatversion=0\nremote.origin.url=ssh://git@git.prod.internal/platform/web.git\nbranch.release/2026.08.remote=origin"
		}
	case "clone":
		name := "platform-web"
		if len(args) >= 3 {
			name = args[2]
		}
		_ = w.setVirtualDir(w.resolve(name))
		_ = w.setVirtualDir(w.resolve(name + "/.git"))
		_ = w.setVirtualFile(w.resolve(name+"/.env.example"), "DB_HOST=db-internal\n")
		r.Output = "Cloning into '" + name + "'...\nremote: Enumerating objects: 841, done.\nremote: Counting objects: 100% (841/841), done.\nReceiving objects: 100% (841/841), 2.18 MiB | 18.4 MiB/s, done."
		r.LoopInc = 1
	default:
		r.Output = "git: '" + args[0] + "' is not a git command. See 'git --help'."
		r.Status = 1
	}
	return r
}

func (w *virtualSSHWorld) fakeApt(cmd string, args []string) virtualSSHResult {
	r := virtualBaseResult(cmd, "software", 5, 91, "tool-installation", "package manager use")
	if len(args) == 0 {
		r.Output = "apt 2.7.14 (amd64)\nUsage: apt [options] command"
		return r
	}
	switch args[0] {
	case "update":
		r.Output = "Hit:1 http://archive.ubuntu.com/ubuntu noble InRelease\nHit:2 http://archive.ubuntu.com/ubuntu noble-updates InRelease\nReading package lists... Done\nBuilding dependency tree... Done\nAll packages are up to date."
		r.Delay = 400 * time.Millisecond
	case "install":
		pkg := lastNonOption(args)
		if pkg == "install" || pkg == "" {
			pkg = "package"
		}
		r.Output = "Reading package lists... Done\nBuilding dependency tree... Done\nThe following NEW packages will be installed:\n  " + pkg + "\n0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.\nSetting up " + pkg + " (1.0-1ubuntu1) ..."
		r.LoopInc = 1
		r.Delay = 500 * time.Millisecond
	case "list":
		r.Output = "curl/noble-updates,now 8.5.0-2ubuntu10.6 amd64 [installed]\nopenssh-server/noble-updates,now 1:9.6p1-3ubuntu13.13 amd64 [installed]\nvim/noble,now 2:9.1.0016-1ubuntu7 amd64 [installed]"
	default:
		r.Output = "Reading package lists... Done"
	}
	return r
}

func (w *virtualSSHWorld) expandVirtualLine(line string) string {
	line = w.expandVirtualCommandSubstitutions(line)

	var out strings.Builder
	for i := 0; i < len(line); {
		if line[i] != '$' {
			out.WriteByte(line[i])
			i++
			continue
		}
		if i+1 < len(line) && line[i+1] == '?' {
			out.WriteString(strconv.Itoa(w.lastStatus))
			i += 2
			continue
		}
		if i+1 < len(line) && line[i+1] == '{' {
			if end := strings.IndexByte(line[i+2:], '}'); end >= 0 {
				end += i + 2
				name := line[i+2 : end]
				if value, ok := w.env[name]; ok {
					out.WriteString(value)
				} else {
					out.WriteString(line[i : end+1])
				}
				i = end + 1
				continue
			}
		}
		j := i + 1
		for j < len(line) {
			c := line[j]
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
				j++
				continue
			}
			break
		}
		if j == i+1 {
			out.WriteByte('$')
			i++
			continue
		}
		name := line[i+1 : j]
		if value, ok := w.env[name]; ok {
			out.WriteString(value)
		} else {
			out.WriteString(line[i:j])
		}
		i = j
	}
	return out.String()
}

func (w *virtualSSHWorld) expandVirtualCommandSubstitutions(line string) string {
	if w.substDepth >= 6 || !strings.Contains(line, "$(") {
		return line
	}
	for pass := 0; pass < 12; pass++ {
		start, end := findInnermostVirtualSubstitution(line)
		if start < 0 || end < 0 {
			break
		}
		inner := line[start+2 : end]
		w.substDepth++
		res := w.executeGrouped(inner)
		w.substDepth--
		value := strings.TrimRight(res.Output, "\r\n")
		line = line[:start] + value + line[end+1:]
	}
	return line
}

func findInnermostVirtualSubstitution(v string) (int, int) {
	start := strings.LastIndex(v, "$(")
	if start < 0 {
		return -1, -1
	}
	depth := 1
	var quote byte
	escaped := false
	for i := start + 2; i < len(v); i++ {
		c := v[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if c == '(' {
			depth++
			continue
		}
		if c == ')' {
			depth--
			if depth == 0 {
				return start, i
			}
		}
	}
	return -1, -1
}

func (w *virtualSSHWorld) setVirtualTTY(term string, cols, rows int) {
	w.ttyMu.Lock()
	defer w.ttyMu.Unlock()
	if term != "" {
		w.ttyTerm = term
		w.env["TERM"] = term
	}
	if cols >= 20 && cols <= 1000 {
		w.ttyCols = cols
	}
	if rows >= 5 && rows <= 1000 {
		w.ttyRows = rows
	}
}

func (w *virtualSSHWorld) setVirtualEnv(name, value string) {
	if !validVirtualEnvName(name) || len(value) > 256 {
		return
	}
	w.env[name] = value
}

func (w *virtualSSHWorld) fakeInterpreter(cmd string, args []string) virtualSSHResult {
	r := virtualBaseResult(cmd, "execution", 6, 97, "command-execution", "simulated interpreter execution")
	joined := strings.Join(args, " ")
	low := strings.ToLower(joined)
	switch {
	case strings.Contains(low, "os.getuid") || strings.Contains(low, "geteuid"):
		if w.user == "root" {
			r.Output = "0"
		} else {
			r.Output = "1000"
		}
	case strings.Contains(low, "platform.machine") || strings.Contains(low, "uname"):
		r.Output = "x86_64"
	case strings.Contains(low, "socket.gethostname"):
		r.Output = w.hostname
	case strings.Contains(low, "requests.get") || strings.Contains(low, "urllib") || strings.Contains(low, "socket.socket"):
		r.Output = "connected"
		r.Family, r.Persona, r.Depth, r.Risk, r.LoopInc = "network", "network-tooling", 6, 98, 1
	default:
		r.Output = ""
	}
	return r
}

func containsShortFlag(args []string, flag byte) bool {
	for _, a := range args {
		if len(a) > 1 && a[0] == '-' && !strings.HasPrefix(a, "--") && strings.ContainsRune(a[1:], rune(flag)) {
			return true
		}
	}
	return false
}

func virtualByteCount(args []string) int {
	for i, a := range args {
		if (a == "-c" || a == "--bytes") && i+1 < len(args) {
			if n, err := strconv.Atoi(args[i+1]); err == nil && n > 0 && n <= 65536 {
				return n
			}
		}
		if strings.HasPrefix(a, "-c") && len(a) > 2 {
			if n, err := strconv.Atoi(a[2:]); err == nil && n > 0 && n <= 65536 {
				return n
			}
		}
	}
	return 0
}

func virtualLineCount(args []string, fallback int) int {
	for i, a := range args {
		if (a == "-n" || a == "--lines") && i+1 < len(args) {
			if n, err := strconv.Atoi(args[i+1]); err == nil && n > 0 && n <= 200 {
				return n
			}
		}
		if strings.HasPrefix(a, "-n") && len(a) > 2 {
			if n, err := strconv.Atoi(a[2:]); err == nil && n > 0 && n <= 200 {
				return n
			}
		}
	}
	return fallback
}

func virtualEchoOutput(cmd string, args []string) string {
	if cmd == "printf" {
		if len(args) == 0 {
			return ""
		}
		format := args[0]
		values := args[1:]
		format = strings.ReplaceAll(format, "\\n", "\n")
		format = strings.ReplaceAll(format, "\\t", "\t")
		format = strings.ReplaceAll(format, "\\r", "\r")
		for _, v := range values {
			if strings.Contains(format, "%s") {
				format = strings.Replace(format, "%s", v, 1)
			} else if strings.Contains(format, "%q") {
				format = strings.Replace(format, "%q", strconv.Quote(v), 1)
			}
		}
		return format
	}
	newline := true
	start := 0
	if len(args) > 0 && args[0] == "-n" {
		newline = false
		start = 1
	}
	out := strings.Join(args[start:], " ")
	if newline {
		return out
	}
	return out
}

func (w *virtualSSHWorld) fakeInterpreterVersion(cmd string) virtualSSHResult {
	r := virtualBaseResult(cmd, "recon", 3, 82, "tool-discovery", "interpreter version discovery")
	switch cmd {
	case "bash":
		r.Output = "GNU bash, version 5.2.21(1)-release (x86_64-pc-linux-gnu)\nCopyright (C) 2022 Free Software Foundation, Inc."
	case "sh", "dash":
		r.Output = "dash 0.5.12-6ubuntu5"
	case "python", "python3":
		r.Output = "Python 3.12.3"
	case "perl":
		r.Output = "This is perl 5, version 38, subversion 2 (v5.38.2) built for x86_64-linux-gnu-thread-multi"
	case "php":
		r.Output = "PHP 8.3.6 (cli) (built: Jul 11 2026 09:14:22) (NTS)"
	}
	return r
}

func (w *virtualSSHWorld) virtualTopOutput() string {
	s := w.system.snapshot()
	webCPU := 0.4 + s.Load1*1.8
	dockerCPU := 0.1 + s.Load1*0.7
	base := fmt.Sprintf("top - %s up %s,  2 users,  load average: %.2f, %.2f, %.2f\n"+
		"Tasks: 143 total,   1 running, 142 sleeping,   0 stopped,   0 zombie\n"+
		"%%Cpu(s): %4.1f us, %4.1f sy,  0.0 ni, %4.1f id, %4.1f wa,  0.0 hi,  0.0 si,  0.0 st\n"+
		"MiB Mem : %8.1f total, %8.1f free, %8.1f used, %8.1f buff/cache\n"+
		"MiB Swap:   2048.0 total,   2048.0 free,      0.0 used. %8.1f avail Mem\n\n"+
		"    PID USER      PR  NI    VIRT    RES    SHR S  %%CPU  %%MEM     TIME+ COMMAND\n"+
		"    844 svc-web   20   0  891244 154212  27840 S  %4.1f   1.9  51:32.18 web\n"+
		"   1021 root      20   0 1127840  62412  29120 S  %4.1f   0.8   3:07.44 dockerd\n"+
		"    612 root      20   0   15420   8200   6144 S   0.0   0.1   0:04.33 sshd\n"+
		"   1842 svc-bac+   20   0   18240   7800   5120 S   0.1   0.1   0:12.41 backup-agent",
		s.Now.Format("15:04:05"), virtualUptimeHuman(s.Uptime), s.Load1, s.Load5, s.Load15,
		s.CPUUser, s.CPUSystem, s.CPUIdle, s.CPUWait,
		s.MemTotalMiB, s.MemFreeMiB, s.MemUsedMiB, s.MemCacheMiB, s.MemAvailMiB, webCPU, dockerCPU)
	var extra strings.Builder
	for _, p := range w.processes {
		if !p.Alive {
			continue
		}
		fmt.Fprintf(&extra, "\n%7d %-9s 20   0  925432 251020  10240 R %5.1f %5.1f   0:12.44 %s", p.PID, p.User, p.CPU, p.Mem, path.Base(strings.Fields(p.Command)[0]))
	}
	return base + extra.String()
}

func virtualWgetDestination(args []string, url string) (string, bool) {
	for i, a := range args {
		if a == "-O" && i+1 < len(args) {
			if args[i+1] == "-" {
				return "", true
			}
			return args[i+1], false
		}
		if strings.HasPrefix(a, "-O") && len(a) > 2 {
			v := a[2:]
			if v == "-" {
				return "", true
			}
			return v, false
		}
		if strings.Contains(a, "O-") && strings.HasPrefix(a, "-") {
			return "", true
		}
	}
	name := path.Base(strings.SplitN(url, "?", 2)[0])
	if name == "" || name == "/" || name == "." {
		name = "index.html"
	}
	return name, false
}

func sshDestinationWithIndex(args []string) (string, int) {
	requiresValue := map[string]bool{
		"-b": true, "-c": true, "-D": true, "-E": true, "-F": true, "-i": true,
		"-J": true, "-L": true, "-l": true, "-m": true, "-O": true, "-o": true,
		"-p": true, "-Q": true, "-R": true, "-S": true, "-W": true, "-w": true,
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if requiresValue[a] {
			i++
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a, i
	}
	return "", -1
}
