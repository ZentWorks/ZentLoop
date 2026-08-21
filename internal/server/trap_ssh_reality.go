package server

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// observeRealityProbe recognizes common environment/honeypot checks without ever
// executing them on the host. A repeated probe unlocks a larger synthetic Linux
// surface for that SSH session.
func (w *virtualSSHWorld) observeRealityProbe(command string) {
	low := strings.ToLower(command)
	score := 0
	markers := []string{
		"/proc/1/cgroup", "/proc/1/status", "/proc/1/cmdline", "/proc/self/status",
		"/sys/class/dmi/id/", "systemd-detect-virt", "virt-what", "dmidecode",
		"cat /bin/", "file /bin/", "stat /bin/", "ldd /bin/", "readelf ",
		"ssh_connection", "ssh_client", "ssh_tty", "stty", " tty",
		"/proc/version", "/proc/cpuinfo", "/proc/mounts", "/etc/mtab",
	}
	for _, m := range markers {
		if strings.Contains(low, m) {
			score++
		}
	}
	collectorScore := environmentFingerprintCollectorScore(low)
	if score == 0 && collectorScore == 0 {
		return
	}
	w.honeypotProbeScore += score + collectorScore
	if w.honeypotProbeScore >= 2 {
		w.deepReality = true
		w.seedDeepReality()
	}
	// A broad environment collector is already trying to establish host reality.
	// Reuse the existing backup/network story instead of spawning a parallel lure
	// universe, so all follow-up evidence stays internally consistent.
	if collectorScore >= 5 {
		w.seedCredentialLures()
		w.seedNetworkLures()
	}
}

func environmentFingerprintCollectorScore(low string) int {
	groups := [][]string{
		{"uname -s", "/bin/uname", "/usr/bin/uname", "busybox uname"},
		{"/proc/uptime", " uptime"},
		{"nproc", "/proc/cpuinfo"},
		{"lscpu", "model name", "/proc/device-tree/model"},
		{"lspci", "grep -i vga", "grep -i nvidia"},
		{"last 2>", "last_output="},
		{"===shell_behavior===", "path_err=", "cmd_err=", "./xxxxxx"},
	}
	score := 0
	for _, group := range groups {
		for _, marker := range group {
			if strings.Contains(low, marker) {
				score++
				break
			}
		}
	}
	return score
}

func isHoneypotProbeCommand(command string) bool {
	low := strings.ToLower(command)
	trimmed := strings.TrimSpace(low)
	if trimmed == "cat /proc" || strings.HasPrefix(trimmed, "cat /proc 2>") {
		return true
	}
	for _, m := range []string{"/proc/1/cgroup", "/sys/class/dmi/id/", "systemd-detect-virt", "virt-what", "dmidecode", "cat /bin/", "file /bin/", "stat /bin/", "ssh_connection", "ssh_tty", "stty"} {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}

func (w *virtualSSHWorld) seedDeepReality() {
	for _, d := range []string{
		"/dev", "/dev/pts", "/run", "/run/sshd", "/run/systemd", "/sys", "/sys/class", "/sys/class/dmi", "/sys/class/dmi/id",
		"/sys/devices", "/sys/fs", "/sys/fs/cgroup", "/lib", "/lib64", "/lib/x86_64-linux-gnu", "/usr/lib", "/usr/lib/systemd", "/usr/lib/systemd/system",
		"/proc/581", "/proc/612", "/proc/844", "/proc/901", "/proc/932", "/proc/1021", "/proc/1102", "/proc/1842", "/proc/driver", "/proc/driver/nvidia", "/proc/driver/nvidia/gpus", "/proc/driver/nvidia/gpus/0000:00:05.0", "/var/lib/dpkg", "/var/lib/dpkg/info",
	} {
		w.dirs[d] = true
	}
	files := map[string]string{
		"/etc/mtab":                                         "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\nsysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n/dev/vda2 / ext4 rw,relatime,errors=remount-ro 0 0\n/dev/vdb1 /srv/archive ext4 rw,nosuid,nodev,relatime 0 0\n",
		"/sys/class/dmi/id/sys_vendor":                      "QEMU\n",
		"/sys/class/dmi/id/product_name":                    "Standard PC (Q35 + ICH9, 2009)\n",
		"/sys/class/dmi/id/product_version":                 "pc-q35-8.2\n",
		"/sys/class/dmi/id/board_vendor":                    "Red Hat\n",
		"/sys/class/dmi/id/bios_vendor":                     "SeaBIOS\n",
		"/sys/class/dmi/id/bios_version":                    "1.16.3-debian-1.16.3-2\n",
		"/proc/1/cmdline":                                   "\x00/sbin/init\x00splash\x00",
		"/proc/612/cmdline":                                 "/usr/sbin/sshd\x00-D\x00",
		"/proc/844/cmdline":                                 "/opt/app/current/web\x00--config\x00/opt/app/current/config.yaml\x00",
		"/proc/901/cmdline":                                 "postgres\x00-D\x00/var/lib/postgresql/data\x00",
		"/proc/932/cmdline":                                 "redis-server\x0010.10.30.32:6379\x00",
		"/proc/1021/cmdline":                                "/usr/bin/dockerd\x00-H\x00fd://\x00",
		"/proc/1102/cmdline":                                "/usr/bin/docker-proxy\x00-proto\x00tcp\x00-host-ip\x00127.0.0.1\x00-host-port\x005432\x00",
		"/proc/1842/cmdline":                                "/usr/local/bin/backup-agent\x00--profile\x00legacy\x00",
		"/proc/driver/nvidia/version":                       "NVRM version: NVIDIA UNIX x86_64 Kernel Module  550.120  Thu Jul 10 20:31:18 UTC 2026\nGCC version:  gcc version 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04)\n",
		"/proc/driver/nvidia/gpus/0000:00:05.0/information": "Model:           Tesla T4\nIRQ:             16\nGPU UUID:        GPU-7c2d1e4f-91a6-4b72-a3d5-18e249cc7a31\nVideo BIOS:      90.04.96.00.01\nBus Type:        PCIe\nDMA Size:        47 bits\nDMA Mask:        0x7fffffffffff\nBus Location:    0000:00:05.0\n",
		"/proc/1/cgroup":                                    "0::/init.scope\n",
		"/proc/612/cgroup":                                  "0::/system.slice/ssh.service\n",
		"/proc/844/cgroup":                                  "0::/system.slice/platform-web.service\n",
		"/proc/1021/cgroup":                                 "0::/system.slice/docker.service\n",
		"/proc/1842/cgroup":                                 "0::/system.slice/backup-agent.service\n",
	}
	now := w.system.snapshot().Now
	for name, content := range files {
		if _, exists := w.files[name]; !exists {
			w.files[name] = content
			w.fileMeta[name] = virtualFileMeta{Size: int64(len(content)), ModTime: now.Add(-48 * time.Hour), Kind: "text"}
		}
	}
}

func (w *virtualSSHWorld) virtualProcessStatus(pid string) (string, bool) {
	n, err := strconv.Atoi(pid)
	if err == nil {
		if p := w.processes[n]; p != nil && p.Alive {
			fields := virtualWords(p.Command)
			name := "worker"
			if len(fields) > 0 {
				name = path.Base(fields[0])
			}
			uid := virtualUserID(p.User)
			return fmt.Sprintf("Name:\t%s\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t%d\nPid:\t%d\nPPid:\t1\nUid:\t%d\t%d\t%d\t%d\nGid:\t%d\t%d\t%d\t%d\nFDSize:\t64\nThreads:\t1\nNoNewPrivs:\t0\nSeccomp:\t2\n", name, n, n, uid, uid, uid, uid, uid, uid, uid, uid), true
		}
	}
	type proc struct {
		name, state string
		ppid, uid   int
	}
	procs := map[string]proc{
		"1": {"systemd", "S (sleeping)", 0, 0}, "581": {"systemd-logind", "S (sleeping)", 1, 0},
		"612": {"sshd", "S (sleeping)", 1, 0}, "844": {"web", "S (sleeping)", 1, 997},
		"901": {"postgres", "S (sleeping)", 1021, 999}, "932": {"redis-server", "S (sleeping)", 1021, 999},
		"1021": {"dockerd", "S (sleeping)", 1, 0}, "1102": {"docker-proxy", "S (sleeping)", 1021, 0},
		"1842": {"backup-agent", "S (sleeping)", 1, 998},
	}
	p, ok := procs[pid]
	if !ok {
		return "", false
	}
	return fmt.Sprintf("Name:\t%s\nUmask:\t0022\nState:\t%s\nTgid:\t%s\nPid:\t%s\nPPid:\t%d\nUid:\t%d\t%d\t%d\t%d\nGid:\t%d\t%d\t%d\t%d\nFDSize:\t64\nThreads:\t1\nNoNewPrivs:\t0\nSeccomp:\t2\n", p.name, p.state, pid, pid, p.ppid, p.uid, p.uid, p.uid, p.uid, p.uid, p.uid, p.uid, p.uid), true
}

func (w *virtualSSHWorld) deepRealityCommand(cmd string, args []string) (virtualSSHResult, bool) {
	base := func(family string, depth, risk int, persona, message string) virtualSSHResult {
		return virtualBaseResult(cmd, family, depth, risk, persona, message)
	}
	switch cmd {
	case "systemd-detect-virt":
		r := base("recon", 5, 94, "anti-fingerprint", "virtualization environment probe")
		if containsArg(args, "--vm") || len(args) == 0 {
			r.Output = "kvm"
		} else if containsArg(args, "--container") {
			r.Status = 1
		}
		return r, true
	case "virt-what":
		r := base("recon", 5, 94, "anti-fingerprint", "virtualization environment probe")
		r.Output = "kvm"
		return r, true
	case "tty":
		r := base("recon", 4, 90, "anti-fingerprint", "TTY probe")
		r.Output = "/dev/pts/0"
		return r, true
	case "stty":
		r := base("recon", 4, 90, "anti-fingerprint", "TTY characteristics probe")
		cols, rows, term := w.terminalSize()
		if containsArg(args, "size") {
			r.Output = fmt.Sprintf("%d %d", rows, cols)
		} else if containsArg(args, "-a") {
			r.Output = fmt.Sprintf("speed 38400 baud; rows %d; columns %d; line = 0;\nintr = ^C; quit = ^\\; erase = ^?; kill = ^U; eof = ^D;\nicanon echo echoe echok -echonl -noflsh -xcase -tostop -echoprt echoctl echoke; # TERM=%s", rows, cols, term)
		}
		return r, true
	case "dmidecode":
		r := base("recon", 5, 94, "anti-fingerprint", "DMI virtualization probe")
		r.Output = "# dmidecode 3.5\nGetting SMBIOS data from sysfs.\nSMBIOS 2.8 present.\n\nSystem Information\n\tManufacturer: QEMU\n\tProduct Name: Standard PC (Q35 + ICH9, 2009)\n\tVersion: pc-q35-8.2\n\tSerial Number: Not Specified\n\tUUID: " + w.system.bootID()
		return r, true
	case "mount":
		r := base("recon", 4, 90, "anti-fingerprint", "mount namespace probe")
		r.Output = "/dev/vda2 on / type ext4 (rw,relatime,errors=remount-ro)\nproc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\nsysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)\n/dev/vdb1 on /srv/archive type ext4 (rw,relatime)"
		return r, true
	case "env", "printenv":
		// handled elsewhere; leave normal output to preserve exported values.
		return virtualSSHResult{}, false
	}
	return virtualSSHResult{}, false
}

func sortedVirtualPIDs() []string {
	p := []string{"1", "581", "612", "844", "901", "932", "1021", "1102", "1842"}
	sort.Strings(p)
	return p
}
func virtualProcBase(name string) string { return path.Base(strings.TrimSpace(name)) }

func (w *virtualSSHWorld) terminalSize() (int, int, string) {
	w.ttyMu.RLock()
	defer w.ttyMu.RUnlock()
	return w.ttyCols, w.ttyRows, w.ttyTerm
}
