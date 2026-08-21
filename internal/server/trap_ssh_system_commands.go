package server

import (
	"fmt"
	"math"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (w *virtualSSHWorld) seedFileMetadata() {
	s := w.system.snapshot()
	// Static decoy files belong to one virtual machine, so their mtimes must not
	// slide forward on every new SSH connection. Anchor them to the persistent
	// virtual boot/deployment timeline instead of the current wall clock.
	for name, content := range w.files {
		h := stableSSHHash(fmt.Sprintf("%d|%s", w.system.seed, name))
		mod := s.BootTime.Add(20*time.Minute + time.Duration(h%216)*time.Hour + time.Duration((h>>12)%3600)*time.Second).Truncate(time.Second)
		if !mod.Before(s.Now) {
			mod = s.BootTime.Add(time.Duration(h%7200) * time.Second).Truncate(time.Second)
		}
		w.fileMeta[name] = virtualFileMeta{Size: int64(len(content)), ModTime: mod, Kind: inferVirtualFileKind(name, content)}
	}
	for _, name := range []string{"/etc/hostname", "/etc/hosts", "/etc/resolv.conf", "/etc/fstab", "/etc/os-release", "/etc/ssh/sshd_config"} {
		m := w.fileMeta[name]
		m.ModTime = s.BootTime.Add(3*time.Minute + time.Duration(stableSSHHash(name)%1800)*time.Second)
		w.fileMeta[name] = m
	}
	for _, name := range []string{"/opt/app/.env", "/opt/app/current/config.yaml", "/opt/app/current/.env.production"} {
		m := w.fileMeta[name]
		m.ModTime = s.BootTime.Add(36*time.Hour + time.Duration(stableSSHHash(name)%36)*time.Hour).Truncate(time.Second)
		if !m.ModTime.Before(s.Now) {
			m.ModTime = s.BootTime.Add(2 * time.Hour).Truncate(time.Second)
		}
		w.fileMeta[name] = m
	}
	for _, name := range []string{"/srv/archive/nightly/customers-2026-08-14.sql.gz", "/srv/archive/nightly/config-prod.tar.gz"} {
		m := w.fileMeta[name]
		if strings.Contains(name, "customers-2026-08-14") {
			if fixed, err := time.Parse(time.RFC3339, "2026-08-14T02:13:00Z"); err == nil {
				m.ModTime = fixed
			}
			m.Size = 18_391_040
		} else {
			// This path represents the current nightly configuration archive. Its
			// mtime moves once per UTC day rather than on every command/connection.
			day := s.Now.UTC().Truncate(24 * time.Hour)
			m.ModTime = day.Add(2*time.Hour + 7*time.Minute)
			if m.ModTime.After(s.Now) {
				m.ModTime = m.ModTime.Add(-24 * time.Hour)
			}
			m.Size = 4_842_112
		}
		m.Kind = "gzip"
		w.fileMeta[name] = m
	}
}

func inferVirtualFileKind(name, content string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		return "tar-gzip"
	case strings.HasSuffix(lower, ".gz") || strings.HasPrefix(content, "\x1f\x8b"):
		return "gzip"
	case strings.HasSuffix(lower, ".zip") || strings.HasPrefix(content, "PK\x03\x04"):
		return "zip"
	case strings.HasSuffix(lower, ".json"):
		return "json"
	case strings.HasSuffix(lower, ".html"), strings.HasSuffix(lower, ".htm"):
		return "html"
	case strings.HasSuffix(lower, ".csv"):
		return "csv"
	case strings.HasSuffix(lower, ".sh"), strings.HasSuffix(lower, ".bash") || strings.HasPrefix(content, "#!/bin/sh") || strings.HasPrefix(content, "#!/bin/bash"):
		return "shell"
	case strings.HasSuffix(lower, ".deb"):
		return "deb"
	case strings.HasSuffix(lower, ".rpm"):
		return "rpm"
	case strings.HasSuffix(lower, ".so"), strings.HasSuffix(lower, ".bin") || strings.HasPrefix(content, "\x7fELF"):
		return "elf"
	default:
		return "text"
	}
}

func (w *virtualSSHWorld) virtualReadFile(name string) (string, bool) {
	resolved := w.resolve(name)
	if resolved == "/dev/null" {
		return "", true
	}
	if content, ok := w.virtualDynamicFile(resolved); ok {
		return content, true
	}
	content, ok := w.files[resolved]
	return content, ok
}

func (w *virtualSSHWorld) virtualDynamicFile(name string) (string, bool) {
	s := w.system.snapshot()
	if name == "/proc/self/status" {
		uid := virtualUserID(w.user)
		procName := "bash"
		return fmt.Sprintf("Name:\t%s\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t24117\nPid:\t24117\nPPid:\t24092\nUid:\t%d\t%d\t%d\t%d\nGid:\t%d\t%d\t%d\t%d\nThreads:\t1\nNoNewPrivs:\t0\nSeccomp:\t2\n", procName, uid, uid, uid, uid, uid, uid, uid, uid), true
	}
	if strings.HasPrefix(name, "/proc/") && strings.HasSuffix(name, "/status") {
		parts := strings.Split(strings.Trim(name, "/"), "/")
		if len(parts) == 3 {
			if out, ok := w.virtualProcessStatus(parts[1]); ok {
				return out, true
			}
		}
	}
	if strings.HasPrefix(name, "/proc/") && strings.HasSuffix(name, "/cmdline") {
		parts := strings.Split(strings.Trim(name, "/"), "/")
		if len(parts) == 3 {
			if pid, err := strconv.Atoi(parts[1]); err == nil {
				if proc := w.processes[pid]; proc != nil && proc.Alive {
					words := virtualWords(proc.Command)
					if len(words) > 0 {
						return strings.Join(words, "\x00") + "\x00", true
					}
				}
			}
		}
	}
	switch name {
	case "/etc/hostname":
		return w.hostname + "\n", true

	case "/proc/version":
		return "Linux version " + virtualKernelRelease + " (buildd@lcy02-amd64-042) (x86_64-linux-gnu-gcc-13 (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0, GNU ld (GNU Binutils for Ubuntu) 2.42) " + virtualKernelVersion + " Fri Jul 11 15:25:18 UTC 2026\n", true
	case "/proc/cpuinfo":
		var b strings.Builder
		for i := 0; i < virtualCPUCount; i++ {
			fmt.Fprintf(&b, "processor\t: %d\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 158\nmodel name\t: "+virtualCPUModel+"\nstepping\t: 13\nmicrocode\t: 0xf4\ncpu MHz\t\t: %.3f\ncache size\t: 16384 KB\nphysical id\t: 0\nsiblings\t: %d\ncore id\t\t: %d\ncpu cores\t: %d\napicid\t\t: %d\ninitial apicid\t: %d\nfpu\t\t: yes\nfpu_exception\t: yes\ncpuid level\t: 22\nwp\t\t: yes\nflags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx lm constant_tsc rep_good nopl xtopology cpuid tsc_known_freq pni pclmulqdq ssse3 fma cx16 sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch cpuid_fault invpcid_single pti ssbd ibrs ibpb stibp tpr_shadow flexpriority ept vpid ept_ad\nbogomips\t: 7392.00\n\n", i, 3696.000+float64(i)*1.7, virtualCPUCount, i, virtualCPUCount, i, i)
		}
		return b.String(), true
	case "/proc/mounts":
		return "/dev/vda2 / ext4 rw,relatime,errors=remount-ro 0 0\nproc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\nsysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n/dev/vdb1 /srv/archive ext4 rw,nosuid,nodev,relatime 0 0\n", true
	case "/proc/1/cgroup":
		return "0::/init.scope\n", true
	case "/proc/self/cgroup":
		uid := virtualUserID(w.user)
		return fmt.Sprintf("0::/user.slice/user-%d.slice/session-%d.scope\n", uid, 42+int(stableSSHHash(w.peerKey)%700)), true
	case "/proc/uptime":
		secs := s.Uptime.Seconds()
		idle := secs*3.44 + 1731
		return fmt.Sprintf("%.2f %.2f\n", secs, idle), true
	case "/proc/loadavg":
		running := 1 + int(math.Round(s.Load1))
		if running < 1 {
			running = 1
		}
		return fmt.Sprintf("%.2f %.2f %.2f %d/287 1842\n", s.Load1, s.Load5, s.Load15, running), true
	case "/proc/meminfo":
		return fmt.Sprintf("MemTotal:        %d kB\nMemFree:         %d kB\nMemAvailable:    %d kB\nBuffers:          168432 kB\nCached:          %d kB\nSwapCached:            0 kB\nSwapTotal:       2097148 kB\nSwapFree:        2097148 kB\n", int64(s.MemTotalMiB*1024), int64(s.MemFreeMiB*1024), int64(s.MemAvailMiB*1024), int64(s.MemCacheMiB*1024)), true
	case "/proc/stat":
		ticks := int64(s.Uptime.Seconds() * 100 * virtualCPUCount)
		user := int64(float64(ticks) * s.CPUUser / 100)
		sys := int64(float64(ticks) * s.CPUSystem / 100)
		iowait := int64(float64(ticks) * s.CPUWait / 100)
		idle := ticks - user - sys - iowait
		if idle < 0 {
			idle = 0
		}
		var b strings.Builder
		fmt.Fprintf(&b, "cpu  %d 411 %d %d %d 0 1842 0 0 0\n", user, sys, idle, iowait)
		for i := 0; i < virtualCPUCount; i++ {
			pu := user/int64(virtualCPUCount) + int64(i*17)
			ps := sys/int64(virtualCPUCount) + int64(i*7)
			pw := iowait / int64(virtualCPUCount)
			pi := idle/int64(virtualCPUCount) - int64(i*24)
			if pi < 0 {
				pi = 0
			}
			fmt.Fprintf(&b, "cpu%d %d %d %d %d %d 0 %d 0 0 0\n", i, pu, 100+int64(i), ps, pi, pw, 400+int64(i)*11)
		}
		fmt.Fprintf(&b, "intr 58321011 0 9 0 0\nctxt 104492311\nbtime %d\nprocesses 884331\nprocs_running 1\nprocs_blocked 0\n", s.BootTime.Unix())
		return b.String(), true
	case "/proc/sys/kernel/random/boot_id":
		return w.system.bootID() + "\n", true
	case "/etc/machine-id":
		return w.system.machineID() + "\n", true
	case "/var/log/auth.log":
		return w.virtualAuthLog(s), true
	}
	return "", false
}

func (w *virtualSSHWorld) virtualLoginTimeline(s virtualSSHSystemSnapshot) (adminLogin, backupLogin time.Time) {
	// Login records must stay fixed when an actor repeats `last`, `w`, journalctl
	// or auth.log probes. Derive today's plausible operator activity from the
	// persistent machine seed instead of sliding every timestamp with "now".
	day := time.Date(s.Now.Year(), s.Now.Month(), s.Now.Day(), 0, 0, 0, 0, time.UTC)
	adminLogin = day.Add(time.Duration(8+int((w.system.seed>>5)%2))*time.Hour + time.Duration(8+int((w.system.seed>>13)%47))*time.Minute)
	if adminLogin.After(s.Now.Add(-5 * time.Minute)) {
		adminLogin = adminLogin.Add(-24 * time.Hour)
	}
	backupLogin = adminLogin.Add(-time.Duration(90+int((w.system.seed>>21)%95)) * time.Minute)
	if backupLogin.Before(s.BootTime.Add(20 * time.Minute)) {
		backupLogin = s.BootTime.Add(2*time.Hour + time.Duration((w.system.seed>>29)%120)*time.Minute)
	}
	return adminLogin.Truncate(time.Second), backupLogin.Truncate(time.Second)
}

func (w *virtualSSHWorld) virtualAuthLog(s virtualSSHSystemSnapshot) string {
	boot := s.BootTime.Add(4*time.Minute + 11*time.Second)
	login, backup := w.virtualLoginTimeline(s)
	return fmt.Sprintf("%s %s systemd-logind[581]: New seat seat0.\n%s %s CRON[1842]: pam_unix(cron:session): session opened for user root(uid=0)\n%s %s sshd[1881]: Accepted publickey for svc-backup from 10.10.30.12 port 51244 ssh2\n%s %s sshd[23871]: Accepted publickey for admin from 10.10.20.44 port 55132 ssh2\n", syslogTime(boot), w.hostname, syslogTime(backup), w.hostname, syslogTime(backup.Add(2*time.Second)), w.hostname, syslogTime(login), w.hostname)
}

func syslogTime(t time.Time) string { return t.UTC().Format("Jan _2 15:04:05") }

func (w *virtualSSHWorld) virtualDateCommand(args []string) string {
	now := w.system.snapshot().Now
	for _, a := range args {
		if strings.HasPrefix(a, "+") {
			return formatVirtualDate(now, strings.TrimPrefix(a, "+"))
		}
	}
	if containsArg(args, "-Iseconds") || containsArg(args, "--iso-8601=seconds") {
		return now.Format("2006-01-02T15:04:05+00:00")
	}
	if containsArg(args, "-R") || containsArg(args, "--rfc-email") {
		return now.Format("Mon, 02 Jan 2006 15:04:05 +0000")
	}
	return now.Format("Mon Jan _2 15:04:05 UTC 2006")
}

func formatVirtualDate(t time.Time, format string) string {
	repl := strings.NewReplacer(
		"%Y", "2006", "%m", "01", "%d", "02", "%H", "15", "%M", "04", "%S", "05",
		"%F", "2006-01-02", "%T", "15:04:05", "%R", "15:04", "%z", "+0000", "%Z", "UTC",
		"%a", "Mon", "%A", "Monday", "%b", "Jan", "%B", "January", "%e", "_2", "%s", "__UNIX__", "%%", "%",
	)
	layout := repl.Replace(format)
	out := t.Format(layout)
	return strings.ReplaceAll(out, "__UNIX__", strconv.FormatInt(t.Unix(), 10))
}

func (w *virtualSSHWorld) virtualUptimeCommand(args []string) string {
	s := w.system.snapshot()
	if containsArg(args, "-p") || containsArg(args, "--pretty") {
		return virtualUptimePretty(s.Uptime)
	}
	if containsArg(args, "-s") || containsArg(args, "--since") {
		return s.BootTime.Format("2006-01-02 15:04:05")
	}
	return fmt.Sprintf(" %s up %s,  2 users,  load average: %.2f, %.2f, %.2f", s.Now.Format("15:04:05"), virtualUptimeHuman(s.Uptime), s.Load1, s.Load5, s.Load15)
}

func (w *virtualSSHWorld) virtualTimedatectl() string {
	s := w.system.snapshot()
	return fmt.Sprintf("               Local time: %s UTC\n           Universal time: %s UTC\n                 RTC time: %s\n                Time zone: Etc/UTC (UTC, +0000)\nSystem clock synchronized: yes\n              NTP service: active\n          RTC in local TZ: no", s.Now.Format("Mon 2006-01-02 15:04:05"), s.Now.Format("Mon 2006-01-02 15:04:05"), s.Now.Format("15:04:05"))
}

func (w *virtualSSHWorld) virtualWho(cmd string, args []string) string {
	s := w.system.snapshot()
	if cmd == "who" && containsArg(args, "-b") {
		return "         system boot  " + s.BootTime.Format("2006-01-02 15:04")
	}
	adminLogin, backupLogin := w.virtualLoginTimeline(s)
	if cmd == "last" {
		if len(args) > 0 && args[0] == "reboot" {
			return fmt.Sprintf("reboot   system boot  "+virtualKernelRelease+" %s   still running\n\nwtmp begins %s", s.BootTime.Format("Mon Jan _2 15:04"), s.BootTime.Format("Mon Jan _2 15:04:05 2006"))
		}
		return fmt.Sprintf("admin    pts/0        10.10.20.44     %s   still logged in\nsvc-backup pts/1      10.10.30.12     %s - %s  (00:03)\nreboot   system boot  "+virtualKernelRelease+" %s   still running", adminLogin.Format("Mon Jan _2 15:04"), backupLogin.Format("Mon Jan _2 15:04"), backupLogin.Add(3*time.Minute).Format("15:04"), s.BootTime.Format("Mon Jan _2 15:04"))
	}
	if cmd == "w" {
		return fmt.Sprintf(" %s up %s,  2 users,  load average: %.2f, %.2f, %.2f\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\nadmin    pts/0    10.10.20.44      %s   1:22   0.08s  0.02s -bash\nsvc-bac+ pts/1    10.10.30.12      %s   2:01m  0.03s  0.01s -bash", s.Now.Format("15:04:05"), virtualUptimeHuman(s.Uptime), s.Load1, s.Load5, s.Load15, adminLogin.Format("15:04"), backupLogin.Format("15:04"))
	}
	return fmt.Sprintf("admin    pts/0        %s (%s)\nsvc-bac+ pts/1        %s (%s)", adminLogin.Format("2006-01-02 15:04"), "10.10.20.44", backupLogin.Format("2006-01-02 15:04"), "10.10.30.12")
}

func (w *virtualSSHWorld) virtualPSOutput() string {
	s := w.system.snapshot()
	start := func(offset time.Duration) string {
		t := s.BootTime.Add(offset)
		if s.Now.Sub(t) > 24*time.Hour {
			return t.Format("Jan02")
		}
		return t.Format("15:04")
	}
	webCPU := 0.1 + s.Load1*0.55
	base := fmt.Sprintf("USER         PID %%CPU %%MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot           1  0.0  0.2  22584 12140 ?        Ss   %s   0:18 /sbin/init\nroot         612  0.0  0.1  15420  8200 ?        Ss   %s   0:04 /usr/sbin/sshd -D\nsvc-web      844  %.1f  1.9 891244 154212 ?       Ssl  %s  51:32 /opt/app/current/web\npostgres     901  0.2  1.1 303924  87320 ?        Ss   %s   9:41 postgres -D /var/lib/postgresql/data\nredis        932  0.1  0.2  67240  14880 ?        Ssl  %s   4:18 redis-server 10.10.30.32:6379\nroot        1021  0.0  0.3 127820  24812 ?        Ssl  %s   3:07 /usr/bin/dockerd\nroot        1102  0.0  0.1 112436   6412 ?        Sl   %s   0:33 /usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 5432\nsvc-backup  1842  0.1  0.1  18240   7800 ?        Ss   %s   0:12 /usr/local/bin/backup-agent", start(31*time.Second), start(4*time.Minute), webCPU, start(6*time.Minute), start(6*time.Minute+20*time.Second), start(6*time.Minute+34*time.Second), start(8*time.Minute), start(8*time.Minute+20*time.Second), start(11*time.Minute))
	return base + w.dynamicProcessLines()
}

func (w *virtualSSHWorld) virtualFreeOutput(args []string) string {
	s := w.system.snapshot()
	sharedMiB := 103.0
	swapMiB := 2048.0
	switch {
	case containsArg(args, "-h"), containsArg(args, "--human"):
		return fmt.Sprintf("               total        used        free      shared  buff/cache   available\nMem:           %.1fGi       %.1fGi       %.1fGi       %.0fMi       %.1fGi       %.1fGi\nSwap:          2.0Gi          0B       2.0Gi", s.MemTotalMiB/1024, s.MemUsedMiB/1024, s.MemFreeMiB/1024, sharedMiB, s.MemCacheMiB/1024, s.MemAvailMiB/1024)
	case containsArg(args, "-m"), containsArg(args, "--mebi"):
		return fmt.Sprintf("               total        used        free      shared  buff/cache   available\nMem:            %.0f        %.0f        %.0f         %.0f        %.0f        %.0f\nSwap:           %.0f           0        %.0f", s.MemTotalMiB, s.MemUsedMiB, s.MemFreeMiB, sharedMiB, s.MemCacheMiB, s.MemAvailMiB, swapMiB, swapMiB)
	case containsArg(args, "-g"), containsArg(args, "--gibi"):
		return fmt.Sprintf("               total        used        free      shared  buff/cache   available\nMem:               %.0f           %.0f           %.0f           0           %.0f           %.0f\nSwap:              2           0           2", math.Floor(s.MemTotalMiB/1024), math.Floor(s.MemUsedMiB/1024), math.Floor(s.MemFreeMiB/1024), math.Floor(s.MemCacheMiB/1024), math.Floor(s.MemAvailMiB/1024))
	default:
		return fmt.Sprintf("               total        used        free      shared  buff/cache   available\nMem:         %8d    %8d    %8d      %6d    %8d    %8d\nSwap:        %8d           0    %8d", int64(s.MemTotalMiB*1024), int64(s.MemUsedMiB*1024), int64(s.MemFreeMiB*1024), int64(sharedMiB*1024), int64(s.MemCacheMiB*1024), int64(s.MemAvailMiB*1024), int64(swapMiB*1024), int64(swapMiB*1024))
	}
}

func (w *virtualSSHWorld) virtualDFOutput(args []string) string {
	s := w.system.snapshot()
	if containsArg(args, "-h") || containsArg(args, "--human-readable") {
		return fmt.Sprintf("Filesystem      Size  Used Avail Use%% Mounted on\n/dev/vda2       %.0fG  %.0fG   %.0fG  %d%% /\n/dev/vdb1       %.0fG  %.0fG  %.0fG  %d%% /srv/archive", s.RootTotalGiB, s.RootUsedGiB, s.RootAvailGiB, s.RootUsePct, s.ArchiveTotalGiB, s.ArchiveUsedGiB, s.ArchiveAvailGiB, s.ArchiveUsePct)
	}
	toKiB := func(gib float64) int64 { return int64(math.Round(gib * 1024 * 1024)) }
	return fmt.Sprintf("Filesystem     1K-blocks      Used Available Use%% Mounted on\n/dev/vda2        %8d  %8d  %8d %3d%% /\n/dev/vdb1        %8d  %8d  %8d %3d%% /srv/archive", toKiB(s.RootTotalGiB), toKiB(s.RootUsedGiB), toKiB(s.RootAvailGiB), s.RootUsePct, toKiB(s.ArchiveTotalGiB), toKiB(s.ArchiveUsedGiB), toKiB(s.ArchiveAvailGiB), s.ArchiveUsePct)
}

func (w *virtualSSHWorld) virtualJournal() string {
	s := w.system.snapshot()
	adminLogin, backupLogin := w.virtualLoginTimeline(s)
	return fmt.Sprintf("%s %s systemd[1]: Started backup-agent.service - Legacy Backup Agent.\n%s %s backup-agent[1842]: profile=legacy sync completed objects=184 duration=12.4s\n%s %s sshd[23871]: Accepted publickey for admin from 10.10.20.44 port 55132 ssh2", s.BootTime.Add(11*time.Minute).Format("Jan _2 15:04:05"), w.hostname, backupLogin.Add(3*time.Minute).Format("Jan _2 15:04:05"), w.hostname, adminLogin.Format("Jan _2 15:04:05"), w.hostname)
}

func (w *virtualSSHWorld) fileDescription(name string) (string, bool) {
	p := w.resolve(name)
	content, ok := w.files[p]
	if !ok {
		if dynamic, dyn := w.virtualDynamicFile(p); dyn {
			content, ok = dynamic, true
		}
	}
	if !ok {
		return "", false
	}
	kind := inferVirtualFileKind(p, content)
	if meta, exists := w.fileMeta[p]; exists && meta.Kind != "" {
		kind = meta.Kind
	}
	switch kind {
	case "gzip":
		return "gzip compressed data, from Unix, original size modulo 2^32 18391040", true
	case "tar-gzip":
		return "gzip compressed data, was \"archive.tar\", from Unix, original size modulo 2^32 32460800", true
	case "zip":
		return "Zip archive data, at least v2.0 to extract", true
	case "json":
		return "JSON text data", true
	case "html":
		return "HTML document, ASCII text", true
	case "csv":
		return "CSV text", true
	case "shell":
		return "POSIX shell script, ASCII text executable", true
	case "deb":
		return "Debian binary package (format 2.0)", true
	case "rpm":
		return "RPM v3.0 bin i386/x86_64", true
	case "elf":
		return "ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped", true
	default:
		return "ASCII text", true
	}
}

func (w *virtualSSHWorld) virtualFileStat(name string) (string, int) {
	p := w.resolve(name)
	content, ok := w.files[p]
	if !ok {
		if dynamic, dyn := w.virtualDynamicFile(p); dyn {
			content, ok = dynamic, true
		}
	}
	if !ok && !w.dirs[p] {
		return "stat: cannot statx '" + name + "': No such file or directory", 1
	}
	meta := w.fileMeta[p]
	if meta.ModTime.IsZero() {
		meta.ModTime = w.system.snapshot().Now.Add(-2 * time.Hour)
	}
	if meta.Size == 0 && ok {
		meta.Size = int64(len(content))
	}
	mode := "regular file"
	vmode := w.virtualFileMode(p)
	perm := fmt.Sprintf("%04o/%s", vmode, virtualModeString(vmode, false))
	owner, group := virtualFileOwner(p)
	ownerID, groupID := virtualIdentityID(owner), virtualIdentityID(group)
	uid := fmt.Sprintf("%d/ %s", ownerID, owner)
	gid := fmt.Sprintf("%d/ %s", groupID, group)
	if w.dirs[p] {
		vmode = virtualDirMode(p)
		mode, perm, meta.Size = "directory", fmt.Sprintf("%04o/%s", vmode, virtualModeString(vmode, true)), 4096
	}
	return fmt.Sprintf("  File: %s\n  Size: %d\tBlocks: %d          IO Block: 4096 %s\nAccess: (%s)  Uid: (  %s)   Gid: (  %s)\nAccess: %s +0000\nModify: %s +0000\nChange: %s +0000", p, meta.Size, maxInt64(8, (meta.Size+511)/512), mode, perm, uid, gid, meta.ModTime.Add(4*time.Minute).Format("2006-01-02 15:04:05.000000000"), meta.ModTime.Format("2006-01-02 15:04:05.000000000"), meta.ModTime.Add(2*time.Second).Format("2006-01-02 15:04:05.000000000")), 0
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func virtualLSDate(now, mod time.Time) string {
	if mod.IsZero() {
		mod = now.Add(-24 * time.Hour)
	}
	if now.Sub(mod) > 180*24*time.Hour || mod.After(now.Add(30*24*time.Hour)) {
		return mod.Format("Jan _2  2006")
	}
	return mod.Format("Jan _2 15:04")
}

func virtualFileOwner(name string) (string, string) {
	name = path.Clean(name)
	base := path.Base(name)
	if name == "/" || name == "/root" || strings.HasPrefix(name, "/root/") || strings.Contains(base, "id_ed25519") {
		return "root", "root"
	}
	if strings.HasPrefix(name, "/home/") {
		rel := strings.TrimPrefix(name, "/home/")
		user := strings.SplitN(rel, "/", 2)[0]
		if user != "" {
			return user, user
		}
	}
	if strings.HasPrefix(name, "/var/lib/backup") || strings.HasPrefix(name, "/opt/backup") {
		return "svc-backup", "svc-backup"
	}
	if strings.HasPrefix(name, "/opt/app") {
		return "svc-web", "svc-web"
	}
	if name == "/bin" || name == "/sbin" || name == "/usr" || name == "/usr/bin" || name == "/usr/sbin" || name == "/etc" || name == "/proc" || name == "/srv" || name == "/var" || name == "/var/log" || name == "/tmp" || name == "/var/tmp" || name == "/dev" || name == "/dev/shm" || name == "/home" || name == "/opt" || strings.HasPrefix(name, "/bin/") || strings.HasPrefix(name, "/usr/bin/") || strings.HasPrefix(name, "/sbin/") || strings.HasPrefix(name, "/usr/sbin/") || strings.HasPrefix(name, "/etc/") || strings.HasPrefix(name, "/proc/") || strings.HasPrefix(name, "/srv/") || strings.HasPrefix(name, "/var/log/") {
		return "root", "root"
	}
	return "svc-web", "svc-web"
}

func virtualIdentityID(name string) int {
	switch name {
	case "root":
		return 0
	case "svc-web":
		return 997
	case "svc-backup":
		return 998
	case "admin":
		return 1000
	default:
		return virtualUserID(name)
	}
}

func virtualActivityWeight(r virtualSSHResult) float64 {
	switch r.Family {
	case "archive":
		return 1.6
	case "execution", "payload-preparation", "command-execution":
		return 1.9
	case "download":
		return 1.1
	case "filesystem":
		if r.Depth >= 5 {
			return 0.8
		}
		return 0.25
	case "containers", "network", "lateral":
		return 0.7
	case "persistence", "privilege":
		return 0.9
	default:
		return 0.12
	}
}

func (w *virtualSSHWorld) virtualPSCompactOutput(raw string) string {
	type row struct {
		pid  int
		cpu  float64
		name string
	}
	s := w.system.snapshot()
	rows := []row{
		{844, 0.1 + s.Load1*0.55, "web"},
		{901, 0.2, "postgres"},
		{932, 0.1, "redis-server"},
		{1021, 0.0, "dockerd"},
		{1102, 0.0, "docker-proxy"},
		{1842, 0.1, "backup-agent"},
		{612, 0.0, "sshd"},
		{1, 0.0, "systemd"},
	}
	for _, p := range w.processes {
		if p == nil || !p.Alive {
			continue
		}
		fields := strings.Fields(p.Command)
		name := "worker"
		if len(fields) > 0 {
			name = path.Base(fields[0])
		}
		rows = append(rows, row{p.PID, p.CPU, name})
	}
	low := strings.ToLower(raw)
	switch {
	case strings.Contains(low, "--sort=-pcpu") || strings.Contains(low, "--sort=-%cpu"):
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].cpu > rows[j].cpu })
	case strings.Contains(low, "--sort=pcpu") || strings.Contains(low, "--sort=%cpu"):
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].cpu < rows[j].cpu })
	case strings.Contains(low, "--sort=-pid"):
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].pid > rows[j].pid })
	case strings.Contains(low, "--sort=pid"):
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].pid < rows[j].pid })
	}
	lines := []string{"    PID %CPU COMMAND"}
	for _, item := range rows {
		lines = append(lines, fmt.Sprintf("%7d %4.1f %s", item.pid, item.cpu, item.name))
	}
	return strings.Join(lines, "\n")
}

func virtualModeString(mode uint32, dir bool) string {
	prefix := byte('-')
	if dir {
		prefix = 'd'
	}
	b := []byte{prefix, '-', '-', '-', '-', '-', '-', '-', '-', '-'}
	bits := []uint32{0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001}
	chars := []byte{'r', 'w', 'x', 'r', 'w', 'x', 'r', 'w', 'x'}
	for i, bit := range bits {
		if mode&bit != 0 {
			b[i+1] = chars[i]
		}
	}
	if mode&0o4000 != 0 {
		if b[3] == 'x' {
			b[3] = 's'
		} else {
			b[3] = 'S'
		}
	}
	if mode&0o2000 != 0 {
		if b[6] == 'x' {
			b[6] = 's'
		} else {
			b[6] = 'S'
		}
	}
	if mode&0o1000 != 0 {
		if b[9] == 'x' {
			b[9] = 't'
		} else {
			b[9] = 'T'
		}
	}
	return string(b)
}
