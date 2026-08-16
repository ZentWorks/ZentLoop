package server

import (
	"fmt"
	"math"
	"path"
	"strconv"
	"strings"
	"time"
)

func (w *virtualSSHWorld) seedFileMetadata() {
	s := w.system.snapshot()
	for name, content := range w.files {
		h := stableSSHHash(fmt.Sprintf("%d|%s", w.system.seed, name))
		age := time.Duration(2+int(h%240)) * time.Hour
		mod := s.Now.Add(-age).Truncate(time.Second)
		if mod.Before(s.BootTime) {
			mod = s.BootTime.Add(time.Duration(h%7200) * time.Second)
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
		m.ModTime = s.Now.Add(-time.Duration(5+stableSSHHash(name)%48) * time.Hour).Truncate(time.Second)
		w.fileMeta[name] = m
	}
	for _, name := range []string{"/srv/archive/nightly/customers-2026-08-14.sql.gz", "/srv/archive/nightly/config-prod.tar.gz"} {
		m := w.fileMeta[name]
		m.ModTime = s.Now.Add(-time.Duration(6+stableSSHHash(name)%30) * time.Hour).Truncate(time.Second)
		if strings.Contains(name, "customers") {
			m.Size = 18_391_040
		} else {
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
		uid := 0
		procName := "bash"
		if w.user != "root" {
			uid = 1000
		}
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
	switch name {
	case "/etc/hostname":
		return w.hostname + "\n", true

	case "/proc/version":
		return "Linux version 6.8.0-64-generic (buildd@lcy02-amd64-042) (x86_64-linux-gnu-gcc-13 (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0, GNU ld (GNU Binutils for Ubuntu) 2.42) #67-Ubuntu SMP PREEMPT_DYNAMIC Fri Jul 11 15:25:18 UTC 2026\n", true
	case "/proc/cpuinfo":
		var b strings.Builder
		for i := 0; i < 4; i++ {
			fmt.Fprintf(&b, "processor\t: %d\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 158\nmodel name\t: Intel(R) Xeon(R) CPU E-2288G @ 3.70GHz\nstepping\t: 13\ncpu MHz\t\t: %.3f\ncache size\t: 16384 KB\nflags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx lm constant_tsc rep_good nopl xtopology cpuid tsc_known_freq pni pclmulqdq ssse3 fma cx16 sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch cpuid_fault invpcid_single pti ssbd ibrs ibpb stibp tpr_shadow flexpriority ept vpid ept_ad\n\n", i, 3696.000+float64(i)*1.7)
		}
		return b.String(), true
	case "/proc/mounts":
		return "/dev/vda2 / ext4 rw,relatime,errors=remount-ro 0 0\nproc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\nsysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n/dev/vdb1 /srv/archive ext4 rw,relatime 0 0\n", true
	case "/proc/1/cgroup":
		return "0::/init.scope\n", true
	case "/proc/self/cgroup":
		return "0::/user.slice/user-0.slice/session-42.scope\n", true
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
		ticks := int64(s.Uptime.Seconds() * 100 * 4)
		user := int64(float64(ticks) * s.CPUUser / 100)
		sys := int64(float64(ticks) * s.CPUSystem / 100)
		idle := ticks - user - sys
		return fmt.Sprintf("cpu  %d 411 %d %d 923 0 1842 0 0 0\nintr 58321011 0 9 0 0\nctxt 104492311\nbtime %d\nprocesses 884331\nprocs_running 1\nprocs_blocked 0\n", user, sys, idle, s.BootTime.Unix()), true
	case "/proc/sys/kernel/random/boot_id":
		return w.system.bootID() + "\n", true
	case "/etc/machine-id":
		return w.system.machineID() + "\n", true
	case "/var/log/auth.log":
		return w.virtualAuthLog(s), true
	}
	return "", false
}

func (w *virtualSSHWorld) virtualAuthLog(s virtualSSHSystemSnapshot) string {
	boot := s.BootTime.Add(4*time.Minute + 11*time.Second)
	backup := s.Now.Add(-2*time.Hour - 3*time.Minute)
	login := s.Now.Add(-34*time.Minute - 12*time.Second)
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
	adminLogin := s.Now.Add(-34*time.Minute - 12*time.Second)
	backupLogin := s.Now.Add(-2*time.Hour - 3*time.Minute)
	if cmd == "last" {
		if len(args) > 0 && args[0] == "reboot" {
			return fmt.Sprintf("reboot   system boot  6.8.0-64-generic %s   still running\n\nwtmp begins %s", s.BootTime.Format("Mon Jan _2 15:04"), s.BootTime.Format("Mon Jan _2 15:04:05 2006"))
		}
		return fmt.Sprintf("admin    pts/0        10.10.20.44     %s   still logged in\nsvc-backup pts/1      10.10.30.12     %s - %s  (00:03)\nreboot   system boot  6.8.0-64-generic %s   still running", adminLogin.Format("Mon Jan _2 15:04"), backupLogin.Format("Mon Jan _2 15:04"), backupLogin.Add(3*time.Minute).Format("15:04"), s.BootTime.Format("Mon Jan _2 15:04"))
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
	base := fmt.Sprintf("USER         PID %%CPU %%MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot           1  0.0  0.2  22584 12140 ?        Ss   %s   0:18 /sbin/init\nroot         612  0.0  0.1  15420  8200 ?        Ss   %s   0:04 /usr/sbin/sshd -D\nsvc-web      844  %.1f  1.9 891244 154212 ?       Ssl  %s  51:32 /opt/app/current/web\nroot        1021  0.0  0.3 127820 24812 ?        Ssl  %s   3:07 /usr/bin/dockerd\nsvc-backup  1842  0.1  0.1  18240  7800 ?        Ss   %s   0:12 /usr/local/bin/backup-agent", start(31*time.Second), start(4*time.Minute), webCPU, start(6*time.Minute), start(8*time.Minute), start(11*time.Minute))
	return base + w.dynamicProcessLines()
}

func (w *virtualSSHWorld) virtualFreeOutput() string {
	s := w.system.snapshot()
	return fmt.Sprintf("               total        used        free      shared  buff/cache   available\nMem:           %.1fGi       %.1fGi       %.1fGi       103Mi       %.1fGi       %.1fGi\nSwap:          2.0Gi          0B       2.0Gi", s.MemTotalMiB/1024, s.MemUsedMiB/1024, s.MemFreeMiB/1024, s.MemCacheMiB/1024, s.MemAvailMiB/1024)
}

func (w *virtualSSHWorld) virtualJournal() string {
	s := w.system.snapshot()
	return fmt.Sprintf("%s %s systemd[1]: Started backup-agent.service - Legacy Backup Agent.\n%s %s backup-agent[1842]: profile=legacy sync completed objects=184 duration=12.4s\n%s %s sshd[23871]: Accepted publickey for admin from 10.10.20.44 port 55132 ssh2", s.BootTime.Add(11*time.Minute).Format("Jan _2 15:04:05"), w.hostname, s.Now.Add(-2*time.Hour).Format("Jan _2 15:04:05"), w.hostname, s.Now.Add(-34*time.Minute).Format("Jan _2 15:04:05"), w.hostname)
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
	perm := "0640/-rw-r-----"
	uid := "997/ svc-web"
	gid := "997/ svc-web"
	if meta.Kind == "elf" && (strings.HasPrefix(p, "/bin/") || strings.HasPrefix(p, "/usr/bin/") || strings.HasPrefix(p, "/sbin/") || strings.HasPrefix(p, "/usr/sbin/")) {
		perm = "0755/-rwxr-xr-x"
		uid, gid = "0/ root", "0/ root"
	}
	if w.dirs[p] {
		mode, perm, uid, gid, meta.Size = "directory", "0755/drwxr-xr-x", "0/ root", "0/ root", 4096
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
	base := path.Base(name)
	if strings.HasPrefix(name, "/bin/") || strings.HasPrefix(name, "/usr/bin/") || strings.HasPrefix(name, "/sbin/") || strings.HasPrefix(name, "/usr/sbin/") {
		return "root", "root"
	}
	if strings.Contains(name, "/root/") || strings.Contains(base, "id_ed25519") || base == ".env" && strings.HasPrefix(name, "/root") {
		return "root", "root"
	}
	if strings.Contains(name, "/home/admin/") {
		return "admin", "admin"
	}
	if strings.Contains(name, "/var/lib/backup/") || strings.Contains(name, "/opt/backup/") {
		return "svc-backup", "svc-backup"
	}
	return "svc-web", "svc-web"
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

func (w *virtualSSHWorld) virtualPSCompactOutput() string {
	lines := []string{
		"    PID %CPU COMMAND",
		"    844  1.3 web",
		"   1842  0.1 backup-agent",
		"   1021  0.0 dockerd",
		"    612  0.0 sshd",
		"      1  0.0 systemd",
	}
	for _, p := range w.processes {
		if p != nil && p.Alive {
			lines = append(lines, fmt.Sprintf("%7d %4.1f %s", p.PID, p.CPU, path.Base(strings.Fields(p.Command)[0])))
		}
	}
	return strings.Join(lines, "\n")
}
