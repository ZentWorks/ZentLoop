package server

import (
	"crypto/sha256"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"zentloop/internal/lures"
)

const (
	maxVirtualFiles      = 512
	maxVirtualDirs       = 256
	maxVirtualFileBytes  = 16 * 1024
	maxVirtualTotalBytes = 512 * 1024
	maxVirtualOps        = 750
)

type virtualSSHResult struct {
	Output         string
	Status         int
	Exit           bool
	Interactive    string
	Target         string
	TerminalAction string
	Family         string
	CommandName    string
	Depth          int
	Risk           int
	LoopInc        int
	Persona        string
	Message        string
	Delay          time.Duration
	StreamCount    int
	StdinBytes     int
	StdinSHA256    string
	StdinKind      string
	PayloadStage   string
	PayloadPath    string
}

type virtualSSHContext struct {
	user     string
	hostname string
	cwd      string
}

type virtualFileMeta struct {
	Size    int64
	ModTime time.Time
	Kind    string
}

type virtualSSHSharedState struct {
	mu                 sync.Mutex
	files              map[string]string
	fileMeta           map[string]virtualFileMeta
	dirs               map[string]bool
	processes          map[int]*virtualSSHProcess
	fileAttrs          map[string]string
	fileModes          map[string]uint32
	stagingAttempts    map[string]int
	stagingPayloadHash map[string][32]byte
	installerSignals   map[string]bool
	installedPackages  map[string]bool
	nextPID            int
}

func newVirtualSSHSharedState() *virtualSSHSharedState {
	return &virtualSSHSharedState{
		files: make(map[string]string), fileMeta: make(map[string]virtualFileMeta), dirs: make(map[string]bool),
		processes: make(map[int]*virtualSSHProcess), fileAttrs: make(map[string]string), fileModes: make(map[string]uint32),
		stagingAttempts: make(map[string]int), stagingPayloadHash: make(map[string][32]byte), installerSignals: make(map[string]bool),
		installedPackages: map[string]bool{"curl": true, "openssh-server": true, "vim": true}, nextPID: 2841,
	}
}

type virtualSSHWorld struct {
	shared             *virtualSSHSharedState
	user               string
	hostname           string
	cwd                string
	files              map[string]string
	fileMeta           map[string]virtualFileMeta
	dirs               map[string]bool
	history            []string
	nested             []virtualSSHContext
	depth              int
	loop               int
	frustration        int
	ops                int
	sourceDepth        int
	substDepth         int
	lastStatus         int
	env                map[string]string
	aliases            map[string]string
	ttyCols            int
	ttyRows            int
	ttyTerm            string
	system             *virtualSSHSystem
	sourceIP           string
	peerKey            string
	canaries           map[string]string
	interests          map[string]int
	honeypotProbeScore int
	deepReality        bool
	processes          map[int]*virtualSSHProcess
	jobs               map[int]int
	nextJob            int
	crontabExists      bool
	crontabContent     string
	fileAttrs          map[string]string
	fileModes          map[string]uint32
	installedPackages  map[string]bool
	historyCleared     bool
	stagingAttempts    map[string]int
	stagingPayloadHash map[string][32]byte
	installerSignals   map[string]bool
	ttyMu              sync.RWMutex
}

func newVirtualSSHWorld(sessionID, username string) *virtualSSHWorld {
	return newVirtualSSHWorldWithSystem(sessionID, username, newEphemeralVirtualSSHSystem())
}

func newVirtualSSHWorldWithSystem(sessionID, username string, system *virtualSSHSystem) *virtualSSHWorld {
	return newVirtualSSHWorldForSource(sessionID, username, "0.0.0.0", system)
}

func newVirtualSSHWorldForSource(sessionID, username, sourceIP string, system *virtualSSHSystem) *virtualSSHWorld {
	return newVirtualSSHWorldForSourceShared(sessionID, username, sourceIP, system, newVirtualSSHSharedState())
}

func newVirtualSSHWorldForSourceShared(sessionID, username, sourceIP string, system *virtualSSHSystem, shared *virtualSSHSharedState) *virtualSSHWorld {
	user := strings.TrimSpace(username)
	if user == "" {
		user = "root"
	}
	host := "prod-app-02"
	if system == nil {
		system = newEphemeralVirtualSSHSystem()
	}
	suffix := fmt.Sprintf("%02x", system.seed%0xff)
	if shared == nil {
		shared = newVirtualSSHSharedState()
	}
	w := &virtualSSHWorld{
		shared: shared, user: user, hostname: host, files: shared.files, fileMeta: shared.fileMeta, dirs: shared.dirs,
		env: make(map[string]string), aliases: make(map[string]string), ttyCols: 80, ttyRows: 24, ttyTerm: "xterm-256color", system: system,
		sourceIP: sourceIP, peerKey: sourceIP + "|" + user, canaries: lures.CanaryLabels(sourceIP), interests: make(map[string]int),
		processes: shared.processes, jobs: make(map[int]int), nextJob: 1,
		crontabExists: true, crontabContent: "0 2 * * * /usr/local/bin/backupctl sync --profile legacy >/var/log/backup.log 2>&1\n", fileAttrs: shared.fileAttrs, fileModes: shared.fileModes, installedPackages: shared.installedPackages,
		stagingAttempts: shared.stagingAttempts, stagingPayloadHash: shared.stagingPayloadHash, installerSignals: shared.installerSignals,
	}
	if peer := system.peerState(w.peerKey); peer.Initialized {
		w.crontabExists = peer.CrontabExists
		w.crontabContent = peer.CrontabContent
	}
	w.cwd = w.homeDir()
	w.env["SHELL"] = "/bin/bash"
	w.env["HOME"] = w.homeDir()
	w.env["USER"] = w.user
	w.env["LOGNAME"] = w.user
	w.env["HOSTNAME"] = w.hostname
	w.env["PWD"] = w.cwd
	w.env["OLDPWD"] = w.cwd
	w.env["LANG"] = "C.UTF-8"
	w.env["TZ"] = "Etc/UTC"
	w.env["TERM"] = w.ttyTerm
	w.env["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	w.env["SSH_CLIENT"] = sourceIP + " 54321 22"
	w.env["SSH_CONNECTION"] = sourceIP + " 54321 10.10.30.21 22"
	w.env["SSH_TTY"] = "/dev/pts/0"
	w.env["SHLVL"] = "1"
	w.env["APP_ENV"] = "production"
	shared.mu.Lock()
	if len(shared.files) == 0 {
		w.seedFilesystem(suffix)
		w.seedFileMetadata()
		w.seedSystemBinaries()
	}
	shared.mu.Unlock()
	return w
}

func (w *virtualSSHWorld) seedFilesystem(suffix string) {
	for _, d := range []string{"/", "/bin", "/sbin", "/usr", "/usr/bin", "/usr/sbin", "/root", "/root/.ssh", "/home", "/home/admin", "/tmp", "/var/tmp", "/dev", "/dev/shm", "/dev/pts", "/etc", "/etc/ssh", "/proc", "/proc/1", "/proc/sys", "/proc/sys/kernel", "/proc/sys/kernel/random", "/opt", "/opt/app", "/opt/app/current", "/opt/backup", "/srv", "/srv/archive", "/srv/archive/nightly", "/var", "/var/log", "/var/www", "/var/www/html", "/var/lib", "/var/lib/backup"} {
		w.dirs[d] = true
	}
	if w.user != "root" {
		h := w.homeDir()
		w.dirs[h] = true
		w.dirs[h+"/.ssh"] = true
	}
	w.files["/dev/null"] = ""
	w.fileMeta["/dev/null"] = virtualFileMeta{Size: 0, ModTime: w.system.snapshot().BootTime, Kind: "device"}
	w.files["/etc/hostname"] = w.hostname + "\n"
	w.files["/etc/os-release"] = "PRETTY_NAME=\"" + virtualOSName + "\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\nID=ubuntu\n"
	passwd := "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nsvc-web:x:997:997:Web Service:/opt/app:/bin/bash\nsvc-backup:x:998:998:Backup Service:/var/lib/backup:/bin/bash\nadmin:x:1000:1000:Administrator:/home/admin:/bin/bash\n"
	groups := "root:x:0:\nsudo:x:27:admin\nsvc-web:x:997:\nsvc-backup:x:998:\ndocker:x:999:admin\nadmin:x:1000:\n"
	if w.user != "root" && w.user != "admin" && w.user != "svc-web" && w.user != "svc-backup" {
		passwd += virtualUserPasswdEntry(w.user) + "\n"
		groups += virtualUserGroupEntry(w.user) + "\n"
		groups = strings.Replace(groups, "sudo:x:27:admin", "sudo:x:27:admin,"+safeVirtualName(w.user), 1)
		groups = strings.Replace(groups, "docker:x:999:admin", "docker:x:999:admin,"+safeVirtualName(w.user), 1)
	}
	w.files["/etc/passwd"] = passwd
	w.files["/etc/group"] = groups
	shadow := "root:$y$j9T$Qf" + suffix + "n4kM7nQp$u7f8P8K2s9V3f5X1xA0:20308:0:99999:7:::\n" +
		"svc-web:$y$j9T$Wb" + suffix + "p9q$M1x7v2:20306:0:99999:7:::\n" +
		"svc-backup:$y$j9T$X3" + suffix + "Tn9a$R8r9K1v4c2P7m5:20305:0:99999:7:::\n" +
		"admin:$y$j9T$Ad" + suffix + "m2v$P3q8k4:20307:0:99999:7:::\n"
	if w.user != "root" && w.user != "admin" && w.user != "svc-web" && w.user != "svc-backup" {
		shadow += safeVirtualName(w.user) + ":$y$j9T$U" + suffix + "x$N4r6p2:20307:0:99999:7:::\n"
	}
	w.files["/etc/shadow"] = shadow
	w.files["/etc/hosts"] = lures.HostsFile()
	w.files["/etc/ssh/sshd_config"] = "Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\nUsePAM yes\n"
	w.files["/opt/app/.env"] = "APP_ENV=production\nAPP_DEBUG=false\nDB_HOST=db-internal\nDB_PORT=5432\nDB_NAME=platform\nDB_USER=svc_web\nDB_PASSWORD=rotate_after_migration_" + suffix + "\nINTERNAL_API=http://127.0.0.1:8081\nINTERNAL_API_TOKEN=" + w.canaries["internal-api"] + "\nREGISTRY_HOST=registry.internal\nREGISTRY_TOKEN=" + w.canaries["registry"] + "\nBACKUP_DIR=/srv/archive/nightly\nBACKUP_TOKEN=" + w.canaries["backup"] + "\n"
	w.files["/opt/app/current/config.yaml"] = "environment: production\nlisten: 0.0.0.0:8081\ndatabase: db-internal:5432/platform\nbackup_profile: nightly\n"
	w.files["/opt/app/current/docker-compose.yml"] = "services:\n  web:\n    image: registry.internal/platform/web:2026.08\n  worker:\n    image: registry.internal/platform/worker:2026.08\n  redis:\n    image: redis:7-alpine\n"
	w.files["/opt/backup/backup.conf"] = "legacy_export=true\nexport_path=/srv/archive/nightly\nservice_user=svc-backup\nremote_host=backup-01\nremote_ip=10.10.30.12\nauth_token=" + w.canaries["backup"] + "\nretention_days=14\n"
	w.files["/srv/archive/nightly/migration-notes.txt"] = "Temporary legacy backup path remains enabled until cutover.\nService account: svc-backup\nTarget: backup-01 (10.10.30.12)\n"
	w.files["/srv/archive/nightly/customers-2026-08-14.sql.gz"] = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03DBIP-CUSTOMERS-" + suffix + "\n"
	w.files["/srv/archive/nightly/config-prod.tar.gz"] = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03CONFIG-BACKUP-" + suffix + "\n"
	w.files["/root/.bash_history"] = "cd /opt/app\ncat .env\ndocker ps\ncd /opt/backup\ncat backup.conf\nssh svc-backup@10.10.30.12\n"
	w.files["/root/.bashrc"] = "# ~/.bashrc: executed by bash for non-login shells\ncase $- in\n    *i*) ;;\n      *) return;;\nesac\nexport PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
	w.files["/root/.profile"] = "# ~/.profile\n[ -f ~/.bashrc ] && . ~/.bashrc\n"
	if w.user != "root" {
		w.files[path.Join(w.homeDir(), ".bash_history")] = "sudo -l\nuname -a\ncd /var/tmp\n"
		w.files[path.Join(w.homeDir(), ".bashrc")] = "case $- in\n    *i*) ;;\n      *) return;;\nesac\n"
		w.files[path.Join(w.homeDir(), ".profile")] = "[ -f ~/.bashrc ] && . ~/.bashrc\n"
		_ = w.setVirtualDir(path.Join(w.homeDir(), ".ssh"))
		w.files[path.Join(w.homeDir(), ".ssh/authorized_keys")] = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMv7y4n0M0T2d9Rk9g6vJXx0y9S2k4C5qV6L1f8q " + w.user + "@ops-gw-01\n"
	}
	w.files["/root/.ssh/config"] = "Host backup-01\n    HostName 10.10.30.12\n    User svc-backup\n    IdentityFile ~/.ssh/id_ed25519_backup\n"
	w.files["/root/.ssh/known_hosts"] = "backup-01 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG7m4D8g5gA3Rk2qP9tV6cB1nH0xQe5uL8zK" + suffix + "\n"
	w.files["/root/.ssh/id_ed25519_backup"] = "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nb3BlbnNzaC1rZXktbWF0ZXJpYWwt" + suffix + "\n-----END OPENSSH PRIVATE KEY-----\n"
	w.files["/var/log/auth.log"] = "Aug 15 02:00:01 prod-app-02 CRON[1842]: pam_unix(cron:session): session opened for user root\nAug 15 02:00:03 prod-app-02 sshd[1881]: Accepted publickey for svc-backup from 10.10.30.12 port 51244 ssh2\n"
	w.files["/var/www/html/index.html"] = "<html><body>service online</body></html>\n"
	w.files["/etc/resolv.conf"] = "nameserver 10.10.30.1\nsearch prod.internal\noptions edns0 trust-ad\n"
	w.files["/etc/fstab"] = "UUID=4e2a-91bf / ext4 defaults 0 1\nUUID=3ac1-c98d /srv/archive ext4 defaults,nosuid,nodev 0 2\n"
	w.files["/etc/crontab"] = "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n0 2 * * * root /usr/local/bin/backupctl sync --profile legacy\n"
	w.files["/etc/systemd/system/backup-agent.service"] = "[Unit]\nDescription=Legacy Backup Agent\nAfter=network-online.target\n\n[Service]\nUser=svc-backup\nExecStart=/usr/local/bin/backup-agent --config /opt/backup/backup.conf\nRestart=on-failure\n\n[Install]\nWantedBy=multi-user.target\n"
	w.files["/proc/version"] = "Linux version " + virtualKernelRelease + " (buildd@lcy02-amd64-042) (x86_64-linux-gnu-gcc-13) " + virtualKernelVersion + "\n"
	w.files["/proc/cpuinfo"] = "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: " + virtualCPUModel + "\ncpu cores\t: 4\nflags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr\n"
	w.files["/proc/meminfo"] = "MemTotal:        8063184 kB\nMemFree:         4077672 kB\nMemAvailable:    6163920 kB\nBuffers:          168432 kB\nCached:          1853900 kB\nSwapTotal:       2097148 kB\nSwapFree:        2097148 kB\n"
	w.files["/proc/1/cgroup"] = "0::/init.scope\n"
	w.files["/proc/uptime"] = ""
	w.files["/proc/loadavg"] = ""
	w.files["/proc/stat"] = ""
	w.files["/proc/sys/kernel/random/boot_id"] = ""
	w.files["/etc/machine-id"] = ""
	w.files["/opt/app/current/.env.production"] = "APP_ENV=production\nAPP_KEY=base64:Q3J5cHRvZ3JhcGh5LWlzLW5vdC1yZWFsLWhlcmU=\nDB_HOST=db-internal\nREDIS_HOST=cache-01\n"
	w.files["/var/lib/backup/.env"] = "BACKUP_REMOTE=backup-01\nBACKUP_USER=svc-backup\nBACKUP_MODE=legacy\n"
	w.files["/home/admin/.bash_history"] = "sudo -l\ndocker ps\ncd /opt/app/current\ngit status\ncat ../.env\n"
	w.files["/opt/app/current/.git/config"] = "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = ssh://git@git.prod.internal/platform/web.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
	w.files["/opt/app/current/inventory.ini"] = lures.Inventory()
	w.dirs["/opt/app/current/.git"] = true
}

func (w *virtualSSHWorld) homeDir() string {
	switch w.user {
	case "root":
		return "/root"
	case "svc-web":
		return "/opt/app"
	case "svc-backup":
		return "/var/lib/backup"
	default:
		return "/home/" + safeVirtualName(w.user)
	}
}

func safeVirtualName(v string) string {
	var b strings.Builder
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "user"
	}
	return b.String()
}

func (w *virtualSSHWorld) Banner() string {
	s := w.system.snapshot()
	h := w.currentHost()
	memPct := 100 * s.MemUsedMiB / s.MemTotalMiB
	return fmt.Sprintf("Welcome to %s (GNU/Linux %s %s)\r\n\r\n * Documentation:  https://help.ubuntu.com\r\n * Management:     https://landscape.canonical.com\r\n\r\nSystem information as of %s UTC\r\n\r\n  System load:  %.2f              Processes:             %d\r\n  Usage of /:   %.1f%% of %.2fGB   Users logged in:       2\r\n  Memory usage: %.0f%%               IPv4 address for eth0: %s\r\n  Swap usage:   0%%\r\n\r\n", virtualOSName, virtualKernelRelease, virtualMachineArch, s.Now.Format("Mon Jan _2 15:04:05 2006"), s.Load1, w.virtualProcessCount(), float64(s.RootUsePct), s.RootTotalGiB, memPct, h.IP)
}

func (w *virtualSSHWorld) Prompt() string {
	show := w.cwd
	home := w.homeDir()
	if show == home {
		show = "~"
	} else if strings.HasPrefix(show, home+"/") {
		show = "~" + strings.TrimPrefix(show, home)
	}
	mark := "$"
	if w.user == "root" {
		mark = "#"
	}
	return fmt.Sprintf("%s@%s:%s%s ", w.user, w.hostname, show, mark)
}

func (w *virtualSSHWorld) Execute(line string) virtualSSHResult {
	return w.executeWithInput(line, "")
}

func (w *virtualSSHWorld) ExecuteWithInput(line, input string) virtualSSHResult {
	return w.executeWithInput(line, input)
}

func (w *virtualSSHWorld) executeWithInput(line, initialInput string) virtualSSHResult {
	line = strings.TrimSpace(line)
	if line == "" {
		return virtualSSHResult{}
	}
	if looksLikeMinerCleanupSequence(strings.ToLower(line)) {
		w.seedMinerCleanupLures()
		w.seedDropperExecutionTargets(line)
	}
	w.observeRealityProbe(line)
	if res, ok := w.executeKnownEnvironmentCollector(line); ok {
		w.adaptToBehavior(res.Family, line)
		w.lastStatus = res.Status
		w.system.markActivity(virtualActivityWeight(res))
		return res
	}
	if res, ok := w.executeVirtualControlFlow(line, initialInput); ok {
		w.adaptToBehavior(res.Family, line)
		w.lastStatus = res.Status
		w.system.markActivity(virtualActivityWeight(res))
		return res
	}
	if res, ok := w.executeEmbeddedVirtualIf(line, initialInput); ok {
		w.adaptToBehavior(res.Family, line)
		w.lastStatus = res.Status
		w.system.markActivity(virtualActivityWeight(res))
		return res
	}
	parts := splitVirtualChain(line)
	combined := virtualSSHResult{Status: 0, Family: "other", Risk: 70, Message: "virtual command processed"}
	var out strings.Builder
	lastStatus := 0
	executed := false
	for _, part := range parts {
		if part.command == "" {
			continue
		}
		shouldRun := true
		switch part.before {
		case "&&":
			shouldRun = lastStatus == 0
		case "||":
			shouldRun = lastStatus != 0
		}
		if !shouldRun {
			continue
		}
		command := strings.TrimSpace(part.command)
		stageInput := ""
		if initialInput != "" && virtualCommandConsumesInput(command) {
			stageInput = initialInput
		} else if !executed {
			stageInput = initialInput
		}
		res, capturedAssignment := w.executeVirtualCapturedAssignment(command)
		if !capturedAssignment {
			// Control-flow bodies must retain their variable/arithmetic expressions
			// until each iteration/branch executes. Expanding the whole construct
			// here would freeze `$i` in a while loop at its first value.
			var handledControl bool
			res, handledControl = w.executeVirtualControlFlow(command, stageInput)
			if !handledControl {
				command = strings.TrimSpace(w.expandVirtualLine(command))
				res = w.executePipeline(command, stageInput)
			}
		}
		if part.background {
			res = w.backgroundResult(command, res)
		}
		w.adaptToBehavior(res.Family, command)
		executed = true
		lastStatus = res.Status
		// `$?` inside a later command in the same compound line must see the
		// immediately preceding command, just like a real shell.
		w.lastStatus = lastStatus
		if res.Output != "" {
			out.WriteString(res.Output)
			if !strings.HasSuffix(res.Output, "\n") {
				out.WriteByte('\n')
			}
		}
		combined.Status = res.Status
		combined.Exit = res.Exit
		combined.Interactive = res.Interactive
		combined.Target = res.Target
		combined.TerminalAction = res.TerminalAction
		if res.Depth >= combined.Depth {
			combined.Depth, combined.Risk, combined.Family, combined.CommandName, combined.Persona, combined.Message = res.Depth, res.Risk, res.Family, res.CommandName, res.Persona, res.Message
		}
		combined.Delay += res.Delay
		if res.LoopInc > 0 {
			combined.LoopInc += res.LoopInc
			w.loop += res.LoopInc
			w.frustration = minInt(10, w.frustration+res.LoopInc)
		}
		if res.Depth > w.depth {
			w.depth = res.Depth
		}
		if res.Exit || res.Interactive != "" || res.TerminalAction == "break" || res.TerminalAction == "continue" {
			break
		}
	}
	combined.Output = strings.TrimSuffix(out.String(), "\n")
	if combined.Depth == 0 {
		combined.Depth = maxInt(w.depth, 2)
	}
	if executed {
		w.lastStatus = combined.Status
		w.system.markActivity(virtualActivityWeight(combined))
	}
	return combined
}

type virtualChainPart struct {
	before     string
	command    string
	background bool
}

func splitVirtualChain(line string) []virtualChainPart {
	var out []virtualChainPart
	var b, word strings.Builder
	var quote byte
	escaped := false
	parenDepth, braceDepth := 0, 0
	caseDepth, ifDepth, loopDepth := 0, 0, 0
	before := ""
	processWord := func() {
		w := strings.TrimSpace(word.String())
		word.Reset()
		switch w {
		case "case":
			caseDepth++
		case "esac":
			if caseDepth > 0 {
				caseDepth--
			}
		case "if":
			ifDepth++
		case "fi":
			if ifDepth > 0 {
				ifDepth--
			}
		case "for", "while", "until":
			loopDepth++
		case "done":
			if loopDepth > 0 {
				loopDepth--
			}
		}
	}
	flush := func(next string) {
		processWord()
		cmd := strings.TrimSpace(b.String())
		if cmd != "" {
			out = append(out, virtualChainPart{before: before, command: cmd})
			before = next
		}
		b.Reset()
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		if escaped {
			b.WriteByte(c)
			if quote == 0 {
				word.WriteByte(c)
			}
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			b.WriteByte(c)
			continue
		}
		if quote != 0 {
			b.WriteByte(c)
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			b.WriteByte(c)
			continue
		}
		switch c {
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case '{':
			braceDepth++
		case '}':
			if braceDepth > 0 {
				braceDepth--
			}
		}
		if parenDepth == 0 && braceDepth == 0 {
			if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
				processWord()
				b.WriteByte(c)
				continue
			}
			if c == ';' {
				processWord()
				if caseDepth > 0 || ifDepth > 0 || loopDepth > 0 {
					b.WriteByte(c)
					continue
				}
				flush(";")
				continue
			}
			if c == '&' && i+1 < len(line) && line[i+1] == '&' {
				processWord()
				if caseDepth > 0 || ifDepth > 0 || loopDepth > 0 {
					b.WriteString("&&")
					i++
					continue
				}
				flush("&&")
				i++
				continue
			}
			if c == '|' && i+1 < len(line) && line[i+1] == '|' {
				processWord()
				if caseDepth > 0 || ifDepth > 0 || loopDepth > 0 {
					b.WriteString("||")
					i++
					continue
				}
				flush("||")
				i++
				continue
			}
			if c == '&' && !((i+1 < len(line) && line[i+1] == '>') || (i > 0 && (line[i-1] == '>' || line[i-1] == '<'))) {
				processWord()
				if caseDepth > 0 || ifDepth > 0 || loopDepth > 0 {
					b.WriteByte(c)
					continue
				}
				flush(";")
				if len(out) > 0 {
					out[len(out)-1].background = true
				}
				continue
			}
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' {
				word.WriteByte(c)
			} else {
				if word.Len() > 0 {
					processWord()
				}
			}
		}
		b.WriteByte(c)
	}
	flush("")
	return out
}

func (w *virtualSSHWorld) executePipeline(line string, initialInput ...string) virtualSSHResult {
	parts := splitOutsideQuotes(line, '|')
	var input string
	if len(initialInput) > 0 {
		input = initialInput[0]
	}
	best := virtualSSHResult{Status: 0, Family: "other", Risk: 70, Message: "virtual pipeline processed"}
	for i, part := range parts {
		stage := strings.TrimSpace(part)
		// Redirections inside a grouped command belong to the individual commands
		// in that group. Do not hoist an inner `2>/dev/null` to the whole group,
		// otherwise valid stdout from earlier commands would disappear when the
		// final optional probe fails.
		if inner, grouped := unwrapVirtualGroup(stage); grouped {
			res := w.executeGrouped(inner)
			input = res.Output
			if i == 0 || res.Depth >= best.Depth {
				best = res
			} else {
				best.Status = res.Status
				best.Exit = res.Exit
			}
			if res.Exit || res.Interactive != "" {
				break
			}
			continue
		}
		clean, redirect := parseVirtualRedirection(stage)
		if redirect.syntaxError {
			return virtualSSHResult{Output: "bash: syntax error near unexpected token `newline'", Status: 2, Family: "shell", CommandName: path.Base(firstNonOption(virtualWords(clean))), Depth: maxInt(2, w.depth), Risk: 80, Persona: "interactive-shell", Message: "virtual redirection syntax error"}
		}
		stageInput := input
		// curl writes binary response bodies normally when stdout is a pipe/file rather than a TTY.
		// Force the virtual curl down its stdout path for pipeline/redirection stages so archives do not
		// emit the interactive-terminal binary warning in those contexts.
		if i < len(parts)-1 || redirect.stdout != "" {
			words := virtualWords(clean)
			if len(words) > 0 && path.Base(words[0]) == "curl" {
				args := words[1:]
				if optionValue(args, "-o", "--output") == "" && !containsArg(args, "-O") {
					clean += " --output -"
				}
			}
		}
		emptyRedirectedStdin := false
		if redirect.stdin != "" {
			content, ok := w.virtualReadFile(redirect.stdin)
			if !ok {
				return virtualSSHResult{Output: "bash: " + redirect.stdin + ": No such file or directory", Status: 1, Family: "filesystem", Depth: maxInt(3, w.depth), Risk: 84, Persona: "file-discovery", Message: "virtual input redirection failed"}
			}
			stageInput = content
			if content == "" {
				stageInput = "\x00ZL_EMPTY_STDIN\x00"
				emptyRedirectedStdin = true
			}
		}
		res := w.executeOne(clean, stageInput)
		if redirect.suppressStderr && res.Status != 0 {
			// The virtual result has a combined text field; for failed commands the
			// diagnostics represented there are stderr in the cases we model.
			res.Output = ""
		}
		if redirect.suppressStdout {
			res.Output = ""
		}
		if emptyRedirectedStdin && res.Output == "\x00ZL_EMPTY_STDIN\x00" {
			res.Output = ""
		}
		if redirect.stdout != "" {
			if redirect.stdout == "/dev/null" {
				res.Output = ""
			} else {
				ok := false
				content := res.Output
				if content != "" && !strings.HasSuffix(content, "\n") {
					content += "\n"
				}
				resolvedOut := w.resolve(redirect.stdout)
				if redirect.append {
					ok = w.appendVirtualFile(resolvedOut, content)
				} else {
					ok = w.setVirtualFile(resolvedOut, content)
				}
				if !ok {
					res.Output, res.Status = "bash: "+redirect.stdout+": "+w.virtualWriteFailure(resolvedOut), 1
				} else {
					res.Output = ""
					res.Family = "filesystem"
					res.Depth = maxInt(res.Depth, 4)
					res.Risk = maxInt(res.Risk, 88)
					res.Persona = "file-manipulation"
					res.Message = "virtual shell output redirection"
					words := virtualWords(clean)
					if len(words) > 0 && path.Base(words[0]) == "cat" && w.isVirtualPayloadStagingPath(resolvedOut) {
						w.stagingAttempts[resolvedOut]++
						res.PayloadPath = resolvedOut
						if stageInput != "" && stageInput != "\x00ZL_EMPTY_STDIN\x00" {
							sum := sha256.Sum256([]byte(stageInput))
							if previous, ok := w.stagingPayloadHash[resolvedOut]; ok && previous == sum {
								res.PayloadStage = "retry"
								res.LoopInc++
								res.Family, res.Depth, res.Risk, res.Persona, res.Message = "execution", maxInt(6, res.Depth), maxInt(98, res.Risk), "payload-staging", "identical virtual payload staging retry"
							} else {
								w.stagingPayloadHash[resolvedOut] = sum
								res.PayloadStage = "completed"
								res.Family, res.Depth, res.Risk, res.Persona, res.Message = "execution", maxInt(6, res.Depth), maxInt(97, res.Risk), "payload-staging", "virtual payload staging completed"
							}
						} else if w.stagingAttempts[resolvedOut] > 1 {
							res.PayloadStage = "retry"
							res.LoopInc++
							res.Family, res.Depth, res.Risk, res.Persona, res.Message = "execution", maxInt(5, res.Depth), maxInt(94, res.Risk), "payload-staging", "repeated virtual payload staging intent"
						} else {
							res.PayloadStage = "intent"
							res.Family, res.Depth, res.Risk, res.Persona, res.Message = "execution", maxInt(5, res.Depth), maxInt(93, res.Risk), "payload-staging", "virtual payload staging intent"
						}
					}
				}
			}
		}
		input = res.Output
		if i == 0 || res.Depth >= best.Depth {
			best = res
		} else {
			best.Status = res.Status
			best.Exit = res.Exit
		}
		if res.Exit || res.Interactive != "" {
			break
		}
	}
	best.Output = input
	return best
}

type virtualRedirection struct {
	stdin          string
	stdout         string
	append         bool
	suppressStderr bool
	suppressStdout bool
	syntaxError    bool
}

func parseVirtualRedirection(line string) (string, virtualRedirection) {
	var r virtualRedirection
	// Keep stderr/stdout semantics separate enough for common automation probes.
	for _, token := range []string{"&>/dev/null", "&> /dev/null"} {
		if strings.Contains(line, token) {
			r.suppressStdout, r.suppressStderr = true, true
			line = strings.ReplaceAll(line, token, "")
		}
	}
	for _, token := range []string{"2>/dev/null", "2> /dev/null"} {
		if strings.Contains(line, token) {
			r.suppressStderr = true
			line = strings.ReplaceAll(line, token, "")
		}
	}
	// 2>&1 merges stderr into stdout and is therefore intentionally not suppressed.
	for _, token := range []string{"2>&1", "1>&2"} {
		line = strings.ReplaceAll(line, token, "")
	}
	for _, token := range []string{"1>/dev/null", "1> /dev/null", ">/dev/null", "> /dev/null"} {
		if strings.Contains(line, token) {
			r.suppressStdout = true
			line = strings.ReplaceAll(line, token, "")
		}
	}
	if pos, width := findVirtualRedirect(line, '>', true); pos >= 0 {
		r.append = width == 2
		target := strings.TrimSpace(line[pos+width:])
		words := virtualWords(target)
		if len(words) == 0 {
			r.syntaxError = true
			return strings.TrimSpace(line[:pos]), r
		}
		r.stdout = words[0]
		line = strings.TrimSpace(line[:pos])
	}
	if pos, width := findVirtualRedirect(line, '<', false); pos >= 0 {
		target := strings.TrimSpace(line[pos+width:])
		words := virtualWords(target)
		if len(words) == 0 {
			r.syntaxError = true
			return strings.TrimSpace(line[:pos]), r
		}
		r.stdin = words[0]
		line = strings.TrimSpace(line[:pos])
	}
	return strings.TrimSpace(line), r
}

func findVirtualRedirect(line string, op byte, doubled bool) (int, int) {
	quote := byte(0)
	escaped := false
	for i := 0; i < len(line); i++ {
		c := line[i]
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
		if c != op {
			continue
		}
		if i > 0 && line[i-1] >= '0' && line[i-1] <= '9' {
			continue
		}
		if doubled && i+1 < len(line) && line[i+1] == op {
			return i, 2
		}
		return i, 1
	}
	return -1, 0
}

func splitOutsideQuotes(v string, delim rune) []string {
	var out []string
	var b strings.Builder
	var quote rune
	escaped := false
	parenDepth, braceDepth := 0, 0
	for _, r := range v {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			b.WriteRune(r)
			escaped = true
			continue
		}
		if quote != 0 {
			b.WriteRune(r)
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			b.WriteRune(r)
			continue
		}
		switch r {
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case '{':
			braceDepth++
		case '}':
			if braceDepth > 0 {
				braceDepth--
			}
		}
		if r == delim && parenDepth == 0 && braceDepth == 0 {
			out = append(out, b.String())
			b.Reset()
			continue
		}
		b.WriteRune(r)
	}
	out = append(out, b.String())
	return out
}

func virtualWords(v string) []string {
	var out []string
	var b strings.Builder
	var quote byte
	flush := func() {
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
	}
	v = strings.TrimSpace(v)
	for i := 0; i < len(v); i++ {
		c := v[i]
		if quote == '\'' {
			if c == '\'' {
				quote = 0
			} else {
				b.WriteByte(c)
			}
			continue
		}
		if quote == '"' {
			if c == '"' {
				quote = 0
				continue
			}
			if c == '\\' && i+1 < len(v) {
				n := v[i+1]
				if n == '$' || n == '`' || n == '"' || n == '\\' || n == '\n' {
					b.WriteByte(n)
					i++
					continue
				}
				b.WriteByte('\\')
				continue
			}
			b.WriteByte(c)
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if c == '\\' && i+1 < len(v) {
			b.WriteByte(v[i+1])
			i++
			continue
		}
		if c == ' ' || c == '\t' {
			flush()
			continue
		}
		b.WriteByte(c)
	}
	flush()
	return out
}

func unwrapVirtualGroup(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if len(raw) < 2 {
		return "", false
	}
	if raw[0] == '(' && raw[len(raw)-1] == ')' && balancedVirtualDelims(raw[1:len(raw)-1]) {
		return strings.TrimSpace(raw[1 : len(raw)-1]), true
	}
	if raw[0] == '{' && raw[len(raw)-1] == '}' && balancedVirtualDelims(raw[1:len(raw)-1]) {
		return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(raw[1:len(raw)-1]), ";")), true
	}
	return "", false
}

func balancedVirtualDelims(v string) bool {
	paren, brace := 0, 0
	var quote rune
	escaped := false
	for _, r := range v {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		switch r {
		case '(':
			paren++
		case ')':
			paren--
		case '{':
			brace++
		case '}':
			brace--
		}
		if paren < 0 || brace < 0 {
			return false
		}
	}
	return paren == 0 && brace == 0 && quote == 0
}

func splitVirtualAssignment(raw string) (string, string, bool) {
	idx := strings.IndexByte(raw, '=')
	if idx <= 0 {
		return "", "", false
	}
	name := strings.TrimSpace(raw[:idx])
	if !validVirtualEnvName(name) {
		return "", "", false
	}
	// A leading NAME=value assignment is handled as a standalone assignment only
	// when NAME is the first shell word. This covers common recon collectors such
	// as arch=$(uname -m ...), while command arguments containing '=' keep working.
	if strings.ContainsAny(name, " \t") {
		return "", "", false
	}
	return name, strings.TrimSpace(raw[idx+1:]), true
}

func unquoteVirtualAssignmentValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) < 2 {
		return value
	}
	if value[0] == '\'' && value[len(value)-1] == '\'' {
		return value[1 : len(value)-1]
	}
	if value[0] == '"' && value[len(value)-1] == '"' {
		v := value[1 : len(value)-1]
		var b strings.Builder
		for i := 0; i < len(v); i++ {
			if v[i] == '\\' && i+1 < len(v) {
				n := v[i+1]
				if n == '$' || n == '`' || n == '"' || n == '\\' {
					b.WriteByte(n)
					i++
					continue
				}
			}
			b.WriteByte(v[i])
		}
		return b.String()
	}
	return value
}

// executeVirtualCapturedAssignment preserves shell assignment semantics for
// command substitutions such as name=$(command ...). The captured stdout is a
// single assignment value even when it contains spaces/newlines; it must never
// be re-tokenized as a temporary environment prefix plus a new command.
func (w *virtualSSHWorld) executeVirtualCapturedAssignment(raw string) (virtualSSHResult, bool) {
	name, value, ok := splitVirtualAssignment(raw)
	if !ok {
		return virtualSSHResult{}, false
	}
	unquoted := unquoteVirtualAssignmentValue(value)
	// Capture command substitutions before tokenization. Their stdout can contain
	// spaces/newlines and must remain one assignment value. Both modern `$()` and
	// legacy backticks still occur in real installer/recon scripts.
	if !strings.Contains(unquoted, "$(") && !strings.Contains(unquoted, "`") {
		return virtualSSHResult{}, false
	}
	expanded := w.expandVirtualLine(unquoted)
	w.env[name] = expanded
	return virtualSSHResult{Family: "shell", Depth: maxInt(2, w.depth), Risk: 80, Persona: "environment-fingerprint", Message: "captured command substitution assignment"}, true
}

func (w *virtualSSHWorld) executeGrouped(inner string) virtualSSHResult {
	parts := splitVirtualChain(inner)
	combined := virtualSSHResult{Status: 0, Family: "shell", Depth: maxInt(2, w.depth), Risk: 78, Persona: "interactive-shell", Message: "virtual shell group"}
	var out strings.Builder
	lastStatus := 0
	for _, part := range parts {
		if part.command == "" {
			continue
		}
		if part.before == "&&" && lastStatus != 0 {
			continue
		}
		if part.before == "||" && lastStatus == 0 {
			continue
		}
		var res virtualSSHResult
		if captured, ok := w.executeVirtualCapturedAssignment(strings.TrimSpace(part.command)); ok {
			res = captured
		} else {
			rawCmd := strings.TrimSpace(part.command)
			if control, ok := w.executeVirtualControlFlow(rawCmd, ""); ok {
				res = control
			} else {
				cmd := strings.TrimSpace(w.expandVirtualLine(rawCmd))
				res = w.executePipeline(cmd)
			}
		}
		lastStatus = res.Status
		w.lastStatus = lastStatus
		if res.Output != "" {
			out.WriteString(res.Output)
			if !strings.HasSuffix(res.Output, "\n") {
				out.WriteByte('\n')
			}
		}
		combined.Status = res.Status
		if res.Depth >= combined.Depth {
			combined.Depth, combined.Risk, combined.Family, combined.CommandName, combined.Persona, combined.Message = res.Depth, res.Risk, res.Family, res.CommandName, res.Persona, res.Message
		}
		if res.Exit || res.Interactive != "" {
			break
		}
	}
	combined.Output = strings.TrimSuffix(out.String(), "\n")
	return combined
}

func (w *virtualSSHWorld) executeOne(raw, input string) virtualSSHResult {
	return w.executeOneDepth(raw, input, 0)
}

func (w *virtualSSHWorld) executeOneDepth(raw, input string, aliasDepth int) virtualSSHResult {
	raw = strings.TrimSpace(raw)
	if res, ok := w.executeVirtualCapturedAssignment(raw); ok {
		return res
	}
	// NAME=value command uses a temporary environment and must preserve the
	// command's original quoting. A previous implementation re-joined tokenized
	// words, which could visibly corrupt awk/sed programs and also leaked the
	// temporary assignment into later commands.
	if rest, assigns := virtualCommandEnvPrefix(raw); len(assigns) > 0 {
		if rest == "" {
			for _, a := range assigns {
				w.env[a.name] = w.expandVirtualLine(a.value)
			}
			return virtualSSHResult{Family: "shell", Depth: maxInt(2, w.depth), Risk: 76, Persona: "interactive-shell", Message: "environment assignment"}
		}
		restore := w.applyTemporaryEnv(assigns)
		defer restore()
		raw = rest
	}
	if inner, ok := unwrapVirtualGroup(raw); ok {
		return w.executeGrouped(inner)
	}
	if name, value, ok := splitVirtualAssignment(raw); ok {
		w.env[name] = unquoteVirtualAssignmentValue(value)
		return virtualSSHResult{Family: "shell", Depth: maxInt(2, w.depth), Risk: 76, Persona: "interactive-shell", Message: "environment assignment"}
	}
	words := virtualWords(raw)
	if len(words) == 0 {
		return virtualSSHResult{}
	}
	allAssignments := true
	for _, word := range words {
		name, value, ok := strings.Cut(word, "=")
		if !ok || !validVirtualEnvName(name) {
			allAssignments = false
			break
		}
		w.env[name] = value
	}
	if allAssignments {
		return virtualSSHResult{Family: "shell", Depth: maxInt(2, w.depth), Risk: 76, Persona: "interactive-shell", Message: "environment assignment"}
	}
	cmd := path.Base(words[0])
	if alias, ok := w.aliases[cmd]; ok && alias != "" && alias != cmd {
		if aliasDepth >= 8 {
			return virtualSSHResult{Output: "bash: " + cmd + ": alias expansion limit exceeded", Status: 1, Family: "shell", CommandName: cmd, Depth: maxInt(2, w.depth), Risk: 88, Persona: "resource-abuse", Message: "virtual alias expansion bounded"}
		}
		rest := strings.TrimSpace(strings.TrimPrefix(raw, words[0]))
		return w.executeOneDepth(strings.TrimSpace(alias+" "+rest), input, aliasDepth+1)
	}
	w.ops++
	if w.ops > maxVirtualOps {
		return virtualSSHResult{Output: "Connection reset by peer", Status: 255, Exit: true, Family: "limit", CommandName: cmd, Depth: maxInt(2, w.depth), Risk: 98, Persona: "resource-abuse", Message: "virtual command budget exhausted"}
	}
	if strings.HasPrefix(words[0], "./") || strings.Contains(words[0], "/") {
		resolved := w.resolve(words[0])
		_, isSystemBinary := w.fileMeta[resolved]
		isSystemBinary = isSystemBinary && w.fileMeta[resolved].Kind == "elf" && virtualCommandPath(cmd) != "" && (strings.HasPrefix(resolved, "/bin/") || strings.HasPrefix(resolved, "/usr/bin/") || strings.HasPrefix(resolved, "/sbin/") || strings.HasPrefix(resolved, "/usr/sbin/"))
		if content, ok := w.virtualReadFile(words[0]); ok && content != "" && !isSystemBinary {
			if w.virtualFileMode(resolved)&0o111 == 0 {
				return virtualSSHResult{Output: "bash: " + words[0] + ": Permission denied", Status: 126, Family: "execution", CommandName: path.Base(words[0]), Depth: maxInt(5, w.depth), Risk: 94, Persona: "payload-preparation", Message: "virtual executable permission denied"}
			}
			return w.fakeExecute(words[0])
		}
		if strings.HasPrefix(words[0], "./") && !virtualCommandExists(path.Base(words[0])) {
			return virtualSSHResult{Output: "bash: " + words[0] + ": No such file or directory", Status: 127, Family: "execution", CommandName: path.Base(words[0]), Depth: maxInt(4, w.depth), Risk: 90, Persona: "execution-probe", Message: "missing virtual executable probed"}
		}
	}
	args := words[1:]
	base := func(family string, depth, risk int, persona, message string) virtualSSHResult {
		return virtualSSHResult{CommandName: cmd, Family: family, Depth: depth, Risk: risk, Persona: persona, Message: message}
	}

	switch cmd {
	case "break":
		r := base("execution", 4, 88, "shell-control-flow", "simulated shell loop break")
		r.TerminalAction = "break"
		return r
	case "continue":
		r := base("execution", 4, 88, "shell-control-flow", "simulated shell loop continue")
		r.TerminalAction = "continue"
		return r
	case "test", "[":
		testArgs := args
		if cmd == "[" && len(testArgs) > 0 && testArgs[len(testArgs)-1] == "]" {
			testArgs = testArgs[:len(testArgs)-1]
		}
		return w.virtualTest(testArgs)
	case "exit", "logout":
		if len(w.nested) > 0 {
			ctx := w.nested[len(w.nested)-1]
			w.nested = w.nested[:len(w.nested)-1]
			w.user, w.hostname, w.cwd = ctx.user, ctx.hostname, ctx.cwd
			w.env["USER"], w.env["LOGNAME"], w.env["HOME"], w.env["PWD"], w.env["HOSTNAME"] = w.user, w.user, w.homeDir(), w.cwd, w.hostname
			r := base("lateral", 7, 96, "lateral-movement", "returned from simulated internal host")
			r.Output = "Connection to 10.10.30.12 closed."
			return r
		}
		r := base("shell", 2, 80, "interactive-shell", "virtual shell closed")
		r.Exit = true
		return r
	case "pwd":
		r := base("recon", 3, 82, "system-recon", "working directory discovery")
		r.Output = w.cwd
		return r
	case "whoami":
		r := base("recon", 3, 82, "system-recon", "identity discovery")
		r.Output = w.user
		return r
	case "id":
		r := base("recon", 3, 84, "system-recon", "identity and group discovery")
		if w.user == "root" {
			r.Output = "uid=0(root) gid=0(root) groups=0(root)"
		} else {
			uid := virtualUserID(w.user)
			r.Output = fmt.Sprintf("uid=%d(%s) gid=%d(%s) groups=%d(%s),27(sudo),999(docker)", uid, w.user, uid, w.user, uid, w.user)
		}
		return r
	case "hostname":
		r := base("recon", 3, 82, "system-recon", "hostname discovery")
		switch {
		case containsArg(args, "-I"):
			r.Output = w.currentHost().IP + " "
		case containsArg(args, "-f"), containsArg(args, "--fqdn"):
			r.Output = w.hostname + ".prod.internal"
		default:
			r.Output = w.hostname
		}
		return r
	case "uname":
		r := base("recon", 3, 84, "system-recon", "kernel discovery")
		r.Output = virtualGNUUname(w.hostname, args)
		return r
	case "date":
		r := base("recon", 3, 78, "system-recon", "system time discovery")
		r.Output = w.virtualDateCommand(args)
		return r
	case "uptime":
		r := base("recon", 3, 80, "system-recon", "uptime discovery")
		r.Output = w.virtualUptimeCommand(args)
		return r
	case "timedatectl":
		r := base("recon", 3, 80, "system-recon", "time synchronization discovery")
		r.Output = w.virtualTimedatectl()
		return r
	case "ls", "dir":
		r := base("filesystem", 3, 82, "file-discovery", "directory listing")
		target := w.cwd
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				target = w.resolve(a)
			}
		}
		long := containsShortFlag(args, 'l')
		showAll := containsShortFlag(args, 'a') || containsShortFlag(args, 'A')
		r.Output, r.Status = w.listDir(target, long, showAll)
		return r
	case "cd":
		r := base("filesystem", 3, 82, "file-discovery", "directory traversal")
		target := w.homeDir()
		if len(args) > 0 {
			if args[0] == "-" {
				target = w.env["OLDPWD"]
				r.Output = target
			} else {
				target = w.resolve(args[0])
			}
		}
		if !w.dirs[target] {
			r.Output, r.Status = "bash: cd: "+strings.Join(args, " ")+": No such file or directory", 1
			return r
		}
		w.env["OLDPWD"] = w.cwd
		w.cwd = target
		w.env["PWD"] = w.cwd
		return r
	case "cat", "less", "more", "head", "tail":
		r := base("filesystem", 4, 88, "credential-hunter", "file content discovery")
		file := virtualContentFileOperand(cmd, args)
		content := input
		// cat/head/tail with no file operand consume stdin. Empty pipeline stdin is
		// still valid input and must not turn into a misleading "missing operand".
		ok := file == ""
		if file != "" {
			content, ok = w.virtualReadFile(file)
		}
		if !ok {
			if file == "" {
				r.Output, r.Status = cmd+": missing file operand", 1
			} else {
				r.Output, r.Status = cmd+": "+file+": No such file or directory", 1
			}
			return r
		}
		if cmd == "head" {
			if n := virtualByteCount(args); n > 0 {
				b := []byte(content)
				if len(b) > n {
					b = b[:n]
				}
				content = string(b)
			} else {
				content = firstLines(content, virtualLineCount(args, 10))
			}
		} else if cmd == "tail" {
			content = lastLines(content, virtualLineCount(args, 10))
		}
		r.Output = content
		if strings.Contains(file, ".env") || strings.Contains(file, "shadow") || strings.Contains(file, ".ssh") || strings.Contains(file, "backup") {
			r.Depth, r.Risk, r.Persona, r.Message = 5, 94, "credential-hunter", "sensitive-looking lure opened"
		}
		return r
	case "find":
		r := base("filesystem", 5, 94, "credential-hunter", "deep filesystem discovery")
		r.Output = w.fakeFind(raw)
		r.Delay = 350 * time.Millisecond
		return r
	case "grep", "egrep", "fgrep":
		r := w.virtualGrep(args, input)
		r.CommandName = cmd
		return r
	case "stat":
		r := base("filesystem", 4, 87, "file-discovery", "file metadata discovery")
		file := lastNonOption(args)
		r.Output, r.Status = w.virtualFileStat(file)
		return r
	case "file":
		r := base("filesystem", 4, 87, "file-discovery", "file type discovery")
		f := lastNonOption(args)
		desc, ok := w.fileDescription(f)
		if !ok {
			r.Output, r.Status = f+": cannot open `"+f+"' (No such file or directory)", 1
		} else {
			r.Output = f + ": " + desc
		}
		return r
	case "du":
		r := base("filesystem", 4, 86, "file-discovery", "disk usage discovery")
		r.Output = "24K\t./current\n12K\t./logs\n48K\t."
		return r
	case "df":
		r := base("recon", 3, 84, "system-recon", "filesystem capacity discovery")
		r.Output = w.virtualDFOutput(args)
		return r
	case "free":
		r := base("recon", 3, 83, "system-recon", "memory discovery")
		r.Output = w.virtualFreeOutput(args)
		return r
	case "mount":
		r := base("recon", 4, 87, "system-recon", "mount discovery")
		r.Output = "/dev/vda2 on / type ext4 (rw,relatime,errors=remount-ro)\nproc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\nsysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)\n/dev/vdb1 on /srv/archive type ext4 (rw,nosuid,nodev,relatime)"
		return r
	case "env":
		if len(args) > 0 {
			if r, ok := w.executeVirtualEnv(args, input); ok {
				return r
			}
		}
		r := base("credentials", 4, 90, "credential-hunter", "environment discovery")
		r.Output = w.virtualEnvOutput(nil)
		return r
	case "printenv":
		r := base("credentials", 4, 90, "credential-hunter", "environment discovery")
		r.Output = w.virtualEnvOutput(args)
		if len(args) == 1 && r.Output == "" {
			r.Status = 1
		}
		return r
	case "set":
		r := base("shell", 2, 74, "interactive-shell", "shell option or variable inspection")
		if len(args) == 0 {
			r.Output = w.virtualEnvOutput(nil)
		}
		return r
	case "read":
		return w.virtualReadBuiltin(args, input)
	case "history":
		r := base("credentials", 4, 90, "credential-hunter", "shell history discovery")
		if containsArg(args, "-c") {
			w.history = nil
			w.historyCleared = true
			w.deleteVirtualFile(path.Join(w.homeDir(), ".bash_history"))
			r.Output = ""
			r.Family, r.Depth, r.Risk, r.Persona, r.Message = "persistence", 6, 99, "history-evasion", "shell history cleared"
			return r
		}
		var b strings.Builder
		for i, h := range w.history {
			fmt.Fprintf(&b, "%5d  %s\n", i+1, h)
		}
		r.Output = strings.TrimSuffix(b.String(), "\n")
		return r
	case "ps":
		r := base("recon", 4, 88, "system-recon", "process discovery")
		if strings.Contains(raw, "-eo") && strings.Contains(raw, "pid") && strings.Contains(raw, "pcpu") {
			r.Output = w.virtualPSCompactOutput()
		} else {
			r.Output = w.virtualPSOutput()
		}
		return r
	case "top":
		r := base("recon", 4, 87, "system-recon", "process monitoring")
		if containsArg(args, "-b") {
			r.Output = w.virtualTopOutput()
		} else {
			r.Interactive = "top"
		}
		return r
	case "ip", "ifconfig", "route":
		r := base("network", 4, 90, "network-recon", "network configuration discovery")
		h := w.currentHost()
		if cmd == "ip" && len(args) > 0 && args[0] == "route" {
			r.Output = "default via 10.10.30.1 dev eth0 proto dhcp src " + h.IP + " metric 100\n10.10.30.0/24 dev eth0 proto kernel scope link src " + h.IP
		} else {
			r.Output = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n    inet " + h.IP + "/24 brd 10.10.30.255 scope global eth0"
		}
		return r
	case "ss", "netstat":
		r := base("network", 4, 91, "network-recon", "listening service discovery")
		r.Output = "Netid State  Local Address:Port   Peer Address:Port Process\ntcp   LISTEN 0      128      0.0.0.0:22      0.0.0.0:*     users:((\"sshd\",pid=612,fd=3))\ntcp   LISTEN 0      4096     0.0.0.0:8081    0.0.0.0:*     users:((\"web\",pid=844,fd=7))\ntcp   LISTEN 0      128      127.0.0.1:5432  0.0.0.0:*     users:((\"docker-proxy\",pid=1102,fd=4))"
		return r
	case "last", "w", "who":
		r := base("recon", 4, 86, "system-recon", "logged-in user discovery")
		r.Output = w.virtualWho(cmd, args)
		return r
	case "sudo":
		r := base("privilege", 5, 95, "privilege-escalation", "privilege escalation attempt")
		if len(args) == 0 || containsArg(args, "-l") {
			r.Output = "Matching Defaults entries for " + w.user + " on " + w.hostname + ":\n    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n\nUser " + w.user + " may run the following commands on " + w.hostname + ":\n    (ALL) NOPASSWD: /usr/bin/docker, /usr/local/bin/backupctl"
			return r
		}
		innerArgs, _ := virtualSudoCommandArgs(args)
		if len(innerArgs) == 0 {
			return r
		}
		interactiveShell := (innerArgs[0] == "bash" || innerArgs[0] == "sh") && !containsArg(innerArgs[1:], "-c")
		if innerArgs[0] == "-i" || innerArgs[0] == "su" || interactiveShell {
			w.setVirtualUser("root")
			r.LoopInc = 1
			return r
		}
		inner := strings.Join(innerArgs, " ")
		res := w.executeOne(inner, input)
		res.Depth = maxInt(res.Depth, 5)
		res.Risk = maxInt(res.Risk, 95)
		res.Persona = "privilege-escalation"
		return res
	case "su":
		r := base("privilege", 5, 95, "privilege-escalation", "user switch attempt")
		w.setVirtualUser("root")
		r.LoopInc = 1
		return r
	case "systemctl", "service":
		r := base("persistence", 6, 97, "persistence", "service discovery or modification")
		if strings.Contains(raw, "status") {
			snap := w.system.snapshot()
			started := snap.BootTime.Add(11 * time.Minute)
			age := strings.TrimPrefix(virtualUptimePretty(snap.Now.Sub(started)), "up ")
			r.Output = "● backup-agent.service - Legacy Backup Agent\n     Loaded: loaded (/etc/systemd/system/backup-agent.service; enabled; preset: enabled)\n     Active: active (running) since " + started.Format("Mon 2006-01-02 15:04:05 UTC") + "; " + age + " ago\n   Main PID: 1842 (backup-agent)\n      Tasks: 3 (limit: 9354)\n     Memory: 18.7M (peak: 21.1M)\n        CPU: 12min 31.442s"
		} else {
			r.Output = ""
			r.LoopInc = 1
		}
		return r
	case "journalctl":
		r := base("credentials", 5, 93, "credential-hunter", "log discovery")
		r.Output = w.virtualJournal()
		return r
	case "crontab":
		r := base("persistence", 6, 97, "persistence", "scheduled task discovery or modification")
		if containsArg(args, "-e") {
			spool := "/var/spool/cron/crontabs/" + safeVirtualName(w.user)
			_ = w.setVirtualDir("/var/spool")
			_ = w.setVirtualDir("/var/spool/cron")
			_ = w.setVirtualDir("/var/spool/cron/crontabs")
			if _, ok := w.files[spool]; !ok {
				_ = w.setVirtualFile(spool, w.crontabContent)
				w.fileModes[spool] = 0o600
			}
			r.Interactive = "crontab-edit"
			r.Target = spool
			r.LoopInc = 1
		} else if containsArg(args, "-r") {
			w.crontabExists = false
			w.crontabContent = ""
			w.system.setPeerCrontab(w.peerKey, false, "")
			w.deleteVirtualFile("/var/spool/cron/crontabs/" + safeVirtualName(w.user))
			r.Output = ""
			r.LoopInc = 1
		} else if containsArg(args, "-l") {
			if !w.crontabExists {
				r.Output, r.Status = "no crontab for "+w.user, 1
			} else {
				r.Output = strings.TrimSuffix(w.crontabContent, "\n")
			}
		} else {
			w.crontabExists = true
			if input != "" {
				w.crontabContent = input
			}
			w.system.setPeerCrontab(w.peerKey, true, w.crontabContent)
			r.Output = ""
			r.LoopInc = 1
		}
		return r
	case "docker":
		r := base("containers", 5, 95, "container-discovery", "container runtime discovery")
		if len(args) == 0 || args[0] == "ps" {
			snap := w.system.snapshot()
			days := int(snap.Uptime / (24 * time.Hour))
			status := fmt.Sprintf("Up %d days", days)
			r.Output = "CONTAINER ID   IMAGE                                      COMMAND          STATUS          PORTS                    NAMES\n" +
				"7c3f1a2d9b11   registry.internal/platform/web:2026.08     \"/app/web\"      " + status + "      0.0.0.0:8081->8081/tcp   platform-web-1\n" +
				"1d92a1b817cc   postgres:16-alpine                         \"postgres\"      " + status + "      127.0.0.1:5432->5432/tcp db-1\n" +
				"50f6e120c2aa   redis:7-alpine                             \"redis-server\"  " + status + "      6379/tcp                 cache-1"
		} else if args[0] == "inspect" {
			r.Output = "[{\"Name\":\"/platform-web-1\",\"Config\":{\"Env\":[\"APP_ENV=production\",\"DB_HOST=db-internal\"]},\"NetworkSettings\":{\"IPAddress\":\"10.10.30.31\"}}]"
		} else if args[0] == "exec" {
			r.Depth, r.Risk, r.Persona, r.Message, r.LoopInc = 6, 98, "container-escape", "simulated container execution attempt", 1
			r.Output = "root@7c3f1a2d9b11:/app#"
		}
		return r
	case "kubectl":
		r := base("containers", 5, 95, "container-discovery", "orchestrator discovery")
		days := int(w.system.snapshot().Uptime / (24 * time.Hour))
		r.Output = fmt.Sprintf("NAME                         READY   STATUS    RESTARTS   AGE\nplatform-web-7c8d9b6d8-x9f2k  1/1     Running   0          %dd\nworker-6b55dfc7d6-j4wqq        1/1     Running   1          %dd", days, days)
		return r
	case "curl":
		return w.fakeCurl(args)
	case "wget":
		return w.fakeWget(args)
	case "ssh":
		return w.fakeNestedSSH(args)
	case "scp":
		return w.fakeSCP(args)
	case "ping":
		r := base("network", 5, 94, "network-recon", "simulated network reachability probe")
		host := lastNonOption(args)
		if host == "" {
			host = "backup-01"
		}
		ip := host
		if h, ok := lures.Resolve(host); ok {
			ip = h.IP
		}
		r.Output = "PING " + host + " (" + ip + ") 56(84) bytes of data."
		r.Interactive = "ping"
		r.Target = host
		r.StreamCount = virtualPingCount(args)
		return r
	case "nc", "netcat", "ncat", "telnet":
		r := base("network", 5, 95, "network-recon", "simulated service probing")
		r.Delay = 300 * time.Millisecond
		host, port := "db-primary", "5432"
		vals := make([]string, 0, len(args))
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				vals = append(vals, a)
			}
		}
		if len(vals) >= 1 {
			host = vals[len(vals)-1]
		}
		if len(vals) >= 2 {
			host, port = vals[len(vals)-2], vals[len(vals)-1]
		}
		ip := host
		if h, ok := lures.Resolve(host); ok {
			ip = h.IP
		}
		r.Output = "Connection to " + host + " (" + ip + ") " + port + " port [tcp/*] succeeded!"
		return r
	case "chmod", "chown":
		r := base("execution", 6, 97, "payload-preparation", "payload permission/ownership change")
		if cmd == "chmod" && len(args) >= 2 {
			modeArg := args[0]
			for _, target := range args[1:] {
				if strings.HasPrefix(target, "-") {
					continue
				}
				resolved := w.resolve(target)
				if _, ok := w.virtualReadFile(resolved); !ok {
					r.Output, r.Status = "chmod: cannot access '"+target+"': No such file or directory", 1
					continue
				}
				m := w.virtualFileMode(resolved)
				if strings.Contains(modeArg, "+x") {
					m |= 0o111
				} else if strings.Contains(modeArg, "-x") {
					m &^= 0o111
				} else if n, err := strconv.ParseUint(modeArg, 8, 12); err == nil {
					m = uint32(n)
				}
				w.fileModes[resolved] = m
			}
		}
		r.LoopInc = 1
		return r
	case "mkdir":
		r := base("filesystem", 4, 88, "file-manipulation", "virtual directory created")
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				target := w.resolve(a)
				if !w.setVirtualDir(target) {
					r.Output, r.Status = "mkdir: cannot create directory '"+a+"': No space left on device", 1
					break
				}
			}
		}
		return r
	case "touch":
		r := base("filesystem", 4, 88, "file-manipulation", "virtual file created")
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				if !w.setVirtualFile(w.resolve(a), "") {
					r.Output, r.Status = "touch: cannot touch '"+a+"': No space left on device", 1
					break
				}
			}
		}
		return r
	case "rm":
		r := base("filesystem", 5, 93, "file-manipulation", "virtual file removal")
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				resolved := w.resolve(a)
				if w.virtualFileImmutable(resolved) {
					r.Output = "rm: cannot remove '" + a + "': Operation not permitted"
					r.Status = 1
					continue
				}
				w.removeVirtualPattern(a)
			}
		}
		return r
	case "cp", "mv":
		r := base("filesystem", 5, 92, "file-manipulation", "virtual file copy/move")
		if len(args) >= 2 {
			src, dst := w.resolve(args[len(args)-2]), w.resolve(args[len(args)-1])
			if content, ok := w.files[src]; ok {
				if !w.setVirtualFile(dst, content) {
					r.Output, r.Status = cmd+": cannot create '"+args[len(args)-1]+"': No space left on device", 1
					return r
				}
				if cmd == "mv" {
					w.deleteVirtualFile(src)
				}
			} else {
				r.Output, r.Status = cmd+": cannot stat '"+args[len(args)-2]+"': No such file or directory", 1
			}
		}
		return r
	case "echo", "printf":
		r := base("shell", 2, 70, "interactive-shell", "shell output")
		if cmd == "printf" {
			if len(args) == 0 {
				r.Output, r.Status = "printf: usage: printf [-v var] format [arguments]", 2
				return r
			}
			r.Output = virtualFormatPrintf(args[0], args[1:])
		} else {
			r.Output = virtualEchoOutput(cmd, args)
		}
		return r
	case "seq":
		r := base("shell", 2, 74, "interactive-shell", "numeric sequence generation")
		r.Output, r.Status = virtualSeq(args)
		return r
	case "expr":
		r := base("shell", 2, 74, "interactive-shell", "shell expression evaluation")
		r.Output, r.Status = virtualExpr(args)
		return r
	case "getconf":
		return w.virtualGetconf(args)
	case "shutdown", "reboot", "poweroff", "halt":
		r := base("system", 6, 96, "system-control", "system power control requested")
		if w.user != "root" {
			r.Output, r.Status = cmd+": must be superuser.", 1
			return r
		}
		r.Output = "Broadcast message from root@" + w.hostname + " (pts/0):\n\nThe system will power off now!"
		if cmd == "reboot" {
			r.Output = "Broadcast message from root@" + w.hostname + " (pts/0):\n\nThe system will reboot now!"
		}
		r.Exit = true
		return r
	case "htop":
		if !w.packageInstalled("htop") {
			return virtualSSHResult{Output: "bash: htop: command not found", Status: 127, Family: "software", CommandName: "htop", Depth: 4, Risk: 84, Persona: "tool-discovery", Message: "missing package command"}
		}
		r := base("recon", 4, 86, "system-recon", "interactive process monitor")
		r.Interactive = "top"
		return r
	case "bash", "sh", "dash", "python", "python3", "perl", "php":
		if containsArg(args, "--version") || containsArg(args, "-V") || (cmd == "perl" && containsArg(args, "-v")) || (cmd == "php" && containsArg(args, "-v")) {
			return w.fakeInterpreterVersion(cmd)
		}
		if (cmd == "bash" || cmd == "sh" || cmd == "dash") && len(args) >= 2 && args[0] == "-c" {
			res := w.Execute(strings.Join(args[1:], " "))
			res.CommandName = cmd
			res.Family = "execution"
			res.Depth = maxInt(res.Depth, 6)
			res.Risk = maxInt(res.Risk, 98)
			res.Persona = "command-execution"
			res.Message = "simulated shell interpreter command"
			return res
		}
		if input != "" && (cmd == "bash" || cmd == "sh" || cmd == "dash") {
			return w.fakeExecute("stdin-script")
		}
		if len(args) > 0 {
			script := firstNonOption(args)
			if content, ok := w.virtualReadFile(script); ok && content != "" {
				return w.fakeExecute(script)
			}
			return w.fakeInterpreter(cmd, args)
		}
		r := base("shell", 5, 94, "execution", "secondary interpreter requested")
		r.Output = ""
		return r
	case "vim", "vi", "view":
		r := base("filesystem", 5, 93, "interactive-editor", "virtual Vim editor opened")
		if containsArg(args, "--version") {
			r.Output = "VIM - Vi IMproved 9.1 (2024 Jan 02, compiled Jul 11 2026 08:31:42)\nIncluded patches: 1-16, 647-703\nCompiled by buildd@lcy02-amd64-115"
			return r
		}
		r.Interactive = "vim"
		if file := lastNonOption(args); file != "" {
			r.Target = w.resolve(file)
		}
		return r
	case "nano":
		r := base("filesystem", 5, 92, "interactive-editor", "virtual nano editor opened")
		if containsArg(args, "--version") || containsArg(args, "-V") {
			r.Output = " GNU nano, version 7.2\n (C) 2023 the Free Software Foundation and various contributors"
			return r
		}
		r.Interactive = "nano"
		if file := lastNonOption(args); file != "" {
			r.Target = w.resolve(file)
		}
		return r
	case "jobs":
		r := base("execution", 4, 88, "process-control", "shell job listing")
		r.Output = w.virtualJobs()
		return r
	case "disown":
		r := base("persistence", 6, 98, "persistence", "background job detached")
		w.disownVirtual(args)
		r.Output = ""
		r.LoopInc = 1
		return r
	case "clear", "reset":
		r := base("shell", 2, 75, "interactive-shell", "terminal cleared")
		r.TerminalAction = "clear"
		return r
	case "help":
		r := base("shell", 2, 75, "interactive-shell", "shell help requested")
		r.Output = "GNU bash, version 5.2.21(1)-release (x86_64-pc-linux-gnu)\nThese shell commands are defined internally. Type `help' for this list."
		return r
	case "true":
		return base("other", 2, 70, "interactive-shell", "no-op")
	case "false":
		r := base("other", 2, 70, "interactive-shell", "false command")
		r.Status = 1
		return r
	default:
		if r, ok := w.executeExtraCommand(cmd, args, raw, input); ok {
			return r
		}
		r := base("other", maxInt(3, w.depth), 80, "interactive-shell", "unknown command")
		r.Status = 127
		r.Output = virtualCommandNotFound(cmd)
		return r
	}
}

func (w *virtualSSHWorld) fakeFind(raw string) string {
	low := strings.ToLower(raw)
	var rows []string
	switch {
	case strings.Contains(low, ".env"):
		rows = []string{"/opt/app/.env", "/opt/app/current/.env.production", "/var/lib/backup/.env"}
	case strings.Contains(low, "id_rsa") || strings.Contains(low, "id_ed25519") || strings.Contains(low, ".ssh"):
		rows = []string{"/root/.ssh", "/root/.ssh/config", "/root/.ssh/id_ed25519_backup", "/home/admin/.ssh"}
	case strings.Contains(low, "*.conf") || strings.Contains(low, ".conf"):
		rows = []string{"/etc/ssh/sshd_config", "/opt/backup/backup.conf", "/etc/systemd/system/backup-agent.service"}
	case strings.Contains(low, "-4000") || strings.Contains(low, "-perm"):
		rows = []string{"/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/mount", "/usr/local/bin/backupctl"}
	case strings.Contains(low, "backup"):
		rows = []string{"/opt/backup", "/opt/backup/backup.conf", "/srv/archive/nightly", "/srv/archive/nightly/config-prod.tar.gz"}
	default:
		for p := range w.files {
			rows = append(rows, p)
		}
		sort.Strings(rows)
		if len(rows) > 40 {
			rows = rows[:40]
		}
	}
	return strings.Join(rows, "\n")
}

func (w *virtualSSHWorld) fakeCurl(args []string) virtualSSHResult {
	r := virtualSSHResult{CommandName: "curl", Family: "download", Depth: 6, Risk: 98, Persona: "downloader", Message: "simulated curl/download request", LoopInc: 1, Delay: 250 * time.Millisecond}
	if containsArg(args, "--version") || containsArg(args, "-V") {
		r.Family, r.Depth, r.Risk, r.Persona, r.LoopInc, r.Delay = "recon", 3, 82, "tool-discovery", 0, 0
		r.Output = "curl 8.5.0 (x86_64-pc-linux-gnu) libcurl/8.5.0 OpenSSL/3.0.13 zlib/1.3 brotli/1.1.0 zstd/1.5.5 libidn2/2.3.7 libssh/0.10.6 nghttp2/1.59.0\nRelease-Date: 2023-12-06\nProtocols: dict file ftp ftps gopher gophers http https imap imaps ipfs ipns mqtt pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp"
		return r
	}
	url := lastURLLike(args)
	if url == "" {
		r.Output, r.Status = "curl: try 'curl --help' or 'curl --manual' for more information", 2
		return r
	}
	internal := strings.Contains(url, "127.0.0.1:8081") || strings.Contains(url, "db-internal") || strings.Contains(url, "10.10.30.12") || strings.Contains(url, "backup-01")
	payload := w.virtualPayloadForURL(url)
	if internal {
		payload = virtualDownloadPayload{Body: "{\"status\":\"ok\",\"service\":\"internal-platform\",\"node\":\"" + w.hostname + "\",\"backup\":\"10.10.30.12\"}\n", ContentType: "application/json", Kind: "json", Binary: false}
		payload.Size = int64(len(payload.Body))
		if (containsArg(args, "-X") && strings.EqualFold(optionValue(args, "-X", "--request"), "POST")) || optionValue(args, "-d", "--data", "--data-raw") != "" {
			payload.Body = "{\"accepted\":true,\"job\":\"migration-sync-1842\",\"node\":\"backup-01\"}\n"
			payload.Size = int64(len(payload.Body))
		}
		r.Persona, r.Depth, r.Risk = "internal-discovery", 7, 99
	}
	if containsArg(args, "-I") || containsArg(args, "--head") {
		r.Output = virtualDownloadHeaders(w.system.snapshot().Now, payload, internal)
		return r
	}

	outFile := optionValue(args, "-o", "--output")
	if outFile == "" && containsArg(args, "-O") {
		outFile = payload.Filename
	}
	forceStdout := outFile == "-"
	if outFile != "" && outFile != "-" && outFile != "/dev/null" {
		if !w.storeDownloadedVirtualFile(outFile, payload) {
			r.Output, r.Status = "curl: (23) Failed writing body (No space left on device)", 23
			return r
		}
		if !containsArg(args, "-s") && !containsArg(args, "--silent") && !containsArg(args, "-S") {
			r.Output = virtualCurlProgress(payload.Size)
		}
		return r
	}
	if outFile == "/dev/null" {
		if format := optionValue(args, "-w", "--write-out"); format != "" {
			r.Output = strings.NewReplacer("%{http_code}", "200", "%{remote_ip}", "10.10.30.12", "%{time_total}", "0.013482", "%{size_download}", fmt.Sprintf("%d", payload.Size), "%{content_type}", payload.ContentType).Replace(format)
		}
		return r
	}
	if payload.Binary && !forceStdout {
		r.Output = virtualBinaryTerminalWarning()
		return r
	}
	r.Output = payload.Body
	if format := optionValue(args, "-w", "--write-out"); format != "" {
		r.Output += strings.NewReplacer("%{http_code}", "200", "%{remote_ip}", "185.199.110.153", "%{time_total}", "0.041822", "%{size_download}", fmt.Sprintf("%d", payload.Size), "%{content_type}", payload.ContentType).Replace(format)
	}
	return r
}

func (w *virtualSSHWorld) fakeWget(args []string) virtualSSHResult {
	r := virtualSSHResult{CommandName: "wget", Family: "download", Depth: 6, Risk: 98, Persona: "downloader", Message: "simulated wget/download request", LoopInc: 1, Delay: 350 * time.Millisecond}
	if containsArg(args, "--version") || containsArg(args, "-V") {
		r.Family, r.Depth, r.Risk, r.Persona, r.LoopInc, r.Delay = "recon", 3, 82, "tool-discovery", 0, 0
		r.Output = "GNU Wget 1.21.4 built on linux-gnu.\n+https +ipv6 +iri +large-file -metalink +nls +ntlm +opie +psl +ssl/openssl"
		return r
	}
	url := lastURLLike(args)
	if url == "" {
		r.Output, r.Status = "wget: missing URL\nUsage: wget [OPTION]... [URL]...", 1
		return r
	}
	payload := w.virtualPayloadForURL(url)
	name, stdoutOnly := virtualWgetDestination(args, url)
	if stdoutOnly {
		r.Output = payload.Body
		return r
	}
	if !w.storeDownloadedVirtualFile(name, payload) {
		r.Output, r.Status = name+": No space left on device", 1
		return r
	}
	if containsArg(args, "-q") || containsCombinedFlag(args, 'q') {
		return r
	}
	now := w.system.snapshot().Now
	host := hostFromVirtualURL(url)
	protoPort := "443"
	if strings.HasPrefix(strings.ToLower(url), "http://") {
		protoPort = "80"
	}
	r.Output = fmt.Sprintf("--%s--  %s\nResolving %s... 185.199.110.153\nConnecting to %s|185.199.110.153|:%s... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: %s [%s]\nSaving to: '%s'\n\n%s             100%%[===================>]   %s  --.-KB/s\n\n%s (12.8 MB/s) - '%s' saved [%d/%d]", now.Format("2006-01-02 15:04:05"), url, host, host, protoPort, virtualWgetLength(payload.Size), payload.ContentType, name, name, virtualWgetLength(payload.Size), now.Add(time.Second).Format("2006-01-02 15:04:05"), name, payload.Size, payload.Size)
	return r
}

func (w *virtualSSHWorld) fakeNestedSSH(args []string) virtualSSHResult {
	r := virtualSSHResult{CommandName: "ssh", Family: "lateral", Depth: 7, Risk: 100, Persona: "lateral-movement", Message: "simulated lateral SSH movement", LoopInc: 1, Delay: 500 * time.Millisecond}
	if containsArg(args, "-V") {
		r.Family, r.Depth, r.Risk, r.Persona, r.LoopInc, r.Delay = "recon", 3, 82, "tool-discovery", 0, 0
		r.Output = "OpenSSH_9.6p1 Ubuntu-3ubuntu13.13, OpenSSL 3.0.13 30 Jan 2024"
		return r
	}
	target, targetIndex := sshDestinationWithIndex(args)
	if target == "" {
		r.Output, r.Status = "usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] destination [command [argument ...]]", 255
		return r
	}
	user, host := "", target
	if i := strings.LastIndex(target, "@"); i >= 0 {
		user, host = target[:i], target[i+1:]
	}
	host = strings.Trim(host, "[]")
	h, ok := lures.Resolve(host)
	if !ok {
		r.Output, r.Status = "ssh: connect to host "+host+" port 22: Connection timed out", 255
		return r
	}
	if h.Role == "database" || h.Role == "cache" || h.Role == "registry" {
		r.Output, r.Status = "ssh: connect to host "+host+" port 22: Connection refused", 255
		return r
	}
	if user == "" {
		switch h.Role {
		case "backup":
			user = "svc-backup"
		case "git":
			user = "git"
		default:
			user = "admin"
		}
	}
	remoteCWD := "/home/" + safeVirtualName(user)
	if user == "root" {
		remoteCWD = "/root"
	}
	switch h.Role {
	case "backup":
		remoteCWD = "/var/lib/backup"
	case "git":
		remoteCWD = "/srv/git"
		_ = w.setVirtualDir("/srv/git")
		_ = w.setVirtualFile("/srv/git/README", "Git service account. Interactive access is restricted.\nRepositories: platform/web platform/worker ops/backup-agent\n")
	case "operations":
		remoteCWD = "/home/admin"
	}

	remoteCommand := ""
	if targetIndex >= 0 && targetIndex+1 < len(args) {
		remoteCommand = strings.Join(args[targetIndex+1:], " ")
	}
	if remoteCommand != "" {
		ctx := virtualSSHContext{user: w.user, hostname: w.hostname, cwd: w.cwd}
		oldEnvUser, oldEnvLog, oldEnvHome, oldEnvPWD, oldEnvHost := w.env["USER"], w.env["LOGNAME"], w.env["HOME"], w.env["PWD"], w.env["HOSTNAME"]
		w.user, w.hostname, w.cwd = safeVirtualName(user), h.Name, remoteCWD
		w.env["USER"], w.env["LOGNAME"], w.env["HOME"], w.env["PWD"], w.env["HOSTNAME"] = w.user, w.user, w.homeDir(), w.cwd, w.hostname
		remote := w.Execute(remoteCommand)
		w.user, w.hostname, w.cwd = ctx.user, ctx.hostname, ctx.cwd
		w.env["USER"], w.env["LOGNAME"], w.env["HOME"], w.env["PWD"], w.env["HOSTNAME"] = oldEnvUser, oldEnvLog, oldEnvHome, oldEnvPWD, oldEnvHost
		r.Output, r.Status = remote.Output, remote.Status
		if r.Output == "" && remoteCommand == "id" {
			r.Output = "uid=998(" + safeVirtualName(user) + ") gid=998(" + safeVirtualName(user) + ") groups=998(" + safeVirtualName(user) + ")"
		}
		return r
	}

	w.nested = append(w.nested, virtualSSHContext{user: w.user, hostname: w.hostname, cwd: w.cwd})
	w.user, w.hostname, w.cwd = safeVirtualName(user), h.Name, remoteCWD
	w.env["USER"], w.env["LOGNAME"], w.env["HOME"], w.env["PWD"], w.env["HOSTNAME"] = w.user, w.user, w.homeDir(), w.cwd, w.hostname
	_ = w.setVirtualDir(remoteCWD)
	lastLogin := w.system.snapshot().Now.Add(-2*time.Hour - 3*time.Minute)
	version := "Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-139-generic x86_64)"
	if h.Role == "operations" {
		version = virtualOSName + " (GNU/Linux " + virtualKernelRelease + " " + virtualMachineArch + ")"
	}
	r.Output = "Warning: Permanently added '" + host + "' (ED25519) to the list of known hosts.\nWelcome to " + version + "\nLast login: " + lastLogin.Format("Mon Jan _2 15:04:05 2006") + " from 10.10.30.21"
	return r
}

func (w *virtualSSHWorld) fakeExecute(target string) virtualSSHResult {
	word := strings.Fields(target)
	name := target
	if len(word) > 0 {
		name = word[0]
	}
	resolved := w.resolve(name)
	r := virtualSSHResult{CommandName: path.Base(name), Family: "execution", Depth: 6, Risk: 100, Persona: "payload-execution", Message: "simulated payload execution", LoopInc: 1, Delay: 400 * time.Millisecond}
	if w.isVirtualPayloadStagingPath(resolved) {
		if _, ok := w.virtualReadFile(resolved); ok {
			p := w.ensureVirtualPayloadProcess(resolved)
			r.Output = ""
			r.Message = "virtual staged payload started"
			r.PayloadStage = "executed"
			r.PayloadPath = resolved
			if p != nil {
				r.Delay = 250 * time.Millisecond
			}
			return r
		}
	}
	r.Output = "[+] checking architecture\n[+] installing service\n[+] registering worker\n[+] starting worker\n[+] done"
	return r
}

func (w *virtualSSHWorld) isVirtualPayloadStagingPath(target string) bool {
	target = path.Clean(target)
	if !(strings.HasPrefix(target, "/dev/shm/") || strings.HasPrefix(target, "/tmp/") || strings.HasPrefix(target, "/var/tmp/")) {
		return false
	}
	base := path.Base(target)
	return base != "" && base != "." && base != ".."
}

func (w *virtualSSHWorld) setVirtualDir(target string) bool {
	if w.dirs[target] {
		return true
	}
	if len(w.dirs) >= maxVirtualDirs {
		return false
	}
	w.dirs[target] = true
	return true
}

func (w *virtualSSHWorld) setVirtualFile(target, content string) bool {
	target = path.Clean(target)
	if w.virtualFileImmutable(target) {
		return false
	}
	if _, exists := w.files[target]; !exists && len(w.files) >= maxVirtualFiles {
		return false
	}
	stored := limitVirtualContent(content)
	if !w.canStoreVirtualContent(target, stored) {
		return false
	}
	w.files[target] = stored
	now := w.system.snapshot().Now
	w.fileMeta[target] = virtualFileMeta{Size: int64(len(content)), ModTime: now, Kind: inferVirtualFileKind(target, stored)}
	if w.fileModes[target] == 0 {
		w.fileModes[target] = 0o644
	}
	return true
}

func (w *virtualSSHWorld) appendVirtualFile(target, content string) bool {
	target = path.Clean(target)
	if w.virtualFileImmutable(target) {
		return false
	}
	old, exists := w.files[target]
	if !exists && len(w.files) >= maxVirtualFiles {
		return false
	}
	combined := old + content
	stored := limitVirtualContent(combined)
	if !w.canStoreVirtualContent(target, stored) {
		return false
	}
	w.files[target] = stored
	now := w.system.snapshot().Now
	w.fileMeta[target] = virtualFileMeta{Size: int64(len(combined)), ModTime: now, Kind: inferVirtualFileKind(target, stored)}
	if w.fileModes[target] == 0 {
		w.fileModes[target] = 0o644
	}
	return true
}

func (w *virtualSSHWorld) canStoreVirtualContent(target, stored string) bool {
	current := len(w.files[target])
	total := w.virtualStorageBytes() - current + len(stored)
	return total <= maxVirtualTotalBytes
}

func (w *virtualSSHWorld) virtualStorageBytes() int {
	total := 0
	for _, v := range w.files {
		total += len(v)
	}
	return total
}

func (w *virtualSSHWorld) deleteVirtualFile(target string) {
	delete(w.files, target)
	delete(w.fileMeta, target)
	delete(w.fileModes, target)
	delete(w.fileAttrs, target)
}

func limitVirtualContent(v string) string {
	if len(v) <= maxVirtualFileBytes {
		return v
	}
	v = v[:maxVirtualFileBytes]
	for len(v) > 0 && !utf8.ValidString(v) {
		v = v[:len(v)-1]
	}
	return v
}

func (w *virtualSSHWorld) resolve(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || v == "." {
		return w.cwd
	}
	if v == "~" {
		return w.homeDir()
	}
	if strings.HasPrefix(v, "~/") {
		return path.Clean(path.Join(w.homeDir(), strings.TrimPrefix(v, "~/")))
	}
	if strings.HasPrefix(v, "/") {
		return path.Clean(v)
	}
	return path.Clean(path.Join(w.cwd, v))
}

func (w *virtualSSHWorld) listDir(target string, long, showAll bool) (string, int) {
	now := w.system.snapshot().Now
	if content, ok := w.files[target]; ok {
		if long {
			meta := w.fileMeta[target]
			if meta.Size == 0 {
				meta.Size = int64(len(content))
			}
			owner, group := virtualFileOwner(target)
			return fmt.Sprintf("%s 1 %-8s %-8s %8d %s %s", virtualModeString(w.virtualFileMode(target), false), owner, group, meta.Size, virtualLSDate(now, meta.ModTime), path.Base(target)), 0
		}
		return path.Base(target), 0
	}
	if !w.dirs[target] {
		return "ls: cannot access '" + target + "': No such file or directory", 2
	}
	seen := map[string]bool{}
	for d := range w.dirs {
		if d != target && path.Dir(d) == target {
			seen[path.Base(d)] = true
		}
	}
	for f := range w.files {
		if path.Dir(f) == target {
			seen[path.Base(f)] = false
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		if !showAll && strings.HasPrefix(n, ".") {
			continue
		}
		names = append(names, n)
	}
	sort.Strings(names)
	if !long {
		return strings.Join(names, "  "), 0
	}
	rows := []string{"total 48"}
	if showAll {
		owner, group := virtualFileOwner(target)
		parentOwner, parentGroup := virtualFileOwner(path.Dir(target))
		rows = append(rows,
			fmt.Sprintf("%s  5 %-8s %-8s %8d %s .", virtualModeString(virtualDirMode(target), true), owner, group, 4096, virtualLSDate(now, now.Add(-48*time.Hour))),
			fmt.Sprintf("%s 18 %-8s %-8s %8d %s ..", virtualModeString(virtualDirMode(path.Dir(target)), true), parentOwner, parentGroup, 4096, virtualLSDate(now, w.system.snapshot().BootTime.Add(3*time.Minute))),
		)
	}
	for _, n := range names {
		full := path.Join(target, n)
		if seen[n] {
			owner, group := virtualFileOwner(full)
			rows = append(rows, fmt.Sprintf("%s  3 %-8s %-8s %8d %s %s", virtualModeString(virtualDirMode(full), true), owner, group, 4096, virtualLSDate(now, now.Add(-time.Duration(2+stableSSHHash(full)%168)*time.Hour)), n))
		} else {
			meta := w.fileMeta[full]
			sz := meta.Size
			if sz == 0 {
				sz = int64(len(w.files[full]))
			}
			owner, group := virtualFileOwner(full)
			mode := virtualModeString(w.virtualFileMode(full), false)
			rows = append(rows, fmt.Sprintf("%s  1 %-8s %-8s %8d %s %s", mode, owner, group, sz, virtualLSDate(now, meta.ModTime), n))
		}
	}
	return strings.Join(rows, "\n"), 0
}

func containsArg(args []string, target string) bool {
	for _, a := range args {
		if a == target {
			return true
		}
	}
	return false
}

func containsArgPrefix(args []string, target string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, target) {
			return true
		}
	}
	return false
}

func virtualContentFileOperand(cmd string, args []string) string {
	var file string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if (cmd == "head" || cmd == "tail") && (a == "-n" || a == "--lines" || a == "-c" || a == "--bytes") {
			i++
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		file = a
	}
	return file
}

func lastNonOption(args []string) string {
	for i := len(args) - 1; i >= 0; i-- {
		if !strings.HasPrefix(args[i], "-") {
			return args[i]
		}
	}
	return ""
}

func lastURLLike(args []string) string {
	for i := len(args) - 1; i >= 0; i-- {
		if strings.Contains(args[i], "://") {
			return args[i]
		}
	}
	return ""
}

func optionValue(args []string, names ...string) string {
	for i, a := range args {
		for _, n := range names {
			if a == n && i+1 < len(args) {
				return args[i+1]
			}
		}
	}
	return ""
}

func grepVirtual(text, pattern string) string {
	if pattern == "" {
		return text
	}
	pattern = strings.ToLower(pattern)
	var rows []string
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(strings.ToLower(line), pattern) {
			rows = append(rows, line)
		}
	}
	return strings.Join(rows, "\n")
}

func firstLines(v string, n int) string {
	rows := strings.Split(v, "\n")
	if len(rows) > n {
		rows = rows[:n]
	}
	return strings.Join(rows, "\n")
}

func lastLines(v string, n int) string {
	rows := strings.Split(v, "\n")
	if len(rows) > n {
		rows = rows[len(rows)-n:]
	}
	return strings.Join(rows, "\n")
}

func hostFromVirtualURL(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.Index(v, "://"); i >= 0 {
		v = v[i+3:]
	}
	if i := strings.IndexAny(v, "/?"); i >= 0 {
		v = v[:i]
	}
	if h, _, ok := strings.Cut(v, ":"); ok {
		v = h
	}
	if v == "" {
		return "remote-host"
	}
	return v
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
