package server

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

type virtualSSHProcess struct {
	PID      int
	User     string
	Command  string
	Started  time.Time
	CPU      float64
	Mem      float64
	JobID    int
	Disowned bool
	Alive    bool
}

func (w *virtualSSHWorld) looksLikeStagedPayload(name string) bool {
	base := path.Base(strings.TrimSpace(name))
	if len(base) < 6 || len(base) > 16 || strings.Contains(base, ".") {
		return false
	}
	for _, r := range base {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return strings.HasPrefix(w.cwd, "/var/tmp") || strings.HasPrefix(w.cwd, "/tmp") || strings.HasPrefix(w.cwd, "/dev/shm")
}

func (w *virtualSSHWorld) ensureVirtualPayloadProcess(target string) *virtualSSHProcess {
	target = path.Clean(target)
	base := path.Base(target)
	for _, p := range w.processes {
		if p == nil || !p.Alive {
			continue
		}
		words := strings.Fields(p.Command)
		if len(words) > 0 && path.Base(words[0]) == base {
			return p
		}
	}
	p := w.startVirtualProcess(target, false)
	p.CPU = 68.4
	p.Mem = 2.7
	return p
}

func (w *virtualSSHWorld) startVirtualProcess(command string, asJob bool) *virtualSSHProcess {
	pid := 2841
	if w.shared != nil {
		pid = w.shared.nextPID
		if pid < 2000 {
			pid = 2841
		}
		w.shared.nextPID = pid + 1
	}
	p := &virtualSSHProcess{PID: pid, User: w.user, Command: strings.TrimSpace(command), Started: w.system.snapshot().Now, CPU: 172.4, Mem: 3.1, Alive: true}
	if asJob {
		p.JobID = w.nextJob
		w.nextJob++
		w.jobs[p.JobID] = pid
	}
	w.processes[pid] = p
	w.system.markActivity(5.5)
	return p
}

func (w *virtualSSHWorld) backgroundResult(command string, res virtualSSHResult) virtualSSHResult {
	low := strings.ToLower(command)
	if strings.Contains(low, "rm ") || strings.HasPrefix(strings.TrimSpace(low), "pkill ") || strings.HasPrefix(strings.TrimSpace(low), "killall ") {
		return res
	}
	words := virtualWords(command)
	if len(words) == 0 {
		return res
	}
	first := words[0]
	if strings.HasPrefix(first, "./") || strings.HasPrefix(first, "/tmp/") || strings.HasPrefix(first, "/var/tmp/") || strings.HasPrefix(first, "/dev/shm/") || first == "nohup" {
		var p *virtualSSHProcess
		if res.Message == "virtual staged payload started" && first != "nohup" {
			p = w.ensureVirtualPayloadProcess(w.resolve(first))
			if p.JobID == 0 {
				p.JobID = w.nextJob
				w.nextJob++
				w.jobs[p.JobID] = p.PID
			}
		} else {
			p = w.startVirtualProcess(command, true)
		}
		res.Output = fmt.Sprintf("[%d] %d", p.JobID, p.PID)
		res.Status = 0
		res.Family, res.Depth, res.Risk, res.Persona, res.Message = "execution", 7, 100, "payload-execution", "virtual background payload started"
		res.LoopInc++
	}
	return res
}

func (w *virtualSSHWorld) virtualJobs() string {
	ids := make([]int, 0, len(w.jobs))
	for id := range w.jobs {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	var lines []string
	for _, id := range ids {
		pid := w.jobs[id]
		p := w.processes[pid]
		if p == nil || !p.Alive || p.Disowned {
			continue
		}
		lines = append(lines, fmt.Sprintf("[%d]+  Running                 %s &", id, strings.TrimSpace(p.Command)))
	}
	return strings.Join(lines, "\n")
}

func (w *virtualSSHWorld) disownVirtual(args []string) {
	if len(args) == 0 {
		maxID := 0
		for id := range w.jobs {
			if id > maxID {
				maxID = id
			}
		}
		if maxID > 0 {
			if p := w.processes[w.jobs[maxID]]; p != nil {
				p.Disowned = true
			}
			delete(w.jobs, maxID)
		}
		return
	}
	for _, a := range args {
		a = strings.TrimPrefix(a, "%")
		id, _ := strconv.Atoi(a)
		if id <= 0 {
			continue
		}
		if p := w.processes[w.jobs[id]]; p != nil {
			p.Disowned = true
		}
		delete(w.jobs, id)
	}
}

func (w *virtualSSHWorld) killVirtualProcesses(pattern string) bool {
	pattern = strings.ToLower(path.Base(strings.TrimSpace(pattern)))
	if pattern == "" {
		return false
	}
	matched := false
	for _, p := range w.processes {
		if !p.Alive {
			continue
		}
		cmd := strings.ToLower(p.Command)
		if strings.Contains(cmd, pattern) {
			p.Alive = false
			matched = true
			if p.JobID > 0 {
				delete(w.jobs, p.JobID)
			}
		}
	}
	// Seeded competing miners are intentionally plausible cleanup targets.
	if pattern == "xmrig" || pattern == "cnrig" || pattern == "java" || pattern == "opera" {
		matched = true
	}
	return matched
}

func (w *virtualSSHWorld) dynamicProcessLines() string {
	var pids []int
	for pid, p := range w.processes {
		if p.Alive {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)
	var b strings.Builder
	for _, pid := range pids {
		p := w.processes[pid]
		age := w.system.snapshot().Now.Sub(p.Started)
		cpu := p.CPU
		if age > time.Minute {
			cpu = 245.1
		}
		fmt.Fprintf(&b, "\n%-11s %5d %5.1f %4.1f 925432 251020 ?       Rsl  %s   0:%02d %s", p.User, p.PID, cpu, p.Mem, p.Started.Format("15:04"), int(age.Seconds())%60, p.Command)
	}
	return b.String()
}

func (w *virtualSSHWorld) removeVirtualPattern(raw string) bool {
	resolved := w.resolve(raw)
	removed := false
	if !strings.ContainsAny(resolved, "*?") {
		if _, ok := w.files[resolved]; ok {
			if w.virtualFileImmutable(resolved) {
				return false
			}
			w.deleteVirtualFile(resolved)
			removed = true
		}
		prefix := strings.TrimSuffix(resolved, "/") + "/"
		for f := range w.files {
			if strings.HasPrefix(f, prefix) && !w.virtualFileImmutable(f) {
				w.deleteVirtualFile(f)
				removed = true
			}
		}
		for d := range w.dirs {
			if d == resolved || strings.HasPrefix(d, prefix) {
				delete(w.dirs, d)
				removed = true
			}
		}
		return removed
	}
	for f := range w.files {
		if ok, _ := path.Match(resolved, f); ok && !w.virtualFileImmutable(f) {
			w.deleteVirtualFile(f)
			removed = true
		}
	}
	for d := range w.dirs {
		if ok, _ := path.Match(resolved, d); ok {
			delete(w.dirs, d)
			removed = true
		}
	}
	return removed
}

func (w *virtualSSHWorld) seedDropperExecutionTargets(command string) {
	// Only called after a multi-signal miner/dropper cleanup sequence was
	// recognized. If that sequence later chmods/executes a local ./name, seed the
	// expected pre-existing staged artifact in the selected temporary directory.
	baseDir := w.cwd
	for _, candidate := range []string{"/dev/shm", "/var/tmp", "/tmp"} {
		if strings.Contains(command, "cd "+candidate) || strings.Contains(command, "cd "+candidate+"/") {
			baseDir = candidate
			break
		}
	}
	for offset := 0; ; {
		i := strings.Index(command[offset:], "./")
		if i < 0 {
			break
		}
		i += offset + 2
		j := i
		for j < len(command) {
			c := command[j]
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' {
				j++
				continue
			}
			break
		}
		if j > i {
			name := command[i:j]
			if name != "." && name != ".." && len(name) <= 48 {
				target := path.Join(baseDir, name)
				if _, exists := w.files[target]; !exists {
					_ = w.setVirtualFile(target, "\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00GLIBC_2.34\x00worker\n")
					w.fileModes[target] = 0o644
				}
			}
		}
		offset = j
		if offset <= i {
			offset = i + 1
		}
	}
}

func (w *virtualSSHWorld) seedMinerCleanupLures() {
	for _, d := range []string{"/var/tmp/Documents", "/var/tmp/.update-logs"} {
		_ = w.setVirtualDir(d)
	}
	for _, f := range []string{"/dev/shm/.x", "/dev/shm/rete.lock", "/tmp/.diicot", "/var/tmp/xmrig", "/var/tmp/.black", "/var/tmp/Documents/.diicot", "/var/tmp/.update-logs/History", "/var/tmp/.update-logs/Update"} {
		if _, ok := w.files[f]; !ok {
			_ = w.setVirtualFile(f, "\x7fELF\x02\x01\x01legacy-worker\n")
		}
	}
}

func virtualStaticPID(pid int) bool {
	switch pid {
	case 1, 581, 612, 844, 901, 932, 1021, 1102, 1842:
		return true
	default:
		return false
	}
}

func (w *virtualSSHWorld) virtualProcExe(pid int) (string, bool) {
	if p := w.processes[pid]; p != nil && p.Alive {
		words := virtualWords(p.Command)
		if len(words) > 0 {
			cmd := words[0]
			if strings.HasPrefix(cmd, "/") {
				return cmd, true
			}
			return w.resolve(cmd), true
		}
	}
	switch pid {
	case 1:
		return "/usr/lib/systemd/systemd", true
	case 581:
		return "/usr/lib/systemd/systemd-logind", true
	case 612:
		return "/usr/sbin/sshd", true
	case 844:
		return "/opt/app/current/web", true
	case 901:
		return "/usr/lib/postgresql/16/bin/postgres", true
	case 932:
		return "/usr/bin/redis-server", true
	case 1021:
		return "/usr/bin/dockerd", true
	case 1102:
		return "/usr/bin/docker-proxy", true
	case 1842:
		return "/usr/local/bin/backup-agent", true
	default:
		return "", false
	}
}

func (w *virtualSSHWorld) virtualProcessCount() int {
	n := 143
	for _, p := range w.processes {
		if p != nil && p.Alive {
			n++
		}
	}
	return n
}

func (w *virtualSSHWorld) virtualProcessPIDsByName(name string) []int {
	name = path.Base(strings.TrimSpace(name))
	if name == "" {
		return nil
	}
	static := map[string][]int{
		"systemd": {1}, "init": {1}, "sshd": {612}, "web": {844}, "postgres": {901},
		"redis-server": {932}, "dockerd": {1021}, "docker-proxy": {1102}, "backup-agent": {1842},
	}
	out := append([]int(nil), static[name]...)
	for pid, p := range w.processes {
		if p == nil || !p.Alive {
			continue
		}
		fields := strings.Fields(p.Command)
		if len(fields) == 0 {
			continue
		}
		if path.Base(fields[0]) == name {
			out = append(out, pid)
		}
	}
	sort.Ints(out)
	return out
}
