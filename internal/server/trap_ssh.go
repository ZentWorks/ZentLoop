package server

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"

	"zentloop/internal/config"
	"zentloop/internal/model"
	"zentloop/internal/store"
)

// TrapSSH is a fully simulated SSH service. It never starts an operating-system
// shell, executes attacker commands, opens outbound network connections or
// exposes the container filesystem. Every accepted session lives in an
// in-memory virtual world owned by that SSH channel.
type TrapSSH struct {
	cfg      config.Config
	store    *store.Store
	listener net.Listener
	signer   ssh.Signer
	geo      *geoResolver
	system   *virtualSSHSystem
	sem      chan struct{}
	mu       sync.Mutex
	perIP    map[string]int
	close    sync.Once
}

type sshAuthState struct {
	sessionID     string
	ip            string
	country       string
	countrySource string
	attempts      int
}

func NewTrapSSH(cfg config.Config, st *store.Store) (*TrapSSH, error) {
	signer, err := loadOrCreateSSHHostSigner(cfg.SSHHostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("SSH trap host key: %w", err)
	}
	ln, err := net.Listen("tcp", cfg.SSHAddr)
	if err != nil {
		return nil, err
	}
	return &TrapSSH{
		cfg: cfg, store: st, listener: ln, signer: signer, geo: newGeoResolver(cfg.GeoIPDB), system: loadVirtualSSHSystem(cfg.DataDir),
		sem: make(chan struct{}, cfg.SSHMaxConcurrent), perIP: make(map[string]int),
	}, nil
}

func (s *TrapSSH) Addr() net.Addr { return s.listener.Addr() }

func (s *TrapSSH) Serve() error {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.acceptConn(conn)
	}
}

func (s *TrapSSH) Close() error {
	var err error
	s.close.Do(func() { err = s.listener.Close() })
	return err
}

func (s *TrapSSH) acceptConn(conn net.Conn) {
	ip := remoteIP(conn.RemoteAddr().String())
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		s.store.RecordHealth("ssh_rejected_global")
		_ = conn.Close()
		return
	}
	if !s.acquireIP(ip) {
		s.store.RecordHealth("ssh_rejected_per_ip")
		_ = conn.Close()
		return
	}
	defer s.releaseIP(ip)

	sessionID := newID(16)
	country, countrySource := s.geo.country(ip)
	base := model.SSHEvent{ID: newID(6), At: time.Now(), SessionID: sessionID, IP: ip, Country: country, CountrySource: countrySource, Type: "connect", RiskScore: 25, Classification: model.ClassSuspicious, Actor: model.ActorUnknown, Message: "SSH connection opened"}
	if err := s.store.AddSSHEvent(base); err != nil {
		log.Printf("SSH event store: %v", err)
	}
	s.handleConn(conn, sshAuthState{sessionID: sessionID, ip: ip, country: country, countrySource: countrySource})
}

func (s *TrapSSH) acquireIP(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perIP[ip] >= s.cfg.SSHMaxPerIP {
		return false
	}
	s.perIP[ip]++
	return true
}

func (s *TrapSSH) releaseIP(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perIP[ip] <= 1 {
		delete(s.perIP, ip)
		return
	}
	s.perIP[ip]--
}

func (s *TrapSSH) handleConn(conn net.Conn, auth sshAuthState) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))

	algorithms := ssh.SupportedAlgorithms()
	sshCfg := &ssh.ServerConfig{
		Config:                  ssh.Config{KeyExchanges: algorithms.KeyExchanges, Ciphers: algorithms.Ciphers, MACs: algorithms.MACs},
		PublicKeyAuthAlgorithms: algorithms.PublicKeyAuths,
		ServerVersion:           "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.13",
		MaxAuthTries:            s.cfg.SSHMaxAuthTries,
	}
	sshCfg.AddHostKey(s.signer)
	sshCfg.PasswordCallback = func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		auth.attempts++
		user := cleanSSHField(meta.User(), 64)
		client := cleanSSHField(string(meta.ClientVersion()), 128)
		accept := shouldAcceptTrapPassword(auth.ip, user, password, auth.attempts, s.cfg.SSHMaxAuthTries)
		if !accept && shouldAcceptRecurringProbe(s.store.SSHRecurrence(auth.ip, time.Now()), auth.ip, user, password, auth.attempts) {
			accept = true
		}
		s.recordSSHAuth(auth, client, user, "password", accept, len(password), "")
		if accept {
			return nil, nil
		}
		return nil, errors.New("permission denied")
	}
	sshCfg.PublicKeyCallback = func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		auth.attempts++
		user := cleanSSHField(meta.User(), 64)
		client := cleanSSHField(string(meta.ClientVersion()), 128)
		fingerprint := ssh.FingerprintSHA256(key)
		s.recordSSHAuth(auth, client, user, "publickey", false, 0, fingerprint)
		return nil, errors.New("permission denied")
	}
	sshCfg.KeyboardInteractiveCallback = func(meta ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		auth.attempts++
		user := cleanSSHField(meta.User(), 64)
		client := cleanSSHField(string(meta.ClientVersion()), 128)
		answers, err := challenge("", "Password authentication", []string{"Password: "}, []bool{false})
		if err != nil || len(answers) != 1 {
			s.recordSSHAuth(auth, client, user, "keyboard-interactive", false, 0, "")
			return nil, errors.New("permission denied")
		}
		password := []byte(answers[0])
		accept := shouldAcceptTrapPassword(auth.ip, user, password, auth.attempts, s.cfg.SSHMaxAuthTries)
		if !accept && shouldAcceptRecurringProbe(s.store.SSHRecurrence(auth.ip, time.Now()), auth.ip, user, password, auth.attempts) {
			accept = true
		}
		s.recordSSHAuth(auth, client, user, "keyboard-interactive", accept, len(password), "")
		for i := range answers {
			answers[i] = ""
		}
		if accept {
			return nil, nil
		}
		return nil, errors.New("permission denied")
	}

	serverConn, channels, requests, err := ssh.NewServerConn(conn, sshCfg)
	if err != nil {
		base := model.SSHEvent{SessionID: auth.sessionID, IP: auth.ip, Country: auth.country, CountrySource: auth.countrySource}
		s.recordSSHEvent(base, "handshake_error", "", "", "", "SSH handshake/authentication ended", 45, 0, 0, 0, model.ActorAutomated)
		return
	}
	defer serverConn.Close()
	_ = conn.SetDeadline(time.Time{})
	maxSessionTimer := time.AfterFunc(time.Duration(s.cfg.SSHMaxSessionMinutes)*time.Minute, func() { _ = conn.Close() })
	defer maxSessionTimer.Stop()
	client := cleanSSHField(string(serverConn.ClientVersion()), 128)
	user := cleanSSHField(serverConn.User(), 64)
	actor := classifySSHActor(client, false)
	base := model.SSHEvent{SessionID: auth.sessionID, IP: auth.ip, Country: auth.country, CountrySource: auth.countrySource, ClientVersion: client, Username: user}

	go s.handleGlobalSSHRequests(base, requests)
	for ch := range channels {
		if ch.ChannelType() != "session" {
			_ = ch.Reject(ssh.Prohibited, "administratively prohibited")
			s.recordSSHEvent(base, "request", "channel", "protocol", "", "non-session channel rejected: "+cleanSSHField(ch.ChannelType(), 64), 75, 3, 0, 0, actor)
			continue
		}
		channel, reqs, err := ch.Accept()
		if err != nil {
			continue
		}
		go s.handleTrapSSHSession(conn, channel, reqs, base)
	}
	s.recordSSHEvent(base, "disconnect", "", "", "", "SSH connection closed", 70, 0, 0, 0, actor)
}

func (s *TrapSSH) handleGlobalSSHRequests(base model.SSHEvent, requests <-chan *ssh.Request) {
	for req := range requests {
		ok := req.Type == "keepalive@openssh.com"
		replySSHRequest(req, ok)
		if !ok {
			s.recordSSHEvent(base, "request", "forwarding", "network", "", "SSH global request rejected: "+cleanSSHField(req.Type, 64), 90, 6, 0, 1, model.ActorAutomated)
		}
	}
}

func (s *TrapSSH) handleTrapSSHSession(conn net.Conn, channel ssh.Channel, requests <-chan *ssh.Request, base model.SSHEvent) {
	defer channel.Close()
	world := newVirtualSSHWorldForSource(base.SessionID, base.Username, base.IP, s.system)
	started := false
	done := make(chan struct{}, 1)
	for {
		select {
		case req, ok := <-requests:
			if !ok {
				return
			}
			switch req.Type {
			case "pty-req":
				var pty struct {
					Term    string
					Columns uint32
					Rows    uint32
					Width   uint32
					Height  uint32
					Modes   string
				}
				if !started && ssh.Unmarshal(req.Payload, &pty) == nil {
					world.setVirtualTTY(cleanSSHField(pty.Term, 64), int(pty.Columns), int(pty.Rows))
				}
				replySSHRequest(req, true)
			case "window-change":
				var win struct {
					Columns uint32
					Rows    uint32
					Width   uint32
					Height  uint32
				}
				if ssh.Unmarshal(req.Payload, &win) == nil {
					world.setVirtualTTY("", int(win.Columns), int(win.Rows))
				}
				replySSHRequest(req, true)
			case "env":
				var envReq struct{ Name, Value string }
				if !started && ssh.Unmarshal(req.Payload, &envReq) == nil {
					world.setVirtualEnv(cleanSSHField(envReq.Name, 64), cleanSSHField(envReq.Value, 256))
				}
				replySSHRequest(req, true)
			case "shell":
				if started {
					replySSHRequest(req, false)
					continue
				}
				started = true
				replySSHRequest(req, true)
				s.recordSSHEvent(base, "shell", "shell", "interactive", world.cwd, "interactive virtual shell opened", 82, 2, 0, 0, classifySSHActor(base.ClientVersion, true))
				go func() {
					s.runVirtualSSHShell(conn, channel, base, world)
					_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					done <- struct{}{}
				}()
			case "exec":
				if started {
					replySSHRequest(req, false)
					continue
				}
				started = true
				var payload struct{ Command string }
				if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
					replySSHRequest(req, false)
					return
				}
				replySSHRequest(req, true)
				command := cleanSSHCommand(payload.Command, maxSSHExecCommandBytes)
				world.addHistory(command)
				var stdin []byte
				var stdinTruncated bool
				if commandMayConsumeExecStdin(command) {
					stdin, stdinTruncated = readVirtualExecStdin(channel)
				}
				result := world.ExecuteWithInput(command, string(stdin))
				annotateVirtualExecStdin(&result, stdin, stdinTruncated)
				switch result.Interactive {
				case "ping":
					result.Output = virtualPingBatchOutput(result.Target, result.StreamCount)
					result.Interactive = ""
				case "traceroute":
					result.Output = virtualTracerouteBatchOutput(result.Target)
					result.Interactive = ""
				case "":
				default:
					result.Status = 1
					result.Output = firstNonEmpty(result.Output, result.CommandName+": Warning: Input is not from a terminal")
				}
				if result.Delay > 0 {
					time.Sleep(result.Delay)
				}
				if result.Output != "" {
					_, _ = fmt.Fprint(channel, normalizeSSHOutput(result.Output))
				}
				s.recordSSHCommand(base, "exec", command, world, result, model.ActorAutomated)
				_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(result.Status)}))
				return
			case "subsystem":
				replySSHRequest(req, false)
				s.recordSSHEvent(base, "request", "subsystem", "file-transfer", "", "subsystem/SFTP rejected", 88, 5, 0, 1, model.ActorAutomated)
			case "auth-agent-req@openssh.com", "x11-req":
				replySSHRequest(req, false)
				s.recordSSHEvent(base, "request", "forwarding", "network", "", "forwarding request rejected: "+cleanSSHField(req.Type, 64), 90, 6, 0, 1, model.ActorAutomated)
			default:
				replySSHRequest(req, false)
			}
		case <-done:
			return
		}
	}
}

func (s *TrapSSH) runVirtualSSHShell(conn net.Conn, channel ssh.Channel, base model.SSHEvent, world *virtualSSHWorld) {
	_, _ = fmt.Fprint(channel, world.Banner())
	reader := newVirtualSSHLineReader(channel, world)
	reader.SetReadActivity(func() {
		_ = conn.SetReadDeadline(time.Now().Add(time.Duration(s.cfg.SSHIdleSeconds) * time.Second))
	})
	for {
		_ = conn.SetReadDeadline(time.Now().Add(time.Duration(s.cfg.SSHIdleSeconds) * time.Second))
		prompt := world.Prompt()
		_, _ = fmt.Fprint(channel, prompt)
		line, err := reader.ReadLine(channel, prompt, 2048)
		if err != nil {
			return
		}
		command := cleanSSHCommand(line, maxSSHInteractiveCommandBytes)
		if strings.TrimSpace(command) == "" {
			continue
		}
		world.addHistory(command)
		result := world.Execute(command)
		if result.Delay > 0 {
			time.Sleep(result.Delay)
		}
		if result.TerminalAction == "clear" {
			_, _ = fmt.Fprint(channel, "\x1b[2J\x1b[H")
		}
		if result.Output != "" {
			_, _ = fmt.Fprint(channel, normalizeSSHOutput(result.Output))
		}
		s.recordSSHCommand(base, "command", command, world, result, classifySSHActor(base.ClientVersion, true))
		switch result.Interactive {
		case "ping":
			world.runVirtualPing(reader, channel, result.Target, result.StreamCount)
		case "traceroute":
			world.runVirtualTraceroute(channel, result.Target)
		case "vim":
			world.runVirtualVim(reader, channel, result.Target)
		case "nano":
			world.runVirtualNano(reader, channel, result.Target)
		case "top":
			world.runVirtualTop(reader, channel)
		}
		if result.Exit {
			return
		}
	}
}

func (s *TrapSSH) recordSSHAuth(auth sshAuthState, client, user, method string, accepted bool, passwordLen int, fingerprint string) {
	base := model.SSHEvent{SessionID: auth.sessionID, IP: auth.ip, Country: auth.country, CountrySource: auth.countrySource, ClientVersion: client, Username: user}
	message := "authentication rejected"
	risk := 65
	if accepted {
		message = "authentication accepted by deception policy"
		risk = 78
	}
	e := model.SSHEvent{ID: newID(6), At: time.Now(), SessionID: base.SessionID, IP: base.IP, Country: base.Country, CountrySource: base.CountrySource, ClientVersion: client, Username: user, Type: "auth", AuthMethod: method, AuthAccepted: accepted, PasswordSupplied: passwordLen > 0, PasswordLength: passwordLen, KeyFingerprint: fingerprint, RiskScore: risk, Classification: model.ClassHostile, Actor: classifySSHActor(client, false), Message: message}
	if err := s.store.AddSSHEvent(e); err != nil {
		log.Printf("SSH event store: %v", err)
	}
}

func (s *TrapSSH) recordSSHCommand(base model.SSHEvent, eventType, command string, world *virtualSSHWorld, result virtualSSHResult, actor model.ActorType) {
	canaries := world.CanaryTouches(command)
	fingerprint := sshBehaviorFingerprint(result, command)
	if installer := world.sshInstallerSequenceFingerprint(result, command); installer != "" && (fingerprint == "" || result.PayloadStage == "retry" || result.PayloadStage == "executed") {
		fingerprint = installer
	}
	e := model.SSHEvent{
		ID: newID(6), At: time.Now(), SessionID: base.SessionID, IP: base.IP, Country: base.Country, CountrySource: base.CountrySource,
		ClientVersion: base.ClientVersion, Username: base.Username, Type: eventType, Command: sanitizeLogText(command, maxSSHLoggedCommandBytes), CommandName: result.CommandName,
		CommandFamily: result.Family, CWD: world.cwd, Output: sanitizeLogText(result.Output, 2048), Depth: result.Depth, Loop: world.loop,
		Frustration: world.frustration, Persona: result.Persona, RiskScore: result.Risk, Classification: model.ClassHostile, Actor: actor, Message: result.Message,
		CanaryTouches: canaries, Fingerprint: fingerprint,
		StdinBytes: result.StdinBytes, StdinSHA256: result.StdinSHA256, StdinKind: result.StdinKind,
		PayloadStage: result.PayloadStage, PayloadPath: result.PayloadPath,
	}
	if err := s.store.AddSSHEvent(e); err != nil {
		log.Printf("SSH event store: %v", err)
	}
	recordSSHIntelligence(s.store, base, command, canaries)
	if result.PayloadStage == "intent" || result.PayloadStage == "retry" || result.PayloadStage == "completed" {
		_ = s.store.AddIntelSignal(model.IntelSignal{ID: newID(6), At: time.Now(), IP: base.IP, Protocol: "ssh", SessionID: base.SessionID, Kind: "payload", Technique: "exec-stdin-staging", Filename: result.PayloadPath, Summary: "SSH payload staging " + result.PayloadStage + ": " + result.PayloadPath})
	}
	switch {
	case strings.Contains(result.Message, "command budget"):
		s.store.RecordHealth("ssh_command_budget")
	case strings.Contains(result.Message, "alias expansion") || strings.Contains(result.Message, "source recursion"):
		s.store.RecordHealth("ssh_recursion_guard")
	case strings.Contains(result.Output, "No space left on device"):
		s.store.RecordHealth("ssh_virtual_storage")
	}
}

func (s *TrapSSH) recordSSHEvent(base model.SSHEvent, typ, name, family, cwd, message string, risk, depth, loop, frustration int, actor model.ActorType) {
	e := model.SSHEvent{
		ID: newID(6), At: time.Now(), SessionID: base.SessionID, IP: base.IP, Country: base.Country, CountrySource: base.CountrySource,
		ClientVersion: base.ClientVersion, Username: base.Username, Type: typ, CommandName: name, CommandFamily: family,
		CWD: cwd, Depth: depth, Loop: loop, Frustration: frustration, RiskScore: risk, Classification: model.ClassHostile,
		Actor: actor, Message: sanitizeLogText(message, 256),
	}
	if err := s.store.AddSSHEvent(e); err != nil {
		log.Printf("SSH event store: %v", err)
	}
}

func classifySSHActor(client string, interactive bool) model.ActorType {
	v := strings.ToLower(client)
	for _, marker := range []string{"paramiko", "libssh", "golang", "go-ssh", "masscan", "nmap"} {
		if strings.Contains(v, marker) {
			return model.ActorAutomated
		}
	}
	if interactive && strings.Contains(v, "openssh") {
		return model.ActorHuman
	}
	return model.ActorUnknown
}

func cleanSSHField(v string, max int) string { return sanitizeLogText(v, max) }

const (
	maxSSHExecCommandBytes        = 16 * 1024
	maxSSHInteractiveCommandBytes = 2048
	maxSSHLoggedCommandBytes      = 2048
)

func cleanSSHCommand(v string, max int) string {
	v = strings.ReplaceAll(v, "\x00", "")
	var b strings.Builder
	lastSep := false
	for _, r := range v {
		if r == '\r' || r == '\n' {
			if !lastSep && b.Len() > 0 {
				b.WriteString("; ")
				lastSep = true
			}
		} else if r == '\t' || r >= 0x20 {
			if r != 0x7f && r != 0x1b {
				b.WriteRune(r)
				lastSep = false
			}
		}
		if max > 0 && b.Len() >= max {
			break
		}
	}
	return strings.Trim(strings.TrimSpace(b.String()), ";")
}

func sanitizeLogText(v string, max int) string {
	var b strings.Builder
	for _, r := range v {
		if r == '\n' || r == '\r' || r == '\t' || (r >= 0x20 && r != 0x7f && r != 0x1b && !unicode.IsControl(r)) {
			b.WriteRune(r)
		}
		if max > 0 && b.Len() >= max {
			break
		}
	}
	out := b.String()
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out
}

func normalizeSSHOutput(v string) string {
	v = strings.ReplaceAll(v, "\r\n", "\n")
	v = strings.ReplaceAll(v, "\r", "\n")
	v = sanitizeLogText(v, 8192)
	if v == "" {
		return ""
	}
	v = strings.ReplaceAll(v, "\n", "\r\n")
	if !strings.HasSuffix(v, "\r\n") {
		v += "\r\n"
	}
	return v
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
