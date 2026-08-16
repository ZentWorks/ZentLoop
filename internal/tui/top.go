package tui

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"zentloop/internal/model"
)

type client struct {
	base, user, password string
	http                 *http.Client
}

func Run(args []string) error {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)

	quit := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		select {
		case <-stop:
			requestQuit(quit)
		case <-done:
		}
	}()
	err := run(args, os.Stdin, os.Stdout, quit)
	close(done)
	return err
}

// RunRemote renders the same live TUI over an arbitrary interactive stream,
// such as an SSH session. q/Q, Ctrl+C or EOF closes the remote view.
func RunRemote(args []string, in io.Reader, out io.Writer) error {
	quit := make(chan struct{}, 1)
	return run(args, in, out, quit)
}

func run(args []string, in io.Reader, out io.Writer, quit chan struct{}) error {
	fs := flag.NewFlagSet("top", flag.ContinueOnError)
	url := fs.String("url", env("ZENTLOOP_TOP_URL", "http://127.0.0.1:9090"), "admin API URL")
	user := fs.String("user", env("ZENTLOOP_ADMIN_USER", "admin"), "admin user")
	pass := fs.String("password", env("ZENTLOOP_ADMIN_PASSWORD", ""), "admin password")
	interval := fs.Duration("interval", time.Second, "refresh interval")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *interval <= 0 {
		return fmt.Errorf("interval must be greater than zero")
	}

	c := &client{base: strings.TrimRight(*url, "/"), user: *user, password: *pass, http: &http.Client{Timeout: 4 * time.Second}}
	go readQuit(in, quit)

	t := time.NewTicker(*interval)
	defer t.Stop()
	_, _ = fmt.Fprint(out, "\x1b[?25l")
	defer fmt.Fprint(out, "\x1b[?25h\x1b[0m\r\n")

	for {
		if err := draw(c, out); err != nil {
			_, _ = fmt.Fprintf(out, "\x1b[2J\x1b[H ZentLoop top\r\n\r\n error: %v\r\n", err)
		}
		select {
		case <-t.C:
			continue
		case <-quit:
			return nil
		}
	}
}

func readQuit(in io.Reader, quit chan struct{}) {
	buf := make([]byte, 1)
	for {
		n, err := in.Read(buf)
		if n > 0 && (buf[0] == 'q' || buf[0] == 'Q' || buf[0] == 3) {
			requestQuit(quit)
			return
		}
		if err != nil {
			requestQuit(quit)
			return
		}
	}
}

func requestQuit(quit chan struct{}) {
	select {
	case quit <- struct{}{}:
	default:
	}
}

func draw(c *client, out io.Writer) error {
	var o model.Overview
	var sessions []model.Session
	var events []model.Event
	var sshOverview model.SSHOverview
	var sshSessions []model.SSHSession
	var actorOverview model.ActorOverview
	var health model.HealthOverview
	if err := c.get("/api/overview", &o); err != nil {
		return err
	}
	if err := c.get("/api/sessions?limit=30", &sessions); err != nil {
		return err
	}
	if err := c.get("/api/events?limit=200", &events); err != nil {
		return err
	}
	if err := c.get("/api/ssh/overview", &sshOverview); err != nil {
		return err
	}
	if err := c.get("/api/ssh/live-sessions?limit=12&left_seconds=10", &sshSessions); err != nil {
		return err
	}
	if err := c.get("/api/actors/overview", &actorOverview); err != nil {
		return err
	}
	if err := c.get("/api/health", &health); err != nil {
		return err
	}
	sort.SliceStable(sessions, func(i, j int) bool {
		if sessions[i].RiskScore == sessions[j].RiskScore {
			return sessions[i].LastSeen.After(sessions[j].LastSeen)
		}
		return sessions[i].RiskScore > sessions[j].RiskScore
	})
	_, _ = fmt.Fprint(out, "\x1b[2J\x1b[H")
	_, _ = fmt.Fprintf(out, " \x1b[1;33m⬡ ZentLoop top\x1b[0m   %s   \x1b[31m● LIVE\x1b[0m\r\n", time.Now().Format("2006-01-02 15:04:05"))
	_, _ = fmt.Fprint(out, " ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────\r\n")
	_, _ = fmt.Fprintf(out, " ACTIVE %-5d  \x1b[31mHOSTILE %-5d\x1b[0m  \x1b[33mSUSPICIOUS %-5d\x1b[0m  \x1b[32mBENIGN %-5d\x1b[0m  REQ/s %-7.1f  TODAY %-9d  LOOPS %-5d\r\n", o.ActiveSessions, o.Hostile, o.Suspicious, o.Benign, o.RequestsPerSec, o.RequestsToday, o.LoopsTotal)
	_, _ = fmt.Fprintf(out, " ACTOR  automated %-5d  human %-5d  unknown %-5d     avg depth %.1f     uptime %s\r\n", o.Automated, o.Human, o.Unknown, o.AvgDepth, fmtDuration(time.Duration(o.UptimeSeconds)*time.Second))
	sshState := "OFF"
	if sshOverview.Enabled {
		sshState = "ON"
	}
	_, _ = fmt.Fprintf(out, " SSH %-3s  active %-4d  conn today %-6d  auth today %-6d  shells %-6d  commands today %-7d  avg depth %.1f\r\n", sshState, sshOverview.ActiveSessions, sshOverview.ConnectionsToday, sshOverview.AuthAttemptsToday, sshOverview.ShellsToday, sshOverview.CommandsToday, sshOverview.AvgDepth)
	_, _ = fmt.Fprintf(out, " TRACK actors %-5d cross %-5d engaged %-8s canary %-5d payload %-5d\r\n", actorOverview.ActorsTotal, actorOverview.CrossProtocol, fmtDuration(time.Duration(actorOverview.EngagementSeconds)*time.Second), actorOverview.CanaryTouches, actorOverview.PayloadAttempts)
	guardHits := health.SSHCommandBudgetHits + health.SSHVirtualStorageHits + health.SSHRecursionGuardHits
	sshShed := health.SSHRejectedGlobal + health.SSHRejectedPerIP
	storage := health.EventsBytes + health.SSHEventsBytes + health.IntelEventsBytes
	_, _ = fmt.Fprintf(out, " GUARD http shed %-5d ssh shed %-5d guard hits %-5d storage %-9s mem events %-7d\r\n", health.HTTPRejected, sshShed, guardHits, fmtBytes(storage), health.HTTPEventsInMemory+health.SSHEventsInMemory+health.IntelEventsInMemory)
	_, _ = fmt.Fprint(out, "\r\n \x1b[1mSESSIONS\x1b[0m\r\n")
	_, _ = fmt.Fprint(out, " LAST     TARGET                 IP                     CC   VIA      RISK  ACTOR       AUTO  REQ    D  L  F  CURRENT\r\n")
	_, _ = fmt.Fprint(out, " ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────\r\n")
	for i, s := range sessions {
		if i >= 12 {
			break
		}
		risk := fmt.Sprintf("%3d", s.RiskScore)
		if s.RiskScore >= 60 {
			risk = "\x1b[31m" + risk + "\x1b[0m"
		} else if s.RiskScore >= 30 {
			risk = "\x1b[33m" + risk + "\x1b[0m"
		}
		_, _ = fmt.Fprintf(out, " %-8s %-22s %-22s %-4s %-8s %s  %-11s %3d%%  %-5d %2d %2d %2d %-45s\r\n", ago(s.LastSeen), clip(s.Target, 22), clip(s.IP, 22), clip(s.Country, 4), clip(networkLabel(s), 8), risk, clip(string(s.Actor), 11), s.AutomationScore, s.RequestCount, s.Depth, s.Loop, s.Frustration, clip(s.CurrentPath, 45))
	}
	if len(sshSessions) > 0 {
		_, _ = fmt.Fprint(out, "\r\n \x1b[1mSSH SESSIONS\x1b[0m\r\n")
		_, _ = fmt.Fprint(out, " LAST     IP                     CC   USER             CLIENT                 CMD   D  CURRENT\r\n")
		_, _ = fmt.Fprint(out, " ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────\r\n")
		for i, ss := range sshSessions {
			if i >= 6 {
				break
			}
			if !ss.Active {
				left := "LEFT"
				if !ss.DisconnectedAt.IsZero() {
					left = fmt.Sprintf("LEFT %ds", maxInt64(0, int64(time.Since(ss.DisconnectedAt).Seconds())))
				}
				_, _ = fmt.Fprintf(out, " %-8s %-22s %-4s %-16s  \x1b[2m%-9s last: %-55s\x1b[0m\r\n", ago(ss.LastSeen), clip(ss.IP, 22), clip(ss.Country, 4), clip(ss.Username, 16), left, clip(ss.LastAction, 55))
				continue
			}
			_, _ = fmt.Fprintf(out, " %-8s %-22s %-4s %-16s %-22s %-5d %2d %-45s\r\n", ago(ss.LastSeen), clip(ss.IP, 22), clip(ss.Country, 4), clip(ss.Username, 16), clip(ss.ClientVersion, 22), ss.CommandCount, ss.Depth, clip(ss.CurrentCommand, 45))
		}
	}

	_, _ = fmt.Fprint(out, "\r\n \x1b[1mLIVE EVENTS\x1b[0m\r\n")
	_, _ = fmt.Fprint(out, " TIME      IP                     METHOD STATUS RISK  PATH\r\n")
	_, _ = fmt.Fprint(out, " ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────\r\n")
	activeSessionIDs := make(map[string]struct{}, len(sessions))
	for _, s := range sessions {
		activeSessionIDs[s.ID] = struct{}{}
	}
	shown := 0
	for _, e := range events {
		if _, ok := activeSessionIDs[e.SessionID]; !ok {
			continue
		}
		if shown >= 10 {
			break
		}
		risk := fmt.Sprintf("%3d", e.RiskScore)
		if e.RiskScore >= 60 {
			risk = "\x1b[31m" + risk + "\x1b[0m"
		} else if e.RiskScore >= 30 {
			risk = "\x1b[33m" + risk + "\x1b[0m"
		}
		_, _ = fmt.Fprintf(out, " %-9s %-22s %-6s %3d    %s  %-56s\r\n", e.At.Local().Format("15:04:05"), clip(e.IP, 22), clip(e.Method, 6), e.Status, risk, clip(e.Path, 56))
		shown++
	}
	_, _ = fmt.Fprint(out, "\r\n q / Ctrl+C quit  ·  detailed analysis: web admin\r\n")
	return nil
}

func (c *client) get(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.user, c.password)
	r, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return fmt.Errorf("admin API returned %s", r.Status)
	}
	return json.NewDecoder(r.Body).Decode(out)
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func clip(s string, n int) string {
	s = safeTUIText(s)
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}

func safeTUIText(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r != 0x7f && r != 0x1b {
			b.WriteRune(r)
		} else if r == '\t' {
			b.WriteByte(' ')
		}
	}
	return b.String()
}

func ago(t time.Time) string {
	d := time.Since(t)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
}

func fmtDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%02dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}

func fmtBytes(n int64) string {
	switch {
	case n >= 1024*1024*1024:
		return fmt.Sprintf("%.1fG", float64(n)/(1024*1024*1024))
	case n >= 1024*1024:
		return fmt.Sprintf("%.1fM", float64(n)/(1024*1024))
	case n >= 1024:
		return fmt.Sprintf("%.1fK", float64(n)/1024)
	default:
		return fmt.Sprintf("%dB", n)
	}
}

func networkLabel(s model.Session) string {
	if s.Proxy == "cloudflare" {
		if s.CloudflareColo != "" {
			return "CF/" + s.CloudflareColo
		}
		return "CF"
	}
	if s.Proxy == "generic" {
		return "PROXY"
	}
	return "DIRECT"
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
