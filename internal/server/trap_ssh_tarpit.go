package server

import (
	"net"
	"time"
)

// applyAdaptiveSSHTarpit delays the SSH banner for very aggressive repeat
// sources. The separate small semaphore guarantees the delay can never occupy
// more than a handful of global SSH slots. If all tarpit slots are busy, ZentLoop
// skips the delay rather than consuming extra resources.
func (s *TrapSSH) applyAdaptiveSSHTarpit(conn net.Conn, ip string) {
	if s == nil || s.store == nil || conn == nil || s.tarpitSem == nil {
		return
	}
	delay := s.store.SSHTarpitDelay(ip, time.Now())
	if delay <= 0 {
		return
	}
	select {
	case s.tarpitSem <- struct{}{}:
		defer func() { <-s.tarpitSem }()
		s.store.RecordHealth("ssh_tarpit")
	case <-time.After(5 * time.Millisecond):
		return
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	<-timer.C
}
