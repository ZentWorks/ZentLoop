package server

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"zentloop/internal/lures"
)

func virtualPingCount(args []string) int {
	for i, a := range args {
		if (a == "-c" || a == "--count") && i+1 < len(args) {
			if n, err := strconv.Atoi(args[i+1]); err == nil && n > 0 {
				if n > 20 {
					return 20
				}
				return n
			}
		}
		if strings.HasPrefix(a, "-c") && len(a) > 2 {
			if n, err := strconv.Atoi(strings.TrimPrefix(a, "-c")); err == nil && n > 0 {
				if n > 20 {
					return 20
				}
				return n
			}
		}
	}
	return 0 // normal ping runs until Ctrl+C
}

func virtualPingReply(ip string, seq int) string {
	ms := 0.31 + float64((seq*37)%83)/1000.0
	return fmt.Sprintf("64 bytes from %s: icmp_seq=%d ttl=64 time=%.3f ms\r\n", ip, seq, ms)
}

func (w *virtualSSHWorld) runVirtualPing(reader *virtualSSHLineReader, out io.Writer, target string, count int) {
	host := target
	ip := host
	if h, ok := lures.Resolve(host); ok {
		ip = h.IP
	}
	started := time.Now()
	if count > 0 {
		for seq := 1; seq <= count; seq++ {
			if seq > 1 {
				time.Sleep(time.Second)
			} else {
				time.Sleep(120 * time.Millisecond)
			}
			_, _ = io.WriteString(out, virtualPingReply(ip, seq))
		}
		elapsed := time.Since(started).Milliseconds()
		_, _ = fmt.Fprintf(out, "\r\n--- %s ping statistics ---\r\n%d packets transmitted, %d received, 0%% packet loss, time %dms\r\nrtt min/avg/max/mdev = 0.311/0.352/0.393/0.031 ms\r\n", host, count, count, elapsed)
		return
	}

	keys := make(chan byte, 1)
	errCh := make(chan error, 1)
	go func() {
		for {
			b, err := reader.readByte()
			if err != nil {
				errCh <- err
				return
			}
			if b == 3 {
				keys <- b
				return
			}
		}
	}()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	seq := 0
	for {
		select {
		case <-ticker.C:
			seq++
			_, _ = io.WriteString(out, virtualPingReply(ip, seq))
		case <-keys:
			elapsed := time.Since(started).Milliseconds()
			_, _ = fmt.Fprintf(out, "^C\r\n--- %s ping statistics ---\r\n%d packets transmitted, %d received, 0%% packet loss, time %dms\r\nrtt min/avg/max/mdev = 0.311/0.352/0.393/0.031 ms\r\n", host, seq, seq, elapsed)
			return
		case <-errCh:
			return
		}
	}
}

func virtualTracerouteHops(target string) []string {
	ip := target
	if h, ok := lures.Resolve(target); ok {
		ip = h.IP
	}
	return []string{
		" 1  _gateway (10.10.30.1)  0.381 ms  0.352 ms  0.341 ms",
		" 2  core-sw-01.prod.internal (10.10.20.1)  0.812 ms  0.773 ms  0.801 ms",
		fmt.Sprintf(" 3  %s (%s)  1.204 ms  1.176 ms  1.191 ms", target, ip),
	}
}

func (w *virtualSSHWorld) runVirtualTraceroute(out io.Writer, target string) {
	for i, hop := range virtualTracerouteHops(target) {
		if i == 0 {
			time.Sleep(180 * time.Millisecond)
		} else {
			time.Sleep(420 * time.Millisecond)
		}
		_, _ = io.WriteString(out, hop+"\r\n")
	}
}

func virtualPingBatchOutput(target string, count int) string {
	if count <= 0 {
		count = 4
	}
	host := target
	ip := host
	if h, ok := lures.Resolve(host); ok {
		ip = h.IP
	}
	var b strings.Builder
	fmt.Fprintf(&b, "PING %s (%s) 56(84) bytes of data.\n", host, ip)
	for seq := 1; seq <= count; seq++ {
		b.WriteString(strings.ReplaceAll(virtualPingReply(ip, seq), "\r\n", "\n"))
	}
	fmt.Fprintf(&b, "\n--- %s ping statistics ---\n%d packets transmitted, %d received, 0%% packet loss\nrtt min/avg/max/mdev = 0.311/0.352/0.393/0.031 ms", host, count, count)
	return b.String()
}

func virtualTracerouteBatchOutput(target string) string {
	ip := target
	if h, ok := lures.Resolve(target); ok {
		ip = h.IP
	}
	return "traceroute to " + target + " (" + ip + "), 30 hops max, 60 byte packets\n" + strings.Join(virtualTracerouteHops(target), "\n")
}
