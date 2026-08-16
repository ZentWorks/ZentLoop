package server

import (
	"context"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

type geoResolver struct {
	dbPath string
	mu     sync.RWMutex
	cache  map[string]string
}

func newGeoResolver(dbPath string) *geoResolver {
	return &geoResolver{dbPath: dbPath, cache: make(map[string]string)}
}

func (g *geoResolver) country(ipString string) (string, string) {
	ip := net.ParseIP(strings.TrimSpace(ipString))
	if ip == nil {
		return "", ""
	}
	if isPrivateIP(ip) {
		return "LAN", "private"
	}
	if g == nil || g.dbPath == "" {
		return "", ""
	}
	g.mu.RLock()
	v, ok := g.cache[ip.String()]
	g.mu.RUnlock()
	if ok {
		if v == "" {
			return "", ""
		}
		return v, "geoip"
	}
	if _, err := os.Stat(g.dbPath); err != nil {
		return "", ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()
	out, err := exec.CommandContext(ctx, "mmdblookup", "--file", g.dbPath, "--ip", ip.String(), "country", "iso_code").CombinedOutput()
	code := ""
	if err == nil {
		code = parseMMDBCountry(string(out))
	}
	g.mu.Lock()
	g.cache[ip.String()] = code
	g.mu.Unlock()
	if code == "" {
		return "", ""
	}
	return code, "geoip"
}

var quotedMMDB = regexp.MustCompile(`"([A-Za-z]{2})"`)

func parseMMDBCountry(v string) string {
	m := quotedMMDB.FindStringSubmatch(v)
	if len(m) != 2 {
		return ""
	}
	return strings.ToUpper(m[1])
}

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	return false
}
