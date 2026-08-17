package server

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

const currentZentLoopVersion = "0.2.21"

func parseIPIntelligencePath(path string) (ip string, export bool, ok bool) {
	raw := strings.TrimPrefix(path, "/api/ip/")
	if strings.HasSuffix(raw, "/export.json") {
		export = true
		raw = strings.TrimSuffix(raw, "/export.json")
	}
	if raw == "" || strings.Contains(raw, "/") {
		return "", export, false
	}
	decoded, err := url.PathUnescape(raw)
	if err != nil || net.ParseIP(decoded) == nil {
		return "", export, false
	}
	return decoded, export, true
}

func (s *AdminServer) ipIntelligence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	ip, export, ok := parseIPIntelligencePath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	intel, found := s.store.IPIntelligence(ip, currentZentLoopVersion)
	if !found {
		http.NotFound(w, r)
		return
	}
	if export {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=zentloop-ip-%s.json", strings.ReplaceAll(ip, ":", "_")))
	}
	writeJSON(w, intel)
}
