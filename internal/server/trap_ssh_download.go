package server

import (
	"fmt"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"zentloop/internal/lures"
)

type virtualDownloadPayload struct {
	Body        string
	ContentType string
	Kind        string
	Size        int64
	Filename    string
	Binary      bool
}

func (w *virtualSSHWorld) virtualPayloadForURL(raw string) virtualDownloadPayload {
	parsed, _ := url.Parse(raw)
	cleanPath := parsed.Path
	name := path.Base(cleanPath)
	if name == "" || name == "." || name == "/" {
		name = "index.html"
	}
	lower := strings.ToLower(cleanPath)
	payload := virtualDownloadPayload{Filename: name, ContentType: "application/octet-stream", Kind: "binary", Size: 8421, Binary: true}
	if host, ok := lures.Resolve(parsed.Hostname()); ok {
		switch {
		case strings.Contains(lower, "/api/v1/internal") || strings.HasSuffix(lower, "/status"):
			body := fmt.Sprintf("{\"status\":\"ok\",\"node\":\"%s\",\"node_ip\":\"%s\",\"database\":\"db-primary:5432\",\"backup\":\"backup-01\",\"registry\":\"registry.internal\",\"api_token\":\"%s\"}\n", host.Name, host.IP, w.canaries["internal-api"])
			return virtualDownloadPayload{Body: body, ContentType: "application/json", Kind: "json", Size: int64(len(body)), Filename: name}
		case strings.Contains(lower, "/ops/inventory") || strings.Contains(lower, "/internal/inventory"):
			body := lures.Inventory() + "\n# backup token: " + w.canaries["backup"] + "\n"
			return virtualDownloadPayload{Body: body, ContentType: "text/plain", Kind: "text", Size: int64(len(body)), Filename: name}
		case host.Role == "registry" && (lower == "/v2/" || strings.Contains(lower, "_catalog")):
			body := "{\"repositories\":[\"platform/web\",\"platform/worker\",\"ops/backup-agent\"]}\n"
			return virtualDownloadPayload{Body: body, ContentType: "application/json", Kind: "json", Size: int64(len(body)), Filename: name}
		}
	}

	script := "#!/bin/sh\n# bootstrap worker\nARCH=$(uname -m)\necho installing worker for $ARCH\necho starting worker\n"
	switch {
	case strings.HasSuffix(lower, ".sh"), strings.HasSuffix(lower, ".bash"), strings.HasSuffix(lower, ".run"), strings.Contains(lower, "bootstrap"), strings.Contains(lower, "install"):
		payload.Body, payload.ContentType, payload.Kind, payload.Size, payload.Binary = script, "text/x-shellscript", "shell", int64(len(script)), false
	case strings.HasSuffix(lower, ".json"), strings.Contains(lower, "/api/"), strings.HasSuffix(lower, "/status"):
		body := "{\"status\":\"ok\",\"release\":\"2026.08\",\"node\":\"edge-02\",\"region\":\"eu-central\"}\n"
		payload.Body, payload.ContentType, payload.Kind, payload.Size, payload.Binary = body, "application/json", "json", int64(len(body)), false
	case strings.HasSuffix(lower, ".csv"):
		body := "network,continent,country\n1.0.0.0/24,OC,AU\n1.0.1.0/24,AS,CN\n1.0.2.0/23,AS,CN\n"
		payload.Body, payload.ContentType, payload.Kind, payload.Size, payload.Binary = body, "text/csv", "csv", 4_224_197, false
	case strings.HasSuffix(lower, ".csv.gz"):
		body := "\x1f\x8b\x08\x00virtual-gzip-country-database\n"
		payload.Body, payload.ContentType, payload.Kind, payload.Size, payload.Binary = body, "application/gzip", "gzip", 4_089_614, true
		if strings.Contains(strings.ToLower(raw), "dbip-country-lite") {
			payload.Size = 4_176_922
		}
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		payload.Body, payload.ContentType, payload.Kind, payload.Size, payload.Binary = "\x1f\x8b\x08\x00virtual-tar-gzip\n", "application/gzip", "tar-gzip", 2_941_872, true
	case strings.HasSuffix(lower, ".gz"):
		payload.Body, payload.ContentType, payload.Kind, payload.Size, payload.Binary = "\x1f\x8b\x08\x00virtual-gzip-data\n", "application/gzip", "gzip", 1_842_771, true
	case strings.HasSuffix(lower, ".zip"):
		payload.Body, payload.ContentType, payload.Kind, payload.Size, payload.Binary = "PK\x03\x04virtual-zip-data\n", "application/zip", "zip", 3_214_640, true
	case strings.HasSuffix(lower, ".deb"):
		payload.Body, payload.ContentType, payload.Kind, payload.Size, payload.Binary = "!<arch>\ndebian-binary/\n", "application/vnd.debian.binary-package", "deb", 7_924_816, true
	case strings.HasSuffix(lower, ".rpm"):
		payload.Body, payload.ContentType, payload.Kind, payload.Size, payload.Binary = "\xed\xab\xee\xdbvirtual-rpm\n", "application/x-rpm", "rpm", 8_614_204, true
	case strings.HasSuffix(lower, ".so"), strings.HasSuffix(lower, ".bin"):
		payload.Body, payload.ContentType, payload.Kind, payload.Size, payload.Binary = "\x7fELF\x02\x01\x01virtual-binary\n", "application/octet-stream", "elf", 1_274_944, true
	case strings.HasSuffix(lower, ".conf"), strings.HasSuffix(lower, ".ini"), strings.HasSuffix(lower, ".env"), strings.HasSuffix(lower, ".yaml"), strings.HasSuffix(lower, ".yml"):
		body := "environment=production\nendpoint=https://api.internal\nworkers=4\n"
		payload.Body, payload.ContentType, payload.Kind, payload.Size, payload.Binary = body, "text/plain", "text", int64(len(body)), false
	case strings.HasSuffix(lower, ".txt"), strings.HasSuffix(lower, ".log"):
		body := "service online\nlast deployment: successful\n"
		payload.Body, payload.ContentType, payload.Kind, payload.Size, payload.Binary = body, "text/plain", "text", int64(len(body)), false
	case strings.HasSuffix(lower, ".html"), strings.HasSuffix(lower, ".htm"), cleanPath == "" || cleanPath == "/":
		body := "<!doctype html><html><head><title>service</title></head><body><h1>It works</h1></body></html>\n"
		payload.Body, payload.ContentType, payload.Kind, payload.Size, payload.Binary = body, "text/html; charset=UTF-8", "html", int64(len(body)), false
	default:
		body := "<!doctype html><html><body>service online</body></html>\n"
		payload.Body, payload.ContentType, payload.Kind, payload.Size, payload.Binary = body, "text/html; charset=UTF-8", "html", int64(len(body)), false
	}
	return payload
}

func virtualDownloadHeaders(now time.Time, p virtualDownloadPayload, internal bool) string {
	server := "nginx"
	if internal {
		server = "nginx/1.24.0 (Ubuntu)"
	}
	return fmt.Sprintf("HTTP/1.1 200 OK\nServer: %s\nDate: %s\nContent-Type: %s\nContent-Length: %d\nLast-Modified: %s\nETag: \"%x-%x\"\nConnection: keep-alive", server, now.UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"), p.ContentType, p.Size, now.Add(-6*time.Hour).UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"), p.Size, now.Unix()&0xfffffff)
}

func (w *virtualSSHWorld) storeDownloadedVirtualFile(name string, p virtualDownloadPayload) bool {
	resolved := w.resolve(name)
	if !w.setVirtualFile(resolved, p.Body) {
		return false
	}
	meta := w.fileMeta[resolved]
	meta.Size = p.Size
	meta.Kind = p.Kind
	meta.ModTime = w.system.snapshot().Now
	w.fileMeta[resolved] = meta
	return true
}

func virtualCurlProgress(size int64) string {
	shown := size
	unit := ""
	if size >= 1024*1024 {
		shown = size / (1024 * 1024)
		unit = "M"
	} else if size >= 1024 {
		shown = size / 1024
		unit = "k"
	}
	return fmt.Sprintf("  %% Total    %% Received %% Xferd  Average Speed   Time    Time     Time  Current\n                                 Dload  Upload   Total   Spent    Left  Speed\n100 %4d%s  100 %4d%s    0     0  12.6M      0 --:--:-- --:--:-- --:--:-- 12.6M", shown, unit, shown, unit)
}

func virtualWgetLength(size int64) string {
	if size >= 1024*1024 {
		return fmt.Sprintf("%d (%.1fM)", size, float64(size)/(1024*1024))
	}
	if size >= 1024 {
		return fmt.Sprintf("%d (%.1fK)", size, float64(size)/1024)
	}
	return strconv.FormatInt(size, 10)
}

func virtualBinaryTerminalWarning() string {
	return "Warning: Binary output can interfere with your terminal.\nWarning: Use --output <FILE> to save it instead, or --output - to force terminal output."
}
