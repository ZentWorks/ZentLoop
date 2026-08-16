package lures

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

type Host struct {
	Name    string
	IP      string
	Role    string
	Aliases []string
	Ports   []int
}

var hosts = []Host{
	{Name: "prod-app-02", IP: "10.10.30.21", Role: "application", Aliases: []string{"portal.internal", "app.internal"}, Ports: []int{22, 8081}},
	{Name: "backup-01", IP: "10.10.30.12", Role: "backup", Aliases: []string{"backup.internal"}, Ports: []int{22, 873}},
	{Name: "db-primary", IP: "10.10.30.14", Role: "database", Aliases: []string{"db-internal", "db.prod.internal"}, Ports: []int{5432}},
	{Name: "cache-01", IP: "10.10.30.18", Role: "cache", Aliases: []string{"cache-internal"}, Ports: []int{6379}},
	{Name: "registry-01", IP: "10.10.30.25", Role: "registry", Aliases: []string{"registry.internal"}, Ports: []int{443, 5000}},
	{Name: "git-01", IP: "10.10.30.27", Role: "git", Aliases: []string{"git.prod.internal", "git.internal"}, Ports: []int{22, 443}},
	{Name: "ops-gw-01", IP: "10.10.30.30", Role: "operations", Aliases: []string{"ops.internal"}, Ports: []int{22, 443, 8443}},
}

func Hosts() []Host {
	out := make([]Host, len(hosts))
	copy(out, hosts)
	return out
}

func Resolve(name string) (Host, bool) {
	name = strings.TrimSpace(strings.ToLower(strings.TrimSuffix(name, ".")))
	for _, h := range hosts {
		if strings.ToLower(h.Name) == name || h.IP == name {
			return h, true
		}
		for _, a := range h.Aliases {
			if strings.ToLower(a) == name {
				return h, true
			}
		}
	}
	return Host{}, false
}

func HostsFile() string {
	rows := []string{"127.0.0.1 localhost", "127.0.1.1 prod-app-02"}
	for _, h := range hosts {
		aliases := append([]string{h.Name}, h.Aliases...)
		rows = append(rows, h.IP+" "+strings.Join(aliases, " "))
	}
	return strings.Join(rows, "\n") + "\n"
}

func Inventory() string {
	rows := make([]string, 0, len(hosts))
	for _, h := range hosts {
		rows = append(rows, h.Name+" ansible_host="+h.IP+" role="+h.Role)
	}
	sort.Strings(rows)
	return strings.Join(rows, "\n") + "\n"
}

// Canary returns a deterministic decoy credential for one source address and label.
// The value is intentionally synthetic and is safe to expose inside the deception world.
func Canary(sourceIP, label string) string {
	h := sha256.Sum256([]byte("zentloop-decoy-v1|" + strings.TrimSpace(sourceIP) + "|" + label))
	return "svc_live_" + hex.EncodeToString(h[:10])
}

func CanaryLabels(sourceIP string) map[string]string {
	return map[string]string{
		"internal-api": Canary(sourceIP, "internal-api"),
		"backup":       Canary(sourceIP, "backup"),
		"registry":     Canary(sourceIP, "registry"),
	}
}
