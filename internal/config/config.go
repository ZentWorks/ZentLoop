package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	ProxyAuto       = "auto"
	ProxyDirect     = "direct"
	ProxyGeneric    = "generic"
	ProxyCloudflare = "cloudflare"
)

type Config struct {
	TrapAddr              string
	AdminAddr             string
	AdminUser             string
	AdminPassword         string
	DataDir               string
	BenignDir             string
	ProxyMode             string
	ProxyRules            string
	HostileThreshold      int
	SuspiciousThreshold   int
	LiveSessionMinutes    int
	ResumeWindowHours     int
	RetentionDays         int
	MaxDelayMS            int
	MaxConcurrent         int
	Brand                 string
	GeoIPDB               string
	IntegrationSecret     string
	IntegrationMaxSkew    int
	OfficialBotsEnabled   bool
	OfficialBotsRefreshH  int
	OfficialBotsCache     string
	SSHEnabled            bool
	SSHAddr               string
	SSHHostKeyPath        string
	SSHMaxConcurrent      int
	SSHMaxPerIP           int
	SSHIdleSeconds        int
	SSHMaxSessionMinutes  int
	SSHMaxAuthTries       int
	SSHProviderOrg        string
	AdminSSHEnabled       bool
	AdminSSHAddr          string
	AdminSSHUser          string
	AdminSSHAuthorizedKey string
	AdminSSHHostKeyPath   string
}

func Load() Config {
	proxyMode := strings.ToLower(strings.TrimSpace(env("ZENTLOOP_PROXY_MODE", ProxyAuto)))
	adminUser := env("ZENTLOOP_ADMIN_USER", "admin")

	return Config{
		TrapAddr:              env("ZENTLOOP_TRAP_ADDR", ":8080"),
		AdminAddr:             env("ZENTLOOP_ADMIN_ADDR", ":9090"),
		AdminUser:             adminUser,
		AdminPassword:         env("ZENTLOOP_ADMIN_PASSWORD", ""),
		DataDir:               env("ZENTLOOP_DATA_DIR", "/data"),
		BenignDir:             env("ZENTLOOP_BENIGN_DIR", "/site"),
		ProxyMode:             proxyMode,
		ProxyRules:            env("ZENTLOOP_PROXY_RULES", ""),
		HostileThreshold:      envInt("ZENTLOOP_HOSTILE_THRESHOLD", 60),
		SuspiciousThreshold:   envInt("ZENTLOOP_SUSPICIOUS_THRESHOLD", 30),
		LiveSessionMinutes:    envInt("ZENTLOOP_LIVE_SESSION_MINUTES", 5),
		ResumeWindowHours:     envInt("ZENTLOOP_RESUME_WINDOW_HOURS", 720),
		RetentionDays:         clampInt(envInt("ZENTLOOP_RETENTION_DAYS", 30), 1, 30),
		MaxDelayMS:            envInt("ZENTLOOP_MAX_DELAY_MS", 1500),
		MaxConcurrent:         envInt("ZENTLOOP_MAX_CONCURRENT", 256),
		Brand:                 env("ZENTLOOP_BRAND", "ZentLoop"),
		GeoIPDB:               env("ZENTLOOP_GEOIP_DB", "/data/dbip-country-lite.mmdb"),
		IntegrationSecret:     env("ZENTLOOP_INTEGRATION_SECRET", ""),
		IntegrationMaxSkew:    envInt("ZENTLOOP_INTEGRATION_MAX_SKEW_SECONDS", 300),
		OfficialBotsEnabled:   envBool("ZENTLOOP_OFFICIAL_BOTS_ENABLED", true),
		OfficialBotsRefreshH:  envInt("ZENTLOOP_OFFICIAL_BOTS_REFRESH_HOURS", 24),
		OfficialBotsCache:     env("ZENTLOOP_OFFICIAL_BOTS_CACHE", "/data/official-bots.json"),
		SSHEnabled:            envBool("ZENTLOOP_SSH_ENABLED", false),
		SSHAddr:               env("ZENTLOOP_SSH_ADDR", ":22"),
		SSHHostKeyPath:        env("ZENTLOOP_SSH_HOST_KEY_PATH", "/data/ssh_trap_host_ed25519_key"),
		SSHMaxConcurrent:      envInt("ZENTLOOP_SSH_MAX_CONCURRENT", 64),
		SSHMaxPerIP:           envInt("ZENTLOOP_SSH_MAX_PER_IP", 4),
		SSHIdleSeconds:        envInt("ZENTLOOP_SSH_IDLE_SECONDS", 120),
		SSHMaxSessionMinutes:  envInt("ZENTLOOP_SSH_MAX_SESSION_MINUTES", 30),
		SSHMaxAuthTries:       envInt("ZENTLOOP_SSH_MAX_AUTH_TRIES", 6),
		SSHProviderOrg:        strings.TrimSpace(env("ZENTLOOP_SSH_PROVIDER_ORG", "AS16276 OVH SAS")),
		AdminSSHEnabled:       envBool("ZENTLOOP_ADMIN_SSH_ENABLED", false),
		AdminSSHAddr:          env("ZENTLOOP_ADMIN_SSH_ADDR", ":22222"),
		AdminSSHUser:          env("ZENTLOOP_ADMIN_SSH_USER", adminUser),
		AdminSSHAuthorizedKey: strings.TrimSpace(env("ZENTLOOP_ADMIN_SSH_AUTHORIZED_KEY", "")),
		AdminSSHHostKeyPath:   env("ZENTLOOP_ADMIN_SSH_HOST_KEY_PATH", "/data/ssh_host_ed25519_key"),
	}
}

func (c Config) IntegrationSecrets() []string {
	parts := strings.Split(c.IntegrationSecret, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		secret := strings.TrimSpace(part)
		if secret != "" {
			out = append(out, secret)
		}
	}
	return out
}

func (c Config) IntegrationSecretConfigured() bool {
	return len(c.IntegrationSecrets()) > 0
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.AdminUser) == "" {
		return fmt.Errorf("ZENTLOOP_ADMIN_USER must not be empty")
	}
	if c.HostileThreshold <= c.SuspiciousThreshold {
		return fmt.Errorf("hostile threshold must be higher than suspicious threshold")
	}
	if c.LiveSessionMinutes < 1 {
		return fmt.Errorf("ZENTLOOP_LIVE_SESSION_MINUTES must be at least 1")
	}
	if c.ResumeWindowHours < 1 {
		return fmt.Errorf("ZENTLOOP_RESUME_WINDOW_HOURS must be at least 1")
	}
	if c.RetentionDays < 1 || c.RetentionDays > 30 {
		return fmt.Errorf("ZENTLOOP_RETENTION_DAYS must be between 1 and 30")
	}
	if c.MaxConcurrent < 1 {
		return fmt.Errorf("ZENTLOOP_MAX_CONCURRENT must be at least 1")
	}
	if c.OfficialBotsRefreshH < 1 || c.OfficialBotsRefreshH > 168 {
		return fmt.Errorf("ZENTLOOP_OFFICIAL_BOTS_REFRESH_HOURS must be between 1 and 168")
	}
	if c.OfficialBotsEnabled && strings.TrimSpace(c.OfficialBotsCache) == "" {
		return fmt.Errorf("ZENTLOOP_OFFICIAL_BOTS_CACHE must not be empty when official bot verification is enabled")
	}
	if c.IntegrationMaxSkew < 30 {
		return fmt.Errorf("ZENTLOOP_INTEGRATION_MAX_SKEW_SECONDS must be at least 30")
	}
	if c.SSHEnabled {
		if strings.TrimSpace(c.SSHAddr) == "" {
			return fmt.Errorf("ZENTLOOP_SSH_ADDR must not be empty when SSH trap is enabled")
		}
		if strings.TrimSpace(c.SSHHostKeyPath) == "" {
			return fmt.Errorf("ZENTLOOP_SSH_HOST_KEY_PATH must not be empty when SSH trap is enabled")
		}
		if c.SSHMaxConcurrent < 1 || c.SSHMaxConcurrent > 4096 {
			return fmt.Errorf("ZENTLOOP_SSH_MAX_CONCURRENT must be between 1 and 4096")
		}
		if c.SSHMaxPerIP < 1 || c.SSHMaxPerIP > c.SSHMaxConcurrent {
			return fmt.Errorf("ZENTLOOP_SSH_MAX_PER_IP must be between 1 and ZENTLOOP_SSH_MAX_CONCURRENT")
		}
		if c.SSHIdleSeconds < 15 || c.SSHIdleSeconds > 3600 {
			return fmt.Errorf("ZENTLOOP_SSH_IDLE_SECONDS must be between 15 and 3600")
		}
		if c.SSHMaxSessionMinutes < 1 || c.SSHMaxSessionMinutes > 240 {
			return fmt.Errorf("ZENTLOOP_SSH_MAX_SESSION_MINUTES must be between 1 and 240")
		}
		if c.SSHMaxAuthTries < 1 || c.SSHMaxAuthTries > 20 {
			return fmt.Errorf("ZENTLOOP_SSH_MAX_AUTH_TRIES must be between 1 and 20")
		}
	}
	if c.SSHEnabled && c.AdminSSHEnabled && filepath.Clean(c.SSHHostKeyPath) == filepath.Clean(c.AdminSSHHostKeyPath) {
		return fmt.Errorf("SSH trap and admin SSH must use different host key paths")
	}
	if c.AdminSSHEnabled {
		if strings.TrimSpace(c.AdminSSHAddr) == "" {
			return fmt.Errorf("ZENTLOOP_ADMIN_SSH_ADDR must not be empty when admin SSH is enabled")
		}
		if strings.TrimSpace(c.AdminSSHUser) == "" {
			return fmt.Errorf("ZENTLOOP_ADMIN_SSH_USER must not be empty when admin SSH is enabled")
		}
		if strings.TrimSpace(c.AdminSSHAuthorizedKey) == "" {
			return fmt.Errorf("ZENTLOOP_ADMIN_SSH_AUTHORIZED_KEY must not be empty when admin SSH is enabled")
		}
		if strings.TrimSpace(c.AdminSSHHostKeyPath) == "" {
			return fmt.Errorf("ZENTLOOP_ADMIN_SSH_HOST_KEY_PATH must not be empty when admin SSH is enabled")
		}
	}
	switch c.ProxyMode {
	case ProxyAuto, ProxyDirect, ProxyGeneric, ProxyCloudflare:
	default:
		return fmt.Errorf("ZENTLOOP_PROXY_MODE must be auto, direct, generic or cloudflare")
	}
	return nil
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func envInt(k string, d int) int {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return d
	}
	return n
}

func envBool(k string, d bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(k)))
	if v == "" {
		return d
	}
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return d
	}
}

func clampInt(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
