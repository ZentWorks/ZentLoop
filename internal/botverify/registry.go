package botverify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Claim struct {
	Provider string `json:"provider,omitempty"`
	Bot      string `json:"bot,omitempty"`
	Claimed  bool   `json:"claimed"`
	Verified bool   `json:"verified"`
}

type source struct {
	Provider string
	URL      string
}

// All URLs are controlled by ZentLoop. Request traffic can never influence them.
var officialSources = []source{
	{"google", "https://developers.google.com/static/crawling/ipranges/common-crawlers.json"},
	{"google", "https://developers.google.com/static/crawling/ipranges/special-crawlers.json"},
	{"google", "https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers.json"},
	{"google", "https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers-google.json"},
	{"google", "https://developers.google.com/static/crawling/ipranges/user-triggered-agents.json"},
	{"apple", "https://search.developer.apple.com/applebot.json"},
	{"duckduckgo", "https://duckduckgo.com/duckduckbot.json"},
	{"duckduckgo", "https://duckduckgo.com/duckassistbot.json"},
	{"openai", "https://openai.com/searchbot.json"},
	{"openai", "https://openai.com/gptbot.json"},
	{"openai", "https://openai.com/chatgpt-user.json"},
	{"openai", "https://openai.com/adsbot.json"},
	{"perplexity", "https://www.perplexity.com/perplexitybot.json"},
	{"perplexity", "https://www.perplexity.com/perplexity-user.json"},
}

type cacheFile struct {
	UpdatedAt time.Time           `json:"updated_at"`
	Providers map[string][]string `json:"providers"`
}

type Registry struct {
	mu        sync.RWMutex
	providers map[string][]netip.Prefix
	updatedAt time.Time
	cachePath string
	client    *http.Client
}

func New(cachePath string) *Registry {
	r := &Registry{
		providers: make(map[string][]netip.Prefix),
		cachePath: cachePath,
		client:    &http.Client{Timeout: 12 * time.Second},
	}
	_ = r.loadCache()
	return r
}

func (r *Registry) Start(ctx context.Context, enabled bool, refresh time.Duration) {
	if !enabled {
		return
	}
	if refresh < time.Hour {
		refresh = 24 * time.Hour
	}
	go func() {
		// Startup refresh is asynchronous so the trap never waits on the Internet.
		_ = r.Refresh(ctx)
		ticker := time.NewTicker(refresh)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				refreshCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
				_ = r.Refresh(refreshCtx)
				cancel()
			}
		}
	}()
}

func (r *Registry) UpdatedAt() time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.updatedAt
}

func (r *Registry) HasProvider(provider string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.providers[provider]) > 0
}

func (r *Registry) PrefixCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := 0
	for _, rows := range r.providers {
		n += len(rows)
	}
	return n
}

func (r *Registry) Verify(ipText, ua string) Claim {
	provider, bot := claimFromUA(ua)
	if provider == "" {
		return Claim{}
	}
	c := Claim{Provider: provider, Bot: bot, Claimed: true}
	ip, err := netip.ParseAddr(strings.TrimSpace(ipText))
	if err != nil {
		return c
	}
	ip = ip.Unmap()
	r.mu.RLock()
	rows := r.providers[provider]
	r.mu.RUnlock()
	for _, p := range rows {
		if p.Contains(ip) {
			c.Verified = true
			return c
		}
	}
	return c
}

func claimFromUA(ua string) (string, string) {
	l := strings.ToLower(ua)
	switch {
	case strings.Contains(l, "googlebot") || strings.Contains(l, "googleother") || strings.Contains(l, "google-cloudvertexbot") || strings.Contains(l, "googleinspectiontool") || strings.Contains(l, "adsbot-google"):
		return "google", firstBotName(ua, []string{"Googlebot", "GoogleOther", "Google-CloudVertexBot", "GoogleInspectionTool", "AdsBot-Google"})
	case strings.Contains(l, "applebot"):
		return "apple", "Applebot"
	case strings.Contains(l, "duckduckbot"):
		return "duckduckgo", "DuckDuckBot"
	case strings.Contains(l, "duckassistbot"):
		return "duckduckgo", "DuckAssistBot"
	case strings.Contains(l, "oai-searchbot"):
		return "openai", "OAI-SearchBot"
	case strings.Contains(l, "gptbot"):
		return "openai", "GPTBot"
	case strings.Contains(l, "chatgpt-user"):
		return "openai", "ChatGPT-User"
	case strings.Contains(l, "oai-adsbot"):
		return "openai", "OAI-AdsBot"
	case strings.Contains(l, "perplexitybot"):
		return "perplexity", "PerplexityBot"
	case strings.Contains(l, "perplexity-user"):
		return "perplexity", "Perplexity-User"
	// Recognize common claims even where ZentLoop intentionally has no trusted
	// machine-readable source. They remain unverified and can contribute to UA rotation.
	case strings.Contains(l, "bingbot"):
		return "bing", "bingbot"
	case strings.Contains(l, "baiduspider"):
		return "baidu", "Baiduspider"
	case strings.Contains(l, "yandexbot"):
		return "yandex", "YandexBot"
	case strings.Contains(l, "ccbot"):
		return "commoncrawl", "CCBot"
	}
	return "", ""
}

func firstBotName(ua string, names []string) string {
	l := strings.ToLower(ua)
	for _, n := range names {
		if strings.Contains(l, strings.ToLower(n)) {
			return n
		}
	}
	return names[0]
}

func (r *Registry) Refresh(ctx context.Context) error {
	expected := make(map[string]int)
	for _, src := range officialSources {
		expected[src.Provider]++
	}
	fresh := make(map[string][]netip.Prefix)
	succeeded := make(map[string]int)
	for _, src := range officialSources {
		prefixes, err := r.fetch(ctx, src.URL)
		if err != nil {
			continue
		}
		succeeded[src.Provider]++
		fresh[src.Provider] = append(fresh[src.Provider], prefixes...)
	}

	// Update a provider only when every official source configured for that
	// provider succeeded. This prevents a transient failure of one Google/OpenAI
	// feed from silently shrinking a previously good cache.
	r.mu.RLock()
	merged := cloneProviders(r.providers)
	r.mu.RUnlock()
	updatedProviders := 0
	for provider, want := range expected {
		if succeeded[provider] != want || len(fresh[provider]) == 0 {
			continue
		}
		merged[provider] = dedupe(fresh[provider])
		updatedProviders++
	}
	if updatedProviders == 0 {
		return errors.New("no complete official bot provider could be refreshed")
	}
	now := time.Now().UTC()
	r.mu.Lock()
	r.providers = merged
	r.updatedAt = now
	r.mu.Unlock()
	return r.saveCache(now, merged)
}

func cloneProviders(in map[string][]netip.Prefix) map[string][]netip.Prefix {
	out := make(map[string][]netip.Prefix, len(in))
	for provider, rows := range in {
		out[provider] = append([]netip.Prefix(nil), rows...)
	}
	return out
}

func (r *Registry) fetch(ctx context.Context, url string) ([]netip.Prefix, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ZentLoop official-bot-registry/1")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var raw any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	values := collectPrefixStrings(raw)
	out := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		if ip, err := netip.ParseAddr(value); err == nil {
			ip = ip.Unmap()
			bits := 128
			if ip.Is4() {
				bits = 32
			}
			out = append(out, netip.PrefixFrom(ip, bits))
			continue
		}
		if p, err := netip.ParsePrefix(value); err == nil {
			out = append(out, p.Masked())
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no IP prefixes in source")
	}
	return out, nil
}

func collectPrefixStrings(v any) []string {
	var out []string
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			for k, value := range t {
				lk := strings.ToLower(k)
				if s, ok := value.(string); ok && (strings.Contains(lk, "prefix") || lk == "ipv4" || lk == "ipv6" || lk == "ip") {
					out = append(out, strings.TrimSpace(s))
				} else {
					walk(value)
				}
			}
		case []any:
			for _, item := range t {
				walk(item)
			}
		case string:
			// DuckDuckGo/OpenAI/Perplexity formats may expose plain strings in arrays.
			s := strings.TrimSpace(t)
			if _, err := netip.ParseAddr(s); err == nil {
				out = append(out, s)
				return
			}
			if _, err := netip.ParsePrefix(s); err == nil {
				out = append(out, s)
			}
		}
	}
	walk(v)
	return out
}

func dedupe(in []netip.Prefix) []netip.Prefix {
	seen := make(map[string]struct{}, len(in))
	out := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		k := p.String()
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, p)
	}
	return out
}

func (r *Registry) loadCache() error {
	if strings.TrimSpace(r.cachePath) == "" {
		return nil
	}
	b, err := os.ReadFile(r.cachePath)
	if err != nil {
		return err
	}
	var c cacheFile
	if err := json.Unmarshal(b, &c); err != nil {
		return err
	}
	next := make(map[string][]netip.Prefix)
	for provider, rows := range c.Providers {
		for _, raw := range rows {
			if p, err := netip.ParsePrefix(raw); err == nil {
				next[provider] = append(next[provider], p.Masked())
			}
		}
	}
	r.mu.Lock()
	r.providers = next
	r.updatedAt = c.UpdatedAt
	r.mu.Unlock()
	return nil
}

func (r *Registry) saveCache(at time.Time, providers map[string][]netip.Prefix) error {
	if strings.TrimSpace(r.cachePath) == "" {
		return nil
	}
	c := cacheFile{UpdatedAt: at, Providers: make(map[string][]string, len(providers))}
	for provider, rows := range providers {
		for _, p := range rows {
			c.Providers[provider] = append(c.Providers[provider], p.String())
		}
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := os.MkdirAll(filepath.Dir(r.cachePath), 0o750); err != nil {
		return err
	}
	tmp := r.cachePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, r.cachePath)
}
