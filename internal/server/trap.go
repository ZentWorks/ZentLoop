package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"zentloop/internal/botverify"
	"zentloop/internal/config"
	"zentloop/internal/engine"
	"zentloop/internal/model"
	"zentloop/internal/store"
)

type TrapServer struct {
	cfg       config.Config
	store     *store.Store
	scorer    *engine.Scorer
	deception *engine.Deception
	geo       *geoResolver
	benign    http.Handler
	bots      *botverify.Registry
	stripes   [256]sync.Mutex
	sem       chan struct{}
}

func NewTrap(cfg config.Config, st *store.Store) *TrapServer {
	var benign http.Handler
	if fi, err := os.Stat(cfg.BenignDir); err == nil && fi.IsDir() {
		benign = http.FileServer(http.Dir(cfg.BenignDir))
	} else {
		benign = http.HandlerFunc(defaultBenign)
	}
	bots := botverify.New(cfg.OfficialBotsCache)
	bots.Start(context.Background(), cfg.OfficialBotsEnabled, time.Duration(cfg.OfficialBotsRefreshH)*time.Hour)
	return &TrapServer{cfg: cfg, store: st, scorer: engine.NewScorer(cfg), deception: engine.NewDeception(cfg), geo: newGeoResolver(cfg.GeoIPDB), benign: benign, bots: bots, sem: make(chan struct{}, cfg.MaxConcurrent)}
}

func (s *TrapServer) Handler() http.Handler { return http.HandlerFunc(s.handle) }

const integrationCheckPath = "/.well-known/zentloop/integration-check"

func (s *TrapServer) handle(w http.ResponseWriter, r *http.Request) {
	arrival := time.Now()
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		s.store.RecordHealth("http_rejected")
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	integration := s.integrationMeta(r, arrival)
	integrationCheck := r.URL.Path == integrationCheckPath
	integrationClaim := cleanIntegrationName(r.Header.Get("X-ZentLoop-Integration"))
	if integrationCheck && r.Method == http.MethodGet && integration.Valid {
		s.store.RecordIntegrationVerified(integration.Name, remoteIP(r.RemoteAddr), integration.Trust, arrival)
		w.Header().Set("X-ZentLoop-Integration-Verified", "1")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if integrationCheck && integrationClaim != "" && !integration.Valid {
		sourceIP := remoteIP(r.RemoteAddr)
		s.store.RecordIntegrationFailure(integrationClaim, sourceIP, "integration verification failed", arrival, isPrivateOrLoopback(sourceIP))
	}
	target := canonicalTarget(r)
	if integration.Valid && integration.Target != "" {
		target = integration.Target
	}
	client := s.clientMeta(r, target)
	ip := client.IP
	fp := fingerprint(ip+"|"+target, r.UserAgent())
	lock := s.stripeFor(fp)
	lock.Lock()
	defer lock.Unlock()
	ss, _ := s.sessionFor(r, fp, client, target)
	requestMeta := extractRequestMeta(r, target, integration)
	applyRequestMeta(ss, requestMeta)
	probe, knownProbe := identifyProbe(r.URL.Path)
	activityPubInbox := isActivityPubInboxRequest(r)
	wasHostile := (ss.Classification == model.ClassHostile || ss.Depth >= 2) && !activityPubInbox
	http.SetCookie(w, &http.Cookie{Name: "zl_sid", Value: ss.ID, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: effectiveResumeHours(s.cfg) * 60 * 60})
	bodySample := ""
	if r.Body != nil && (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
		bodySample = string(b)
		r.Body.Close()
	}
	s.recordHTTPIntelligence(ip, ss.ID, r.URL.RawQuery, bodySample)
	ass := s.scorer.AssessAt(r, ss, bodySample, arrival)
	behavior := s.store.HTTPBehavior(ip, r.UserAgent(), arrival)
	ass.Automation = clampInt(ass.Automation+behavior.AutomationBoost, 0, 100)
	ass.Risk = clampInt(ass.Risk+behavior.RiskBoost, 0, 100)
	claim := s.bots.Verify(ip, r.UserAgent())
	ss.BotProvider, ss.BotName, ss.BotClaimed, ss.BotVerified = claim.Provider, claim.Bot, claim.Claimed, claim.Verified
	if activityPubInbox {
		// Federation relays are automated but not hostile. Keep them observable as
		// benign protocol traffic without letting their request cadence inflate
		// attack metrics or poison the unknown-path learning export.
		ass.Risk = 0
		ass.Automation = 100
		ass.Classification = model.ClassBenign
		ass.Actor = model.ActorAutomated
		ass.Confidence = "high"
		ass.Category = "activitypub-relay"
		behavior.AutomationBoost = 0
		behavior.RiskBoost = 0
		behavior.Fingerprints = append(behavior.Fingerprints, "http:activitypub-relay")
	}
	if claim.Verified {
		ass.Automation = maxScoreInt(ass.Automation, 95)
		ass.Actor = model.ActorAutomated
		ass.Confidence = "high"
		behavior.Fingerprints = append(behavior.Fingerprints, "http:verified-bot:"+claim.Provider)
	} else if claim.Claimed && s.bots.HasProvider(claim.Provider) {
		ass.Automation = maxScoreInt(ass.Automation, 92)
		ass.Risk = clampInt(ass.Risk+12, 0, 100)
		ass.Actor = model.ActorAutomated
		ass.Confidence = "high"
		ass.Category = "spoofed-bot"
		behavior.Fingerprints = append(behavior.Fingerprints, "http:spoofed-bot:"+claim.Provider)
	}
	if ass.Automation >= 65 {
		ass.Actor = model.ActorAutomated
		if ass.Automation >= 85 {
			ass.Confidence = "high"
		} else {
			ass.Confidence = "medium"
		}
	}
	s.store.ApplyHTTPActorFingerprint(ip, behavior.Fingerprints)
	if ass.Automation >= 65 || behavior.AutomationBoost >= 30 {
		s.store.PromoteHTTPAutomation(ip, ass.Automation)
	}
	ss.RiskScore = ass.Risk
	ss.AutomationScore = ass.Automation
	ss.Classification = ass.Classification
	if wasHostile {
		ss.Classification = model.ClassHostile
		if ss.RiskScore < s.cfg.HostileThreshold {
			ss.RiskScore = s.cfg.HostileThreshold
		}
	}
	ss.Actor = ass.Actor
	ss.Confidence = ass.Confidence
	if ass.Persona != "" {
		ss.Persona = ass.Persona
	}
	now := arrival
	ss.RequestCount++
	ss.LastSeen = now
	ss.LastMethod = r.Method
	ss.CurrentPath = r.URL.Path
	ss.RecentTimes = append(ss.RecentTimes, now)
	if len(ss.RecentTimes) > 12 {
		ss.RecentTimes = ss.RecentTimes[len(ss.RecentTimes)-12:]
	}
	ss.AvgIntervalMS, ss.IntervalVarMS = calcIntervals(ss.RecentTimes)

	status := 200
	bytesWritten := 0
	label := "benign"
	cw := &captureWriter{ResponseWriter: w, status: 200}
	if integrationCheck {
		if integrationClaim != "" {
			status = http.StatusForbidden
			label = "integration verification failed"
			ss.Classification = model.ClassSuspicious
			if ss.RiskScore < s.cfg.SuspiciousThreshold {
				ss.RiskScore = s.cfg.SuspiciousThreshold
			}
		} else {
			status = http.StatusNotFound
			label = "not found"
		}
		ss.LastStatus = status
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		if r.Method != http.MethodHead {
			n, _ := w.Write([]byte(http.StatusText(status) + "\n"))
			bytesWritten = n
		}
	} else if activityPubInbox {
		status = http.StatusAccepted
		label = "activitypub-relay"
		ss.LastStatus = status
		w.Header().Set("Content-Type", "application/activity+json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
	} else if ss.Classification == model.ClassHostile || looksLikeBait(r.URL.Path) {
		resp := s.deception.Build(r, ss)
		if resp.Delay > 0 {
			time.Sleep(resp.Delay)
		}
		ss.Depth = resp.Depth
		newJourneyStep := len(ss.Journey) == 0 || ss.Journey[len(ss.Journey)-1].Path != r.URL.Path
		if resp.LoopInc > 0 && newJourneyStep {
			ss.Loop += resp.LoopInc
			ss.Frustration = minInt(10, ss.Frustration+resp.LoopInc)
		}
		label = resp.Label
		status = resp.Status
		ss.LastStatus = status
		for k, v := range resp.Headers {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", resp.ContentType)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if w.Header().Get("Content-Length") == "" {
			w.Header().Set("Content-Length", strconv.Itoa(len(resp.Body)))
		}
		w.WriteHeader(status)
		if r.Method != http.MethodHead {
			n, _ := w.Write(resp.Body)
			bytesWritten = n
		}
		if ss.Depth > 0 {
			addJourney(ss, now, r.URL.Path, label)
		}
	} else {
		ss.LastStatus = 200
		if isBenignDiscovery(r.URL.Path) {
			serveBenignDiscovery(cw, r)
		} else {
			s.benign.ServeHTTP(cw, r)
		}
		status = cw.status
		bytesWritten = cw.bytes
	}
	s.store.UpsertSession(ss, fp)
	e := model.Event{ID: newID(6), At: now, SessionID: ss.ID, SessionFirstSeen: ss.FirstSeen, SessionRequests: ss.RequestCount, SessionVisits: ss.VisitCount, SessionVisitStarted: ss.VisitStarted, IP: ss.IP, IPSource: ss.IPSource, Proxy: ss.Proxy, Country: ss.Country, CountrySource: ss.CountrySource, CloudflareRay: ss.CloudflareRay, CloudflareColo: ss.CloudflareColo, Referrer: requestMeta.Referrer, ReferrerHost: requestMeta.ReferrerHost, RequestHost: requestMeta.RequestHost, Target: ss.Target, ProbeName: probe.Name, ProbeProduct: probe.Product, ProbeCVE: probe.CVE, KnownProbe: knownProbe, Origin: requestMeta.Origin, AcceptLanguage: requestMeta.AcceptLanguage, HTTPProtocol: requestMeta.HTTPProtocol, Integration: requestMeta.Integration, IntegrationTrust: requestMeta.IntegrationTrust, CatchAll: requestMeta.CatchAll, Method: r.Method, Path: r.URL.Path, Status: status, Bytes: bytesWritten, RiskScore: ss.RiskScore, AutomationScore: ss.AutomationScore, Classification: ss.Classification, Actor: ss.Actor, Confidence: ss.Confidence, AvgIntervalMS: ss.AvgIntervalMS, IntervalVarMS: ss.IntervalVarMS, Persona: ss.Persona, Depth: ss.Depth, Loop: ss.Loop, Frustration: ss.Frustration, Category: ass.Category, Message: label, UserAgent: ss.UserAgent, BotProvider: ss.BotProvider, BotName: ss.BotName, BotClaimed: ss.BotClaimed, BotVerified: ss.BotVerified}
	if err := s.store.AddEvent(e); err != nil {
		log.Printf("event store: %v", err)
	}
}

type requestMeta struct {
	Referrer         string
	ReferrerHost     string
	RequestHost      string
	Target           string
	Origin           string
	AcceptLanguage   string
	HTTPProtocol     string
	Integration      string
	IntegrationTrust string
	CatchAll         bool
}

func extractRequestMeta(r *http.Request, target string, integration integrationMeta) requestMeta {
	ref := cleanHeader(r.Referer(), 1024)
	return requestMeta{
		Referrer:         ref,
		ReferrerHost:     referrerHost(ref),
		RequestHost:      cleanHeader(r.Host, 255),
		Target:           target,
		Origin:           cleanHeader(r.Header.Get("Origin"), 512),
		AcceptLanguage:   cleanHeader(r.Header.Get("Accept-Language"), 256),
		HTTPProtocol:     cleanHeader(r.Proto, 32),
		Integration:      integration.Name,
		IntegrationTrust: integration.Trust,
		CatchAll:         integration.CatchAll,
	}
}

func applyRequestMeta(ss *model.Session, meta requestMeta) {
	if ss.FirstPath == "" {
		ss.FirstPath = ss.CurrentPath
	}
	if meta.Referrer != "" {
		if ss.FirstReferrer == "" {
			ss.FirstReferrer = meta.Referrer
		}
		ss.LastReferrer = meta.Referrer
		ss.ReferrerHost = meta.ReferrerHost
	}
	if meta.RequestHost != "" {
		ss.RequestHost = meta.RequestHost
	}
	if meta.Target != "" {
		ss.Target = meta.Target
	}
	if meta.Origin != "" {
		ss.Origin = meta.Origin
	}
	if meta.AcceptLanguage != "" {
		ss.AcceptLanguage = meta.AcceptLanguage
	}
	if meta.HTTPProtocol != "" {
		ss.HTTPProtocol = meta.HTTPProtocol
	}
	if meta.Integration != "" {
		ss.Integration = meta.Integration
		ss.IntegrationTrust = meta.IntegrationTrust
	}
	if meta.CatchAll {
		ss.CatchAll = true
	}
}

func canonicalTarget(r *http.Request) string {
	host := strings.TrimSpace(strings.ToLower(r.Host))
	if host == "" {
		return "(unknown)"
	}
	if h, port, err := net.SplitHostPort(host); err == nil {
		if (r.TLS != nil && port == "443") || (r.TLS == nil && port == "80") {
			return h
		}
		return net.JoinHostPort(h, port)
	}
	return strings.TrimSuffix(host, ".")
}

func referrerHost(ref string) string {
	if ref == "" {
		return ""
	}
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	return cleanHeader(host, 255)
}

type integrationMeta struct {
	Name     string
	Target   string
	CatchAll bool
	Trust    string
	Valid    bool
}

func (s *TrapServer) integrationMeta(r *http.Request, now time.Time) integrationMeta {
	name := cleanIntegrationName(r.Header.Get("X-ZentLoop-Integration"))
	if name == "" {
		return integrationMeta{}
	}
	target := canonicalIntegrationTarget(r.Header.Get("X-ZentLoop-Target"))
	if target == "" {
		target = canonicalTarget(r)
	}
	catchAll := headerBool(r.Header.Get("X-ZentLoop-Catch-All"))
	remote := remoteIP(r.RemoteAddr)

	// Easy local integrations (NPM/nginx/Traefik on the same Docker/LAN network)
	// can use trusted metadata without a shared secret. If a secret is configured,
	// signed metadata is mandatory even from a private peer.
	if s.cfg.IntegrationSecret == "" {
		if !isPrivateOrLoopback(remote) {
			return integrationMeta{}
		}
		return integrationMeta{Name: name, Target: target, CatchAll: catchAll, Trust: "private-peer", Valid: true}
	}

	tsRaw := strings.TrimSpace(r.Header.Get("X-ZentLoop-Timestamp"))
	ts, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil {
		return integrationMeta{}
	}
	maxSkew := s.cfg.IntegrationMaxSkew
	if maxSkew <= 0 {
		maxSkew = 300
	}
	delta := now.Unix() - ts
	if delta < 0 {
		delta = -delta
	}
	if delta > int64(maxSkew) {
		return integrationMeta{}
	}

	sig := strings.TrimSpace(r.Header.Get("X-ZentLoop-Signature"))
	sig = strings.TrimPrefix(strings.ToLower(sig), "sha256=")
	got, err := hex.DecodeString(sig)
	if err != nil || len(got) != sha256.Size {
		return integrationMeta{}
	}
	payload := integrationSignaturePayload(tsRaw, name, target, catchAll, r.Method, r.URL.RequestURI())
	mac := hmac.New(sha256.New, []byte(s.cfg.IntegrationSecret))
	_, _ = mac.Write([]byte(payload))
	if !hmac.Equal(got, mac.Sum(nil)) {
		return integrationMeta{}
	}
	return integrationMeta{Name: name, Target: target, CatchAll: catchAll, Trust: "signed", Valid: true}
}

func integrationSignaturePayload(timestamp, name, target string, catchAll bool, method, requestURI string) string {
	ca := "0"
	if catchAll {
		ca = "1"
	}
	return strings.Join([]string{"v1", timestamp, name, target, ca, strings.ToUpper(method), requestURI}, "\n")
}

func cleanIntegrationName(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" || len(v) > 64 {
		return ""
	}
	for _, r := range v {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
			return ""
		}
	}
	return v
}

func canonicalIntegrationTarget(v string) string {
	v = strings.ToLower(cleanHeader(v, 255))
	v = strings.TrimSpace(v)
	if v == "" || strings.ContainsAny(v, "/\\?#@") {
		return ""
	}
	if h, port, err := net.SplitHostPort(v); err == nil {
		if h == "" || port == "" {
			return ""
		}
		return net.JoinHostPort(strings.TrimSuffix(strings.ToLower(h), "."), port)
	}
	return strings.TrimSuffix(v, ".")
}

func headerBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

type clientMeta struct {
	IP             string
	IPSource       string
	Proxy          string
	Country        string
	CountrySource  string
	CloudflareRay  string
	CloudflareColo string
}

func (s *TrapServer) sessionFor(r *http.Request, fp string, client clientMeta, target string) (*model.Session, bool) {
	now := time.Now()
	resumeWindow := time.Duration(effectiveResumeHours(s.cfg)) * time.Hour
	if c, err := r.Cookie("zl_sid"); err == nil {
		if ss, ok := s.store.GetSession(c.Value); ok && now.Sub(ss.LastSeen) <= resumeWindow && (ss.Target == "" || strings.EqualFold(ss.Target, target)) {
			// Network metadata can improve after the first request (for example when
			// a deployment is switched to Cloudflare proxy mode). Keep the latest
			// trustworthy values on the existing session.
			applyClientMeta(ss, client)
			prepareReturnVisit(ss, now, time.Duration(effectiveLiveMinutes(s.cfg))*time.Minute)
			return ss, false
		}
	}
	if ss, ok := s.store.GetSessionByFingerprint(fp); ok && now.Sub(ss.LastSeen) <= resumeWindow {
		applyClientMeta(ss, client)
		prepareReturnVisit(ss, now, time.Duration(effectiveLiveMinutes(s.cfg))*time.Minute)
		return ss, false
	}
	id := newID(16)
	ss := &model.Session{ID: id, IP: client.IP, IPSource: client.IPSource, Proxy: client.Proxy, Country: client.Country, CountrySource: client.CountrySource, CloudflareRay: client.CloudflareRay, CloudflareColo: client.CloudflareColo, Target: target, FirstPath: r.URL.Path, UserAgent: r.UserAgent(), FirstSeen: now, LastSeen: now, VisitCount: 1, VisitStarted: now, Classification: model.ClassBenign, Actor: model.ActorUnknown, Confidence: "low"}
	return ss, true
}

func prepareReturnVisit(ss *model.Session, now time.Time, inactiveAfter time.Duration) {
	if ss.VisitCount == 0 {
		ss.VisitCount = 1
	}
	if ss.VisitStarted.IsZero() {
		ss.VisitStarted = ss.FirstSeen
	}
	if !ss.LastSeen.IsZero() && now.Sub(ss.LastSeen) > inactiveAfter {
		ss.VisitCount++
		ss.VisitStarted = now
		// Long pauses are not useful for human-vs-automation timing. Keep the
		// long-lived deception state, but start timing this visit from scratch.
		ss.RecentTimes = nil
		ss.AvgIntervalMS = 0
		ss.IntervalVarMS = 0
	}
}

func effectiveLiveMinutes(cfg config.Config) int {
	if cfg.LiveSessionMinutes > 0 {
		return cfg.LiveSessionMinutes
	}
	return 5
}

func effectiveResumeHours(cfg config.Config) int {
	if cfg.ResumeWindowHours > 0 {
		return cfg.ResumeWindowHours
	}
	return 720
}

func applyClientMeta(ss *model.Session, client clientMeta) {
	ss.IP = client.IP
	ss.IPSource = client.IPSource
	ss.Proxy = client.Proxy
	if client.Country != "" {
		ss.Country = client.Country
		ss.CountrySource = client.CountrySource
	}
	if client.CloudflareRay != "" {
		ss.CloudflareRay = client.CloudflareRay
	}
	if client.CloudflareColo != "" {
		ss.CloudflareColo = client.CloudflareColo
	}
}

func (s *TrapServer) clientMeta(r *http.Request, target string) clientMeta {
	remote := remoteIP(r.RemoteAddr)
	meta := clientMeta{IP: remote, IPSource: "remote", Proxy: "direct"}
	proxyMode := s.proxyModeForRequest(r, remote, target)

	switch proxyMode {
	case config.ProxyCloudflare:
		meta.Proxy = "cloudflare"
		meta.Country = cleanCountry(r.Header.Get("CF-IPCountry"))
		if meta.Country != "" {
			meta.CountrySource = "cloudflare"
		}
		meta.CloudflareRay = cleanHeader(r.Header.Get("CF-Ray"), 96)
		meta.CloudflareColo = cloudflareColo(meta.CloudflareRay)

		// Cloudflare documents CF-Connecting-IP as the original visitor IP sent
		// to the origin. If Pseudo IPv4 overwrites that header, the actual IPv6
		// address is preserved in CF-Connecting-IPv6, so prefer it only when the
		// connecting IP is in the Class E pseudo range.
		cfIP := validIP(r.Header.Get("CF-Connecting-IP"))
		if isCloudflarePseudoIPv4(cfIP) {
			if v6 := validIP(r.Header.Get("CF-Connecting-IPv6")); v6 != "" {
				meta.IP = v6
				meta.IPSource = "cf-connecting-ipv6"
				if meta.Country == "" {
					meta.Country, meta.CountrySource = s.geo.country(meta.IP)
				}
				return meta
			}
		}
		if cfIP != "" {
			meta.IP = cfIP
			meta.IPSource = "cf-connecting-ip"
			if meta.Country == "" {
				meta.Country, meta.CountrySource = s.geo.country(meta.IP)
			}
			return meta
		}
		// Deliberately do not trust X-Forwarded-For as a silent Cloudflare
		// fallback. A missing CF-Connecting-IP should stay visible instead of
		// making attribution look correct when the ingress is misconfigured.
		meta.IPSource = "remote (cf header missing)"
		if meta.Country == "" {
			meta.Country, meta.CountrySource = s.geo.country(meta.IP)
		}
		return meta

	case config.ProxyGeneric:
		meta.Proxy = "generic"
		if x := firstForwardedIP(r.Header.Get("X-Forwarded-For")); x != "" {
			meta.IP = x
			meta.IPSource = "x-forwarded-for"
			meta.Country, meta.CountrySource = s.geo.country(meta.IP)
			return meta
		}
		if x := validIP(r.Header.Get("X-Real-IP")); x != "" {
			meta.IP = x
			meta.IPSource = "x-real-ip"
		}
	}
	if meta.Country == "" {
		meta.Country, meta.CountrySource = s.geo.country(meta.IP)
	}
	return meta
}

func (s *TrapServer) proxyModeForRequest(r *http.Request, remote, target string) string {
	// Explicit target rules always win. This makes one ZentLoop instance safe
	// for mixed ingress: e.g. one hostname via Cloudflare, another via NPM and
	// a public IP directly.
	if mode := matchProxyRule(target, s.cfg.ProxyRules); mode != "" {
		return mode
	}
	if s.cfg.ProxyMode != config.ProxyAuto {
		return s.cfg.ProxyMode
	}

	// Conservative auto detection: only trust forwarding headers automatically
	// when the TCP peer itself is private/loopback. That matches the common
	// Docker layouts where cloudflared or Nginx Proxy Manager sits on the
	// same host/network, while preventing an arbitrary public client from
	// spoofing CF-Connecting-IP/X-Forwarded-For.
	if isPrivateOrLoopback(remote) {
		if validIP(r.Header.Get("CF-Connecting-IP")) != "" && strings.TrimSpace(r.Header.Get("CF-Ray")) != "" {
			return config.ProxyCloudflare
		}
		if firstForwardedIP(r.Header.Get("X-Forwarded-For")) != "" || validIP(r.Header.Get("X-Real-IP")) != "" {
			return config.ProxyGeneric
		}
	}
	return config.ProxyDirect
}

func matchProxyRule(target, raw string) string {
	target = strings.ToLower(strings.TrimSpace(target))
	hostOnly := targetHostOnly(target)
	if target == "" || strings.TrimSpace(raw) == "" {
		return ""
	}
	for _, item := range strings.Split(raw, ",") {
		parts := strings.SplitN(strings.TrimSpace(item), "=", 2)
		if len(parts) != 2 {
			continue
		}
		pattern := strings.ToLower(strings.TrimSpace(parts[0]))
		mode := strings.ToLower(strings.TrimSpace(parts[1]))
		if mode != config.ProxyDirect && mode != config.ProxyGeneric && mode != config.ProxyCloudflare {
			continue
		}
		matched := target == pattern || hostOnly == pattern
		if !matched && strings.HasPrefix(pattern, "*.") {
			suffix := strings.TrimPrefix(pattern, "*")
			matched = (strings.HasSuffix(target, suffix) && len(target) > len(suffix)) ||
				(strings.HasSuffix(hostOnly, suffix) && len(hostOnly) > len(suffix))
		}
		if matched {
			return mode
		}
	}
	return ""
}

func targetHostOnly(target string) string {
	if h, _, err := net.SplitHostPort(target); err == nil {
		return strings.ToLower(strings.TrimSpace(h))
	}
	return strings.Trim(strings.ToLower(strings.TrimSpace(target)), "[]")
}

func isPrivateOrLoopback(raw string) bool {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

func remoteIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return host
	}
	if ip := validIP(addr); ip != "" {
		return ip
	}
	return addr
}

func validIP(v string) string {
	v = strings.TrimSpace(v)
	ip := net.ParseIP(v)
	if ip == nil {
		return ""
	}
	return ip.String()
}

func firstForwardedIP(v string) string {
	for _, part := range strings.Split(v, ",") {
		if ip := validIP(part); ip != "" {
			return ip
		}
	}
	return ""
}

func isCloudflarePseudoIPv4(v string) bool {
	ip := net.ParseIP(v)
	if ip == nil {
		return false
	}
	v4 := ip.To4()
	return v4 != nil && v4[0] >= 240
}

func cleanCountry(v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	if v == "T1" || v == "XX" {
		return v
	}
	if len(v) == 2 && v[0] >= 'A' && v[0] <= 'Z' && v[1] >= 'A' && v[1] <= 'Z' {
		return v
	}
	return ""
}

func cleanHeader(v string, maxLen int) string {
	v = strings.TrimSpace(v)
	if len(v) > maxLen {
		v = v[:maxLen]
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return v
}

func cloudflareColo(ray string) string {
	i := strings.LastIndex(ray, "-")
	if i < 0 || i+1 >= len(ray) {
		return ""
	}
	colo := strings.ToUpper(ray[i+1:])
	if len(colo) != 3 {
		return ""
	}
	for _, r := range colo {
		if r < 'A' || r > 'Z' {
			return ""
		}
	}
	return colo
}

func (s *TrapServer) stripeFor(key string) *sync.Mutex {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return &s.stripes[h.Sum32()%uint32(len(s.stripes))]
}
func fingerprint(ip, ua string) string { return ip + "|" + ua }
func newID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
func looksLikeBait(p string) bool {
	_, ok := identifyProbe(p)
	return ok
}

func addJourney(ss *model.Session, at time.Time, path, label string) {
	if len(ss.Journey) > 0 && ss.Journey[len(ss.Journey)-1].Path == path {
		return
	}
	ss.Journey = append(ss.Journey, model.JourneyStep{At: at, Path: path, Label: label})
	if len(ss.Journey) > 30 {
		ss.Journey = ss.Journey[len(ss.Journey)-30:]
	}
}
func calcIntervals(ts []time.Time) (int64, int64) {
	if len(ts) < 2 {
		return 0, 0
	}
	ts = append([]time.Time(nil), ts...)
	sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
	var sum int64
	vals := make([]int64, 0, len(ts)-1)
	for i := 1; i < len(ts); i++ {
		v := ts[i].Sub(ts[i-1]).Milliseconds()
		vals = append(vals, v)
		sum += v
	}
	avg := sum / int64(len(vals))
	var dev int64
	for _, v := range vals {
		d := v - avg
		if d < 0 {
			d = -d
		}
		dev += d
	}
	return avg, dev / int64(len(vals))
}
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type captureWriter struct {
	http.ResponseWriter
	status, bytes int
}

func (c *captureWriter) WriteHeader(code int) { c.status = code; c.ResponseWriter.WriteHeader(code) }
func (c *captureWriter) Write(b []byte) (int, error) {
	n, e := c.ResponseWriter.Write(b)
	c.bytes += n
	return n, e
}
func serveBenignDiscovery(w http.ResponseWriter, r *http.Request) {
	switch strings.ToLower(r.URL.Path) {
	case "/.well-known/passkey-endpoints":
		body := "{}\n"
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		if r.Method != http.MethodHead {
			io.WriteString(w, body)
		}
	default:
		http.NotFound(w, r)
	}
}

func defaultBenign(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	body := "<!doctype html><html><head><meta name=viewport content='width=device-width'><title>Welcome</title><style>body{font:16px system-ui;margin:10vh auto;max-width:680px;padding:24px;color:#222}small{color:#777}</style></head><body><h1>Welcome</h1><p>This service is online.</p><small>HTTP service</small></body></html>"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method != http.MethodHead {
		io.WriteString(w, body)
	}
}

func maxScoreInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
