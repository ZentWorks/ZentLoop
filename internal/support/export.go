package support

import (
	"archive/zip"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"zentloop/internal/model"
	"zentloop/internal/store"
)

type Manifest struct {
	ExportedAt              time.Time `json:"exported_at"`
	Version                 string    `json:"version"`
	IPIntelligenceExports   int       `json:"ip_intelligence_exports"`
	SSHSessionExports       int       `json:"ssh_session_exports"`
	WebSessionExports       int       `json:"web_session_exports"`
	SourceIPsAnonymized     bool      `json:"source_ips_anonymized"`
	TargetsAnonymized       bool      `json:"targets_anonymized"`
	ReferencedIOCsPreserved bool      `json:"referenced_iocs_preserved"`
}

const supportKeyFile = ".zentloop-support.key"

type anonymizer struct {
	key       []byte
	ipMap     map[string]string
	targetMap map[string]string
	actorMap  map[string]string
}

func loadOrCreateInstallKey(dataDir string) ([]byte, error) {
	path := filepath.Join(dataDir, supportKeyFile)
	if b, err := os.ReadFile(path); err == nil {
		decoded, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(decoded) != 32 {
			return nil, fmt.Errorf("invalid support key")
		}
		return decoded, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	encoded := []byte(hex.EncodeToString(key) + "\n")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			b, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil, readErr
			}
			decoded, decodeErr := hex.DecodeString(strings.TrimSpace(string(b)))
			if decodeErr != nil || len(decoded) != 32 {
				return nil, fmt.Errorf("invalid support key")
			}
			return decoded, nil
		}
		return nil, err
	}
	if _, err := f.Write(encoded); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	return key, nil
}

func newAnonymizer(key []byte) *anonymizer {
	cp := append([]byte(nil), key...)
	return &anonymizer{
		key:       cp,
		ipMap:     make(map[string]string),
		targetMap: make(map[string]string),
		actorMap:  make(map[string]string),
	}
}

func (a *anonymizer) token(namespace, value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	mac := hmac.New(sha256.New, a.key)
	_, _ = mac.Write([]byte(namespace))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(value))
	// 48 bits keeps the identifiers compact while making accidental collisions
	// across realistic support datasets vanishingly unlikely.
	digest := hex.EncodeToString(mac.Sum(nil)[:6])
	return namespace + "-" + digest
}

func (a *anonymizer) IP(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return value
	}
	parsed := net.ParseIP(value)
	if parsed == nil {
		return value
	}
	canonical := parsed.String()
	if mapped, ok := a.ipMap[canonical]; ok {
		return mapped
	}
	mapped := a.token("ip", canonical)
	a.ipMap[canonical] = mapped
	return mapped
}

func (a *anonymizer) Target(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return value
	}
	if mapped, ok := a.targetMap[value]; ok {
		return mapped
	}
	mapped := a.token("target", value)
	a.targetMap[value] = mapped
	return mapped
}

func (a *anonymizer) ActorID(sourceIP string) string {
	sourceIP = strings.TrimSpace(sourceIP)
	if sourceIP == "" {
		return ""
	}
	if parsed := net.ParseIP(sourceIP); parsed != nil {
		sourceIP = parsed.String()
	}
	if id, ok := a.actorMap[sourceIP]; ok {
		return id
	}
	id := a.token("actor", sourceIP)
	a.actorMap[sourceIP] = id
	return id
}

func anonymizeActor(in model.ActorProfile, a *anonymizer) model.ActorProfile {
	originalIP := in.IP
	in.IP = a.IP(originalIP)
	in.ID = a.ActorID(originalIP)
	return in
}

func trustedTarget(target, trust string) bool {
	return strings.TrimSpace(target) != "" && strings.TrimSpace(trust) != "" && !strings.EqualFold(strings.TrimSpace(trust), "untrusted")
}

func anonymizeTargetHost(value, target string, a *anonymizer) string {
	value = strings.TrimSpace(value)
	target = strings.TrimSpace(strings.ToLower(target))
	if value == "" || target == "" {
		return value
	}
	host := strings.ToLower(strings.TrimSpace(value))
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	} else if strings.Count(host, ":") == 1 {
		host = strings.SplitN(host, ":", 2)[0]
	}
	host = strings.TrimSuffix(host, ".")
	if host == target || strings.HasSuffix(host, "."+target) {
		return a.Target(target)
	}
	return value
}

func anonymizeTargetURL(value, target string, a *anonymizer) string {
	value = strings.TrimSpace(value)
	if value == "" || target == "" {
		return value
	}
	u, err := url.Parse(value)
	if err != nil || u.Hostname() == "" {
		return value
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	target = strings.ToLower(strings.TrimSpace(target))
	if host != target && !strings.HasSuffix(host, "."+target) {
		return value
	}
	port := u.Port()
	u.Host = a.Target(target)
	if port != "" {
		u.Host += ":" + port
	}
	return u.String()
}

func anonymizeWebSession(in model.Session, a *anonymizer) model.Session {
	in.IP = a.IP(in.IP)
	if trustedTarget(in.Target, in.TargetTrust) {
		original := strings.ToLower(strings.TrimSpace(in.Target))
		in.Target = a.Target(original)
		in.RequestHost = anonymizeTargetHost(in.RequestHost, original, a)
		in.ReferrerHost = anonymizeTargetHost(in.ReferrerHost, original, a)
		in.Origin = anonymizeTargetURL(in.Origin, original, a)
		in.FirstReferrer = anonymizeTargetURL(in.FirstReferrer, original, a)
		in.LastReferrer = anonymizeTargetURL(in.LastReferrer, original, a)
	}
	return in
}

func anonymizeHTTPEvent(in model.Event, a *anonymizer) model.Event {
	in.IP = a.IP(in.IP)
	if trustedTarget(in.Target, in.TargetTrust) {
		original := strings.ToLower(strings.TrimSpace(in.Target))
		in.Target = a.Target(original)
		in.RequestHost = anonymizeTargetHost(in.RequestHost, original, a)
		in.ReferrerHost = anonymizeTargetHost(in.ReferrerHost, original, a)
		in.Origin = anonymizeTargetURL(in.Origin, original, a)
		in.Referrer = anonymizeTargetURL(in.Referrer, original, a)
	}
	return in
}

func anonymizeSSHSession(in model.SSHSession, a *anonymizer) model.SSHSession {
	in.IP = a.IP(in.IP)
	return in
}

func anonymizeSSHEvent(in model.SSHEvent, a *anonymizer) model.SSHEvent {
	in.IP = a.IP(in.IP)
	return in
}

func anonymizeIntel(in model.IntelSignal, a *anonymizer) model.IntelSignal {
	originalIP := in.IP
	in.IP = a.IP(originalIP)
	in.ActorID = a.ActorID(originalIP)
	// URL and Host intentionally remain untouched. They are attacker-referenced
	// payload/C2/IOC data, not the observed source address being anonymized.
	return in
}

func anonymizeWebExport(in model.WebSessionExport, a *anonymizer) model.WebSessionExport {
	in.Session = anonymizeWebSession(in.Session, a)
	for i := range in.Events {
		in.Events[i] = anonymizeHTTPEvent(in.Events[i], a)
	}
	return in
}

func anonymizeSSHExport(in model.SSHSessionExport, a *anonymizer) model.SSHSessionExport {
	in.Session = anonymizeSSHSession(in.Session, a)
	for i := range in.Events {
		in.Events[i] = anonymizeSSHEvent(in.Events[i], a)
	}
	if in.Actor != nil {
		cp := anonymizeActor(*in.Actor, a)
		in.Actor = &cp
	}
	for i := range in.Intel {
		in.Intel[i] = anonymizeIntel(in.Intel[i], a)
	}
	return in
}

func anonymizeIPIntelligence(in model.IPIntelligence, a *anonymizer) model.IPIntelligence {
	in.IP = a.IP(in.IP)
	in.Actor = anonymizeActor(in.Actor, a)
	for i := range in.CampaignPeers {
		in.CampaignPeers[i].IP = a.IP(in.CampaignPeers[i].IP)
	}
	for i := range in.HTTPSessions {
		in.HTTPSessions[i] = anonymizeWebSession(in.HTTPSessions[i], a)
	}
	for i := range in.HTTPEvents {
		in.HTTPEvents[i] = anonymizeHTTPEvent(in.HTTPEvents[i], a)
	}
	for i := range in.SSHSessions {
		in.SSHSessions[i] = anonymizeSSHSession(in.SSHSessions[i], a)
	}
	for i := range in.SSHEvents {
		in.SSHEvents[i] = anonymizeSSHEvent(in.SSHEvents[i], a)
	}
	for i := range in.Intelligence {
		in.Intelligence[i] = anonymizeIntel(in.Intelligence[i], a)
	}
	for i := range in.TopTargets {
		if strings.TrimSpace(in.TopTargets[i].Value) != "" {
			in.TopTargets[i].Value = a.Target(in.TopTargets[i].Value)
		}
	}
	return in
}

func safeName(value string) string {
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "entry"
	}
	return b.String()
}

func writeJSONEntry(zw *zip.Writer, name string, value any) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	return json.NewEncoder(w).Encode(value)
}

func archiveName(dataDir string, now time.Time) string {
	base := fmt.Sprintf("support_%s.zip", now.Format("2006-01-02_150405"))
	path := filepath.Join(dataDir, base)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return path
	}
	for i := 2; ; i++ {
		path = filepath.Join(dataDir, fmt.Sprintf("support_%s_%d.zip", now.Format("2006-01-02_150405"), i))
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return path
		}
	}
}

// CreateArchive creates a read-only snapshot from retained ZentLoop data and
// writes the resulting archive atomically into dataDir.
func CreateArchive(dataDir, version string, now time.Time) (string, error) {
	snapshot, err := store.LoadReadOnlySnapshot(dataDir)
	if err != nil {
		return "", err
	}
	installKey, err := loadOrCreateInstallKey(dataDir)
	if err != nil {
		return "", err
	}
	anon := newAnonymizer(installKey)

	actors := snapshot.Actors(0)
	// Allocate all known actor pseudonyms before serializing campaign peers so
	// every reference in the archive uses one stable mapping.
	for _, actor := range actors {
		_ = anon.IP(actor.IP)
		_ = anon.ActorID(actor.IP)
	}

	webSessions := snapshot.SessionsView(0, 0)
	sshSessions := snapshot.AllSSHSessions()

	finalPath := archiveName(dataDir, now)
	tmp, err := os.CreateTemp(dataDir, ".support-*.zip.tmp")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(tmpPath)
		}
	}()

	zw := zip.NewWriter(tmp)
	manifest := Manifest{
		ExportedAt:              now.UTC(),
		Version:                 version,
		SourceIPsAnonymized:     true,
		TargetsAnonymized:       true,
		ReferencedIOCsPreserved: true,
	}

	for _, actor := range actors {
		if strings.TrimSpace(actor.IP) == "" {
			continue
		}
		intel, ok := snapshot.IPIntelligence(actor.IP, version)
		if !ok {
			continue
		}
		intel.ExportedAt = now.UTC()
		intel = anonymizeIPIntelligence(intel, anon)
		name := "ip-intelligence/" + safeName(intel.IP) + ".json"
		if err := writeJSONEntry(zw, name, intel); err != nil {
			_ = zw.Close()
			_ = tmp.Close()
			return "", err
		}
		manifest.IPIntelligenceExports++
	}

	for _, ss := range sshSessions {
		ex, ok := snapshot.SSHSessionExport(ss.ID, version)
		if !ok {
			continue
		}
		ex.ExportedAt = now.UTC()
		ex = anonymizeSSHExport(ex, anon)
		name := "ssh/zentloop-ssh-" + safeName(ss.ID) + ".json"
		if err := writeJSONEntry(zw, name, ex); err != nil {
			_ = zw.Close()
			_ = tmp.Close()
			return "", err
		}
		manifest.SSHSessionExports++
	}

	for _, ss := range webSessions {
		ex, ok := snapshot.WebSessionExport(ss.ID, version)
		if !ok {
			continue
		}
		ex.ExportedAt = now.UTC()
		ex = anonymizeWebExport(ex, anon)
		name := "web/zentloop-web-" + safeName(ss.ID) + ".json"
		if err := writeJSONEntry(zw, name, ex); err != nil {
			_ = zw.Close()
			_ = tmp.Close()
			return "", err
		}
		manifest.WebSessionExports++
	}

	if err := writeJSONEntry(zw, "manifest.json", manifest); err != nil {
		_ = zw.Close()
		_ = tmp.Close()
		return "", err
	}
	if err := zw.Close(); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return "", err
	}
	keep = true
	return finalPath, nil
}
