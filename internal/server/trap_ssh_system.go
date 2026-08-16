package server

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const virtualSSHSystemStateFile = "ssh-system.json"

type virtualSSHSystemDisk struct {
	BootTime time.Time `json:"boot_time"`
	Seed     uint64    `json:"seed"`
}

type virtualSSHPeerState struct {
	CrontabExists  bool
	CrontabContent string
	Initialized    bool
}

type virtualSSHSystem struct {
	mu         sync.Mutex
	bootTime   time.Time
	seed       uint64
	lastUpdate time.Time
	load1      float64
	load5      float64
	load15     float64
	peers      map[string]virtualSSHPeerState
}

type virtualSSHSystemSnapshot struct {
	Now         time.Time
	BootTime    time.Time
	Uptime      time.Duration
	Load1       float64
	Load5       float64
	Load15      float64
	CPUUser     float64
	CPUSystem   float64
	CPUWait     float64
	CPUIdle     float64
	MemTotalMiB float64
	MemUsedMiB  float64
	MemFreeMiB  float64
	MemCacheMiB float64
	MemAvailMiB float64
}

func loadVirtualSSHSystem(dataDir string) *virtualSSHSystem {
	now := time.Now().UTC()
	state := virtualSSHSystemDisk{}
	path := filepath.Join(dataDir, virtualSSHSystemStateFile)
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &state)
	}
	if state.Seed == 0 {
		state.Seed = randomVirtualSeed()
	}
	if state.BootTime.IsZero() || state.BootTime.After(now.Add(-10*time.Minute)) || state.BootTime.Before(now.Add(-180*24*time.Hour)) {
		// Keep the decoy host looking like a normally maintained production VM,
		// without leaking the real container/host boot time.
		days := 12 + int(state.Seed%34)
		hours := 2 + int((state.Seed>>8)%18)
		minutes := int((state.Seed >> 16) % 60)
		state.BootTime = now.Add(-time.Duration(days)*24*time.Hour - time.Duration(hours)*time.Hour - time.Duration(minutes)*time.Minute).Truncate(time.Second)
	}
	_ = persistVirtualSSHSystem(path, state)
	base := 0.08 + float64(state.Seed%13)/100
	return &virtualSSHSystem{
		bootTime:   state.BootTime.UTC(),
		seed:       state.Seed,
		lastUpdate: now,
		load1:      base + 0.05,
		load5:      base + 0.03,
		load15:     base + 0.01,
		peers:      make(map[string]virtualSSHPeerState),
	}
}

func newEphemeralVirtualSSHSystem() *virtualSSHSystem {
	now := time.Now().UTC()
	seed := uint64(0x7a656e746c6f6f70)
	return &virtualSSHSystem{
		bootTime:   now.Add(-27*24*time.Hour - 7*time.Hour - 22*time.Minute).Truncate(time.Second),
		seed:       seed,
		lastUpdate: now,
		load1:      0.18,
		load5:      0.13,
		load15:     0.09,
		peers:      make(map[string]virtualSSHPeerState),
	}
}

func randomVirtualSeed() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err == nil {
		if v := binary.LittleEndian.Uint64(b[:]); v != 0 {
			return v
		}
	}
	return uint64(time.Now().UnixNano()) ^ 0xa55a6c6f6f705aa5
}

func persistVirtualSSHSystem(path string, state virtualSSHSystemDisk) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *virtualSSHSystem) snapshot() virtualSSHSystemSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	s.updateLoadsLocked(now)

	phase := float64((s.seed>>24)%360) * math.Pi / 180
	minute := float64(now.Unix()) / 60
	memTotal := 7874.2
	memUsed := 1775 + 110*math.Sin(minute/8+phase) + s.load1*85
	memCache := 2050 + 85*math.Sin(minute/13+phase/2)
	if memUsed < 1450 {
		memUsed = 1450
	}
	if memUsed > 3000 {
		memUsed = 3000
	}
	if memCache < 1750 {
		memCache = 1750
	}
	free := memTotal - memUsed - memCache
	if free < 700 {
		free = 700
	}
	avail := free + memCache*0.88

	busy := math.Min(23, 1.6+s.load1*7.3)
	user := busy * 0.69
	system := busy * 0.24
	wait := math.Max(0.1, busy*0.07)
	idle := 100 - user - system - wait
	if idle < 70 {
		idle = 70
	}

	return virtualSSHSystemSnapshot{
		Now: now, BootTime: s.bootTime, Uptime: now.Sub(s.bootTime),
		Load1: s.load1, Load5: s.load5, Load15: s.load15,
		CPUUser: user, CPUSystem: system, CPUWait: wait, CPUIdle: idle,
		MemTotalMiB: memTotal, MemUsedMiB: memUsed, MemFreeMiB: free, MemCacheMiB: memCache, MemAvailMiB: avail,
	}
}

func (s *virtualSSHSystem) updateLoadsLocked(now time.Time) {
	if s.lastUpdate.IsZero() {
		s.lastUpdate = now
		return
	}
	dt := now.Sub(s.lastUpdate).Seconds()
	if dt <= 0 {
		return
	}
	phase := float64((s.seed>>12)%360) * math.Pi / 180
	base := 0.09 + 0.035*(1+math.Sin(float64(now.Unix())/240+phase))
	s.load1 = base + (s.load1-base)*math.Exp(-dt/60)
	s.load5 = base + (s.load5-base)*math.Exp(-dt/300)
	s.load15 = base + (s.load15-base)*math.Exp(-dt/900)
	s.lastUpdate = now
}

func (s *virtualSSHSystem) markActivity(weight float64) {
	if s == nil || weight <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	s.updateLoadsLocked(now)
	s.load1 = math.Min(8.5, s.load1+weight*0.22)
	s.load5 = math.Min(5.0, s.load5+weight*0.07)
	s.load15 = math.Min(3.0, s.load15+weight*0.025)
}

func (s *virtualSSHSystem) bootID() string {
	var b [16]byte
	binary.LittleEndian.PutUint64(b[:8], s.seed)
	binary.LittleEndian.PutUint64(b[8:], s.seed^0x9e3779b97f4a7c15)
	h := hex.EncodeToString(b[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}

func (s *virtualSSHSystem) machineID() string {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], s.seed^0x4d616368696e6549)
	binary.BigEndian.PutUint64(b[8:], s.seed^0x445a656e744c6f6f)
	return hex.EncodeToString(b[:])
}

func virtualUptimeHuman(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	totalMinutes := int64(d / time.Minute)
	days := totalMinutes / (24 * 60)
	hours := (totalMinutes / 60) % 24
	mins := totalMinutes % 60
	if days > 0 {
		return fmt.Sprintf("%d days, %2d:%02d", days, hours, mins)
	}
	if hours > 0 {
		return fmt.Sprintf("%2d:%02d", hours, mins)
	}
	return fmt.Sprintf("%d min", mins)
}

func virtualUptimePretty(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	totalMinutes := int64(d / time.Minute)
	days := totalMinutes / (24 * 60)
	hours := (totalMinutes / 60) % 24
	mins := totalMinutes % 60
	parts := make([]string, 0, 3)
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%d days", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%d hours", hours))
	}
	if mins > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%d minutes", mins))
	}
	out := parts[0]
	for i := 1; i < len(parts); i++ {
		out += ", " + parts[i]
	}
	return "up " + out
}

func (s *virtualSSHSystem) peerState(key string) virtualSSHPeerState {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.peers == nil {
		s.peers = make(map[string]virtualSSHPeerState)
	}
	return s.peers[key]
}

func (s *virtualSSHSystem) setPeerCrontab(key string, exists bool, content string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.peers == nil {
		s.peers = make(map[string]virtualSSHPeerState)
	}
	s.peers[key] = virtualSSHPeerState{CrontabExists: exists, CrontabContent: content, Initialized: true}
}
