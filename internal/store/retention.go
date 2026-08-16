package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

const retentionSweepInterval = 15 * time.Minute

func (s *Store) retentionLoop() {
	defer close(s.retentionDone)
	ticker := time.NewTicker(retentionSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := s.pruneExpired(time.Now()); err != nil {
				log.Printf("ZentLoop retention cleanup failed: %v", err)
			}
		case <-s.retentionStop:
			return
		}
	}
}

func (s *Store) pruneExpired(now time.Time) error {
	cutoff := now.AddDate(0, 0, -s.retentionDays)
	s.mu.Lock()
	defer s.mu.Unlock()

	targets := []struct {
		name string
		file **os.File
	}{
		{"events.jsonl", &s.eventFile},
		{"ssh-events.jsonl", &s.sshEventFile},
		{"intel-events.jsonl", &s.intelEventFile},
	}
	for _, target := range targets {
		if err := compactJSONL(filepath.Join(s.dataDir, target.name), cutoff, target.file); err != nil {
			return fmt.Errorf("%s: %w", target.name, err)
		}
	}
	return nil
}

func pruneJSONLPaths(dataDir string, retentionDays int, now time.Time) error {
	if retentionDays < 1 {
		retentionDays = 1
	}
	if retentionDays > 30 {
		retentionDays = 30
	}
	cutoff := now.AddDate(0, 0, -retentionDays)
	for _, name := range []string{"events.jsonl", "ssh-events.jsonl", "intel-events.jsonl"} {
		if err := compactJSONL(filepath.Join(dataDir, name), cutoff, nil); err != nil {
			return fmt.Errorf("retention cleanup %s: %w", name, err)
		}
	}
	return nil
}

func compactJSONL(path string, cutoff time.Time, active **os.File) error {
	if active != nil && *active != nil {
		if err := (*active).Sync(); err != nil {
			return err
		}
		if err := (*active).Close(); err != nil {
			return err
		}
		*active = nil
	}

	reopen := func() error {
		if active == nil {
			return nil
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			return err
		}
		*active = f
		return nil
	}

	src, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return reopen()
	}
	if err != nil {
		_ = reopen()
		return err
	}

	tmp := path + ".retention.tmp"
	_ = os.Remove(tmp)
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		_ = src.Close()
		_ = reopen()
		return err
	}

	ok := false
	defer func() {
		_ = src.Close()
		_ = out.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()

	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	writer := bufio.NewWriter(out)
	for scanner.Scan() {
		line := scanner.Bytes()
		var stamp struct {
			At time.Time `json:"at"`
		}
		if json.Unmarshal(line, &stamp) != nil || stamp.At.IsZero() || stamp.At.Before(cutoff) {
			continue
		}
		if _, err := writer.Write(line); err != nil {
			_ = reopen()
			return err
		}
		if err := writer.WriteByte('\n'); err != nil {
			_ = reopen()
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		_ = reopen()
		return err
	}
	if err := writer.Flush(); err != nil {
		_ = reopen()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = reopen()
		return err
	}
	if err := out.Close(); err != nil {
		_ = reopen()
		return err
	}
	if err := src.Close(); err != nil {
		_ = reopen()
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = reopen()
		return err
	}
	ok = true
	return reopen()
}
