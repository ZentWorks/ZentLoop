package store

import (
	"log"
	"os"
)

func (s *Store) syncEventFiles() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.syncEventFilesLocked()
}

func (s *Store) syncEventFilesLocked() error {
	var first error
	for _, f := range []*os.File{s.eventFile, s.sshEventFile, s.intelEventFile} {
		if f == nil {
			continue
		}
		if err := f.Sync(); err != nil && first == nil {
			first = err
		}
	}
	if first != nil {
		s.health.StorageSyncFailures++
		log.Printf("ZentLoop durable event sync failed: %v", first)
	}
	return first
}
