package model

import (
	"encoding/json"
	"time"
)

// MarshalJSON keeps legacy Target Reality states honest without serializing
// Go's year-one zero time as if it were a real historical commit timestamp.
func (s TargetRealityState) MarshalJSON() ([]byte, error) {
	type wire struct {
		Target         string            `json:"target"`
		Technology     string            `json:"technology,omitempty"`
		Confidence     string            `json:"confidence,omitempty"`
		Locked         bool              `json:"locked"`
		Cloud          string            `json:"cloud,omitempty"`
		Evidence       map[string]int    `json:"evidence,omitempty"`
		PublicFacts    map[string]string `json:"public_facts,omitempty"`
		Revision       uint64            `json:"revision,omitempty"`
		CommittedAt    *time.Time        `json:"committed_at,omitempty"`
		UpdatedAt      *time.Time        `json:"updated_at,omitempty"`
		LastSeen       *time.Time        `json:"last_seen,omitempty"`
		MetadataStatus string            `json:"metadata_status,omitempty"`
	}
	out := wire{
		Target:      s.Target,
		Technology:  s.Technology,
		Confidence:  s.Confidence,
		Locked:      s.Locked,
		Cloud:       s.Cloud,
		Evidence:    s.Evidence,
		PublicFacts: s.PublicFacts,
		Revision:    s.Revision,
	}
	if !s.CommittedAt.IsZero() {
		v := s.CommittedAt
		out.CommittedAt = &v
	}
	if !s.UpdatedAt.IsZero() {
		v := s.UpdatedAt
		out.UpdatedAt = &v
	}
	if !s.LastSeen.IsZero() {
		v := s.LastSeen
		out.LastSeen = &v
	}
	if s.Revision > 0 && (s.CommittedAt.IsZero() || s.UpdatedAt.IsZero()) {
		out.MetadataStatus = "legacy"
	}
	return json.Marshal(out)
}
