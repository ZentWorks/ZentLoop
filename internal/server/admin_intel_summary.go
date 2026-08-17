package server

import (
	"sort"
	"strings"

	"zentloop/internal/model"
)

func intelIndicator(i model.IntelSignal) string {
	if v := strings.TrimSpace(i.Canary); v != "" {
		return "canary:" + v
	}
	for _, v := range []string{i.URL, i.Host, i.Filename, i.Summary} {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return "(unknown)"
}

func aggregateIntel(rows []model.IntelSignal, limit int) []model.IntelSummary {
	type bucket struct {
		row       model.IntelSummary
		protocols map[string]struct{}
		tools     map[string]struct{}
	}
	buckets := make(map[string]*bucket)
	for _, item := range rows {
		indicator := intelIndicator(item)
		kind := strings.TrimSpace(item.Kind)
		if kind == "" {
			kind = "unknown"
		}
		key := kind + "\x00" + indicator
		b := buckets[key]
		if b == nil {
			b = &bucket{
				row:       model.IntelSummary{Indicator: indicator, Kind: kind, FirstSeen: item.At, LastSeen: item.At},
				protocols: make(map[string]struct{}),
				tools:     make(map[string]struct{}),
			}
			buckets[key] = b
		}
		b.row.Count++
		if b.row.FirstSeen.IsZero() || item.At.Before(b.row.FirstSeen) {
			b.row.FirstSeen = item.At
		}
		if b.row.LastSeen.IsZero() || item.At.After(b.row.LastSeen) {
			b.row.LastSeen = item.At
		}
		if protocol := strings.TrimSpace(item.Protocol); protocol != "" {
			b.protocols[protocol] = struct{}{}
		}
		tool := strings.TrimSpace(item.Tool)
		if tool == "" {
			tool = strings.TrimSpace(item.Technique)
		}
		if tool != "" {
			b.tools[tool] = struct{}{}
		}
	}

	out := make([]model.IntelSummary, 0, len(buckets))
	for _, b := range buckets {
		for protocol := range b.protocols {
			b.row.Protocols = append(b.row.Protocols, protocol)
		}
		for tool := range b.tools {
			b.row.Tools = append(b.row.Tools, tool)
		}
		sort.Strings(b.row.Protocols)
		sort.Strings(b.row.Tools)
		out = append(out, b.row)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastSeen.Equal(out[j].LastSeen) {
			if out[i].Count == out[j].Count {
				return out[i].Indicator < out[j].Indicator
			}
			return out[i].Count > out[j].Count
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
