package store

import (
	"strings"
	"time"

	"zentloop/internal/model"
)

func hourKey(t time.Time) int64 { return t.Truncate(time.Hour).Unix() }

func localDayStart(t time.Time) time.Time {
	t = t.In(time.Local)
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.Local)
}

func activityTarget(e model.Event) string {
	target := strings.TrimSpace(e.Target)
	if target == "" {
		target = strings.TrimSpace(e.RequestHost)
	}
	return target
}

func (s *Store) countHTTPActivityLocked(e model.Event) {
	if s.httpHourCounts == nil {
		s.httpHourCounts = make(map[int64]map[string]int64)
	}
	hour := hourKey(e.At)
	byTarget := s.httpHourCounts[hour]
	if byTarget == nil {
		byTarget = make(map[string]int64)
		s.httpHourCounts[hour] = byTarget
	}
	byTarget[activityTarget(e)]++
	s.countIPDailyActivityLocked(e.IP, e.At, true)
}

func (s *Store) countSSHActivityLocked(e model.SSHEvent) {
	if !sshActivityType(e.Type) {
		return
	}
	if s.sshHourCounts == nil {
		s.sshHourCounts = make(map[int64]int64)
	}
	s.sshHourCounts[hourKey(e.At)]++
	s.countIPDailyActivityLocked(e.IP, e.At, false)
}

func (s *Store) countIPDailyActivityLocked(ip string, at time.Time, http bool) {
	if s.ipDailyActivity == nil {
		s.ipDailyActivity = make(map[string]map[int64]*model.IPActivityBucket)
	}
	ip = strings.TrimSpace(ip)
	if ip == "" || at.IsZero() {
		return
	}
	day := localDayStart(at).Unix()
	rows := s.ipDailyActivity[ip]
	if rows == nil {
		rows = make(map[int64]*model.IPActivityBucket)
		s.ipDailyActivity[ip] = rows
	}
	b := rows[day]
	if b == nil {
		b = &model.IPActivityBucket{At: time.Unix(day, 0).In(time.Local)}
		rows[day] = b
	}
	if http {
		b.HTTP++
	} else {
		b.SSH++
	}
}

func sshActivityType(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "connect", "auth", "shell", "exec", "command", "request":
		return true
	default:
		return false
	}
}

// ActivityTimeline renders fixed calendar-day filters as a full 00:00-23:00
// day. Open/live ranges keep the current hour on the right, look back at most
// 24 hours and trim leading empty buckets before the first matching activity.
func (s *Store) durableHTTPCountRangeLocked(from, to time.Time, target string) (int64, bool) {
	if from.IsZero() || !from.Equal(from.Truncate(time.Hour)) || (!to.IsZero() && !to.Equal(to.Truncate(time.Hour))) {
		return 0, false
	}
	var total int64
	for key, byTarget := range s.httpHourCounts {
		at := time.Unix(key, 0)
		if at.Before(from) || (!to.IsZero() && !at.Before(to)) {
			continue
		}
		for rawTarget, count := range byTarget {
			if target == "" || s.targetFilterMatchesLocked(rawTarget, target) {
				total += count
			}
		}
	}
	return total, true
}

func (s *Store) ActivityTimeline(from, to time.Time, target string) model.ActivityTimeline {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activityTimelineLocked(from, to, target, time.Now())
}

func (s *Store) activityTimelineLocked(from, to time.Time, target string, now time.Time) model.ActivityTimeline {
	fixedDay := !from.IsZero() && !to.IsZero() && to.After(from) && to.Sub(from) <= 25*time.Hour
	var start, end time.Time
	if fixedDay {
		start = from.Truncate(time.Hour)
		end = start.Add(24 * time.Hour)
	} else {
		// LIVE: the current clock hour is always the newest bucket. Respect the
		// client's live lower bound when supplied, but never exceed 24 buckets.
		end = now.Truncate(time.Hour).Add(time.Hour)
		start = end.Add(-24 * time.Hour)
		if !from.IsZero() {
			wanted := from.Truncate(time.Hour)
			if wanted.After(start) && wanted.Before(end) {
				start = wanted
			}
		}
	}

	bucketCount := int(end.Sub(start) / time.Hour)
	if bucketCount < 1 {
		bucketCount = 1
	}
	if bucketCount > 24 {
		bucketCount = 24
	}
	buckets := make([]model.IPActivityBucket, 0, bucketCount)
	for i := 0; i < bucketCount; i++ {
		at := start.Add(time.Duration(i) * time.Hour)
		key := hourKey(at)
		var httpCount int64
		for rawTarget, count := range s.httpHourCounts[key] {
			if target == "" || s.targetFilterMatchesLocked(rawTarget, target) {
				httpCount += count
			}
		}
		sshCount := int64(0)
		if strings.TrimSpace(target) == "" {
			sshCount = s.sshHourCounts[key]
		}
		buckets = append(buckets, model.IPActivityBucket{At: at, HTTP: httpCount, SSH: sshCount})
	}

	if !fixedDay && len(buckets) > 1 {
		firstActive := -1
		for i, b := range buckets {
			if b.HTTP > 0 || b.SSH > 0 {
				firstActive = i
				break
			}
		}
		if firstActive > 0 {
			buckets = buckets[firstActive:]
		} else if firstActive < 0 {
			// With no activity at all, keep only the current hour instead of
			// drawing a misleading empty 24-hour span.
			buckets = buckets[len(buckets)-1:]
		}
	}

	outFrom := start
	if len(buckets) > 0 {
		outFrom = buckets[0].At
	}
	return model.ActivityTimeline{Unit: "hour", From: outFrom, To: end, Buckets: buckets}
}

func (s *Store) ipDailyTimelineLocked(ip string, now time.Time) []model.IPActivityBucket {
	rows := s.ipDailyActivity[ip]
	if len(rows) == 0 {
		return nil
	}

	// Show only the period in which this IP actually exists in retained data.
	// Keep zero-activity days inside that period so spacing remains truthful,
	// but never pad the chart with empty days before the IP first appeared.
	var firstKey, lastKey int64
	for key, bucket := range rows {
		if bucket == nil || (bucket.HTTP == 0 && bucket.SSH == 0) {
			continue
		}
		if firstKey == 0 || key < firstKey {
			firstKey = key
		}
		if lastKey == 0 || key > lastKey {
			lastKey = key
		}
	}
	if firstKey == 0 || lastKey == 0 {
		return nil
	}

	start := time.Unix(firstKey, 0).In(time.Local)
	end := time.Unix(lastKey, 0).In(time.Local)
	maxStart := end.AddDate(0, 0, -89)
	if start.Before(maxStart) {
		start = maxStart
	}

	days := 1
	for at := start; at.Before(end) && days < 90; at = at.AddDate(0, 0, 1) {
		days++
	}
	out := make([]model.IPActivityBucket, 0, days)
	for i := 0; i < days; i++ {
		at := start.AddDate(0, 0, i)
		key := at.Unix()
		b := model.IPActivityBucket{At: at}
		if existing := rows[key]; existing != nil {
			b.HTTP = existing.HTTP
			b.SSH = existing.SSH
		}
		out = append(out, b)
	}
	return out
}

func (s *Store) pruneActivityAggregatesLocked(cutoff time.Time) {
	hourCutoff := cutoff.Truncate(time.Hour).Unix()
	for key := range s.httpHourCounts {
		if key < hourCutoff {
			delete(s.httpHourCounts, key)
		}
	}
	for key := range s.sshHourCounts {
		if key < hourCutoff {
			delete(s.sshHourCounts, key)
		}
	}
	dayCutoff := localDayStart(cutoff).Unix()
	for ip, rows := range s.ipDailyActivity {
		for key := range rows {
			if key < dayCutoff {
				delete(rows, key)
			}
		}
		if len(rows) == 0 {
			delete(s.ipDailyActivity, ip)
		}
	}
}
