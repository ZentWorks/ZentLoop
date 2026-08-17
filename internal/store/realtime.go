package store

import "zentloop/internal/model"

type realtimeSubscriber struct {
	ch     chan model.RealtimeMessage
	missed bool
}

func (s *Store) publishRealtimeLocked(msg model.RealtimeMessage) {
	for sub := range s.realtimeSubs {
		if sub.missed {
			select {
			case sub.ch <- model.RealtimeMessage{Type: "resync_required", At: msg.At}:
				sub.missed = false
			default:
			}
			continue
		}
		select {
		case sub.ch <- msg:
		default:
			sub.missed = true
		}
	}
}

func (s *Store) SubscribeRealtime() (<-chan model.RealtimeMessage, func(), bool) {
	sub := &realtimeSubscriber{ch: make(chan model.RealtimeMessage, 128)}
	s.mu.Lock()
	if len(s.realtimeSubs) >= maxRealtimeSubscribers {
		s.health.RealtimeSubscriberRejected++
		s.mu.Unlock()
		return nil, func() {}, false
	}
	s.realtimeSubs[sub] = struct{}{}
	s.mu.Unlock()
	cancel := func() {
		s.mu.Lock()
		if _, ok := s.realtimeSubs[sub]; ok {
			delete(s.realtimeSubs, sub)
			close(sub.ch)
		}
		s.mu.Unlock()
	}
	return sub.ch, cancel, true
}
