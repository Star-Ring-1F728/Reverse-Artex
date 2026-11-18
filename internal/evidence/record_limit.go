package evidence

import "errors"

// LimitRecords aligns live admission with the bounded replay reader. Configure
// before serving. Counts are reconstructed from retained immutable/active files,
// never inferred from compressed byte lengths or a new unaudited sidecar.
func (s *Store) LimitRecords(limit int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit < 1 || s.closed || s.records != nil {
		return errors.New("invalid evidence replay record limit")
	}
	names := []string{"events", "alerts", "evaluations", "host-events", "host-alerts", "host-evaluations"}
	if s.ownedStream != "" {
		names = []string{s.ownedStream}
	}
	counts := make(map[string]int, len(names))
	for _, name := range names {
		counts[name] = 0
		if err := s.visitRecords(name, func([]byte) error {
			counts[name]++
			if counts[name] > limit {
				return errors.New("evidence replay record budget exceeded")
			}
			return nil
		}); err != nil {
			return err
		}
	}
	s.records, s.recordLimit = counts, limit
	return nil
}

// Called under Store.mu before any bytes of the admission are written.
func (s *Store) admitRecords(name string, count int) error {
	if s.records != nil {
		if _, ok := s.records[name]; !ok {
			return errors.New("stream is outside evidence replay record budget")
		}
	}
	if s.recordLimit > 0 && count > s.recordLimit-s.records[name] {
		return errors.New("evidence replay record budget exceeded")
	}
	return nil
}
