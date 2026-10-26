package sensor

import (
	"context"
	"errors"
	"time"
)

// Close stops ingestion and background loops, drains queued work, withdraws
// simulatable/real mitigations, and saves durable state. It is safe to call
// more than once.
func (s *Sensor) Close(ctx context.Context) error {
	var result error
	s.closeOnce.Do(func() {
		s.lifecycleMu.Lock()
		started := s.started
		cancel := s.cancel
		conn := s.conn
		s.closed.Store(true)
		s.lifecycleMu.Unlock()
		s.running.Store(false)

		if !started {
			s.notifier.Close()
			s.hub.Close()
			return
		}
		if cancel != nil {
			cancel()
		}
		if conn != nil {
			_ = conn.Close()
		}
		s.readWG.Wait()
		close(s.datagrams)
		s.ingestWG.Wait()
		close(s.ruleObservations)
		s.loopWG.Wait()
		close(s.findings)
		s.controlWG.Wait()

		shutdownTimeout := 20 * time.Second
		if ctx != nil {
			if deadline, ok := ctx.Deadline(); ok {
				remaining := time.Until(deadline)
				if remaining > 0 && remaining < shutdownTimeout {
					shutdownTimeout = remaining
				}
			}
		}
		shutdownCtx, stop := context.WithTimeout(context.Background(), shutdownTimeout)
		defer stop()
		var errs []error
		if s.mitigator != nil {
			if err := s.mitigator.Shutdown(shutdownCtx); err != nil {
				errs = append(errs, err)
			}
		}
		s.notifier.Close()
		if s.intel != nil {
			if err := s.intel.Save(true); err != nil {
				errs = append(errs, err)
			}
		}
		if s.bgp != nil {
			s.bgp.Close()
		}
		s.hub.Close()
		result = errors.Join(errs...)
	})
	return result
}
