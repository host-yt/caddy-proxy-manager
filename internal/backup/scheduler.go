package backup

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Scheduler periodically runs backups for every enabled destination based on
// the `backup.schedule_interval_hours` setting (0 disables).
//
// We intentionally use a simple interval (not cron) to avoid adding a
// dependency. Cron-style schedules can come later.
type Scheduler struct {
	Service *Service
}

// Run blocks until ctx done. Spawned as a goroutine from main.
func (s *Scheduler) Run(ctx context.Context) {
	// Reuse a single Timer instead of time.After per loop: under leader churn
	// (Redis flapping) a fresh time.After each iteration leaks timers that the
	// runtime can't free until they fire (up to hours away).
	t := time.NewTimer(s.nextInterval(ctx))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.tick(ctx)
		t.Reset(s.nextInterval(ctx))
	}
}

func (s *Scheduler) nextInterval(ctx context.Context) time.Duration {
	h := s.intervalHours(ctx)
	if h <= 0 {
		return 30 * time.Minute // re-check schedule setting periodically
	}
	return time.Duration(h) * time.Hour
}

func (s *Scheduler) intervalHours(ctx context.Context) int {
	if s.Service == nil || s.Service.DB == nil {
		return 0
	}
	db := s.Service.DB()
	if db == nil {
		return 0
	}
	var v string
	err := db.QueryRowContext(ctx,
		"SELECT value FROM settings WHERE `key` = 'backup.schedule_interval_hours'").Scan(&v)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0
	}
	return n
}

func (s *Scheduler) tick(ctx context.Context) {
	if s.Service == nil {
		return
	}
	if s.intervalHours(ctx) <= 0 {
		return
	}
	encrypt := s.encryptByDefault(ctx)
	dests, err := s.Service.LoadDestinations(ctx, true)
	if err != nil {
		s.Service.Logger.Warn("backup scheduler: load destinations", "err", err)
		return
	}
	// Fan out destinations: each gets its own 30min budget so one hung
	// upload (e.g. an FTP stall before the OS TCP timeout) can't block the
	// remaining destinations and miss the whole window.
	var wg sync.WaitGroup
	for _, d := range dests {
		wg.Add(1)
		go func(d Destination) {
			defer wg.Done()
			runCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
			defer cancel()
			if _, err := s.Service.Run(runCtx, RunOptions{
				DestinationID: d.ID,
				Kind:          "scheduled",
				Encrypt:       encrypt,
			}); err != nil {
				s.Service.Logger.Warn("backup scheduler: run failed", "dest", d.Name, "err", err)
			}
		}(d)
	}
	wg.Wait()
	s.pruneOldJobs(ctx)
}

func (s *Scheduler) encryptByDefault(ctx context.Context) bool {
	db := s.Service.DB()
	if db == nil {
		return true
	}
	var v string
	if err := db.QueryRowContext(ctx,
		"SELECT value FROM settings WHERE `key` = 'backup.encrypt'").Scan(&v); err != nil {
		return true
	}
	return v != "0"
}

func (s *Scheduler) pruneOldJobs(ctx context.Context) {
	db := s.Service.DB()
	if db == nil {
		return
	}
	var v string
	if err := db.QueryRowContext(ctx,
		"SELECT value FROM settings WHERE `key` = 'backup.retention_days'").Scan(&v); err != nil {
		return
	}
	days, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || days <= 0 {
		return
	}
	_, _ = db.ExecContext(ctx,
		"DELETE FROM backup_jobs WHERE created_at < (NOW() - INTERVAL ? DAY)", days)
}
