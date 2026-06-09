package scheduler

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RetentionScheduler: ebpf_network_flows를 주기적으로 정리 (시간 + 행수 기준)
type RetentionScheduler struct {
	pg       *pgxpool.Pool
	interval time.Duration
	maxAge   time.Duration
	maxRows  int64
}

func NewRetentionScheduler(pg *pgxpool.Pool, interval, maxAge time.Duration, maxRows int64) *RetentionScheduler {
	return &RetentionScheduler{pg: pg, interval: interval, maxAge: maxAge, maxRows: maxRows}
}

func (s *RetentionScheduler) Start(ctx context.Context) {
	log.Printf("scheduler: flow retention started (interval=%v, maxAge=%v, maxRows=%d)", s.interval, s.maxAge, s.maxRows)
	ticker := time.NewTicker(s.interval)
	go func() {
		defer ticker.Stop()
		s.prune(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.prune(ctx)
			}
		}
	}()
}

func (s *RetentionScheduler) prune(ctx context.Context) {
	days := int(s.maxAge.Hours() / 24)
	if tag, err := s.pg.Exec(ctx,
		`DELETE FROM ebpf_network_flows WHERE timestamp < NOW() - make_interval(days => $1)`, days); err != nil {
		log.Printf("scheduler: flow retention age prune error: %v", err)
	} else if tag.RowsAffected() > 0 {
		log.Printf("scheduler: flow retention age prune: %d rows", tag.RowsAffected())
	}

	if tag, err := s.pg.Exec(ctx,
		`DELETE FROM ebpf_network_flows WHERE id < (SELECT id FROM ebpf_network_flows ORDER BY id DESC OFFSET $1 LIMIT 1)`, s.maxRows); err != nil {
		log.Printf("scheduler: flow retention cap prune error: %v", err)
	} else if tag.RowsAffected() > 0 {
		log.Printf("scheduler: flow retention cap prune: %d rows", tag.RowsAffected())
	}
}
