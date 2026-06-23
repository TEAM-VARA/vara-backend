package scheduler

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vara/backend/internal/iamprivesc/engine"
	"github.com/vara/backend/internal/repository/postgres"
)

// IamPrivescScheduler 는 주기적으로 소스 DB(iam_authorization_snapshots)를 읽어
// IAM 권한상승(privilege-escalation) posture 를 탐지하고 결과를 result 테이블
// (scan_runs / principal_results / findings)에 적재한다.
//
// 별도 CLI 없이 cmd/server 안에서 자동 실행되는 운영 경로다. 탐지 로직은
// 순수 엔진(internal/iamprivesc/engine)을, 입출력은 IamPrivescRepo 를 재사용한다.
type IamPrivescScheduler struct {
	repo     *postgres.IamPrivescRepo
	ruleset  engine.Ruleset
	coreOnly bool

	interval time.Duration
	enabled  bool

	stop chan struct{}
}

// NewIamPrivescScheduler 생성자.
//
//	pool:      vara DB 풀(소스/결과 동일 인스턴스)
//	rulesPath: 룰셋 경로(빈 문자열이면 내장 top9 룰셋)
//	interval:  스캔 주기(0이면 1시간)
func NewIamPrivescScheduler(pool *pgxpool.Pool, rulesPath string, interval time.Duration) (*IamPrivescScheduler, error) {
	rs, err := engine.LoadRuleset(rulesPath)
	if err != nil {
		return nil, err
	}
	if interval == 0 {
		interval = 10 * time.Minute
	}
	return &IamPrivescScheduler{
		repo:     postgres.NewIamPrivescRepo(pool),
		ruleset:  rs,
		coreOnly: false,
		interval: interval,
		enabled:  true,
		stop:     make(chan struct{}),
	}, nil
}

// Start 는 백그라운드 goroutine 으로 스케줄러를 시작한다.
func (s *IamPrivescScheduler) Start(ctx context.Context) {
	if !s.enabled {
		log.Printf("scheduler: iam-privesc is disabled")
		return
	}
	log.Printf("scheduler: iam-privesc started (interval=%v, ruleset=%s)", s.interval, s.ruleset.Name)

	go func() {
		// 서버 부팅 후 20분 뒤 첫 실행.
		time.Sleep(20 * time.Minute)
		s.runScan(ctx)

		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Printf("scheduler: iam-privesc stopped (context cancelled)")
				return
			case <-s.stop:
				log.Printf("scheduler: iam-privesc stopped (manual)")
				return
			case <-ticker.C:
				s.runScan(ctx)
			}
		}
	}()
}

// Stop 은 스케줄러를 중지한다.
func (s *IamPrivescScheduler) Stop() { close(s.stop) }

// runScan 은 한 번의 탐지 사이클: 모든 계정 스냅샷 읽기 → 탐지 → 결과 적재.
func (s *IamPrivescScheduler) runScan(ctx context.Context) {
	start := time.Now()

	snaps, err := s.repo.ReadSnapshots(ctx, "") // 전체 계정(각 최신 1행)
	if err != nil {
		log.Printf("scheduler: iam-privesc read snapshots failed: %v", err)
		return
	}
	if len(snaps) == 0 {
		log.Printf("scheduler: iam-privesc no snapshots to scan")
		return
	}

	accounts, criticalTotal := 0, 0
	for _, snap := range snaps {
		results, sum := engine.DetectSnapshot(snap, s.ruleset)
		runID, werr := s.repo.WriteResults(ctx, snap, results, sum, s.ruleset, s.coreOnly)
		if werr != nil {
			log.Printf("scheduler: iam-privesc write failed (account=%s): %v", snap.AccountID, werr)
			continue
		}
		accounts++
		criticalTotal += sum.Critical
		log.Printf("scheduler: iam-privesc account=%s run_id=%d total=%d critical=%d warning=%d info=%d ok=%d",
			snap.AccountID, runID, sum.Total, sum.Critical, sum.Warning, sum.Info, sum.Ok)
	}

	log.Printf("scheduler: iam-privesc scan done, accounts=%d, critical_total=%d, duration=%v",
		accounts, criticalTotal, time.Since(start))
}
