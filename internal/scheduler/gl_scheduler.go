package scheduler

import (
	"context"
	"log"
	"time"

	"github.com/vara/backend/internal/service"
)

// GLScheduler runs GL-layer (guideline-based LLM) compliance checks periodically.
// For each (company_id, isms_p_item_id) pair that has stored guidelines with extracted text,
// it creates a guideline-only check and runs the async worker (evaluateLLMRAGEntailment etc.).
type GLScheduler struct {
	svc      *service.GRCService
	interval time.Duration
	stop     chan struct{}
}

func NewGLScheduler(svc *service.GRCService, interval time.Duration) *GLScheduler {
	if interval == 0 {
		interval = 24 * time.Hour
	}
	return &GLScheduler{
		svc:      svc,
		interval: interval,
		stop:     make(chan struct{}),
	}
}

// Start launches the GL scheduler as a background goroutine.
// Initial delay is 90s to stagger startup load relative to other schedulers.
func (s *GLScheduler) Start(ctx context.Context) {
	log.Printf("gl-scheduler: started (interval=%v)", s.interval)

	go func() {
		// 서버 시작 90초 후 첫 실행 (GRC 스케줄러 60초보다 늦게 — 부하 분산)
		time.Sleep(90 * time.Second)
		s.run(ctx)

		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Printf("gl-scheduler: stopped (context cancelled)")
				return
			case <-s.stop:
				log.Printf("gl-scheduler: stopped (manual)")
				return
			case <-ticker.C:
				s.run(ctx)
			}
		}
	}()
}

func (s *GLScheduler) Stop() {
	close(s.stop)
}

func (s *GLScheduler) run(ctx context.Context) {
	start := time.Now()

	// Claude API 키 미설정이면 GL 평가를 아예 스킵한다. 돌려봤자 모든 GL 룰이 INDETERMINATE로
	// 저장되어 기존의 좋은 판정을 덮어쓰므로, 트리거조차 하지 않고 직전 결과를 보존한다.
	if !s.svc.VLMAvailable(ctx) {
		log.Printf("gl-scheduler: VLM(Claude) 미설정 — GL 평가 스킵(기존 결과 보존)")
		return
	}

	targets, err := s.svc.ListGLCheckTargets(ctx)
	if err != nil {
		log.Printf("gl-scheduler: failed to list GL check targets: %v", err)
		return
	}

	if len(targets) == 0 {
		log.Printf("gl-scheduler: no guideline targets found, skipping")
		return
	}

	log.Printf("gl-scheduler: running GL checks for %d (company, item) pairs", len(targets))

	succeeded, failed := 0, 0
	for _, t := range targets {
		chk, err := s.svc.TriggerGLCheck(ctx, t.CompanyID, t.ISMSPItemID)
		if err != nil {
			log.Printf("gl-scheduler: trigger failed for company=%s item=%s: %v", t.CompanyID, t.ISMSPItemID, err)
			failed++
			continue
		}
		log.Printf("gl-scheduler: triggered check=%s for company=%s item=%s", chk.CheckID, t.CompanyID, t.ISMSPItemID)
		succeeded++
	}

	log.Printf("gl-scheduler: done (succeeded=%d failed=%d duration=%v)", succeeded, failed, time.Since(start))
}
