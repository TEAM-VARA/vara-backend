package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/vara/backend/internal/domain/notification"
	"github.com/vara/backend/internal/domain/sbom"
	"github.com/vara/backend/internal/service"
)

// VulnScheduler는 매시간 자동으로 OSV.dev에서 vulnerability를 재조회하고,
// 신규 CVE 발견 시 알림 생성 + Risk Scoring 재계산을 수행합니다.
type VulnScheduler struct {
	vulnSvc  *service.PackageVulnService
	notifSvc *service.NotificationService
	finalSvc *service.FinalScoringService

	clusterName string
	interval    time.Duration
	enabled     bool

	mu       sync.Mutex
	lastScan time.Time

	stop chan struct{}
}

// NewVulnScheduler creates a new scheduler.
//
// interval: 스캔 주기 (예: 1 * time.Hour)
// clusterName: 알림 생성 시 사용할 클러스터 이름
func NewVulnScheduler(
	vulnSvc *service.PackageVulnService,
	notifSvc *service.NotificationService,
	finalSvc *service.FinalScoringService,
	clusterName string,
	interval time.Duration,
) *VulnScheduler {
	if interval == 0 {
		interval = 1 * time.Hour
	}
	return &VulnScheduler{
		vulnSvc:     vulnSvc,
		notifSvc:    notifSvc,
		finalSvc:    finalSvc,
		clusterName: clusterName,
		interval:    interval,
		enabled:     true,
		stop:        make(chan struct{}),
	}
}

// Start는 백그라운드 goroutine으로 스케줄러를 시작합니다.
func (s *VulnScheduler) Start(ctx context.Context) {
	if !s.enabled {
		log.Printf("scheduler: vuln scanner is disabled")
		return
	}

	log.Printf("scheduler: vuln scanner started (interval=%v, cluster=%s)", s.interval, s.clusterName)

	go func() {
		// 시작 30초 후 첫 실행 (서버 안정화 대기)
		time.Sleep(30 * time.Second)
		s.runScan(ctx)

		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Printf("scheduler: vuln scanner stopped (context cancelled)")
				return
			case <-s.stop:
				log.Printf("scheduler: vuln scanner stopped (manual)")
				return
			case <-ticker.C:
				s.runScan(ctx)
			}
		}
	}()
}

// Stop은 스케줄러를 중지합니다.
func (s *VulnScheduler) Stop() {
	close(s.stop)
}

// runScan은 한 번의 스캔 사이클을 실행합니다.
func (s *VulnScheduler) runScan(ctx context.Context) {
	s.mu.Lock()
	scanStart := time.Now()
	s.lastScan = scanStart
	s.mu.Unlock()

	log.Printf("scheduler: starting periodic vuln scan at %v", scanStart.Format(time.RFC3339))

	// 1. 모든 이미지 digest 조회
	digests, err := s.vulnSvc.ListAllImageDigests(ctx)
	if err != nil {
		log.Printf("scheduler: list images failed: %v", err)
		return
	}

	if len(digests) == 0 {
		log.Printf("scheduler: no images to scan")
		return
	}

	// 2. 각 이미지 스캔 (force=false: 캐시 활용)
	totalImages := len(digests)
	scanned := 0
	totalNewVulns := 0

	for _, digest := range digests {
		result, err := s.vulnSvc.ScanImage(ctx, digest, false)
		if err != nil {
			log.Printf("scheduler: scan failed for %s: %v", digest, err)
			continue
		}
		scanned++
		totalNewVulns += result.NewVulns
	}

	duration := time.Since(scanStart)
	log.Printf("scheduler: scan done, images=%d, scanned=%d, new_vulns=%d, duration=%v",
		totalImages, scanned, totalNewVulns, duration)

	// 3. 신규 critical/high vuln 처리
	if totalNewVulns > 0 {
		s.processNewVulns(ctx, scanStart)
	}

	// 4. 스캔 완료 알림 (info 등급)
	s.createScanCompleteNotif(ctx, totalImages, scanned, totalNewVulns, duration)
}

// processNewVulns는 이번 스캔에서 새로 발견된 critical/high CVE를 처리합니다.
func (s *VulnScheduler) processNewVulns(ctx context.Context, scanStart time.Time) {
	// fetched_at >= scanStart인 critical/high vuln만 조회
	newVulns, err := s.vulnSvc.ListRecentlyAdded(
		ctx, scanStart, []string{"Critical", "High"},
	)
	if err != nil {
		log.Printf("scheduler: list recently added failed: %v", err)
		return
	}

	if len(newVulns) == 0 {
		return
	}

	// vuln_id 별로 그룹화 (한 vuln이 여러 PURL에 매핑될 수 있음)
	byVulnID := groupByVulnID(newVulns)

	log.Printf("scheduler: processing %d new critical/high CVEs", len(byVulnID))

	for vulnID, vulns := range byVulnID {
		// 영향 자산 식별
		affected, err := s.vulnSvc.SearchByVulnID(ctx, vulnID)
		if err != nil {
			log.Printf("scheduler: search affected failed for %s: %v", vulnID, err)
			continue
		}

		if len(affected) == 0 {
			continue
		}

		// 대표 vuln 선택 (가장 높은 severity)
		repVuln := selectTopVuln(vulns)

		// 알림 생성 (24h dedup 자동 적용)
		meta := notification.NewCVEMetadata{
			VulnID:        vulnID,
			SeverityScore: repVuln.SeverityScore,
			SeverityLabel: repVuln.SeverityLabel,
			AffectedPods:  collectPodNames(affected),
			AffectedCount: len(affected),
			TopCVE:        vulnID,
		}

		notif, err := s.notifSvc.CreateNewCVE(ctx, s.clusterName, meta)
		if err != nil {
			log.Printf("scheduler: create notification failed for %s: %v", vulnID, err)
			continue
		}

		if notif == nil {
			// 24h 내 동일 알림 존재 → skip
			continue
		}

		log.Printf("scheduler: notification created for %s (id=%d, affected=%d)",
			vulnID, notif.ID, len(affected))

		// Risk Scoring 자동 재계산 (영향 Pod별)
		s.recalculateRiskScores(ctx, affected)
	}
}

// recalculateRiskScores는 영향받는 Pod의 final_score를 재계산합니다.
func (s *VulnScheduler) recalculateRiskScores(ctx context.Context, affected []sbom.PackageVulnerability) {
	// affected에 직접 pod_uid가 없음. 영향받는 Pod 식별을 위해 추가 로직 필요.
	// 일단 PURL → image_digest → pod_uid 매핑은 복잡하므로,
	// 클러스터 전체 재계산을 호출 (간단하고 안전)
	if s.finalSvc == nil {
		return
	}

	// 전체 재계산 (비동기로 처리할 수도 있음)
	res, err := s.finalSvc.ComputeForCluster(ctx, s.clusterName)
	if err != nil {
		log.Printf("scheduler: risk score recalc failed: %v", err)
		return
	}

	log.Printf("scheduler: risk scores recalculated for %d pods (emergency=%d, warning=%d, caution=%d)",
		res.Computed, res.EmergencyCount, res.WarningCount, res.CautionCount)
}

// createScanCompleteNotif는 스캔 완료 요약 알림을 생성합니다.
func (s *VulnScheduler) createScanCompleteNotif(
	ctx context.Context,
	totalImages, scannedImages, newVulnsCount int,
	duration time.Duration,
) {
	meta := notification.ScanCompleteMetadata{
		TotalImages:     totalImages,
		ScannedImages:   scannedImages,
		NewVulnsCount:   newVulnsCount,
		DurationSeconds: duration.Seconds(),
	}

	_, err := s.notifSvc.CreateScanComplete(ctx, s.clusterName, meta)
	if err != nil {
		log.Printf("scheduler: scan complete notif failed: %v", err)
	}
}

// ─────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────

// groupByVulnID groups vulnerabilities by vuln_id.
func groupByVulnID(vulns []sbom.PackageVulnerability) map[string][]sbom.PackageVulnerability {
	result := make(map[string][]sbom.PackageVulnerability)
	for _, v := range vulns {
		result[v.VulnID] = append(result[v.VulnID], v)
	}
	return result
}

// selectTopVuln returns the vulnerability with the highest severity score.
func selectTopVuln(vulns []sbom.PackageVulnerability) sbom.PackageVulnerability {
	if len(vulns) == 0 {
		return sbom.PackageVulnerability{}
	}
	sort.Slice(vulns, func(i, j int) bool {
		return vulns[i].SeverityScore > vulns[j].SeverityScore
	})
	return vulns[0]
}

// collectPodNames는 영향받는 PURL 리스트를 사람이 읽을 수 있는 식별자로 변환합니다.
// 정확한 pod_uid 매핑은 추가 쿼리 필요 (Phase 6에서 보강 가능).
func collectPodNames(affected []sbom.PackageVulnerability) []string {
	seen := make(map[string]bool)
	var result []string
	for _, v := range affected {
		key := fmt.Sprintf("%s@%s", v.Name, v.Version)
		if !seen[key] {
			seen[key] = true
			result = append(result, key)
		}
	}
	if len(result) > 20 {
		result = result[:20] // 너무 길지 않게
	}
	return result
}

// jsonMarshal helper
func jsonMarshal(v interface{}) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}