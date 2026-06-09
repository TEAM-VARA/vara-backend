package scheduler

import (
	"context"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vara/backend/internal/domain/notification"
	"github.com/vara/backend/internal/domain/sbom"
	"github.com/vara/backend/internal/platform/osv"
	"github.com/vara/backend/internal/repository/postgres"
	"github.com/vara/backend/internal/service"
)

// VulnScheduler는 매시간 자동으로 OSV.dev에서 vulnerability를 재조회하고,
// 신규 CVE 발견 시 알림 생성 + Risk Scoring 재계산을 수행합니다.
type VulnScheduler struct {
	vulnSvc  *service.PackageVulnService
	notifSvc *service.NotificationService
	finalSvc *service.FinalScoringService
	globalRepo *postgres.GlobalScoringRepo

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
	globalRepo *postgres.GlobalScoringRepo,
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
		globalRepo:  globalRepo,
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

// processNewVulns는 이번 스캔에서 새로 발견된 vuln 중 critical/high를 처리합니다.
//
// 하이브리드 severity 결정:
//   1. vuln_id가 CVE 형식 → cve_global_scores 조회
//   2. aliases에서 CVE 추출 → cve_global_scores 조회
//   3. severity_score (OSV 파싱 결과) 활용
//   4. severity_label 활용
//   5. "Unknown" (skip)
func (s *VulnScheduler) processNewVulns(ctx context.Context, scanStart time.Time) {
	// 모든 신규 vuln 조회 (severity 필터 없음, 하이브리드 방식으로 결정)
	newVulns, err := s.vulnSvc.ListRecentlyAdded(ctx, scanStart, nil)
	if err != nil {
		log.Printf("scheduler: list recently added failed: %v", err)
		return
	}

	if len(newVulns) == 0 {
		return
	}

	// vuln_id 별로 그룹화 (한 vuln이 여러 PURL에 매핑될 수 있음)
	byVulnID := groupByVulnID(newVulns)

	log.Printf("scheduler: processing %d unique new vulns (total rows: %d)", len(byVulnID), len(newVulns))

	criticalHighCount := 0

	for vulnID, vulns := range byVulnID {
		repVuln := selectTopVuln(vulns)

		// 하이브리드 severity 결정 (4단계 fallback)
		score, label := s.resolveSeverity(ctx, repVuln)

		// Critical/High만 알림 생성
		if label != "Critical" && label != "High" {
			continue
		}

		// 영향 패키지 식별 (Risk Scoring 재계산용)
		affected, err := s.vulnSvc.SearchByVulnID(ctx, vulnID)
		if err != nil {
			log.Printf("scheduler: search affected failed for %s: %v", vulnID, err)
			continue
		}

		if len(affected) == 0 {
			continue
		}

		// 영향 Pod 역추적 (cluster_pods 최신 스냅샷 기준)
		// 실패해도 알림은 생성 — Pod 정보만 비워둠
		affectedPods, err := s.vulnSvc.SearchPodsByVulnID(ctx, s.clusterName, vulnID)
		if err != nil {
			log.Printf("scheduler: search affected pods failed for %s: %v", vulnID, err)
			affectedPods = nil
		}
		podRefs, podDisplay, podDigests, podCount := summarizeAffectedPods(affectedPods)

		// 알림 생성 (24h dedup 자동 적용)
		meta := notification.NewCVEMetadata{
			VulnID:          vulnID,
			SeverityScore:   score,
			SeverityLabel:   label,
			AffectedPods:    podDisplay,
			AffectedPodList: podRefs,
			AffectedCount:   podCount,
			TopCVE:          vulnID,
			ImageDigests:    podDigests,
		}

		notif, err := s.notifSvc.CreateNewCVE(ctx, s.clusterName, meta)
		if err != nil {
			log.Printf("scheduler: create notification failed for %s: %v", vulnID, err)
			continue
		}

		if notif == nil {
			continue // 24h dedup
		}

		criticalHighCount++
		log.Printf("scheduler: notification created for %s (id=%d, label=%s, score=%.1f, pods=%d, pkgs=%d)",
			vulnID, notif.ID, label, score, podCount, len(affected))

		// Risk Scoring 자동 재계산
		s.recalculateRiskScores(ctx, affected)
	}

	log.Printf("scheduler: %d critical/high notifications processed", criticalHighCount)
}

// resolveSeverity는 하이브리드 방식으로 vuln의 severity를 결정합니다.
//
// 우선순위:
//   1. vuln_id가 CVE 형식 → cve_global_scores 조회 (가장 신뢰)
//   2. aliases에서 CVE 추출 → cve_global_scores 조회
//   3. OSV가 파싱한 severity_score 활용
//   4. severity_label (Unknown 제외)
//   5. CVSS vector 직접 재추정 (osv 헬퍼)
func (s *VulnScheduler) resolveSeverity(ctx context.Context, vuln sbom.PackageVulnerability) (float64, string) {
	// 1순위: VulnID가 CVE면 직접 조회
	if isCVE(vuln.VulnID) {
		if gs, err := s.globalRepo.GetByCVEID(ctx, vuln.VulnID); err == nil && gs != nil {
			if gs.CVSSScore > 0 || gs.CVSSSeverity != "" {
				return gs.CVSSScore, normalizeSeverityLabel(gs.CVSSSeverity)
			}
		}
	}

	// 2순위: aliases에서 CVE 추출 → 조회
	for _, alias := range vuln.Aliases {
		if isCVE(alias) {
			if gs, err := s.globalRepo.GetByCVEID(ctx, alias); err == nil && gs != nil {
				if gs.CVSSScore > 0 || gs.CVSSSeverity != "" {
					return gs.CVSSScore, normalizeSeverityLabel(gs.CVSSSeverity)
				}
			}
		}
	}

	// 3순위: OSV가 이미 파싱한 score 활용
	if vuln.SeverityScore > 0 {
		return vuln.SeverityScore, classifyScore(vuln.SeverityScore)
	}

	// 4순위: severity_label이 의미 있는 값이면 사용
	if vuln.SeverityLabel != "" && vuln.SeverityLabel != "Unknown" {
		return 0, vuln.SeverityLabel
	}

	// 5순위: CVSS vector를 직접 재추정 (osv 헬퍼 활용)
	// severity_vector에 vector string이 있을 수 있음
	if vuln.SeverityVector != "" {
		if estimated := osv.EstimateCVSSFromVector(vuln.SeverityVector); estimated > 0 {
			return estimated, classifyScore(estimated)
		}
	}

	return 0, "Unknown"
}

// ─────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────

func isCVE(id string) bool {
	return strings.HasPrefix(strings.ToUpper(id), "CVE-")
}

func classifyScore(score float64) string {
	switch {
	case score >= 9.0:
		return "Critical"
	case score >= 7.0:
		return "High"
	case score >= 4.0:
		return "Medium"
	case score > 0:
		return "Low"
	default:
		return "Unknown"
	}
}

// normalizeSeverityLabel은 다양한 케이스를 표준 라벨로 정규화합니다.
//   "CRITICAL" / "critical" / "Critical" → "Critical"
func normalizeSeverityLabel(label string) string {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	default:
		return "Unknown"
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

// summarizeAffectedPods는 역추적된 영향 Pod 목록을 알림 메타용으로 가공합니다.
//
// 반환:
//   - refs:    구조화된 Pod 정보 (최대 50건, 표시 과다 방지)
//   - display: "namespace/pod_name" 표시용 문자열 (고유 Pod, 최대 20건)
//   - digests: 영향 이미지 digest (고유)
//   - count:   영향받는 고유 Pod 수 (pod_uid 기준)
func summarizeAffectedPods(pods []sbom.AffectedPod) (refs []notification.AffectedPodRef, display []string, digests []string, count int) {
	seenPod := make(map[string]bool)
	seenDisplay := make(map[string]bool)
	seenDigest := make(map[string]bool)

	for _, p := range pods {
		if !seenPod[p.PodUID] {
			seenPod[p.PodUID] = true
			count++
		}
		if len(refs) < 50 {
			refs = append(refs, notification.AffectedPodRef{
				PodUID:      p.PodUID,
				PodName:     p.PodName,
				Namespace:   p.Namespace,
				PackageName: p.PackageName,
				Version:     p.Version,
			})
		}
		key := p.Namespace + "/" + p.PodName
		if !seenDisplay[key] && len(display) < 20 {
			seenDisplay[key] = true
			display = append(display, key)
		}
		if p.ImageDigest != "" && !seenDigest[p.ImageDigest] {
			seenDigest[p.ImageDigest] = true
			digests = append(digests, p.ImageDigest)
		}
	}
	return refs, display, digests, count
}
