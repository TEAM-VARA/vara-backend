package scheduler

import (
	"context"
	"fmt"
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
	imageGlobalSvc *service.ImageGlobalCacheService // 신규 CVE 시 영향 이미지 Global 재계산용

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
	imageGlobalSvc *service.ImageGlobalCacheService,
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
		imageGlobalSvc: imageGlobalSvc,
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

	// 3.5 글로벌 캐시 갱신 (이전 AnalysisScheduler Phase 0를 여기로 흡수)
	//     느리고 외부 API(NVD)에 묶이는 작업이라 빠른 분석 루프와 분리했다.
	//     digest별 타임아웃으로 한 이미지가 매달려도 전체가 멈추지 않게 한다.
	s.refreshGlobalCache(ctx, digests)

	// 4. 스캔 완료 알림 (info 등급)
	s.createScanCompleteNotif(ctx, totalImages, scanned, totalNewVulns, duration)
}

// refreshGlobalCache는 모든 이미지의 Global 캐시(cve_global/image_global)를 갱신합니다.
// (AnalysisScheduler Phase 0 흡수 — VulnScheduler 1시간 주기에 얹어 자연 throttle.)
// 각 digest를 per-digest 타임아웃으로 감싸 한 이미지의 외부 호출이 매달려도
// 다음 digest로 넘어가게 한다(전체 스캐너 goroutine 동결 방지).
func (s *VulnScheduler) refreshGlobalCache(ctx context.Context, digests []string) {
	if s.imageGlobalSvc == nil {
		return
	}
	const perDigestTimeout = 90 * time.Second
	var refreshed, failed, skipped int
	for _, d := range digests {
		dctx, cancel := context.WithTimeout(ctx, perDigestTimeout)
		_, err := s.imageGlobalSvc.ComputeAndStore(dctx, d, false)
		cancel()
		switch {
		case err == nil:
			refreshed++
		case strings.Contains(err.Error(), "no CVEs found"):
			skipped++ // 취약점 0인 깨끗한 이미지 — 정상, 로그 스팸 안 함
		default:
			failed++
			log.Printf("scheduler: global refresh failed digest=%s: %v", d, err)
		}
	}
	log.Printf("scheduler: global cache refreshed (%d ok, %d failed, %d clean-skip)", refreshed, failed, skipped)
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

		// 24h dedup 선체크 — 이미 알린 CVE면 점수도 이미 반영됐으니 재계산까지 skip
		if exists, derr := s.notifSvc.ExistsRecentNewCVE(ctx, s.clusterName, vulnID); derr == nil && exists {
			continue
		}

		// 점수 변화(B) — 재계산 전 영향 Pod final_score 스냅샷
		uids := make([]string, 0, len(podRefs))
		for _, p := range podRefs {
			uids = append(uids, p.PodUID)
		}
		before := s.snapshotScores(ctx, uids)

		// 영향 이미지 Global 점수 재계산 — 신규 OSV CVE가 ListCVEsByImageDigest의
		// union으로 이미지 CVE 목록에 들어왔으니, image_global_scores 캐시를 갱신해야 final에 반영된다.
		// (이미지 캐시는 무시하고 재계산하되 per-CVE는 캐시 재사용 → 신규 CVE만 fetch, 기존 점수 안정)
		s.recomputeImageGlobals(ctx, podDigests)
		// Risk Scoring 자동 재계산 (위에서 갱신된 image_global_scores를 읽어 final 산출)
		s.recalculateRiskScores(ctx, affected)

		// 재계산 후 스냅샷 + 델타 산정 (이 CVE로 인한 점수 상승)
		after := s.snapshotScores(ctx, uids)
		maxDelta, maxDeltaPod := 0.0, ""
		for i := range podRefs {
			b, a := before[podRefs[i].PodUID], after[podRefs[i].PodUID]
			podRefs[i].ScoreBefore = b
			podRefs[i].ScoreAfter = a
			podRefs[i].ScoreDelta = a - b
			if d := a - b; d > maxDelta {
				maxDelta = d
				maxDeltaPod = podRefs[i].PodName
			}
		}

		// 알림 생성 (점수 델타 포함, 24h dedup 자동 적용)
		meta := notification.NewCVEMetadata{
			VulnID:               vulnID,
			SeverityScore:        score,
			SeverityLabel:        label,
			AffectedPods:         podDisplay,
			AffectedPodList:      podRefs,
			AffectedCount:        podCount,
			TopCVE:               vulnID,
			ImageDigests:         podDigests,
			MaxScoreDelta:        maxDelta,
			MaxScoreDeltaPodName: maxDeltaPod,
		}

		notif, err := s.notifSvc.CreateNewCVE(ctx, s.clusterName, meta)
		if err != nil {
			log.Printf("scheduler: create notification failed for %s: %v", vulnID, err)
			continue
		}
		if notif == nil {
			continue // 경합으로 그 사이 생성됨
		}

		criticalHighCount++
		log.Printf("scheduler: notification created for %s (id=%d, label=%s, score=%.1f, pods=%d, maxDelta=%.1f)",
			vulnID, notif.ID, label, score, podCount, maxDelta)
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
// recomputeImageGlobals는 주어진 이미지 digest들의 Global 점수를 강제 재계산(force)하여
// image_global_scores 캐시를 갱신합니다. 신규 OSV CVE가 union을 통해 CVE 목록에 들어왔으니,
// 이 갱신이 있어야 final 점수 재계산 시 새 CVE가 반영됩니다.
// DemoResult는 RunDemoForVuln 응답입니다 (발표 데모용).
type DemoResult struct {
	VulnID               string                        `json:"vuln_id"`
	SeverityLabel        string                        `json:"severity_label"`
	AffectedCount        int                           `json:"affected_count"`
	MaxScoreDelta        float64                       `json:"max_score_delta"`
	MaxScoreDeltaPodName string                        `json:"max_score_delta_pod_name"`
	NotificationID       int64                         `json:"notification_id"`
	Pods                 []notification.AffectedPodRef `json:"pods"`
}

// RunDemoForVuln은 주어진 vuln_id에 대해 신규 CVE 처리(영향 파드 역추적 + 점수 재계산 + 델타 + 알림)를
// dedup 없이 즉시 실행합니다. 발표 실연 전용 — "CVE 추가 → 알림에 +N점" 시연용.
// 운영 자동 경로(processNewVulns)와 동일 로직이되, "이번 스캔 신규" 필터를 건너뜁니다.
func (s *VulnScheduler) RunDemoForVuln(ctx context.Context, vulnID string) (*DemoResult, error) {
	affected, err := s.vulnSvc.SearchByVulnID(ctx, vulnID)
	if err != nil {
		return nil, fmt.Errorf("search vuln %s: %w", vulnID, err)
	}
	if len(affected) == 0 {
		return nil, fmt.Errorf("vuln_id %s가 package_vulnerabilities에 없습니다 (먼저 주입 필요)", vulnID)
	}

	score, label := s.resolveSeverity(ctx, selectTopVuln(affected))

	affectedPods, err := s.vulnSvc.SearchPodsByVulnID(ctx, s.clusterName, vulnID)
	if err != nil {
		affectedPods = nil
	}
	podRefs, podDisplay, podDigests, podCount := summarizeAffectedPods(affectedPods)

	uids := make([]string, 0, len(podRefs))
	for _, p := range podRefs {
		uids = append(uids, p.PodUID)
	}
	before := s.snapshotScores(ctx, uids)

	s.recomputeImageGlobals(ctx, podDigests)
	s.recalculateRiskScores(ctx, affected)

	after := s.snapshotScores(ctx, uids)
	maxDelta, maxDeltaPod := 0.0, ""
	for i := range podRefs {
		b, a := before[podRefs[i].PodUID], after[podRefs[i].PodUID]
		podRefs[i].ScoreBefore = b
		podRefs[i].ScoreAfter = a
		podRefs[i].ScoreDelta = a - b
		if d := a - b; d > maxDelta {
			maxDelta = d
			maxDeltaPod = podRefs[i].PodName
		}
	}

	meta := notification.NewCVEMetadata{
		VulnID:               vulnID,
		SeverityScore:        score,
		SeverityLabel:        label,
		AffectedPods:         podDisplay,
		AffectedPodList:      podRefs,
		AffectedCount:        podCount,
		TopCVE:               vulnID,
		ImageDigests:         podDigests,
		MaxScoreDelta:        maxDelta,
		MaxScoreDeltaPodName: maxDeltaPod,
	}
	notif, err := s.notifSvc.CreateNewCVEForce(ctx, s.clusterName, meta)
	if err != nil {
		return nil, fmt.Errorf("create notification: %w", err)
	}

	log.Printf("scheduler: DEMO new_cve for %s (label=%s, pods=%d, maxDelta=%.1f)", vulnID, label, podCount, maxDelta)

	res := &DemoResult{
		VulnID:               vulnID,
		SeverityLabel:        label,
		AffectedCount:        podCount,
		MaxScoreDelta:        maxDelta,
		MaxScoreDeltaPodName: maxDeltaPod,
		Pods:                 podRefs,
	}
	if notif != nil {
		res.NotificationID = notif.ID
	}
	return res, nil
}

// snapshotScores는 주어진 Pod들의 현재 final_score를 map으로 반환합니다 (없으면 미포함).
// 점수 델타(B) 산정 시 재계산 전/후 비교용.
func (s *VulnScheduler) snapshotScores(ctx context.Context, podUIDs []string) map[string]float64 {
	out := make(map[string]float64, len(podUIDs))
	if s.finalSvc == nil {
		return out
	}
	for _, uid := range podUIDs {
		if uid == "" {
			continue
		}
		if r, err := s.finalSvc.GetByPodUID(ctx, s.clusterName, uid); err == nil && r != nil {
			out[uid] = r.FinalScore
		}
	}
	return out
}

func (s *VulnScheduler) recomputeImageGlobals(ctx context.Context, imageDigests []string) {
	if s.imageGlobalSvc == nil || len(imageDigests) == 0 {
		return
	}
	seen := make(map[string]bool, len(imageDigests))
	for _, digest := range imageDigests {
		if digest == "" || seen[digest] {
			continue
		}
		seen[digest] = true
		// RecomputeAndStore: 이미지 캐시는 무시(재계산)하되 per-CVE는 캐시 재사용 →
		// 신규 CVE만 새로 fetch, 기존 점수는 안정 유지(외부 API 실패 출렁임 방지).
		if _, err := s.imageGlobalSvc.RecomputeAndStore(ctx, digest); err != nil {
			log.Printf("scheduler: image global recompute failed for %s: %v", digest, err)
		}
	}
}

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
