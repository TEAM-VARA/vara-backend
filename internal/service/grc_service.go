package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"mime/multipart"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vara/backend/internal/domain/grc"
	"github.com/vara/backend/internal/domain/scoring"
	"github.com/vara/backend/internal/platform/embedding"
	"github.com/vara/backend/internal/platform/ocr"
	"github.com/vara/backend/internal/platform/pdfext"
	"github.com/vara/backend/internal/platform/vlm"
	"github.com/vara/backend/internal/repository/postgres"
)

// GRCService orchestrates the compliance check workflow.
type GRCService struct {
	repo            *postgres.GRCRepo
	clusterRepo     *postgres.ClusterReaderRepo
	rulesetStore    *RulesetStore
	storagePath     string // local storage root for evidence files
	embeddingURL    string
	vlmAPIKey       string
	vlmModel        string
	ocrClient       *ocr.Client
	embeddingClient *embedding.Client
	vlmClient       *vlm.Client
	precomputeSem   chan struct{} // semaphore: limits concurrent GL precomputes (cap=2)
}

func NewGRCService(repo *postgres.GRCRepo, clusterRepo *postgres.ClusterReaderRepo, rulesetStore *RulesetStore, embClient *embedding.Client, vlmClient *vlm.Client) *GRCService {
	storagePath := os.Getenv("EVIDENCE_STORAGE_PATH")
	if storagePath == "" {
		storagePath = "evidence_storage"
	}

	// Tesseract OCR 초기화 (없으면 nil, 경고 로그만)
	ocrClient := ocr.NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := ocrClient.CheckBinary(ctx); err != nil {
		log.Printf("[grc] tesseract not available, OCR disabled: %v", err)
		ocrClient = nil
	} else {
		log.Println("[grc] tesseract OCR enabled")
	}

	if embClient != nil && embClient.Available() {
		log.Println("[grc] embedding client enabled")
	} else {
		log.Println("[grc] embedding client disabled (server URL not set)")
	}

	if vlmClient != nil && vlmClient.Available() {
		log.Println("[grc] VLM judge client enabled")
	} else {
		log.Println("[grc] VLM judge client disabled (VLM_SERVER_URL not set)")
	}

	return &GRCService{
		repo:            repo,
		clusterRepo:     clusterRepo,
		rulesetStore:    rulesetStore,
		storagePath:     storagePath,
		embeddingURL:    envOrDefault("EMBEDDING_SERVER_URL", "http://localhost:9000/embed"),
		vlmAPIKey:       os.Getenv("ANTHROPIC_API_KEY"),
		vlmModel:        envOrDefault("VLM_MODEL", "claude-sonnet-4-5"),
		ocrClient:       ocrClient,
		embeddingClient: embClient,
		vlmClient:       vlmClient,
		precomputeSem:   make(chan struct{}, 2), // allow up to 2 concurrent precomputes
	}
}

// EvaluateCluster reads pods from cluster_* DB tables and evaluates each pod.
func (s *GRCService) EvaluateCluster(ctx context.Context, req ClusterEvalRequest) (*ClusterEvalResult, error) {
	if req.CompanyID == "" {
		return nil, &GRCError{Code: "INVALID_REQUEST", Message: "company_id 필수", HTTPStatus: 400}
	}
	if req.ClusterName == "" {
		return nil, &GRCError{Code: "INVALID_REQUEST", Message: "cluster_name 필수", HTTPStatus: 400}
	}
	if s.clusterRepo == nil {
		return nil, &GRCError{Code: "NOT_CONFIGURED", Message: "cluster reader repo not configured", HTTPStatus: 500}
	}

	limit := req.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	offset := req.Offset
	if offset < 0 {
		offset = 0
	}

	// 1. Get latest snapshot
	snapshotAt, err := s.clusterRepo.GetLatestSnapshotAt(ctx, req.ClusterName)
	if err != nil {
		return nil, &GRCError{Code: "NO_SNAPSHOT", Message: fmt.Sprintf("클러스터 스냅샷 없음: %v", err), HTTPStatus: 404}
	}
	log.Printf("[cluster-eval] cluster=%s snapshot=%s ns=%s limit=%d offset=%d",
		req.ClusterName, snapshotAt.Format(time.RFC3339), req.Namespace, limit, offset)

	// 2. List pods
	pods, totalCount, err := s.clusterRepo.ListPods(ctx, req.ClusterName, snapshotAt, req.Namespace, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	log.Printf("[cluster-eval] found %d pods (total %d)", len(pods), totalCount)

	// 3. Get related resources per namespace (cache to avoid redundant queries)
	nsRelatedCache := map[string]*postgres.ClusterRelatedRows{}

	result := &ClusterEvalResult{
		ClusterName:    req.ClusterName,
		SnapshotAt:     snapshotAt.Format(time.RFC3339),
		TotalPodsScope: totalCount,
	}

	// 4. Evaluate each pod
	for _, pod := range pods {
		// Load related resources (cached per namespace)
		related, ok := nsRelatedCache[pod.Namespace]
		if !ok {
			related, err = s.clusterRepo.GetRelatedResources(ctx, req.ClusterName, snapshotAt, pod.Namespace)
			if err != nil {
				log.Printf("[cluster-eval] skip pod=%s ns=%s (related resources error: %v)", pod.Name, pod.Namespace, err)
				continue
			}
			nsRelatedCache[pod.Namespace] = related
		}

		// Assemble PodGraphRequest
		pgReq := AssembleClusterPodGraph(req.CompanyID, req.ClusterName, pod, related)

		// Evaluate
		evalResult, err := s.EvaluatePodGraph(ctx, pgReq)
		if err != nil {
			log.Printf("[cluster-eval] skip pod=%s ns=%s (eval error: %v)", pod.Name, pod.Namespace, err)
			continue
		}

		result.Results = append(result.Results, ClusterEvalResultItem{
			PodName:        evalResult.PodName,
			Namespace:      evalResult.Namespace,
			OverallVerdict: evalResult.OverallVerdict,
			TotalRules:     evalResult.TotalRules,
			Passed:         evalResult.Passed,
			Failed:         evalResult.Failed,
			Skipped:        evalResult.Skipped,
			ID:             evalResult.ID,
		})
	}

	result.Evaluated = len(result.Results)
	log.Printf("[cluster-eval] evaluated %d/%d pods", result.Evaluated, totalCount)

	return result, nil
}

// EvaluateClusterFindings evaluates all manual rules against a cluster snapshot.
// Manual rules are loaded from the ruleset JSON files (judgment_mode == "manual").
func (s *GRCService) EvaluateClusterFindings(ctx context.Context, req FindingEvalRequest) (*grc.FindingClusterResult, error) {
	if req.CompanyID == "" {
		return nil, &GRCError{Code: "INVALID_REQUEST", Message: "company_id 필수", HTTPStatus: 400}
	}
	if req.ClusterName == "" {
		return nil, &GRCError{Code: "INVALID_REQUEST", Message: "cluster_name 필수", HTTPStatus: 400}
	}
	if s.clusterRepo == nil {
		return nil, &GRCError{Code: "NOT_CONFIGURED", Message: "cluster reader repo not configured", HTTPStatus: 500}
	}

	// 1. Load manual rules from ruleset JSON files
	var manualRules []Rule
	for _, rs := range s.rulesetStore.LoadAll() {
		for _, r := range rs.Rules {
			if r.IsManual() {
				manualRules = append(manualRules, r)
			}
		}
	}
	log.Printf("[finding-eval] loaded %d manual rules from rulesets", len(manualRules))

	// 2. Get latest snapshot
	snapshotAt, err := s.clusterRepo.GetLatestSnapshotAt(ctx, req.ClusterName)
	if err != nil {
		return nil, &GRCError{Code: "NO_SNAPSHOT", Message: fmt.Sprintf("클러스터 스냅샷 없음: %v", err), HTTPStatus: 404}
	}
	log.Printf("[finding-eval] cluster=%s snapshot=%s", req.ClusterName, snapshotAt.Format(time.RFC3339))

	// 3. Load all pods
	pods, _, err := s.clusterRepo.ListPods(ctx, req.ClusterName, snapshotAt, req.Namespace, 10000, 0)
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}

	// 4. Load all cluster-wide resources
	related, err := s.clusterRepo.GetClusterWideResources(ctx, req.ClusterName, snapshotAt)
	if err != nil {
		return nil, fmt.Errorf("get cluster resources: %w", err)
	}

	// 5. Build cluster snapshot
	snap := &ClusterSnapshot{
		ClusterName: req.ClusterName,
		SnapshotAt:  snapshotAt,
		Pods:        pods,
		Namespaces:  related.Namespaces,
		Related:     related,
	}

	// 6. Evaluate all manual rules
	results := EvaluateManualRules(manualRules, snap)

	// 7. Compute summary
	matchedCount := 0
	unmatchedCount := 0
	byVerdict := map[string]int{}
	for _, fr := range results {
		if fr.Matched {
			matchedCount++
		} else {
			unmatchedCount++
		}
		byVerdict[fr.VerdictType]++
	}

	now := time.Now().UTC()
	return &grc.FindingClusterResult{
		CompanyID:      req.CompanyID,
		ClusterName:    req.ClusterName,
		Namespace:      req.Namespace,
		SnapshotAt:     snapshotAt.Format(time.RFC3339),
		EvaluatedAt:    now.Format(time.RFC3339),
		TotalFindings:  len(results),
		MatchedCount:   matchedCount,
		UnmatchedCount: unmatchedCount,
		ByVerdict:      byVerdict,
		Findings:       results,
	}, nil
}

// ListFindingClusterSummaries returns paginated finding cluster summaries.
func (s *GRCService) ListFindingClusterSummaries(ctx context.Context, companyID string, page, pageSize int) ([]grc.FindingClusterResult, int, error) {
	return s.repo.ListFindingClusterSummaries(ctx, companyID, page, pageSize)
}

// ── GL 지침서 자동 점검 ──

// ListGLRuleItemIDs returns all ISMS-P item IDs that have at least one GL rule
// (judgment_source=text_extraction, method=llm_rag_entailment).
func (s *GRCService) ListGLRuleItemIDs() []string {
	rulesets := s.rulesetStore.LoadAll()
	var items []string
	for _, rs := range rulesets {
		for _, rule := range rs.Rules {
			if rule.JudgmentSource == "text_extraction" &&
				rule.JudgmentLogic.Type == "semantic_match" &&
				rule.JudgmentLogic.Method == "llm_rag_entailment" {
				items = append(items, rs.Item.ID)
				break
			}
		}
	}
	return items
}

// ListGLCheckTargets returns all (company_id, isms_p_item_id) pairs for GL evaluation.
// Includes item-specific guidelines AND expands global guidelines (isms_p_item_id=NULL)
// across all GL rule items.
func (s *GRCService) ListGLCheckTargets(ctx context.Context) ([]grc.GLCheckTarget, error) {
	targets, err := s.repo.ListCompanyItemsWithGuidelines(ctx)
	if err != nil {
		return nil, err
	}

	// Companies with global (no item_id) guidelines → expand to all GL rule items
	globalCompanies, err := s.repo.ListCompaniesWithGlobalGuidelines(ctx)
	if err != nil {
		return nil, err
	}
	if len(globalCompanies) > 0 {
		glItems := s.ListGLRuleItemIDs()
		seen := make(map[string]bool, len(targets))
		for _, t := range targets {
			seen[t.CompanyID+"/"+t.ISMSPItemID] = true
		}
		for _, company := range globalCompanies {
			for _, itemID := range glItems {
				key := company + "/" + itemID
				if !seen[key] {
					targets = append(targets, grc.GLCheckTarget{CompanyID: company, ISMSPItemID: itemID})
					seen[key] = true
				}
			}
		}
	}
	return targets, nil
}

// TriggerGLCheck creates a guideline-only compliance check (no evidence files) for the
// given company and ISMS-P item. The check runs asynchronously using DB guidelines for
// GL-rule evaluation (llm_rag_entailment, embedding_similarity, etc.).
func (s *GRCService) TriggerGLCheck(ctx context.Context, companyID, ismspItemID string) (*grc.Check, error) {
	// GL 평가는 전적으로 VLM(LLM)에 의존한다. VLM 비가동 시 평가를 돌리면 모든 GL 룰이
	// INDETERMINATE로 저장되어 기존의 좋은 판정을 덮어쓴다. 따라서 비가동이면 아예 스킵해
	// 직전 저장 결과를 그대로 보존한다.
	if !s.VLMAvailable(ctx) {
		return nil, &GRCError{Code: "VLM_UNAVAILABLE", Message: "VLM 서버 비가동 — GL 평가 스킵(기존 결과 보존)", HTTPStatus: 503}
	}
	return s.CreateCheck(ctx, companyID, ismspItemID, false, nil, nil)
}

// VLMAvailable reports whether the VLM(LLM) judge backend is configured AND actually reachable.
// URL만 설정돼 있고 ollama가 죽은 경우도 false → GL 평가를 스킵해 기존 결과를 보존한다.
func (s *GRCService) VLMAvailable(ctx context.Context) bool {
	return s.vlmClient != nil && s.vlmClient.Available() && s.vlmClient.Healthy(ctx)
}

// ResetStaleChecks marks any checks left in 'running'/'queued' as 'failed'.
// Should be called once at server startup to clean up orphaned checks.
func (s *GRCService) ResetStaleChecks(ctx context.Context) (int64, error) {
	return s.repo.ResetStaleRunningChecks(ctx)
}

// ── 통합 클러스터 컴플라이언스 (경로 B+C 병합) ──

// ClusterComplianceRequest is the input for unified cluster compliance evaluation.
type ClusterComplianceRequest struct {
	CompanyID   string `json:"company_id"`
	ClusterName string `json:"cluster_name"`
	Namespace   string `json:"namespace,omitempty"`
}

// EvaluateClusterCompliance runs both R-rules (per-pod) and F-rules (cluster-wide)
// in a single pass, then groups results by ISMS-P item with violated assets.
func (s *GRCService) EvaluateClusterCompliance(ctx context.Context, req ClusterComplianceRequest) (*grc.ClusterComplianceResult, error) {
	if req.CompanyID == "" {
		req.CompanyID = req.ClusterName
	}
	if req.ClusterName == "" {
		return nil, &GRCError{Code: "INVALID_REQUEST", Message: "cluster_name 필수", HTTPStatus: 400}
	}
	if s.clusterRepo == nil {
		return nil, &GRCError{Code: "NOT_CONFIGURED", Message: "cluster reader repo not configured", HTTPStatus: 500}
	}

	evalStart := time.Now()

	// 1. Get latest snapshot (한 번만 로드)
	snapshotAt, err := s.clusterRepo.GetLatestSnapshotAt(ctx, req.ClusterName)
	if err != nil {
		return nil, &GRCError{Code: "NO_SNAPSHOT", Message: fmt.Sprintf("클러스터 스냅샷 없음: %v", err), HTTPStatus: 404}
	}
	log.Printf("[cluster-compliance] cluster=%s snapshot=%s", req.ClusterName, snapshotAt.Format(time.RFC3339))

	// 2. Load pods
	pods, totalPods, err := s.clusterRepo.ListPods(ctx, req.ClusterName, snapshotAt, req.Namespace, 10000, 0)
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}

	// 3. Load cluster-wide resources (for F-rules)
	clusterWide, err := s.clusterRepo.GetClusterWideResources(ctx, req.ClusterName, snapshotAt)
	if err != nil {
		return nil, fmt.Errorf("get cluster resources: %w", err)
	}

	// 4. Build cluster snapshot (for F-rules)
	snap := &ClusterSnapshot{
		ClusterName: req.ClusterName,
		SnapshotAt:  snapshotAt,
		Pods:        pods,
		Namespaces:  clusterWide.Namespaces,
		Related:     clusterWide,
	}

	// ── itemID → item tracker ──
	type itemTracker struct {
		itemName    string
		ruleResults []grc.RuleResult
		// asset key → violated rules
		assets        map[string]*grc.ViolatedAsset
		glResults     []grc.RuleResult
		rResults      []grc.RuleResult
		fResults      []grc.RuleResult
		reportResults []grc.RuleResult // LayerReport: 인벤토리/방증, 합격률 분모 제외
	}
	items := map[string]*itemTracker{}
	getItem := func(itemID, itemName string) *itemTracker {
		if it, ok := items[itemID]; ok {
			return it
		}
		it := &itemTracker{
			itemName: itemName,
			assets:   map[string]*grc.ViolatedAsset{},
		}
		items[itemID] = it
		return it
	}

	// ── Stage 2: R룰 manual_check_output 주입을 위한 룰 정의 맵 ──
	// 19개 흡수된 R룰에 ARI/MCA/AC/KDC 등을 enrichManualOutput으로 부착한다.
	ruleDef := buildRuleDefMap(s.rulesetStore)

	// 5. R-rules: per-pod evaluation
	nsRelatedCache := map[string]*postgres.ClusterRelatedRows{}
	for _, pod := range pods {
		related, ok := nsRelatedCache[pod.Namespace]
		if !ok {
			related, err = s.clusterRepo.GetRelatedResources(ctx, req.ClusterName, snapshotAt, pod.Namespace)
			if err != nil {
				log.Printf("[cluster-compliance] skip pod=%s (related err: %v)", pod.Name, err)
				continue
			}
			nsRelatedCache[pod.Namespace] = related
		}

		pgReq := AssembleClusterPodGraph(req.CompanyID, req.ClusterName, pod, related)
		evalResult, err := s.EvaluatePodGraph(ctx, pgReq)
		if err != nil {
			log.Printf("[cluster-compliance] skip pod=%s (eval err: %v)", pod.Name, err)
			continue
		}

		// Collect R-rule results per ISMS-P item
		for _, rr := range evalResult.RuleResults {
			it := getItem(rr.ISMSPItem, rr.ISMSPItemName)
			// Convert PodRuleResult → grc.RuleResult
			grr := grc.RuleResult{
				RuleID:            rr.RuleID,
				ISMSPItemID:       rr.ISMSPItem,
				CheckCategory:     "pod_graph",
				Verdict:           rr.Verdict,
				Violations:        rr.Violations,
				MatchedIndicators: rr.MatchedIndicators,
				SkipReason:        rr.SkipReason,
				FailMessage:       rr.FailMessage,
				Remediation:       rr.Remediation,
				JudgmentMode:      "auto",
				Reason:            rr.Reason,
				MissingInputs:     rr.MissingInputs,
				Layer:             rr.Layer,
			}
			if grr.Layer == "" {
				grr.Layer = grc.LayerR
			}

			// Stage 2: 흡수된 F룰의 수동점검 출력(ARI/MCA/AC/KDC)을 R 결과에 주입.
			def := ruleDef[grr.RuleID]
			if def != nil {
				enrichManualOutput(&grr, def)
				// cluster/account 스코프 룰(CNI·etcd 등)은 pod마다 평가되므로 canonical_id를
				// 찍어 클러스터 합산 시 1회로 dedup + pod에 fan-out되게 한다.
				stampInheritedScope(&grr, def, req.ClusterName)
			}
			// 통일된 강등 정책: 미준수 && (대체통제 || non-direct 매핑) → NEEDS_REVIEW.
			applyReviewDemotion(&grr, def)

			// INDETERMINATE인데 표시문자열이 비면 Reason으로 채워 빈 줄 렌더를 막는다.
			grr = ensureVerdictDisplay(grr)

			it.ruleResults = append(it.ruleResults, grr)
			it.rResults = append(it.rResults, grr)

			// If failed, record the pod as a violated asset.
			// needs_review 출신은 enrichManualOutput이 NEEDS_REVIEW로 덮어쓰므로
			// 이 블록에 진입하지 않는다 (위양성 방지).
			if grr.Verdict == "미준수" || grr.Verdict == grc.VerdictNOT_MET {
				ri := grc.ViolatedRuleInfo{
					RuleID:      rr.RuleID,
					FailMessage: rr.FailMessage,
					Remediation: rr.Remediation,
				}
				normalName := scoring.NormalizePodName(pod.Name)
				assetKey := fmt.Sprintf("Pod/%s/%s", pod.Namespace, normalName)
				if a, ok := it.assets[assetKey]; ok {
					a.ViolatedRules = append(a.ViolatedRules, ri)
				} else {
					it.assets[assetKey] = &grc.ViolatedAsset{
						Kind:          "Pod",
						Name:          normalName,
						Namespace:     pod.Namespace,
						ViolatedRules: []grc.ViolatedRuleInfo{ri},
					}
				}
			}
		}
	}

	// 6. F-rules: cluster-wide evaluation
	var manualRules []Rule
	manualRuleItemMap := map[string]string{} // ruleID → itemID
	manualRuleItemNameMap := map[string]string{} // ruleID → itemName
	for _, rs := range s.rulesetStore.LoadAll() {
		for _, r := range rs.Rules {
			if r.IsManual() {
				manualRules = append(manualRules, r)
				manualRuleItemMap[r.RuleID] = rs.Item.ID
				manualRuleItemNameMap[r.RuleID] = rs.Item.Name
			}
		}
	}
	log.Printf("[cluster-compliance] R-rules evaluated %d pods, F-rules evaluating %d manual rules", len(pods), len(manualRules))

	fResults := EvaluateManualRules(manualRules, snap)
	for _, fr := range fResults {
		itemID := manualRuleItemMap[fr.RuleID]
		itemName := manualRuleItemNameMap[fr.RuleID]
		it := getItem(itemID, itemName)
		fr.ISMSPItemID = itemID
		if fr.Layer == "" {
			fr.Layer = grc.LayerF
		}
		it.ruleResults = append(it.ruleResults, fr)

		// Stage 2: 레이어별 분기
		// LayerR  → 승격/deferred 룰 (합격률 분모 포함/skipped로 제외)
		// LayerReport → 리포트형 룰 (합격률 분모 제외, 별도 섹션)
		// LayerF  → 흡수 완료 후 잔여 없음, 하위호환 보존
		switch fr.Layer {
		case grc.LayerR:
			it.rResults = append(it.rResults, fr)
		case grc.LayerReport:
			it.reportResults = append(it.reportResults, fr)
		default: // LayerF (하위호환)
			it.fResults = append(it.fResults, fr)
		}

		// 위반 자산 기록: NOT_MET인 경우만 (NEEDS_REVIEW·REPORT 제외).
		// 승격 룰(LayerR, NOT_MET)은 AffectedResources를 통해 기록된다.
		if fr.Verdict == "미준수" || fr.Verdict == grc.VerdictNOT_MET {
			ri := grc.ViolatedRuleInfo{
				RuleID:      fr.RuleID,
				FailMessage: fr.FailMessage,
				Remediation: fr.Remediation,
			}
			for _, ar := range fr.AffectedResources {
				assetKey := fmt.Sprintf("%s/%s/%s", ar.Kind, ar.Namespace, ar.Name)
				if a, ok := it.assets[assetKey]; ok {
					a.ViolatedRules = append(a.ViolatedRules, ri)
				} else {
					it.assets[assetKey] = &grc.ViolatedAsset{
						Kind:          ar.Kind,
						Name:          ar.Name,
						Namespace:     ar.Namespace,
						ViolatedRules: []grc.ViolatedRuleInfo{ri},
					}
				}
			}
		}
	}

	// 7. Build response grouped by ISMS-P item
	now := time.Now().UTC()
	result := &grc.ClusterComplianceResult{
		CompanyID:   req.CompanyID,
		ClusterName: req.ClusterName,
		SnapshotAt:  snapshotAt.Format(time.RFC3339),
		EvaluatedAt: now.Format(time.RFC3339),
		DurationMs:  time.Since(evalStart).Milliseconds(),
		TotalPods:   totalPods,
	}

	for itemID, it := range items {
		// P2-10: rule_results와 layers가 동일 데이터를 중복 수록하던 문제(응답 ~2배) 수정.
		// layers(gl/r/f/report 분리)만 응답에 포함하고 평탄화된 rule_results는 생략한다.
		// 집계는 아래에서 it.ruleResults(내부 슬라이스)로 수행하므로 영향 없음.
		item := grc.ItemComplianceResult{
			ISMSPItemID: itemID,
			ItemName:    it.itemName,
			TotalRules:  len(it.ruleResults),
			Layers: &grc.ItemLayers{
				GL:     it.glResults,
				R:      it.rResults,
				F:      it.fResults,
				Report: it.reportResults,
			},
		}

		// 점수 dedup: 같은 canonical_id(cluster/account 결함이 여러 pod·자산에 투영된 경우)는 1회만 계상.
		// canonical_id가 빈 결과(레거시/미태깅)는 각각 distinct로 취급해 기존 동작 보존.
		seenCanonical := map[string]bool{}
		for _, rr := range it.ruleResults {
			// Stage 2: 리포트형 룰(LayerReport)은 합격률 분모에서 제외.
			// 인벤토리/방증 출력이므로 충족/미충족 어디에도 포함하지 않는다.
			if rr.Layer == grc.LayerReport {
				continue
			}
			if rr.CanonicalID != "" {
				if seenCanonical[rr.CanonicalID] {
					continue // 동일 결함 재계상 방지 (blast-radius는 표시용, count는 1)
				}
				seenCanonical[rr.CanonicalID] = true
			}
			switch rr.Verdict {
			case "준수", grc.VerdictMET:
				item.Passed++
			case "미준수", grc.VerdictNOT_MET:
				item.Failed++
			case "검토필요", grc.VerdictNEEDS_REVIEW:
				item.NeedsReview++ // 확인불가: 분모 제외 (NEEDS_REVIEW origin 포함)
			case grc.VerdictNA, "해당없음":
				item.NotApplicable++ // 점검 대상 부재 — 준수와 분리 집계
			case grc.VerdictNO_DATA:
				item.NoData++
			case grc.VerdictINDETERMINATE:
				item.Indeterminate++
			default: // skipped (deferred 등) — 분모 제외
				item.Skipped++
			}
		}

		// Determine item-level composite verdict:
		// GL NOT_MET or R NOT_MET → 항목 = NOT_MET (결함)
		// No clear failures but R NO_DATA or F NEEDS_REVIEW or GL INDETERMINATE → NEEDS_REVIEW (확인필요)
		// 실제 통과 룰 존재 → MET (준수)
		// 전부 해당없음 → N_A (점검 대상 부재 — 준수로 부풀리지 않음)
		if item.Failed > 0 {
			item.Verdict = grc.VerdictNOT_MET
		} else if item.NeedsReview > 0 || item.NoData > 0 || item.Indeterminate > 0 {
			item.Verdict = grc.VerdictNEEDS_REVIEW
		} else if item.Passed > 0 {
			// 커버리지 게이트(overview와 동일): 정의된 룰 중 미평가가 남아 있으면
			// 통과만으로 준수 단정하지 않고 NEEDS_REVIEW로 둔다.
			expected := s.expectedRuleCount(itemID)
			evaluated := distinctEvaluatedRules(it.ruleResults)
			if expected > 0 && evaluated < expected {
				item.Verdict = grc.VerdictNEEDS_REVIEW
			} else {
				item.Verdict = grc.VerdictMET
			}
		} else if item.NotApplicable > 0 {
			item.Verdict = grc.VerdictNA
		} else {
			item.Verdict = grc.VerdictSKIPPED
		}

		// Collect violated assets
		for _, a := range it.assets {
			item.ViolatedAssets = append(item.ViolatedAssets, *a)
		}

		result.Items = append(result.Items, item)
		result.TotalRules += item.TotalRules
	}

	result.TotalItems = len(result.Items)
	for _, it := range result.Items {
		switch it.Verdict {
		case "준수", grc.VerdictMET:
			result.CompliantItems++
		case "미준수", grc.VerdictNOT_MET:
			result.NonCompliantItems++
		case "검토필요", grc.VerdictNEEDS_REVIEW:
			result.NeedsReviewItems++
		case grc.VerdictNA, "해당없음":
			result.NotApplicableItems++
		case grc.VerdictNO_DATA:
			result.NoDataItems++
		case grc.VerdictINDETERMINATE:
			result.IndeterminateItems++
		}
	}

	log.Printf("[cluster-compliance] done: %d items, %d compliant, %d non-compliant, %d needs-review",
		result.TotalItems, result.CompliantItems, result.NonCompliantItems, result.NeedsReviewItems)

	// 8. Persist to DB
	if id, err := s.repo.SaveClusterComplianceResult(ctx, result); err != nil {
		log.Printf("[cluster-compliance] DB save failed: %v", err)
	} else {
		log.Printf("[cluster-compliance] saved id=%d", id)
	}

	// 9. Persist F-rule findings to finding_cluster_summaries (for [13] findings/summary)
	if len(fResults) > 0 {
		matchedCount := 0
		unmatchedCount := 0
		byVerdict := map[string]int{}
		for _, fr := range fResults {
			if fr.Matched {
				matchedCount++
			} else {
				unmatchedCount++
			}
			byVerdict[fr.VerdictType]++
		}
		findingResult := &grc.FindingClusterResult{
			CompanyID:      req.CompanyID,
			ClusterName:    req.ClusterName,
			SnapshotAt:     snapshotAt.Format(time.RFC3339),
			EvaluatedAt:    now.Format(time.RFC3339),
			TotalFindings:  len(fResults),
			MatchedCount:   matchedCount,
			UnmatchedCount: unmatchedCount,
			ByVerdict:      byVerdict,
			Findings:       fResults,
		}
		if fid, ferr := s.repo.SaveFindingClusterSummary(ctx, findingResult); ferr != nil {
			log.Printf("[cluster-compliance] finding summary save failed: %v", ferr)
		} else {
			log.Printf("[cluster-compliance] finding summary saved id=%d (%d findings)", fid, len(fResults))
		}
	}

	return result, nil
}

// ── 통합 실행: R/F (동기) + GL (비동기 트리거) 한 번에 ──

// EvaluateAllRequest is the input for the combined cluster (R/F) + GL evaluation.
type EvaluateAllRequest struct {
	CompanyID   string `json:"company_id"`
	ClusterName string `json:"cluster_name"`
	Namespace   string `json:"namespace,omitempty"`
}

// GLCheckTrigger records the outcome of triggering one item's GL check.
type GLCheckTrigger struct {
	ISMSPItemID string `json:"isms_p_item_id"`
	CheckID     string `json:"check_id,omitempty"`
	Status      string `json:"status"` // queued | error
	Error       string `json:"error,omitempty"`
}

// EvaluateAllResult bundles the synchronous cluster (R+F) result with the
// asynchronously-triggered per-item GL checks.
type EvaluateAllResult struct {
	Cluster     *grc.ClusterComplianceResult `json:"cluster"`
	GLChecks    []GLCheckTrigger             `json:"gl_checks"`
	GLTriggered int                          `json:"gl_triggered"`
	GLFailed    int                          `json:"gl_failed"`
	TriggeredAt string                       `json:"triggered_at"`
}

// EvaluateAll runs the cluster R+F evaluation synchronously and triggers GL
// checks for every GL-rule item, in a single call ("R룰 + GL 점검 한 번에").
//
// R/F 결과는 동기로 완료되어 즉시 반환된다. GL 점검은 항목별 비동기 워커(LLM RAG)로
// 큐잉되며, 완료 후 GetComplianceOverview(GET /compliance/overview)가 R/F+GL을
// 병합해 보여준다. 트리거 실패(지침 없음 등)는 항목별로 기록하되 전체를 실패시키지 않는다.
func (s *GRCService) EvaluateAll(ctx context.Context, req EvaluateAllRequest) (*EvaluateAllResult, error) {
	if req.ClusterName == "" {
		return nil, &GRCError{Code: "INVALID_REQUEST", Message: "cluster_name 필수", HTTPStatus: 400}
	}
	companyID := req.CompanyID
	if companyID == "" {
		companyID = req.ClusterName // EvaluateClusterCompliance와 동일한 fallback
	}

	// 1. R + F (동기 — 클러스터 스냅샷 기반)
	cluster, err := s.EvaluateClusterCompliance(ctx, ClusterComplianceRequest{
		CompanyID:   req.CompanyID,
		ClusterName: req.ClusterName,
		Namespace:   req.Namespace,
	})
	if err != nil {
		return nil, err // 스냅샷 없음(NO_SNAPSHOT) 등은 그대로 전파
	}

	// 2. GL (전체 GL-룰 항목, 비동기 트리거)
	glItems := s.ListGLRuleItemIDs()
	sort.Strings(glItems) // 응답 순서 안정화
	out := &EvaluateAllResult{
		Cluster:     cluster,
		TriggeredAt: time.Now().UTC().Format(time.RFC3339),
	}
	for _, itemID := range glItems {
		chk, terr := s.TriggerGLCheck(ctx, companyID, itemID)
		if terr != nil {
			out.GLFailed++
			out.GLChecks = append(out.GLChecks, GLCheckTrigger{
				ISMSPItemID: itemID, Status: "error", Error: terr.Error(),
			})
			log.Printf("[evaluate-all] GL trigger 실패 item=%s: %v", itemID, terr)
			continue
		}
		out.GLTriggered++
		out.GLChecks = append(out.GLChecks, GLCheckTrigger{
			ISMSPItemID: itemID, CheckID: chk.CheckID, Status: chk.Status,
		})
	}
	log.Printf("[evaluate-all] cluster=%s R/F done (%d items), GL triggered=%d failed=%d",
		req.ClusterName, cluster.TotalItems, out.GLTriggered, out.GLFailed)

	return out, nil
}

// ── Compliance Overview (전체 항목 한눈에) ──

// GetComplianceOverview returns the latest cluster compliance result merged with GL check results.
func (s *GRCService) GetComplianceOverview(ctx context.Context, companyID, clusterName string) (*grc.ClusterComplianceResult, error) {
	if companyID == "" {
		return nil, &GRCError{Code: "INVALID_REQUEST", Message: "company_id 필수", HTTPStatus: 400}
	}

	// 1. Load latest cluster evaluation (R+F rules)
	result, err := s.repo.GetLatestClusterComplianceResult(ctx, companyID, clusterName)
	if err != nil {
		// No cluster eval yet — start with empty result
		result = &grc.ClusterComplianceResult{
			CompanyID:   companyID,
			ClusterName: clusterName,
		}
	}

	// 2. Load latest GL check per ISMS-P item
	glChecks, err := s.repo.GetLatestGLCheckPerItem(ctx, companyID)
	if err != nil {
		log.Printf("[overview] GL checks query failed: %v", err)
		// continue with R+F only
		if result.TotalItems == 0 {
			return nil, &GRCError{Code: "NOT_FOUND", Message: "평가 결과 없음", HTTPStatus: 404}
		}
		return result, nil
	}

	// 3. Build item map from existing R+F results
	itemMap := map[string]int{} // isms_p_item_id → index in result.Items
	for i, item := range result.Items {
		itemMap[item.ISMSPItemID] = i
	}

	// 4. Merge GL results into items
	rulesetStore := s.rulesetStore.LoadAll()
	itemNameMap := map[string]string{}
	for _, rs := range rulesetStore {
		itemNameMap[rs.Item.ID] = rs.Item.Name
	}

	for _, gl := range glChecks {
		// Load GL rule_results for layers.gl
		var glRuleResults []grc.RuleResult
		if gl.CheckID != "" {
			if rr, err := s.repo.GetCheckRuleResults(ctx, gl.CheckID); err == nil {
				glRuleResults = rr
			}
		}

		idx, exists := itemMap[gl.ISMSPItemID]
		if exists {
			item := &result.Items[idx]
			item.TotalRules += gl.TotalRules
			item.Passed += gl.Passed
			item.Failed += gl.Failed
			item.NeedsReview += gl.NeedsReview
			item.NotApplicable += gl.Skipped // N_A/리포트형 버킷 — 이전엔 통째로 누락돼 accounting gap 발생
			result.TotalRules += gl.TotalRules
			if item.Layers == nil {
				item.Layers = &grc.ItemLayers{}
			}
			item.Layers.GL = glRuleResults
		} else {
			name := itemNameMap[gl.ISMSPItemID]
			if name == "" {
				if rs, loadErr := s.rulesetStore.Load(gl.ISMSPItemID); loadErr == nil {
					name = rs.Item.Name
				}
			}
			if name == "" {
				name = gl.ISMSPItemID
			}
			item := grc.ItemComplianceResult{
				ISMSPItemID:   gl.ISMSPItemID,
				ItemName:      name,
				TotalRules:    gl.TotalRules,
				Passed:        gl.Passed,
				Failed:        gl.Failed,
				NeedsReview:   gl.NeedsReview,
				NotApplicable: gl.Skipped, // N_A/리포트형 버킷 — 누락 방지
				Layers:        &grc.ItemLayers{GL: glRuleResults},
			}
			result.Items = append(result.Items, item)
			itemMap[gl.ISMSPItemID] = len(result.Items) - 1
			result.TotalRules += gl.TotalRules
		}
	}

	// 5. Fill missing items from ruleset (평가 안 된 항목도 표시)
	for _, rs := range rulesetStore {
		if _, exists := itemMap[rs.Item.ID]; !exists {
			result.Items = append(result.Items, grc.ItemComplianceResult{
				ISMSPItemID: rs.Item.ID,
				ItemName:    rs.Item.Name,
				Verdict:     "데이터없음",
			})
			itemMap[rs.Item.ID] = len(result.Items) - 1
		}
	}

	// 6. Recalculate item verdicts, totals, and generate notes
	// (EvaluateClusterCompliance와 동일한 분기 순서 — overview/evaluate 판정 일관성)
	result.TotalItems = len(result.Items)
	result.CompliantItems = 0
	result.NonCompliantItems = 0
	result.NeedsReviewItems = 0
	result.NotApplicableItems = 0
	noDataItems := 0
	for i := range result.Items {
		item := &result.Items[i]

		// Determine verdict
		if item.Failed > 0 {
			item.Verdict = "미준수"
			result.NonCompliantItems++
		} else if item.NeedsReview > 0 || item.NoData > 0 || item.Indeterminate > 0 {
			item.Verdict = "검토필요"
			result.NeedsReviewItems++
		} else if item.Passed > 0 {
			// 커버리지 게이트: 정의된 룰 중 실제 판정난 distinct 룰이 적으면(미실행 룰 존재)
			// 통과만으로 '준수'를 단정하지 않고 '검토필요'로 둔다.
			expected := s.expectedRuleCount(item.ISMSPItemID)
			evaluated := distinctEvaluatedRules(collectItemRuleResults(item))
			if expected > 0 && evaluated < expected {
				item.Verdict = "검토필요"
				result.NeedsReviewItems++
			} else {
				item.Verdict = "준수"
				result.CompliantItems++
			}
		} else if item.NotApplicable > 0 {
			item.Verdict = "해당없음"
			result.NotApplicableItems++
		} else {
			item.Verdict = "데이터없음"
			noDataItems++
		}

		// Generate note per verdict
		switch item.Verdict {
		case "미준수":
			podCount := len(item.ViolatedAssets)
			// Collect unique fail reasons
			reasons := map[string]bool{}
			remediations := map[string]bool{}
			for _, a := range item.ViolatedAssets {
				for _, r := range a.ViolatedRules {
					if r.FailMessage != "" {
						reasons[r.FailMessage] = true
					}
					if r.Remediation != "" {
						remediations[r.Remediation] = true
					}
				}
			}
			reasonList := mapKeys(reasons)
			remList := mapKeys(remediations)
			item.Note = fmt.Sprintf("%d개 룰 미준수, %d개 Pod 위반", item.Failed, podCount)
			if len(reasonList) > 0 {
				top := reasonList
				if len(top) > 3 {
					top = top[:3]
				}
				item.Note += " — 원인: " + strings.Join(top, "; ")
			}
			if len(remList) > 0 {
				top := remList
				if len(top) > 2 {
					top = top[:2]
				}
				item.Note += " — 조치: " + strings.Join(top, "; ")
			}
		case "검토필요":
			if item.NeedsReview > 0 {
				item.Note = fmt.Sprintf("%d개 룰 검토 필요 (자동 판단 불가, 수동 확인 권장)", item.NeedsReview)
			} else if item.NoData > 0 || item.Indeterminate > 0 {
				item.Note = fmt.Sprintf("데이터 부족 (NO_DATA %d건, 확인불가 %d건) — 수동 확인 권장", item.NoData, item.Indeterminate)
			} else {
				// 커버리지 부족 강등: 통과 룰은 있으나 정의된 룰 일부가 아직 미평가
				expected := s.expectedRuleCount(item.ISMSPItemID)
				evaluated := distinctEvaluatedRules(collectItemRuleResults(item))
				item.Note = fmt.Sprintf("정의된 룰 %d개 중 %d개만 평가됨 (%d개 미실행) — 통과만으로 준수 단정 불가, 나머지 룰 평가 필요",
					expected, evaluated, expected-evaluated)
			}
		case "준수":
			if item.NotApplicable > 0 {
				item.Note = fmt.Sprintf("적용 가능 룰 %d개 통과 (해당없음 %d건 별도)", item.Passed, item.NotApplicable)
			} else {
				item.Note = fmt.Sprintf("%d개 룰 전부 통과", item.Passed)
			}
			// Add matched indicators from rule results if available
			// (P2-10 이후 rule_results 대신 layers에 저장될 수 있어 둘 다 조회)
			indicators := []string{}
			for _, rr := range collectItemRuleResults(item) {
				if grc.NormalizeVerdict(rr.Verdict) == grc.VerdictMET && len(rr.MatchedIndicators) > 0 {
					for _, mi := range rr.MatchedIndicators {
						if len(indicators) < 3 {
							indicators = append(indicators, mi)
						}
					}
				}
			}
			if len(indicators) > 0 {
				item.Note += " — " + strings.Join(indicators, "; ")
			}
		case "해당없음":
			item.Note = fmt.Sprintf("점검 대상 리소스 부재 (%d건) — 해당 환경에 적용되지 않는 항목 (준수 아님)", item.NotApplicable)
		case "데이터없음":
			item.Note = "아직 평가되지 않은 항목 — 클러스터 평가 또는 GL 점검 실행 필요"
		}
	}
	result.NoDataItems = noDataItems

	return result, nil
}

// collectItemRuleResults returns all rule results of an item, regardless of
// whether they're stored in the flat RuleResults field (legacy) or Layers (P2-10 이후).
func collectItemRuleResults(item *grc.ItemComplianceResult) []grc.RuleResult {
	if len(item.RuleResults) > 0 {
		return item.RuleResults
	}
	if item.Layers == nil {
		return nil
	}
	var all []grc.RuleResult
	all = append(all, item.Layers.GL...)
	all = append(all, item.Layers.R...)
	all = append(all, item.Layers.F...)
	all = append(all, item.Layers.Report...)
	return all
}

// expectedRuleCount returns how many of an item's ruleset-defined rules are
// expected to yield a verdict, excluding report/deferred rules (합격률 분모 제외).
// 룰셋 캐시는 호출 전 LoadAll로 데워져 있어 pod 룰셋까지 병합된 정의 수를 반환한다.
func (s *GRCService) expectedRuleCount(itemID string) int {
	rs, err := s.rulesetStore.Load(itemID)
	if err != nil || rs == nil {
		return 0
	}
	n := 0
	for i := range rs.Rules {
		r := &rs.Rules[i]
		if r.OutputType == "report" || r.ReclassifiedFrom != "" || r.DeferredFrom != "" {
			continue // 인벤토리/방증·보류 룰은 판정 분모에서 제외
		}
		n++
	}
	return n
}

// distinctEvaluatedRules counts unique rule IDs that produced a real verdict
// (MET/NOT_MET/NEEDS_REVIEW/NO_DATA/INDETERMINATE/N_A). per-pod 팬아웃으로 같은
// 룰이 여러 번 나와도 rule_id 기준 distinct로 집계해 커버리지를 정확히 센다.
func distinctEvaluatedRules(results []grc.RuleResult) int {
	seen := map[string]bool{}
	for _, rr := range results {
		if rr.RuleID == "" {
			continue
		}
		switch grc.NormalizeVerdict(rr.Verdict) {
		case grc.VerdictMET, grc.VerdictNOT_MET, grc.VerdictNEEDS_REVIEW,
			grc.VerdictNO_DATA, grc.VerdictINDETERMINATE, grc.VerdictNA:
			seen[rr.RuleID] = true
		}
	}
	return len(seen)
}

// mapKeys returns sorted keys from a map[string]bool.
func mapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// ── Rule Catalog ──

// FindingCatalogItem is metadata for a single manual rule (previously F-finding).
type FindingCatalogItem struct {
	FindingID      string `json:"finding_id"`
	ISMSPItemID    string `json:"isms_p_item_id"`
	Title          string `json:"title"`
	VerdictType    string `json:"verdict_type"`
	TargetResource string `json:"target_resource"`
}

// RuleCatalogItem is metadata for a single auto-judgment rule.
type RuleCatalogItem struct {
	RuleID         string `json:"rule_id"`
	ISMSPItemID    string `json:"isms_p_item_id"`
	Name           string `json:"name"`
	JudgmentSource string `json:"judgment_source,omitempty"`
}

// RuleCatalogResponse is the response for GET /compliance/rulesets/catalog.
type RuleCatalogResponse struct {
	Findings []FindingCatalogItem `json:"findings"`
	Rules    []RuleCatalogItem    `json:"rules"`
}

// GetRuleCatalog returns all rule definitions split by judgment_mode.
// "findings" = manual rules (judgment_mode: "manual") from ruleset JSON files.
// "rules"    = auto rules  (judgment_mode: "" or "auto") from ruleset JSON files.
func (s *GRCService) GetRuleCatalog(ctx context.Context) (*RuleCatalogResponse, error) {
	var findingItems []FindingCatalogItem
	var ruleItems []RuleCatalogItem

	for _, rs := range s.rulesetStore.LoadAll() {
		for _, r := range rs.Rules {
			if r.IsManual() {
				targetResource := ""
				if r.ManualMeta != nil {
					targetResource = r.ManualMeta.TargetResource
				}
				findingItems = append(findingItems, FindingCatalogItem{
					FindingID:      r.RuleID,
					ISMSPItemID:    rs.Item.ID,
					Title:          r.Name,
					VerdictType:    r.VerdictType,
					TargetResource: targetResource,
				})
			} else {
				ruleItems = append(ruleItems, RuleCatalogItem{
					RuleID:         r.RuleID,
					ISMSPItemID:    rs.Item.ID,
					Name:           r.Name,
					JudgmentSource: r.JudgmentSource,
				})
			}
		}
	}

	return &RuleCatalogResponse{
		Findings: findingItems,
		Rules:    ruleItems,
	}, nil
}

// ── Findings Summary (전체 뷰) ──

// GetLatestFindingClusterSummary returns the most recent cluster finding summary.
func (s *GRCService) GetLatestFindingClusterSummary(ctx context.Context, companyID, clusterName string) (*grc.FindingClusterResult, error) {
	items, _, err := s.repo.ListFindingClusterSummaries(ctx, companyID, 1, 200)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, &GRCError{Code: "NOT_FOUND", Message: "finding summary 없음", HTTPStatus: 404}
	}

	// cluster_name이 비면 최신 결과 반환
	if clusterName == "" {
		return &items[0], nil
	}

	for i := range items {
		if items[i].ClusterName == clusterName {
			return &items[i], nil
		}
	}
	return nil, &GRCError{Code: "NOT_FOUND", Message: fmt.Sprintf("클러스터 '%s' finding summary 없음", clusterName), HTTPStatus: 404}
}

// ── Pod Compliance (Pod 상세 뷰) ──

// PodComplianceFindingItem is a finding that affects a specific pod.
type PodComplianceFindingItem struct {
	FindingID   string `json:"finding_id"`
	ISMSPItemID string `json:"isms_p_item_id"`
	Title       string `json:"title"`
	VerdictType string `json:"verdict_type"`
	Matched     bool   `json:"matched"`
	Observation string `json:"observation"`
}

// RuleComplianceSummary holds R-rule pass/fail/skip counts for a pod.
// Evaluated = Compliant + NonCompliant (Skipped is excluded from the denominator).
type RuleComplianceSummary struct {
	Evaluated    int `json:"evaluated"`
	Compliant    int `json:"compliant"`
	NonCompliant int `json:"non_compliant"`
	Skipped      int `json:"skipped"`
}

// RelatedFindingsSummary counts F-rule findings for a pod by verdict type.
type RelatedFindingsSummary struct {
	PotentialFinding   int `json:"potential_finding"`
	NeedsReview        int `json:"needs_review"`
	CompliantIndicator int `json:"compliant_indicator"`
}

// PodComplianceSummary aggregates pod-level compliance with strict R/F separation.
type PodComplianceSummary struct {
	RuleCompliance  RuleComplianceSummary  `json:"rule_compliance"`
	RelatedFindings RelatedFindingsSummary `json:"related_findings"`
}

// PodComplianceResult is the response for GET /compliance/pods/:pod_name/compliance.
type PodComplianceResult struct {
	PodName         string                     `json:"pod_name"`
	Namespace       string                     `json:"namespace"`
	ClusterName     string                     `json:"cluster_name"`
	ClusterFindings []PodComplianceFindingItem `json:"cluster_findings"`
	Summary         PodComplianceSummary       `json:"summary"`
}

// GetPodCompliance filters the latest cluster finding summary for findings
// that affect the specified pod, based on AffectedResources.
func (s *GRCService) GetPodCompliance(ctx context.Context, companyID, clusterName, namespace, podName string) (*PodComplianceResult, error) {
	result := &PodComplianceResult{
		PodName:     podName,
		Namespace:   namespace,
		ClusterName: clusterName,
	}

	// Build rule_compliance from R-rule pod graph evaluation (most recent snapshot)
	podEval, err := s.repo.GetLatestPodGraphEvalByPod(ctx, companyID, clusterName, namespace, podName)
	if err == nil && podEval != nil {
		result.Summary.RuleCompliance = RuleComplianceSummary{
			Compliant:    podEval.Passed,
			NonCompliant: podEval.Failed,
			Skipped:      podEval.Skipped,
			Evaluated:    podEval.Passed + podEval.Failed,
		}
	}

	// Load latest cluster finding summary (F-rules)
	summary, err := s.GetLatestFindingClusterSummary(ctx, companyID, clusterName)
	if err != nil {
		// No finding summary yet is ok — return result with R-rule data only
		if ge, ok := err.(*GRCError); ok && ge.HTTPStatus == 404 {
			return result, nil
		}
		return nil, err
	}

	// Filter manual rules that mention this pod in AffectedResources
	for _, fr := range summary.Findings {
		for _, ar := range fr.AffectedResources {
			if ar.Kind == "Pod" && ar.Name == podName && (namespace == "" || ar.Namespace == namespace) {
				result.ClusterFindings = append(result.ClusterFindings, PodComplianceFindingItem{
					FindingID:   fr.RuleID,
					ISMSPItemID: fr.ISMSPItemID,
					Title:       fr.RuleID,
					VerdictType: fr.VerdictType,
					Matched:     fr.Matched,
					Observation: fr.Observation,
				})
				break
			}
		}
	}

	// Build related_findings counts from F-rules (by verdict_type)
	for _, f := range result.ClusterFindings {
		switch f.VerdictType {
		case VerdictPotentialFinding:
			result.Summary.RelatedFindings.PotentialFinding++
		case VerdictNeedsReview:
			result.Summary.RelatedFindings.NeedsReview++
		case VerdictCompliantIndicator:
			result.Summary.RelatedFindings.CompliantIndicator++
		}
	}

	return result, nil
}

// ── ISMS-P 항목별 위반 자산 조회 ──

// ISMSPItemViolationsResult is the response for GET /compliance/items/:item_id/violations.
type ISMSPItemViolationsResult struct {
	ISMSPItemID    string              `json:"isms_p_item_id"`
	ISMSPItemName  string              `json:"isms_p_item_name"`
	CompanyID      string              `json:"company_id"`
	ClusterName    string              `json:"cluster_name"`
	TotalViolated  int                 `json:"total_violated_assets"`
	ViolatedAssets []grc.ViolatedAsset `json:"violated_assets"`
}

// GetISMSPItemViolations returns pods violating rules under a specific ISMS-P item.
func (s *GRCService) GetISMSPItemViolations(ctx context.Context, companyID, clusterName, ismspItemID string) (*ISMSPItemViolationsResult, error) {
	if companyID == "" {
		return nil, &GRCError{Code: "INVALID_REQUEST", Message: "company_id 필수", HTTPStatus: 400}
	}
	if ismspItemID == "" {
		return nil, &GRCError{Code: "INVALID_REQUEST", Message: "item_id 필수", HTTPStatus: 400}
	}

	rows, err := s.repo.GetViolatedAssetsByISMSPItem(ctx, companyID, clusterName, ismspItemID)
	if err != nil {
		return nil, fmt.Errorf("query violated assets: %w", err)
	}

	result := &ISMSPItemViolationsResult{
		ISMSPItemID: ismspItemID,
		CompanyID:   companyID,
		ClusterName: clusterName,
	}
	for _, row := range rows {
		if result.ISMSPItemName == "" && row.ISMSPItemName != "" {
			result.ISMSPItemName = row.ISMSPItemName
		}
		var ruleInfos []grc.ViolatedRuleInfo
		for _, rid := range row.ViolatedRules {
			ri := grc.ViolatedRuleInfo{RuleID: rid}
			nid := strings.Replace(rid, "-POD-", "-", 1)
			if info, ok := podRuleFailInfo[nid]; ok {
				ri.FailMessage = info.failMessage
				ri.Remediation = info.remediation
			}
			ruleInfos = append(ruleInfos, ri)
		}
		result.ViolatedAssets = append(result.ViolatedAssets, grc.ViolatedAsset{
			Kind:          "Pod",
			Name:          row.PodName,
			Namespace:     row.Namespace,
			ViolatedRules: ruleInfos,
		})
	}
	result.TotalViolated = len(result.ViolatedAssets)
	return result, nil
}

// ── Pod별 위반 ISMS-P 항목 조회 ──

// PodViolatedISMSPItem holds violations for a single ISMS-P item from a pod's perspective.
type PodViolatedISMSPItem struct {
	ISMSPItemID   string          `json:"isms_p_item_id"`
	ISMSPItemName string          `json:"isms_p_item_name"`
	TotalRules    int             `json:"total_rules"`
	Passed        int             `json:"passed"`
	Failed        int             `json:"failed"`
	Skipped       int             `json:"skipped"`
	FailedRules   []PodRuleResult `json:"failed_rules"`
}

// PodViolationsResult is the response for GET /compliance/pods/:pod_name/violations.
type PodViolationsResult struct {
	PodName            string                 `json:"pod_name"`
	Namespace          string                 `json:"namespace"`
	ClusterName        string                 `json:"cluster_name"`
	OverallVerdict     string                 `json:"overall_verdict"`
	EvaluatedAt        string                 `json:"evaluated_at"`
	TotalViolatedItems int                    `json:"total_violated_items"`
	ViolatedItems      []PodViolatedISMSPItem `json:"violated_items"`
}

// GetPodViolations returns ISMS-P items that a specific pod violates.
func (s *GRCService) GetPodViolations(ctx context.Context, companyID, clusterName, namespace, podName string) (*PodViolationsResult, error) {
	if companyID == "" {
		return nil, &GRCError{Code: "INVALID_REQUEST", Message: "company_id 필수", HTTPStatus: 400}
	}
	if podName == "" {
		return nil, &GRCError{Code: "INVALID_REQUEST", Message: "pod_name 필수", HTTPStatus: 400}
	}

	// 1. Get latest evaluation metadata
	evalItem, err := s.repo.GetLatestPodGraphEvalByPod(ctx, companyID, clusterName, namespace, podName)
	if err != nil {
		return nil, &GRCError{Code: "NOT_FOUND", Message: fmt.Sprintf("Pod 평가 결과 없음: %v", err), HTTPStatus: 404}
	}

	// 2. Get full rule_results
	_, ruleResultsRaw, err := s.repo.GetPodGraphEvaluation(ctx, evalItem.ID)
	if err != nil {
		return nil, fmt.Errorf("get rule results: %w", err)
	}

	// 3. Unmarshal rule results
	var ruleResults []PodRuleResult
	if err := json.Unmarshal(ruleResultsRaw, &ruleResults); err != nil {
		return nil, fmt.Errorf("unmarshal rule_results: %w", err)
	}

	// 4. Group by ISMS-P item
	type itemAccum struct {
		name    string
		passed  int
		failed  int
		skipped int
		total   int
		fails   []PodRuleResult
	}
	itemMap := map[string]*itemAccum{}
	for _, rr := range ruleResults {
		acc, ok := itemMap[rr.ISMSPItem]
		if !ok {
			acc = &itemAccum{name: rr.ISMSPItemName}
			itemMap[rr.ISMSPItem] = acc
		}
		acc.total++
		switch grc.NormalizeVerdict(rr.Verdict) {
		case grc.VerdictMET:
			acc.passed++
		case grc.VerdictNOT_MET:
			acc.failed++
			acc.fails = append(acc.fails, rr)
		default: // skip / NA / NO_DATA / NEEDS_REVIEW — 위반 집계 제외
			acc.skipped++
		}
	}

	// 5. Build result (only items with failures)
	result := &PodViolationsResult{
		PodName:        evalItem.PodName,
		Namespace:      evalItem.Namespace,
		ClusterName:    evalItem.ClusterName,
		OverallVerdict: evalItem.OverallVerdict,
		EvaluatedAt:    evalItem.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}
	for itemID, acc := range itemMap {
		if acc.failed == 0 {
			continue
		}
		result.ViolatedItems = append(result.ViolatedItems, PodViolatedISMSPItem{
			ISMSPItemID:   itemID,
			ISMSPItemName: acc.name,
			TotalRules:    acc.total,
			Passed:        acc.passed,
			Failed:        acc.failed,
			Skipped:       acc.skipped,
			FailedRules:   acc.fails,
		})
	}
	result.TotalViolatedItems = len(result.ViolatedItems)
	return result, nil
}

// ── Stage 2 helpers: F→R 흡수 / manual_check_output 주입 ──

// buildRuleDefMap returns a flat map of ruleID → *Rule across all loaded rulesets.
// Used to look up ManualCheckOutput when enriching per-pod R-rule results.
func buildRuleDefMap(store *RulesetStore) map[string]*Rule {
	m := map[string]*Rule{}
	for _, rs := range store.LoadAll() {
		for i := range rs.Rules {
			r := &rs.Rules[i]
			m[r.RuleID] = r
		}
	}
	return m
}

// demoteToReviewOverride lists rule IDs that must be demoted (미준수 → NEEDS_REVIEW)
// even though they carry no ManualCheckOutput metadata. These are rules where the
// K8s measurement is only one possible implementation of the control and
// off-cluster alternative controls can satisfy the ISMS-P requirement.
// (Currently empty — the internal-mTLS rule (R-2.6.3-02) that used this was removed.)
var demoteToReviewOverride = map[string]bool{}

// complianceMappingEntry is the minimal shape of a compliance_mappings element.
type complianceMappingEntry struct {
	MatchStrength string `json:"match_strength"`
}

// hasDirectMapping reports whether any compliance mapping has match_strength "direct".
// Empty/unparseable mappings are treated as direct (conservative: no demotion).
func hasDirectMapping(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	var entries []complianceMappingEntry
	if err := json.Unmarshal(raw, &entries); err != nil || len(entries) == 0 {
		return true
	}
	for _, e := range entries {
		if e.MatchStrength == "direct" {
			return true
		}
	}
	return false
}

// applyReviewDemotion implements the unified demotion policy (심사 일관성):
//
//	자동측정 미준수(NOT_MET) && (대체통제 존재 || ISMS-P 매핑이 direct가 아님)
//	  → NEEDS_REVIEW (확인불가 — 합격률 분모 제외, 수동 검토 대상)
//
// 준수/N_A/NO_DATA 등 비-미준수 verdict는 절대 강등하지 않는다
// (기존 needsReviewAbsorbedFromIDs가 준수까지 강등하던 과잉 동작 제거 — R-2.10.3-03 노이즈 수정).
// direct 매핑이면서 대체통제가 없는 룰(예: R-2.5.1-01 default SA)만 NOT_MET이 확정된다.
// 주의: OffclusterSatisfactionConditions는 거의 모든 룰에 존재하므로 기준에서 제외.
func applyReviewDemotion(grr *grc.RuleResult, def *Rule) {
	if grr.Verdict != grc.VerdictNOT_MET && grr.Verdict != "미준수" {
		return // 미준수만 강등 대상
	}

	normID := strings.Replace(grr.RuleID, "-POD-", "-", 1)
	demote := demoteToReviewOverride[normID]

	if !demote && def != nil && def.ManualCheckOutput != nil {
		mco := def.ManualCheckOutput
		if len(mco.AlternativeControls) > 0 || !hasDirectMapping(mco.ComplianceMappings) {
			demote = true
		}
	}

	if demote {
		grr.Reason = fmt.Sprintf("R 자동측정: %s → 수동 검토 필요 (대체통제/클러스터 외 충족 가능 — 확인불가)", grr.Verdict)
		grr.Verdict = grc.VerdictNEEDS_REVIEW
	}
}

// enrichManualOutput copies absorbed F-finding metadata (ARI/MCA/AC/KDC/etc.) into
// an R-rule result according to the applies_when policy:
//   - "fail"   → expose only when R verdict is NOT_MET (potential_finding 출신)
//   - "always" → always expose (needs_review / additional_evidence 출신)
//
// needs_review 출신은 R verdict를 NEEDS_REVIEW로 덮어써 합격률 분모에서 제외한다
// (§6-6 결정: "집계 단계 제외가 더 안전").
// additional_evidence 출신은 verdict를 그대로 두고 방증 컨텍스트만 부착한다.
func enrichManualOutput(grr *grc.RuleResult, def *Rule) {
	mco := def.ManualCheckOutput
	if mco == nil {
		return
	}

	isFail := grr.Verdict == grc.VerdictNOT_MET || grr.Verdict == "미준수"
	if mco.AppliesWhen == "fail" && !isFail {
		return // potential_finding 출신: R 미충족일 때만 수동점검 컨텍스트 노출
	}

	// ARI / MCA / AC / offcluster 복사
	if len(mco.AdditionalReviewItems) > 0 {
		grr.AdditionalReviewItems = toRawJSON(mco.AdditionalReviewItems)
	}
	if len(mco.ManualCheckAreas) > 0 {
		grr.ManualCheckAreas = toRawJSON(mco.ManualCheckAreas)
	}
	if len(mco.AlternativeControls) > 0 {
		grr.AlternativeControls = toRawJSON(mco.AlternativeControls)
	}
	if len(mco.OffclusterSatisfactionConditions) > 0 {
		grr.OffclusterSatisfactionConditions = toRawJSON(mco.OffclusterSatisfactionConditions)
	}
	// KDC / compliance_mappings: json.RawMessage는 그대로 참조
	if len(mco.KisaDefectCaseRefs) > 0 {
		grr.KisaDefectCaseRefs = mco.KisaDefectCaseRefs
	}
	if len(mco.ComplianceMappings) > 0 {
		grr.ComplianceMappings = mco.ComplianceMappings
	}

	// verdict 강등은 applyReviewDemotion에서 통일 처리한다 (미준수만 대상).
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// GenerateJobID creates a "ck_" prefixed nanoid-style ID.
func GenerateJobID() string {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	b := make([]byte, 10)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		b[i] = alphabet[n.Int64()]
	}
	return "ck_" + string(b)
}

// CreateCheck validates the request, saves files, creates a DB check, and starts the async worker.
func (s *GRCService) CreateCheck(
	ctx context.Context,
	companyID, ismspItemID string,
	autoCollect bool,
	files []*multipart.FileHeader,
	metadataList []grc.EvidenceMetadata,
) (*grc.Check, error) {
	// Validate ruleset exists (document, pod, or unified).
	_, err := s.rulesetStore.Load(ismspItemID)
	if err != nil {
		return nil, &GRCError{Code: "UNSUPPORTED_ITEM", Message: fmt.Sprintf("지원하지 않는 ISMS-P 항목: %s", ismspItemID), HTTPStatus: 400}
	}

	// 파일 없이 지침서 전용 점검 가능 (DB 지침만 사용)
	if len(files) == 0 {
		checkID := GenerateJobID()
		now := time.Now().UTC()
		chk := &grc.Check{
			CheckID:     checkID,
			CompanyID:   companyID,
			ISMSPItemID: ismspItemID,
			Status:      "queued",
			ProgressPct: 0,
			AutoCollect: autoCollect,
			SubmittedAt: now,
		}
		if err := s.repo.CreateCheck(ctx, chk); err != nil {
			return nil, fmt.Errorf("check 생성 실패: %w", err)
		}
		go s.runWorker(checkID)
		return chk, nil
	}

	// Validate file count matches metadata count.
	if len(files) != len(metadataList) {
		return nil, &GRCError{Code: "INVALID_EVIDENCE_METADATA", Message: "files와 evidence_metadata 길이 불일치", HTTPStatus: 400}
	}

	// Validate file count limits.
	if len(files) > grc.MaxFileCount {
		return nil, &GRCError{Code: "INVALID_REQUEST", Message: fmt.Sprintf("파일 수는 1~%d개여야 합니다", grc.MaxFileCount), HTTPStatus: 400}
	}

	var totalSize int64
	for i, f := range files {
		// Validate filename matches metadata.
		if f.Filename != metadataList[i].Filename {
			return nil, &GRCError{
				Code:       "INVALID_EVIDENCE_METADATA",
				Message:    fmt.Sprintf("파일명 불일치: files[%d]=%s, metadata[%d]=%s", i, f.Filename, i, metadataList[i].Filename),
				HTTPStatus: 400,
			}
		}

		// Validate file extension.
		ext := strings.ToLower(filepath.Ext(f.Filename))
		if !grc.AllowedFileExtensions[ext] {
			return nil, &GRCError{
				Code:       "UNSUPPORTED_FILE_FORMAT",
				Message:    fmt.Sprintf("지원하지 않는 파일 형식: %s", ext),
				HTTPStatus: 400,
			}
		}

		// Validate single file size.
		if f.Size > grc.MaxFileSize {
			return nil, &GRCError{Code: "PAYLOAD_TOO_LARGE", Message: fmt.Sprintf("파일 크기 초과: %s (%.1fMB > 50MB)", f.Filename, float64(f.Size)/1024/1024), HTTPStatus: 413}
		}
		totalSize += f.Size

		// Validate evidence_type.
		if !grc.AllowedEvidenceTypes[metadataList[i].EvidenceType] {
			return nil, &GRCError{
				Code:       "INVALID_EVIDENCE_TYPE",
				Message:    fmt.Sprintf("유효하지 않은 evidence_type: %s", metadataList[i].EvidenceType),
				HTTPStatus: 400,
			}
		}
	}
	if totalSize > grc.MaxTotalSize {
		return nil, &GRCError{Code: "PAYLOAD_TOO_LARGE", Message: fmt.Sprintf("전체 파일 크기 초과: %.1fMB > 200MB", float64(totalSize)/1024/1024), HTTPStatus: 413}
	}

	// Create check.
	checkID := GenerateJobID()
	now := time.Now().UTC()

	chk := &grc.Check{
		CheckID:     checkID,
		CompanyID:   companyID,
		ISMSPItemID: ismspItemID,
		Status:      "queued",
		ProgressPct: 0,
		AutoCollect: autoCollect,
		SubmittedAt: now,
	}

	if err := s.repo.CreateCheck(ctx, chk); err != nil {
		return nil, fmt.Errorf("check 생성 실패: %w", err)
	}

	// Save files to local storage.
	jobDir := filepath.Join(s.storagePath, companyID, checkID)
	if err := os.MkdirAll(jobDir, 0o755); err != nil {
		return nil, fmt.Errorf("storage directory 생성 실패: %w", err)
	}

	for i, f := range files {
		storagePath := filepath.Join(jobDir, f.Filename)
		contentHash, err := saveUploadedFile(f, storagePath)
		if err != nil {
			return nil, fmt.Errorf("파일 저장 실패 %s: %w", f.Filename, err)
		}
		ef := &grc.EvidenceFile{
			CheckID:       checkID,
			Filename:      f.Filename,
			EvidenceType:  metadataList[i].EvidenceType,
			System:        metadataList[i].System,
			Description:   metadataList[i].Description,
			StoragePath:   storagePath,
			FileSizeBytes: f.Size,
			TargetRuleIDs: metadataList[i].TargetRuleIDs,
			K8sSource:     metadataList[i].K8sSource,
			ContentHash:   contentHash,
		}
		if err := s.repo.InsertEvidenceFile(ctx, ef); err != nil {
			return nil, fmt.Errorf("evidence file DB 저장 실패: %w", err)
		}
	}

	// Launch async worker.
	go s.runWorker(checkID)

	return chk, nil
}

// saveUploadedFile writes the uploaded file to dst and returns its SHA-256 hex hash.
func saveUploadedFile(fh *multipart.FileHeader, dst string) (string, error) {
	src, err := fh.Open()
	if err != nil {
		return "", err
	}
	defer src.Close()

	out, err := os.Create(dst)
	if err != nil {
		return "", err
	}
	defer out.Close()

	h := sha256.New()
	w := io.MultiWriter(out, h)
	if _, err = io.Copy(w, src); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// GetCheckDetail returns the full check detail for the GET endpoint.
func (s *GRCService) GetCheckDetail(ctx context.Context, checkID string) (*grc.CheckDetailResponse, error) {
	chk, err := s.repo.GetCheck(ctx, checkID)
	if err != nil {
		return nil, &GRCError{Code: "CHECK_NOT_FOUND", Message: "check_id 미존재", HTTPStatus: 404}
	}

	resp := &grc.CheckDetailResponse{
		CheckID:        chk.CheckID,
		CompanyID:      chk.CompanyID,
		ISMSPItemID:    chk.ISMSPItemID,
		RulesetVersion: chk.RulesetVersion,
		Status:         chk.Status,
		ProgressPct:    chk.ProgressPct,
		Verdict:        chk.Verdict,
		Severity:       chk.Severity,
		SubmittedAt:    chk.SubmittedAt,
		StartedAt:      chk.StartedAt,
		CompletedAt:    chk.CompletedAt,
		Error:          chk.Error,
	}

	if chk.Status == "completed" {
		resp.Summary = &grc.Summary{
			TotalRules:        chk.TotalRules,
			Passed:            chk.PassedRules,
			Failed:            chk.FailedRules,
			Skipped:           chk.SkippedRules,
			EvidenceCollected: chk.EvidenceCount,
			SummaryText:       chk.SummaryText,
		}
		resp.RuleResults, _ = s.repo.GetCheckRuleResults(ctx, checkID)
		resp.Recommendations, _ = s.repo.GetCheckRecommendations(ctx, checkID)
	}

	return resp, nil
}

// ListChecks returns paginated compliance checks with optional filters.
func (s *GRCService) ListChecks(ctx context.Context, filters postgres.CheckFilters, page, pageSize int) ([]grc.CheckListItem, int, error) {
	return s.repo.ListChecks(ctx, filters, page, pageSize)
}

// ListEvidence returns evidence files for a check.
func (s *GRCService) ListEvidence(ctx context.Context, checkID string) ([]grc.EvidenceListItem, error) {
	return s.repo.ListEvidenceForAPI(ctx, checkID)
}

// ── Guidelines (지침) ──

// UploadGuideline saves a guideline file, extracts text, generates embedding, and persists.
// ismspItemID가 nil이면 회사 공용 지침으로 저장 (모든 항목 점검 시 자동 포함).
func (s *GRCService) UploadGuideline(
	ctx context.Context,
	companyID string,
	ismspItemID *string,
	fh *multipart.FileHeader,
) (*grc.Guideline, error) {
	// Validate file extension.
	ext := strings.ToLower(filepath.Ext(fh.Filename))
	allowed := map[string]bool{".pdf": true, ".txt": true, ".json": true, ".yaml": true, ".yml": true}
	if !allowed[ext] {
		return nil, &GRCError{Code: "UNSUPPORTED_FILE_FORMAT", Message: fmt.Sprintf("지침 파일 형식 미지원: %s", ext), HTTPStatus: 400}
	}

	if fh.Size > grc.MaxFileSize {
		return nil, &GRCError{Code: "PAYLOAD_TOO_LARGE", Message: "파일 크기 초과 (50MB)", HTTPStatus: 413}
	}

	// Save file to storage.
	subDir := "_common"
	if ismspItemID != nil {
		subDir = *ismspItemID
	}
	guidelineDir := filepath.Join(s.storagePath, companyID, "guidelines", subDir)
	if err := os.MkdirAll(guidelineDir, 0o755); err != nil {
		return nil, fmt.Errorf("지침 디렉토리 생성 실패: %w", err)
	}

	storagePath := filepath.Join(guidelineDir, fh.Filename)
	contentHash, err := saveUploadedFile(fh, storagePath)
	if err != nil {
		return nil, fmt.Errorf("지침 파일 저장 실패: %w", err)
	}

	g := &grc.Guideline{
		CompanyID:     companyID,
		ISMSPItemID:   ismspItemID,
		Filename:      fh.Filename,
		StoragePath:   storagePath,
		FileSizeBytes: fh.Size,
		ContentHash:   contentHash,
	}

	// Check hash-based cache for extracted text.
	if cached, found, _ := s.repo.FindGuidelineTextByHash(ctx, contentHash); found {
		g.ExtractedText = cached
		log.Printf("[grc-guideline] text cache HIT (hash=%s) %s", contentHash[:12], fh.Filename)
	} else {
		// Extract text from file.
		data, extractErr := s.extractGuidelineText(storagePath, ext)
		if extractErr != nil {
			log.Printf("[grc-guideline] text extraction failed %s: %v", fh.Filename, extractErr)
		} else {
			g.ExtractedText = data
		}
	}

	// Generate embedding from extracted text (with hash cache).
	if g.ExtractedText != "" && s.embeddingClient != nil && s.embeddingClient.Available() {
		if cachedEmb, found, _ := s.repo.FindGuidelineEmbeddingByHash(ctx, contentHash); found {
			g.Embedding = cachedEmb
			log.Printf("[grc-guideline] embedding cache HIT (hash=%s) %s", contentHash[:12], fh.Filename)
		} else {
			emb, embErr := s.embeddingClient.Embed(ctx, g.ExtractedText)
			if embErr != nil {
				log.Printf("[grc-guideline] embed error %s: %v", fh.Filename, embErr)
			} else {
				g.Embedding = emb
			}
		}
	}

	// ── 시간 기준 버전 관리 ──
	// 같은 (company_id, isms_p_item_id, filename)의 최신 버전과 content_hash를 비교한다.
	latestID, latestVer, latestHash, latestUploadedAt, found, verErr := s.repo.GetLatestGuidelineVersion(ctx, companyID, ismspItemID, fh.Filename)
	if verErr != nil {
		return nil, fmt.Errorf("기존 지침 버전 조회 실패: %w", verErr)
	}
	if found && latestHash == contentHash {
		// 내용 동일 → 새 버전을 만들지 않고 기존 최신 버전을 그대로 재사용 (멱등).
		g.ID = latestID
		g.Version = latestVer
		g.UploadedAt = latestUploadedAt
		g.UpdatedAt = latestUploadedAt
		log.Printf("[grc-guideline] identical content, reuse v%d (id=%d) %s", latestVer, latestID, fh.Filename)
		// Ensure sentence embeddings exist (may be missing if uploaded before this feature)
		go s.embedAndSaveGuidelineSentences(context.Background(), g.ID, g.ExtractedText)
		return g, nil
	}
	// 신규(found=false) 또는 내용 변경 → 새 버전으로 누적 보관.
	g.Version = 1
	if found {
		g.Version = latestVer + 1
	}

	// Insert into DB.
	if err := s.repo.InsertGuideline(ctx, g); err != nil {
		// Duplicate check (unique constraint) — 동시 업로드 경합 안전망.
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			return nil, &GRCError{Code: "DUPLICATE_GUIDELINE", Message: fmt.Sprintf("동일 지침 파일 이미 존재: %s", fh.Filename), HTTPStatus: 409}
		}
		return nil, fmt.Errorf("지침 DB 저장 실패: %w", err)
	}

	itemLabel := "_common"
	if ismspItemID != nil {
		itemLabel = *ismspItemID
	}
	log.Printf("[grc-guideline] uploaded %s for %s/%s (id=%d, text=%d chars, emb=%d dims)",
		fh.Filename, companyID, itemLabel, g.ID, len(g.ExtractedText), len(g.Embedding))

	// Embed sentences in background — upload returns immediately, GL check uses fast path
	// once embeddings are stored, or falls back to slow path if not yet ready.
	go s.embedAndSaveGuidelineSentences(context.Background(), g.ID, g.ExtractedText)

	return g, nil
}

// embedAndSaveGuidelineSentences embeds guideline sentences and stores in DB.
// Runs asynchronously (goroutine) so upload returns immediately.
// Idempotent: skips if sentence embeddings already exist for this guidelineID.
func (s *GRCService) embedAndSaveGuidelineSentences(ctx context.Context, guidelineID int64, extractedText string) {
	if s.embeddingClient == nil || !s.embeddingClient.Available() || extractedText == "" {
		return
	}
	if exists, _ := s.repo.HasGuidelineSentenceEmbeddings(ctx, guidelineID); exists {
		log.Printf("[grc-embed] guideline_id=%d: sentence embeddings already in DB, skipping", guidelineID)
		return
	}
	sentences := splitTextSentences(extractedText)
	if len(sentences) == 0 {
		return
	}
	const maxSentencesForRAG = 300
	if len(sentences) > maxSentencesForRAG {
		origLen := len(sentences)
		sampled := make([]string, 0, maxSentencesForRAG)
		step := len(sentences) / maxSentencesForRAG
		for i := 0; i < len(sentences) && len(sampled) < maxSentencesForRAG; i += step {
			sampled = append(sampled, sentences[i])
		}
		sentences = sampled
		log.Printf("[grc-embed] guideline_id=%d: capped %d→%d sentences", guidelineID, origLen, len(sentences))
	}
	log.Printf("[grc-embed] guideline_id=%d: embedding %d sentences at upload time...", guidelineID, len(sentences))
	embeddings, err := s.embeddingClient.EmbedBatch(ctx, sentences)
	if err != nil || len(embeddings) == 0 {
		log.Printf("[grc-embed] guideline_id=%d: sentence embedding failed: %v", guidelineID, err)
		return
	}
	if err := s.repo.SaveGuidelineSentenceEmbeddings(ctx, guidelineID, sentences, embeddings); err != nil {
		log.Printf("[grc-embed] guideline_id=%d: save failed: %v", guidelineID, err)
		return
	}
	log.Printf("[grc-embed] guideline_id=%d: saved %d sentence embeddings", guidelineID, len(sentences))
}

// splitTextSentences splits extracted text into individual sentences for embedding.
func splitTextSentences(text string) []string {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	var sentences []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "---" {
			continue
		}
		if len([]rune(line)) > 5 {
			sentences = append(sentences, line)
		}
	}
	return sentences
}

// extractGuidelineText extracts text from a guideline file.
func (s *GRCService) extractGuidelineText(path, ext string) (string, error) {
	switch ext {
	case ".pdf":
		return s.extractPDFText(path)
	case ".txt":
		return readTextFile(path)
	case ".json":
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return string(data), nil
	case ".yaml", ".yml":
		return readTextFile(path)
	default:
		return "", fmt.Errorf("unsupported guideline format: %s", ext)
	}
}

// ListGuidelines returns guideline list items for a company and optional item.
func (s *GRCService) ListGuidelines(ctx context.Context, companyID, ismspItemID string) ([]grc.GuidelineListItem, error) {
	return s.repo.ListGuidelines(ctx, companyID, ismspItemID)
}

// DeleteGuideline deletes a guideline by ID and its storage file.
func (s *GRCService) DeleteGuideline(ctx context.Context, id int64) error {
	// Get guideline to find storage path.
	g, err := s.repo.GetGuideline(ctx, id)
	if err != nil {
		return &GRCError{Code: "GUIDELINE_NOT_FOUND", Message: "지침 미존재", HTTPStatus: 404}
	}

	// Delete from DB first.
	if err := s.repo.DeleteGuideline(ctx, id); err != nil {
		return fmt.Errorf("지침 삭제 실패: %w", err)
	}

	// Delete file from storage (best-effort).
	if g.StoragePath != "" {
		if err := os.Remove(g.StoragePath); err != nil && !os.IsNotExist(err) {
			log.Printf("[grc-guideline] file delete warning %s: %v", g.StoragePath, err)
		}
	}

	return nil
}

// ── Cloud Environments ──

// CreateCloudEnvironments inserts cloud environment resources with text extraction.
func (s *GRCService) CreateCloudEnvironments(ctx context.Context, envs []grc.CloudEnvironment) ([]grc.CloudEnvironment, error) {
	for i := range envs {
		if envs[i].ExtractedText == "" {
			envs[i].ExtractedText = ExtractCloudEnvText(envs[i].ResourceType, envs[i].RawData)
		}
		if err := s.repo.InsertCloudEnvironment(ctx, &envs[i]); err != nil {
			return nil, fmt.Errorf("insert cloud env %s/%s: %w", envs[i].ResourceType, envs[i].ResourceName, err)
		}
	}
	return envs, nil
}

// ListCloudEnvironments returns paginated cloud environment resources.
func (s *GRCService) ListCloudEnvironments(ctx context.Context, companyID, resourceType string, page, pageSize int) ([]grc.CloudEnvListItem, int, error) {
	return s.repo.ListCloudEnvironments(ctx, companyID, resourceType, page, pageSize)
}

// ─────────────────────────────────────────────
// Async Worker
// ─────────────────────────────────────────────

// checkWallClockLimit bounds a single GL check's total runtime so checks can't
// hang in running/40% indefinitely (LLM/임베딩 지연 시 명시적 실패 처리).
// env GRC_CHECK_TIMEOUT_MIN으로 조정 가능 (기본 15분).
func checkWallClockLimit() time.Duration {
	if v := os.Getenv("GRC_CHECK_TIMEOUT_MIN"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Minute
		}
	}
	return 15 * time.Minute
}

func (s *GRCService) runWorker(checkID string) {
	ctx, cancel := context.WithTimeout(context.Background(), checkWallClockLimit())
	defer cancel()

	if err := s.repo.UpdateCheckStarted(ctx, checkID); err != nil {
		log.Printf("[grc-worker] failed to mark check started: %s: %v", checkID, err)
		return
	}

	result, err := s.processCheck(ctx, checkID)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			// 타임아웃은 영구 running 상태 대신 명시적 failed로 마감
			log.Printf("[grc-worker] check %s timed out after %s", checkID, checkWallClockLimit())
			_ = s.repo.UpdateCheckFailed(context.Background(), checkID, &grc.ErrorDetail{
				Code:    "TIMEOUT",
				Message: fmt.Sprintf("점검이 %s 내에 완료되지 않아 중단됨 (LLM/임베딩 서버 상태 확인 필요)", checkWallClockLimit()),
			})
			return
		}
		log.Printf("[grc-worker] check %s failed: %v", checkID, err)
		errDetail := &grc.ErrorDetail{
			Code:    "INTERNAL_ERROR",
			Message: err.Error(),
		}
		if ge, ok := err.(*GRCError); ok {
			errDetail.Code = ge.Code
			errDetail.Message = ge.Message
		}
		_ = s.repo.UpdateCheckFailed(ctx, checkID, errDetail)
		return
	}

	if err := s.repo.SaveCheckResult(ctx, result); err != nil {
		log.Printf("[grc-worker] failed to save result: %s: %v", checkID, err)
		_ = s.repo.UpdateCheckFailed(ctx, checkID, &grc.ErrorDetail{Code: "INTERNAL_ERROR", Message: "결과 저장 실패"})
		return
	}
}

func (s *GRCService) processCheck(ctx context.Context, checkID string) (*grc.ComplianceCheckResult, error) {
	// Load check & evidence files.
	chk, err := s.repo.GetCheck(ctx, checkID)
	if err != nil {
		return nil, err
	}

	evidenceFiles, err := s.repo.ListEvidenceFiles(ctx, checkID)
	if err != nil {
		return nil, err
	}

	ruleset, err := s.rulesetStore.Load(chk.ISMSPItemID)
	if err != nil {
		return nil, err
	}

	// Step 1: Extract evidence data from files (with hash-based caching).
	_ = s.repo.UpdateCheckProgress(ctx, checkID, 10)
	evidenceStore := make(map[string]any) // filename -> extracted data
	for _, ef := range evidenceFiles {
		// Cache hit: DB에 이미 추출된 텍스트가 있으면 재사용
		if ef.ExtractedText != "" {
			log.Printf("[grc-cache] HIT (same check) %s", ef.Filename)
			evidenceStore[ef.Filename] = ef.ExtractedText
			continue
		}
		// Cache hit: 동일 해시의 이전 파일에서 추출 텍스트 조회
		if ef.ContentHash != "" {
			if cached, found, _ := s.repo.FindExtractedTextByHash(ctx, ef.ContentHash); found {
				log.Printf("[grc-cache] HIT (hash=%s) %s", ef.ContentHash[:12], ef.Filename)
				evidenceStore[ef.Filename] = cached
				// 현재 레코드에도 캐시 저장
				_ = s.repo.UpdateEvidenceExtractedText(ctx, checkID, ef.Filename, cached)
				continue
			}
		}

		// Cache miss: 파일에서 새로 추출
		data, err := s.extractEvidence(ef)
		if err != nil {
			return nil, &GRCError{
				Code:    "EXTRACTION_FAILED",
				Message: fmt.Sprintf("%s 파일에서 추출 실패", ef.Filename),
			}
		}
		evidenceStore[ef.Filename] = data

		// 추출된 텍스트를 DB에 저장 (다음 점검에서 캐시로 사용)
		var textForDB string
		switch v := data.(type) {
		case string:
			textForDB = v
		case map[string]any:
			if b, err := json.Marshal(v); err == nil {
				textForDB = string(b)
			}
		case []any:
			if b, err := json.Marshal(v); err == nil {
				textForDB = string(b)
			}
		case []map[string]string:
			if b, err := json.Marshal(v); err == nil {
				textForDB = string(b)
			}
		}
		if textForDB != "" {
			_ = s.repo.UpdateEvidenceExtractedText(ctx, checkID, ef.Filename, textForDB)
			log.Printf("[grc-cache] SAVED %s (hash=%s, %d chars)", ef.Filename, ef.ContentHash, len(textForDB))
		}
	}
	_ = s.repo.UpdateCheckProgress(ctx, checkID, 30)

	// Step 1.5: Load DB guidelines for this company + item (지침 임베딩 사용).
	dbGuidelines, _ := s.repo.GetGuidelinesForItem(ctx, chk.CompanyID, chk.ISMSPItemID)
	if len(dbGuidelines) > 0 {
		var ids []int64
		for _, g := range dbGuidelines {
			ids = append(ids, g.ID)
		}
		_ = s.repo.UpdateCheckGuidelineIDs(ctx, checkID, ids)
		log.Printf("[grc-worker] loaded %d DB guidelines for %s/%s", len(dbGuidelines), chk.CompanyID, chk.ISMSPItemID)
	}

	// Step 1.6: Generate embeddings for evidence + guideline text.
	s.generateEvidenceEmbeddings(ctx, checkID, evidenceFiles, evidenceStore, ruleset, dbGuidelines)
	_ = s.repo.UpdateCheckProgress(ctx, checkID, 40)

	// Step 1.7: Pre-compute GL rule top sentences (serialized via mutex).
	// Only 1 check runs embedding at a time so the embedding server isn't overwhelmed.
	// Cache hits skip embedding entirely; each item only needs 2 HTTP calls on first run.
	glTopSentences := s.precomputeGLRuleTopSentences(ctx, chk.CompanyID, chk.ISMSPItemID, dbGuidelines, ruleset)

	embByFile, errEmb := s.repo.ListEvidenceEmbeddingsForCheck(ctx, checkID)
	if errEmb != nil {
		log.Printf("[grc-embed] reload evidence vectors: %v", errEmb)
		embByFile = nil
	}

	// Step 2: Evaluate each rule.
	var ruleResults []grc.RuleResult
	for i, rule := range ruleset.Rules {
		// Skip k8s_api/k8s_native rules — handled by pod_graph_evaluator
		if rule.JudgmentSource == "k8s_api" || rule.JudgmentSource == "k8s_native" {
			continue
		}
		// Skip F- (finding) rules — handled by finding_evaluator
		if strings.HasPrefix(rule.RuleID, "F-") {
			continue
		}
		matched := matchEvidenceToRule(evidenceFiles, rule, evidenceStore)
		var result grc.RuleResult

		// GL (guideline RAG) rules don't need evidence files — their "evidence"
		// is the DB guideline text passed via dbGuidelines. Let them through.
		isGuidelineRAG := rule.JudgmentLogic.Type == "semantic_match" &&
			rule.JudgmentLogic.Method == "llm_rag_entailment"

		// Look up pre-computed top sentences for this rule (may be nil for non-GL rules)
		cachedSentences := glTopSentences[rule.RuleID]

		if len(matched) == 0 && !isGuidelineRAG {
			// 증적 미제출은 위반(NOT_MET)이 아니라 평가불가(NO_DATA) —
			// 증거 부재 ≠ 위반 (P0-3과 동일 원칙). 항목 verdict는 검토필요로 집계된다.
			// 빈 줄로 렌더링되지 않도록 룰 이름·필요 증적 힌트를 표시 텍스트에 채운다
			// (예: 2.5.4 R-03~15 evidence_upload 룰이 GL 점검 출력에 빈 메시지로 섞이던 문제).
			result = grc.RuleResult{
				RuleID:        rule.RuleID,
				Verdict:       grc.VerdictNO_DATA,
				Reason:        noEvidenceReason(rule),
				MatchedIndicators: []string{noEvidenceReason(rule)},
				EvidenceFiles: []string{},
			}
		} else if len(matched) == 0 && isGuidelineRAG {
			// Guideline RAG: no evidence files needed, evaluate directly.
			result = s.evaluateRule(ctx, rule, nil, []string{}, dbGuidelines, cachedSentences)
		} else {
			filenames := make([]string, len(matched))
			var extractedData []any
			for j, ef := range matched {
				filenames[j] = ef.Filename
				if d, ok := evidenceStore[ef.Filename]; ok {
					extractedData = append(extractedData, d)
				}
			}

			result = s.evaluateRule(ctx, rule, extractedData, filenames, dbGuidelines, cachedSentences)
			result.EvidenceSources = evidenceAttributionsFromFiles(matched)
			result = s.applyGuidelineEmbedding(rule, matched, embByFile, dbGuidelines, result)
		}

		result = ensureVerdictDisplay(result)
		ruleResults = append(ruleResults, result)
		pct := 40 + (i+1)*50/len(ruleset.Rules)
		_ = s.repo.UpdateCheckProgress(ctx, checkID, pct)
	}

	// 동일 RuleID가 한 점검에서 중복 평가된 경우 1건으로 정리한다 (definitive 우선).
	ruleResults = dedupRuleResultsByID(ruleResults)

	// Step 3: Aggregate results.
	_ = s.repo.UpdateCheckProgress(ctx, checkID, 95)
	summary := aggregateSummary(ruleResults, len(evidenceFiles))
	summary.SummaryText = fmt.Sprintf("ISMS-P %s (%s) 점검 결과: %d개 룰 중 통과 %d / 미준수 %d / 검토필요 %d / 스킵 %d",
		chk.ISMSPItemID, ruleset.Item.Name,
		summary.TotalRules, summary.Passed, summary.Failed, summary.NeedsReview, summary.Skipped)

	verdict := "준수"
	severity := "low"
	effectiveRules := 0 // skip/NA 제외한 실제 평가 룰 수
	for _, r := range ruleResults {
		nv := grc.NormalizeVerdict(r.Verdict)
		if nv != grc.VerdictSKIPPED && nv != grc.VerdictNA && nv != grc.VerdictREPORT {
			effectiveRules++
		}
		if nv == grc.VerdictNOT_MET {
			verdict = "미준수"
			for _, v := range r.Violations {
				switch v.Severity {
				case "critical":
					severity = "critical"
				case "high":
					if severity != "critical" {
						severity = "high"
					}
				case "medium":
					if severity != "critical" && severity != "high" {
						severity = "medium"
					}
				}
			}
		} else if (nv == grc.VerdictNEEDS_REVIEW || nv == grc.VerdictINDETERMINATE || nv == grc.VerdictNO_DATA) && verdict != "미준수" {
			verdict = "검토필요"
		}
	}
	// 전 룰 skip이면 "준수"가 아니라 "데이터없음" — 하나도 평가되지 않은 점검을
	// 준수로 집계하던 버그 수정 (예: 3룰 전부 skipped인데 verdict 준수).
	if effectiveRules == 0 {
		verdict = "데이터없음"
		severity = ""
	}

	recommendations := generateRecommendations(ruleResults, ruleset)

	finalResult := &grc.ComplianceCheckResult{
		CheckID:         checkID,
		ISMSPItemID:     chk.ISMSPItemID,
		ItemName:        ruleset.Item.Name,
		RulesetVersion:  "2023.11",
		Verdict:         verdict,
		Severity:        severity,
		CompletedAt:     time.Now().UTC(),
		Summary:         summary,
		RuleResults:     ruleResults,
		Recommendations: recommendations,
	}

	return finalResult, nil
}

// ─────────────────────────────────────────────
// Embedding Generation
// ─────────────────────────────────────────────

// generateEvidenceEmbeddings creates BGE-M3 embeddings for extracted evidence text
// and the corresponding guideline text, then stores them in the DB.
// If dbGuidelines are available, their extracted_text is used as the guideline text.
// Otherwise, falls back to buildGuidelineText(rule).
func (s *GRCService) generateEvidenceEmbeddings(
	ctx context.Context,
	checkID string,
	evidenceFiles []grc.EvidenceFile,
	evidenceStore map[string]any,
	ruleset *Ruleset,
	dbGuidelines []grc.Guideline,
) {
	if s.embeddingClient == nil || !s.embeddingClient.Available() {
		return
	}

	// Build guideline text: prefer DB guidelines, fallback to rule-based text.
	var guidelineText string
	if len(dbGuidelines) > 0 {
		var parts []string
		for _, g := range dbGuidelines {
			if g.ExtractedText != "" {
				parts = append(parts, g.ExtractedText)
			}
		}
		guidelineText = strings.Join(parts, "\n---\n")
		log.Printf("[grc-embed] using %d DB guideline texts (%d chars total)", len(parts), len(guidelineText))
	}

	// Phase 1: 텍스트 수집 (evidence + guideline 쌍)
	type embedEntry struct {
		filename string
		glText   string
	}
	var allTexts []string
	var entries []embedEntry

	for _, ef := range evidenceFiles {
		var evidenceText string
		if d, ok := evidenceStore[ef.Filename]; ok {
			switch v := d.(type) {
			case string:
				evidenceText = v
			case map[string]any:
				if b, err := json.Marshal(v); err == nil {
					evidenceText = string(b)
				}
			case []map[string]string:
				if b, err := json.Marshal(v); err == nil {
					evidenceText = string(b)
				}
			}
		}
		if evidenceText == "" {
			continue
		}

		glText := guidelineText
		if glText == "" {
			for _, rule := range ruleset.Rules {
				matched := matchEvidenceToRule([]grc.EvidenceFile{ef}, rule, evidenceStore)
				if len(matched) > 0 {
					glText += buildGuidelineText(rule) + "\n"
				}
			}
		}

		allTexts = append(allTexts, evidenceText, glText)
		entries = append(entries, embedEntry{filename: ef.Filename, glText: glText})
	}

	if len(allTexts) == 0 {
		return
	}

	// Phase 2: 한 번에 임베딩 (N개 파일 × 2 = 2N개 텍스트, 1회 HTTP)
	log.Printf("[grc-embed] batch embedding %d texts (%d evidence files) in single call", len(allTexts), len(entries))
	allEmbeddings, err := s.embeddingClient.EmbedBatch(ctx, allTexts)
	if err != nil {
		log.Printf("[grc-embed] batch embed error: %v", err)
		return
	}

	// Phase 3: 결과 매핑 + DB 저장
	for i, entry := range entries {
		evIdx := i * 2
		glIdx := i*2 + 1
		if evIdx >= len(allEmbeddings) || glIdx >= len(allEmbeddings) {
			continue
		}

		var evidenceEmb, guidelineEmb []float32
		if allEmbeddings[evIdx] != nil {
			evidenceEmb = allEmbeddings[evIdx]
		}
		if allEmbeddings[glIdx] != nil {
			guidelineEmb = allEmbeddings[glIdx]
		}

		if err := s.repo.UpdateEvidenceEmbeddings(ctx, checkID, entry.filename, entry.glText, evidenceEmb, guidelineEmb); err != nil {
			log.Printf("[grc-embed] save embeddings error for %s: %v", entry.filename, err)
		} else {
			log.Printf("[grc-embed] saved embeddings for %s (evidence=%d dims, guideline=%d dims)",
				entry.filename, len(evidenceEmb), len(guidelineEmb))
		}
	}
}

// InvalidateGLCache removes cached GL rule top sentences for a (company, item) pair.
// Called when a guideline is uploaded so next check recomputes fresh top sentences.
func (s *GRCService) InvalidateGLCache(ctx context.Context, companyID, ismspItemID string) {
	if err := s.repo.InvalidateGLRuleCache(ctx, companyID, ismspItemID); err != nil {
		log.Printf("[grc-gl-cache] invalidate failed for %s/%s: %v", companyID, ismspItemID, err)
	} else {
		log.Printf("[grc-gl-cache] invalidated cache for %s/%s", companyID, ismspItemID)
	}
}

// precomputeGLRuleTopSentences pre-computes top-K guideline sentences for each GL rule.
//
// FAST PATH (sentence embeddings in DB from upload time):
//   Load stored embeddings → only embed rule queries (~0.5s each) → cosine sim in Go.
//   No semaphore needed; 18 checks can run fully in parallel.
//
// SLOW PATH (no stored sentence embeddings — legacy or pre-deployment guidelines):
//   Acquire semaphore → embed 300 sentences (~15 min on CPU BGE-M3) → embed queries.
//   Saves top-K to grc_gl_rule_top_sentences; subsequent checks use top-K DB cache.
func (s *GRCService) precomputeGLRuleTopSentences(
	ctx context.Context,
	companyID, ismspItemID string,
	dbGuidelines []grc.Guideline,
	ruleset *Ruleset,
) map[string][]string {
	result := make(map[string][]string)

	if s.embeddingClient == nil || !s.embeddingClient.Available() {
		return result
	}

	// Collect GL rules (text_extraction + llm_rag_entailment only)
	var glRules []Rule
	for _, rule := range ruleset.Rules {
		if rule.JudgmentSource == "text_extraction" &&
			rule.JudgmentLogic.Type == "semantic_match" &&
			rule.JudgmentLogic.Method == "llm_rag_entailment" {
			glRules = append(glRules, rule)
		}
	}
	if len(glRules) == 0 {
		return result
	}

	// Check top-K DB cache first: serve already-computed rules without any HTTP call
	var uncachedRules []Rule
	for _, rule := range glRules {
		if sentences, hit, _ := s.repo.GetGLRuleTopSentences(ctx, companyID, ismspItemID, rule.RuleID); hit {
			result[rule.RuleID] = sentences
			log.Printf("[grc-gl-cache] rule=%s: top-K cache HIT (%d sentences)", rule.RuleID, len(sentences))
		} else {
			uncachedRules = append(uncachedRules, rule)
		}
	}
	if len(uncachedRules) == 0 {
		log.Printf("[grc-gl-cache] all %d GL rules served from top-K cache", len(glRules))
		return result
	}

	log.Printf("[grc-gl-cache] %d/%d GL rules need precompute for %s/%s",
		len(uncachedRules), len(glRules), companyID, ismspItemID)

	// ── FAST PATH: sentence embeddings stored in DB from upload time ──
	storedSentEmbs, _ := s.repo.GetGuidelineSentenceEmbeddingsForItem(ctx, companyID, ismspItemID)
	if len(storedSentEmbs) > 0 {
		log.Printf("[grc-gl-cache] FAST PATH: %d stored sentence embeddings for %s/%s — embedding queries only",
			len(storedSentEmbs), companyID, ismspItemID)
		return s.precomputeWithSentenceEmbeddings(ctx, companyID, ismspItemID, uncachedRules, storedSentEmbs, result)
	}

	// ── SLOW PATH: sentence embeddings not in DB (uploaded before this feature) ──
	// Acquire semaphore to avoid overloading single-worker BGE-M3.
	s.precomputeSem <- struct{}{}
	defer func() { <-s.precomputeSem }()

	// Re-check after acquiring semaphore: another goroutine may have computed them.
	storedSentEmbs, _ = s.repo.GetGuidelineSentenceEmbeddingsForItem(ctx, companyID, ismspItemID)
	if len(storedSentEmbs) > 0 {
		log.Printf("[grc-gl-cache] FAST PATH (after sem): %d stored sentences for %s/%s",
			len(storedSentEmbs), companyID, ismspItemID)
		return s.precomputeWithSentenceEmbeddings(ctx, companyID, ismspItemID, uncachedRules, storedSentEmbs, result)
	}

	// Build guideline sentences from DB guideline text
	var dummyRule Rule
	if len(uncachedRules) > 0 {
		dummyRule = uncachedRules[0]
	}
	sentences := splitGuidelineSentences(dbGuidelines, dummyRule)
	if len(sentences) == 0 {
		log.Printf("[grc-gl-cache] no guideline sentences for %s/%s", companyID, ismspItemID)
		return result
	}

	// Cap at 300 sentences (same limit as at upload time)
	const maxSentencesForRAG = 300
	if len(sentences) > maxSentencesForRAG {
		origLen := len(sentences)
		sampled := make([]string, 0, maxSentencesForRAG)
		step := len(sentences) / maxSentencesForRAG
		for i := 0; i < len(sentences) && len(sampled) < maxSentencesForRAG; i += step {
			sampled = append(sampled, sentences[i])
		}
		sentences = sampled
		log.Printf("[grc-gl-cache] capped %d→%d sentences for %s/%s", origLen, len(sentences), companyID, ismspItemID)
	}

	// HTTP call: embed ALL guideline sentences (slow on CPU)
	log.Printf("[grc-gl-cache] SLOW PATH: embedding %d sentences for %s/%s", len(sentences), companyID, ismspItemID)
	sentenceEmbeddings, err := s.embeddingClient.EmbedBatch(ctx, sentences)
	if err != nil || len(sentenceEmbeddings) == 0 {
		log.Printf("[grc-gl-cache] sentence embedding failed: %v", err)
		return result
	}

	// Convert raw embeddings to SentenceEmbedding slice for the shared helper
	sentEmbs := make([]postgres.SentenceEmbedding, 0, len(sentences))
	for i, emb := range sentenceEmbeddings {
		if emb != nil && i < len(sentences) {
			sentEmbs = append(sentEmbs, postgres.SentenceEmbedding{Text: sentences[i], Embedding: emb})
		}
	}

	return s.precomputeWithSentenceEmbeddings(ctx, companyID, ismspItemID, uncachedRules, sentEmbs, result)
}

// precomputeWithSentenceEmbeddings embeds rule queries and computes cosine similarity
// against pre-loaded sentence embeddings. Shared by fast and slow paths.
func (s *GRCService) precomputeWithSentenceEmbeddings(
	ctx context.Context,
	companyID, ismspItemID string,
	uncachedRules []Rule,
	sentEmbs []postgres.SentenceEmbedding,
	result map[string][]string,
) map[string][]string {
	var queries []string
	for _, rule := range uncachedRules {
		queries = append(queries, buildRuleQuery(rule))
	}
	log.Printf("[grc-gl-cache] embedding %d rule queries for %s/%s", len(queries), companyID, ismspItemID)
	queryEmbeddings, err := s.embeddingClient.EmbedBatch(ctx, queries)
	if err != nil || len(queryEmbeddings) == 0 {
		log.Printf("[grc-gl-cache] query embedding failed: %v", err)
		return result
	}

	for i, rule := range uncachedRules {
		if i >= len(queryEmbeddings) || queryEmbeddings[i] == nil {
			continue
		}
		queryEmb := queryEmbeddings[i]

		var scored []scoredSentence
		for _, se := range sentEmbs {
			if se.Embedding == nil {
				continue
			}
			sim := cosineSimilarity(queryEmb, se.Embedding)
			scored = append(scored, scoredSentence{text: se.Text, score: sim})
		}
		sort.Slice(scored, func(a, b int) bool { return scored[a].score > scored[b].score })

		k := defaultRAGTopK
		if k > len(scored) {
			k = len(scored)
		}
		topTexts := make([]string, k)
		for j, hit := range scored[:k] {
			topTexts[j] = hit.text
		}

		if err := s.repo.SaveGLRuleTopSentences(ctx, companyID, ismspItemID, rule.RuleID, topTexts); err != nil {
			log.Printf("[grc-gl-cache] save failed for rule=%s: %v", rule.RuleID, err)
		} else {
			log.Printf("[grc-gl-cache] cached top-%d sentences for rule=%s", k, rule.RuleID)
		}
		result[rule.RuleID] = topTexts
	}
	return result
}

// buildGuidelineText combines a rule's criteria into a single text for embedding.
func buildGuidelineText(rule Rule) string {
	var parts []string

	parts = append(parts, fmt.Sprintf("점검항목: %s", rule.RuleID))

	if len(rule.Keywords) > 0 {
		parts = append(parts, fmt.Sprintf("식별키워드: %s", strings.Join(rule.Keywords, ", ")))
	}

	for _, ind := range rule.ComplianceIndicators {
		if ind.Description != "" {
			parts = append(parts, fmt.Sprintf("준수기준: %s", ind.Description))
		} else if ind.Field != "" {
			parts = append(parts, fmt.Sprintf("준수기준: %s %s %v", ind.Field, ind.Op, ind.Value))
		} else if ind.Pattern != "" {
			parts = append(parts, fmt.Sprintf("준수패턴: %s", ind.Pattern))
		}
	}

	return strings.Join(parts, "\n")
}

// ─────────────────────────────────────────────
// Cloud Environment Text Extraction
// ─────────────────────────────────────────────

// ExtractCloudEnvText converts a K8s resource's raw_data into a text representation for embedding.
func ExtractCloudEnvText(resourceType string, rawData map[string]any) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("resource_type: %s", resourceType))

	// Extract common metadata fields.
	if meta, ok := rawData["metadata"].(map[string]any); ok {
		if name, ok := meta["name"].(string); ok {
			parts = append(parts, fmt.Sprintf("name: %s", name))
		}
		if ns, ok := meta["namespace"].(string); ok {
			parts = append(parts, fmt.Sprintf("namespace: %s", ns))
		}
		if labels, ok := meta["labels"].(map[string]any); ok {
			for k, v := range labels {
				parts = append(parts, fmt.Sprintf("label: %s=%v", k, v))
			}
		}
	}

	// Flatten the rest as JSON text for embedding.
	if b, err := json.Marshal(rawData); err == nil {
		text := string(b)
		// Truncate very large JSON for embedding (BGE-M3 has context limits).
		if len(text) > 4000 {
			text = text[:4000]
		}
		parts = append(parts, text)
	}

	return strings.Join(parts, "\n")
}

// ─────────────────────────────────────────────
// Evidence Extraction
// ─────────────────────────────────────────────

func (s *GRCService) extractEvidence(ef grc.EvidenceFile) (any, error) {
	ext := strings.ToLower(filepath.Ext(ef.Filename))
	switch ext {
	case ".json":
		return parseJSONFile(ef.StoragePath)
	case ".yaml", ".yml":
		return parseYAMLFile(ef.StoragePath)
	case ".csv":
		return parseCSVFile(ef.StoragePath)
	case ".txt":
		return readTextFile(ef.StoragePath)
	case ".pdf":
		return s.extractPDFText(ef.StoragePath)
	case ".png", ".jpg", ".jpeg", ".webp":
		return s.extractImageText(ef)
	default:
		return nil, fmt.Errorf("unsupported file type: %s", ext)
	}
}

// extractPDFText는 PDF에서 텍스트를 추출합니다.
// 순수 Go 라이브러리로 시도하고, 실패하거나 빈 텍스트면 OCR 폴백.
func (s *GRCService) extractPDFText(path string) (string, error) {
	text, err := pdfext.ExtractText(path)
	if err != nil {
		log.Printf("[grc-pdf] pdftotext FAIL %s: %v", path, err)
	} else {
		log.Printf("[grc-pdf] pdftotext OK %s (%d chars): %.300s", path, len(text), text)
	}
	if err == nil && !pdfext.IsTextEmpty(text) {
		return text, nil
	}
	// PDF 텍스트 추출 실패 → OCR 폴백 (스캔된 PDF일 수 있음)
	if s.ocrClient != nil {
		ocrText, ocrErr := s.ocrClient.ExtractText(context.Background(), path)
		if ocrErr == nil && !pdfext.IsTextEmpty(ocrText) {
			return ocrText, nil
		}
	}
	if err != nil {
		return "", fmt.Errorf("PDF text extraction failed: %w", err)
	}
	return text, nil
}

// extractImageText는 이미지에서 Tesseract OCR로 텍스트를 추출합니다.
// OCR 실패 시 기존 placeholder를 반환합니다.
func (s *GRCService) extractImageText(ef grc.EvidenceFile) (any, error) {
	if s.ocrClient == nil {
		return map[string]any{"_type": "image", "_path": ef.StoragePath, "_filename": ef.Filename}, nil
	}
	text, err := s.ocrClient.ExtractText(context.Background(), ef.StoragePath)
	if err != nil {
		log.Printf("[grc-ocr] FAIL %s: %v", ef.Filename, err)
		return map[string]any{"_type": "image", "_path": ef.StoragePath, "_filename": ef.Filename}, nil
	}
	if strings.TrimSpace(text) == "" {
		log.Printf("[grc-ocr] EMPTY %s", ef.Filename)
		return map[string]any{"_type": "image", "_path": ef.StoragePath, "_filename": ef.Filename}, nil
	}
	log.Printf("[grc-ocr] OK %s (%d chars): %.500s", ef.Filename, len(text), text)
	return text, nil
}

func parseJSONFile(path string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var result any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func parseYAMLFile(path string) (any, error) {
	// Use JSON fallback: read as text.
	return readTextFile(path)
}

func parseCSVFile(path string) ([]map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	reader := csv.NewReader(f)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) < 2 {
		return []map[string]string{}, nil
	}

	headers := records[0]
	var rows []map[string]string
	for _, record := range records[1:] {
		row := make(map[string]string)
		for j, val := range record {
			if j < len(headers) {
				row[headers[j]] = val
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func readTextFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ─────────────────────────────────────────────
// Evidence-to-Rule Matching
// ─────────────────────────────────────────────

// noEvidenceReason builds a human-readable NO_DATA message for a rule whose
// evidence file was not submitted: which rule it is, and what to upload.
// evidence_upload 룰(예: 2.5.4 R-03~15 OS/AD/IAM 설정 점검)이 빈 메시지로
// 렌더링되지 않도록 룰 이름과 증적 힌트(keywords 일부)를 포함한다.
func noEvidenceReason(rule Rule) string {
	name := strings.TrimSpace(rule.Name)
	if name == "" {
		name = rule.RuleID
	}
	msg := fmt.Sprintf("증적 미제출 — '%s' 자동점검 불가", name)
	if len(rule.Keywords) > 0 {
		n := len(rule.Keywords)
		if n > 3 {
			n = 3
		}
		msg += fmt.Sprintf(" (필요 증적 예: %s)", strings.Join(rule.Keywords[:n], ", "))
	}
	return msg
}

func matchEvidenceToRule(files []grc.EvidenceFile, rule Rule, evidenceStore map[string]any) []grc.EvidenceFile {
	var matched []grc.EvidenceFile
	for _, ef := range files {
		// Phase 1a: If target_rule_ids is specified, use that.
		if len(ef.TargetRuleIDs) > 0 {
			for _, rid := range ef.TargetRuleIDs {
				if rid == rule.RuleID {
					matched = append(matched, ef)
					break
				}
			}
			continue
		}
		// Phase 1b: no check_category matching (field removed from Rule).
		// Falls through to keyword-based fallback (Phase 2).
	}
	if len(matched) > 0 {
		return matched
	}

	// Phase 2: Keyword-based fallback matching.
	// 증적의 추출 텍스트에서 룰의 identification_keywords를 검색하여 자동 매칭.
	if len(rule.Keywords) == 0 {
		return nil
	}

	minKW := rule.JudgmentLogic.MinKeywordMatches
	if minKW <= 0 {
		minKW = 1 // default: 키워드 1개 이상 매칭 시 관련 증적으로 간주 (평가는 evaluateRule이 담당)
	}

	for _, ef := range files {
		if len(ef.TargetRuleIDs) > 0 {
			continue // explicit mapping만 사용하는 파일은 건너뜀
		}
		// 추출 텍스트 가져오기 (포맷 무관 — 키워드 매칭만으로 관련성 판단)
		text := extractTextString(evidenceStore[ef.Filename])
		if text == "" {
			continue
		}
		lowerText := strings.ToLower(text)
		kwHits := 0
		for _, kw := range rule.Keywords {
			if strings.Contains(lowerText, strings.ToLower(kw)) {
				kwHits++
			}
		}
		if kwHits >= minKW {
			matched = append(matched, ef)
			log.Printf("[grc-match] keyword fallback: %s → rule %s (%d/%d keywords hit)",
				ef.Filename, rule.RuleID, kwHits, len(rule.Keywords))
		}
	}
	return matched
}

// extractTextString extracts a plain text string from evidence data (string or map).
func extractTextString(data any) string {
	if data == nil {
		return ""
	}
	switch v := data.(type) {
	case string:
		return v
	case map[string]any:
		// JSON 증적의 경우 전체를 직렬화하여 키워드 검색 가능하게
		b, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return string(b)
	default:
		return ""
	}
}

// ─────────────────────────────────────────────
// Evaluation Handlers
// ─────────────────────────────────────────────

// cachedGLSentences: pre-computed top-K guideline sentences for GL rules (may be nil).
// When provided, evaluateLLMRAGEntailment skips the embedding step entirely.
func (s *GRCService) evaluateRule(ctx context.Context, rule Rule, evidenceData []any, filenames []string, dbGuidelines []grc.Guideline, cachedGLSentences []string) grc.RuleResult {
	base := grc.RuleResult{
		RuleID:        rule.RuleID,
		EvidenceFiles: filenames,
	}

	switch rule.JudgmentLogic.Type {
	case "structured_match", "manual_evidence_match", "hybrid_match":
		return evaluateStructured(rule, evidenceData, base)
	case "semantic_match":
		return s.evaluateSemantic(ctx, rule, evidenceData, base, dbGuidelines, cachedGLSentences)
	case "regex_match":
		return evaluateRegex(rule, evidenceData, base)
	case "aggregated_statistics":
		return evaluateAggregated(rule, evidenceData, base)
	case "code_pattern_match":
		return evaluateCodePattern(rule, evidenceData, base)
	default:
		base.Verdict = grc.VerdictINDETERMINATE
		base.SkipReason = fmt.Sprintf("지원하지 않는 judgment_logic type: %s", rule.JudgmentLogic.Type)
		base.Reason = fmt.Sprintf("미지원 평가 방식: %s", rule.JudgmentLogic.Type)
		return base
	}
}

func evaluateStructured(rule Rule, evidenceData []any, base grc.RuleResult) grc.RuleResult {
	// Merge all evidence data into one map, then flatten nested maps.
	merged := make(map[string]any)
	fieldNames := extractFieldNames(rule.ComplianceIndicators)
	for _, d := range evidenceData {
		switch v := d.(type) {
		case map[string]any:
			for k, val := range v {
				merged[k] = val
			}
		case string:
			// OCR 텍스트 → 구조화 파싱
			parsed := parseOCRToStructured(v, fieldNames)
			for k, val := range parsed {
				merged[k] = val
			}
		}
	}
	merged = flattenMap(merged)

	// 복합 JSON 필드 → 구조화 매칭용 파생 불리언 필드 자동 생성
	NormalizeRuleFixtureEvidence(rule.RuleID, merged)

	// Debug: 파싱된 필드 로그
	log.Printf("[grc-eval] rule=%s merged fields (%d):", rule.RuleID, len(merged))
	for k, v := range merged {
		log.Printf("[grc-eval]   %s = %v (%T)", k, v, v)
	}
	// 0개 필드 시 OCR 원문 로그 (디버깅용)
	if len(merged) == 0 {
		for _, d := range evidenceData {
			if s, ok := d.(string); ok {
				log.Printf("[grc-eval] rule=%s RAW OCR TEXT:\n%s", rule.RuleID, s)
			}
		}
	}

	// 원본 텍스트 수집 (필드 계열 존재 여부 판단용)
	var rawTexts []string
	for _, d := range evidenceData {
		if s, ok := d.(string); ok {
			rawTexts = append(rawTexts, strings.ToLower(s))
		}
	}

	var violations []grc.Violation
	var matched []string

	for _, ind := range rule.ComplianceIndicators {
		if ind.Field == "" {
			continue
		}
		actual, exists := merged[ind.Field]
		if !exists {
			// 퍼지 매칭: OCR 오독 보상 (dcredit→deredit 등)
			if fuzzyVal, found := fuzzyFindKey(merged, ind.Field); found {
				actual = fuzzyVal
				exists = true
				log.Printf("[grc-eval] fuzzy match: '%s' → found value %v", ind.Field, actual)
			}
		}
		if !exists {
			// 필드 계열이 증적 원문에 전혀 없으면 → 다른 시스템의 필드이므로 skip
			// 예: Oracle 증적에 "validate_password" 문자열이 없으면 MySQL 전용 필드로 간주
			if !fieldFamilyExistsInText(ind.Field, rawTexts) {
				log.Printf("[grc-eval] skip indicator '%s': field family not in evidence text", ind.Field)
				continue
			}
			violations = append(violations, grc.Violation{
				Field:       ind.Field,
				Expected:    fmt.Sprintf("%s %v", ind.Op, ind.Value),
				Actual:      nil,
				Description: fmt.Sprintf("필드 '%s' 누락", ind.Field),
				Severity:    "high",
			})
			continue
		}
		if !compareValues(actual, ind.Op, ind.Value) {
			desc := ind.Description
			if desc == "" {
				desc = fmt.Sprintf("필드 '%s': 실제값 %v, 기대값 %s %v", ind.Field, actual, ind.Op, ind.Value)
			}
			violations = append(violations, grc.Violation{
				Field:       ind.Field,
				Expected:    fmt.Sprintf("%s %v", ind.Op, ind.Value),
				Actual:      actual,
				Description: desc,
				Severity:    "high",
			})
		} else {
			matched = append(matched, fmt.Sprintf("%s %s %v (%v)", ind.Field, ind.Op, ind.Value, actual))
		}
	}

	if len(violations) > 0 {
		base.Verdict = "미준수"
		// 자원 단위 위반 추출: K8sSource 포함된 상세 violations로 교체
		if detailed := ExtractViolatedResources(rule.RuleID, evidenceData); len(detailed) > 0 {
			base.Violations = detailed
		} else {
			base.Violations = violations
		}
	} else {
		base.Verdict = "준수"
		base.MatchedIndicators = matched
	}
	return base
}

// fieldFamilyExistsInText는 네임스페이스 필드(점 포함)의 "계열"이 증적 원문에 존재하는지 확인합니다.
// 예: "validate_password.length" → "validate_password" 검색 → 없으면 MySQL 전용으로 skip
//
// 점(.)이 없는 필드(PASSWORD_LIFE_TIME 등)는 항상 true를 반환합니다.
// → OCR 오독으로 stem 매칭이 실패해도 skip되지 않고 정상적으로 "누락" 위반 처리됩니다.
func fieldFamilyExistsInText(field string, rawTextsLower []string) bool {
	fieldLower := strings.ToLower(field)
	// 점(.)이 없는 필드는 항상 평가 대상 (skip 안 함)
	dotIdx := strings.Index(fieldLower, ".")
	if dotIdx <= 0 {
		return true
	}
	// 점 이전의 접두사 추출: "validate_password.length" → "validate_password"
	stem := fieldLower[:dotIdx]
	stemAlt := strings.ReplaceAll(stem, "_", " ")

	for _, text := range rawTextsLower {
		if strings.Contains(text, stem) || strings.Contains(text, stemAlt) {
			return true
		}
	}
	return false
}

func (s *GRCService) evaluateSemantic(ctx context.Context, rule Rule, evidenceData []any, base grc.RuleResult, dbGuidelines []grc.Guideline, cachedGLSentences []string) grc.RuleResult {
	// For semantic_match with vlm_behavioral_analysis, we need image analysis.
	// For element_coverage_check, we need embedding search.
	// Simplified implementation: keyword-based matching on text content.

	var textContent string
	for _, d := range evidenceData {
		switch v := d.(type) {
		case string:
			textContent += v + "\n"
		case map[string]any:
			if t, ok := v["_type"]; ok && t == "image" {
				// In production, this would call VLM. For now, skip or handle gracefully.
				textContent += "[image evidence]\n"
			}
		}
	}

	method := rule.JudgmentLogic.Method
	switch method {
	case "embedding_similarity_with_threshold":
		return s.evaluateEmbeddingSimilarity(ctx, rule, evidenceData, base)
	case "element_coverage_check":
		return evaluateElementCoverage(rule, textContent, base)
	case "llm_rag_entailment":
		return s.evaluateLLMRAGEntailment(ctx, rule, dbGuidelines, evidenceData, base, cachedGLSentences)
	case "vlm_behavioral_analysis":
		return evaluateOCRKeywordMatch(rule, evidenceData, base)
	default:
		return evaluateKeywordMatch(rule, textContent, base)
	}
}

func evaluateKeywordMatch(rule Rule, text string, base grc.RuleResult) grc.RuleResult {
	base.Layer = grc.LayerGL

	minMatches := rule.JudgmentLogic.MinKeywordMatches
	if minMatches == 0 {
		minMatches = 2
	}

	matchCount := 0
	var matched []string
	textLower := strings.ToLower(text)
	for _, kw := range rule.Keywords {
		if strings.Contains(textLower, strings.ToLower(kw)) {
			matchCount++
			matched = append(matched, kw)
		}
	}

	if matchCount >= minMatches {
		base.Verdict = grc.VerdictMET
		base.Reason = fmt.Sprintf("%d건 키워드 매칭 (%s)", matchCount, strings.Join(matched, ", "))
		base.MatchedIndicators = []string{fmt.Sprintf("식별 키워드 %d개 매칭 (%s)", matchCount, strings.Join(matched, ", "))}
	} else {
		base.Verdict = grc.VerdictNOT_MET
		base.Reason = fmt.Sprintf("%d건 검색, 규정 없음 (최소 %d개 필요)", matchCount, minMatches)
		base.Violations = []grc.Violation{{
			Description: fmt.Sprintf("식별 키워드 %d개만 매칭 (최소 %d개 필요)", matchCount, minMatches),
			Severity:    "medium",
		}}
	}
	return base
}

func evaluateElementCoverage(rule Rule, text string, base grc.RuleResult) grc.RuleResult {
	base.Layer = grc.LayerGL

	if rule.RequiredContentElements == nil {
		base.Verdict = grc.VerdictSKIPPED
		base.SkipReason = "required_content_elements 정의 없음"
		base.Reason = "required_content_elements 정의 없음"
		return base
	}

	var missing []grc.Violation
	var matched []string
	textLower := strings.ToLower(text)

	for category, elements := range rule.RequiredContentElements {
		for _, elem := range elements {
			found := false
			for _, kw := range elem.MatchKeywords {
				if strings.Contains(textLower, strings.ToLower(kw)) {
					found = true
					break
				}
			}
			if found {
				matched = append(matched, fmt.Sprintf("[%s] %s: %s", category, elem.ID, elem.Description))
			} else {
				missing = append(missing, grc.Violation{
					Description: fmt.Sprintf("필수 요소 누락: [%s] %s - %s", category, elem.ID, elem.Description),
					Severity:    "medium",
				})
			}
		}
	}

	if len(missing) > 0 {
		base.Verdict = grc.VerdictNOT_MET
		base.Reason = fmt.Sprintf("필수 요소 %d건 누락, %d건 충족", len(missing), len(matched))
		base.Violations = missing
		base.MatchedIndicators = matched
	} else {
		base.Verdict = grc.VerdictMET
		base.Reason = fmt.Sprintf("필수 요소 %d건 전부 충족", len(matched))
		base.MatchedIndicators = matched
	}
	return base
}

// evaluateOCRKeywordMatch는 이미지 증적의 OCR 텍스트에서 키워드/패턴 매칭으로 준수 여부를 판단합니다.
// R008(회원가입·비밀번호 변경 화면), R011(임시 비밀번호 강제 변경 화면), R015(로그인 화면)에서 사용.
func evaluateOCRKeywordMatch(rule Rule, evidenceData []any, base grc.RuleResult) grc.RuleResult {
	// 1. OCR 텍스트 수집
	var allText strings.Builder
	hasImageEvidence := false
	for _, d := range evidenceData {
		switch v := d.(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				allText.WriteString(v)
				allText.WriteString("\n")
				hasImageEvidence = true
			}
		case map[string]any:
			// OCR 실패 시 image placeholder
			if t, ok := v["_type"]; ok && t == "image" {
				hasImageEvidence = true
			}
		}
	}

	if !hasImageEvidence {
		base.Verdict = grc.VerdictNOT_MET
		base.SkipReason = "이미지 증적 없음"
		base.Reason = "이미지 증적 미제출"
		base.Violations = []grc.Violation{{Description: "이미지 증적 미제출", Severity: "medium"}}
		return base
	}

	text := allText.String()
	if strings.TrimSpace(text) == "" {
		base.Verdict = grc.VerdictINDETERMINATE
		base.SkipReason = "OCR 텍스트 추출 실패 (Tesseract 미설치 또는 텍스트 인식 불가)"
		base.Reason = "OCR 텍스트 추출 실패"
		return base
	}

	textLower := strings.ToLower(text)
	// Tesseract OCR은 한국어 글자 사이에 공백을 삽입하는 경우가 많음 ("회 원 가 입" → "회원가입")
	// 공백 제거 버전으로 패턴 매칭 (원본도 함께 시도)
	textNoSpace := strings.ReplaceAll(textLower, " ", "")
	log.Printf("[grc-ocr-eval] rule=%s OCR text (%d chars): %.500s", rule.RuleID, len(text), text)

	// ocrContains는 원본 텍스트와 공백 제거 텍스트 모두에서 패턴을 찾습니다.
	ocrContains := func(pattern string) bool {
		p := strings.ToLower(pattern)
		if strings.Contains(textLower, p) {
			return true
		}
		return strings.Contains(textNoSpace, strings.ReplaceAll(p, " ", ""))
	}

	var violations []grc.Violation

	// 2. 준수 신호 카운트: compliance_indicator 패턴 우선, 없으면 identification_keywords 폴백
	var matched []string
	hasPatterns := false
	for _, ind := range rule.ComplianceIndicators {
		if ind.Pattern != "" {
			hasPatterns = true

			desc := ind.Description
			if desc == "" {
				desc = ind.Pattern
			}

			// numeric_extract: 패턴(정규식)으로 숫자 추출 후 op/value 비교
			if ind.Type == "numeric_extract" && ind.Op != "" && ind.Value != nil {
				// 공백 제거한 텍스트에서 정규식 매칭
				rePattern := strings.ReplaceAll(ind.Pattern, " ", "")
				re, err := regexp.Compile(rePattern)
				if err != nil {
					log.Printf("[grc-ocr-eval] rule=%s regex compile error: %v", rule.RuleID, err)
					continue
				}
				m := re.FindStringSubmatch(textNoSpace)
				if len(m) >= 2 {
					extracted, err := strconv.ParseFloat(m[1], 64)
					if err == nil {
						threshold, _ := toFloat64(ind.Value)
						pass := compareValues(extracted, ind.Op, threshold)
						log.Printf("[grc-ocr-eval] rule=%s numeric_extract: %s → %v %s %v = %v",
							rule.RuleID, ind.Pattern, extracted, ind.Op, threshold, pass)
						if pass {
							matched = append(matched, fmt.Sprintf("%s (추출값: %.0f, 기준: %s %.0f)", desc, extracted, ind.Op, threshold))
						}
					}
				}
				continue
			}

			// 기본: 문자열 포함 매칭
			if ocrContains(ind.Pattern) {
				matched = append(matched, desc)
			}
		}
	}

	// compliance_indicator에 pattern이 없는 경우 (R011 등) → identification_keywords로 폴백
	if !hasPatterns {
		for _, kw := range rule.Keywords {
			if ocrContains(kw) {
				matched = append(matched, fmt.Sprintf("키워드: %s", kw))
			}
		}
	}

	minSignals := rule.JudgmentLogic.MinComplianceSignals
	if minSignals == 0 {
		minSignals = 1
	}

	log.Printf("[grc-ocr-eval] rule=%s compliance signals: %d/%d (%v)", rule.RuleID, len(matched), minSignals, matched)

	if len(matched) >= minSignals {
		base.Verdict = "준수"
		base.MatchedIndicators = matched
	} else {
		base.Verdict = "미준수"
		base.Violations = append(violations, grc.Violation{
			Description: fmt.Sprintf("준수 신호 %d개 감지 (최소 %d개 필요, OCR 텍스트에서 규정 안내 문구 부족)", len(matched), minSignals),
			Severity:    "medium",
		})
	}
	return base
}

func evaluateRegex(rule Rule, evidenceData []any, base grc.RuleResult) grc.RuleResult {
	var samples []string
	for _, d := range evidenceData {
		switch v := d.(type) {
		case string:
			// Split by lines.
			for _, line := range strings.Split(v, "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					samples = append(samples, line)
				}
			}
		case []map[string]string:
			for _, row := range v {
				for _, val := range row {
					val = strings.TrimSpace(val)
					if val != "" {
						samples = append(samples, val)
					}
				}
			}
		}
	}

	// Check compliance patterns.
	hasCompliance := false
	var matched []string
	for _, sample := range samples {
		for _, ind := range rule.ComplianceIndicators {
			if ind.Pattern == "" {
				continue
			}
			re, err := regexp.Compile(ind.Pattern)
			if err != nil {
				continue
			}
			if re.MatchString(sample) {
				hasCompliance = true
				matched = append(matched, fmt.Sprintf("%s (%s)", ind.Description, ind.Pattern))
				break
			}
		}
	}

	if hasCompliance {
		base.Verdict = "준수"
		base.MatchedIndicators = matched
	} else {
		base.Verdict = "미준수"
		base.Violations = []grc.Violation{{
			Description: "준수 패턴 미매칭",
			Severity:    "high",
		}}
	}
	return base
}

func evaluateAggregated(rule Rule, evidenceData []any, base grc.RuleResult) grc.RuleResult {
	var records []map[string]string
	for _, d := range evidenceData {
		switch v := d.(type) {
		case []map[string]string:
			records = append(records, v...)
		}
	}

	if len(records) == 0 {
		base.Verdict = grc.VerdictNOT_MET
		base.SkipReason = "구조화된 레코드 없음"
		base.Reason = "계정/사용자 레코드 데이터 미제출"
		base.Violations = []grc.Violation{{Description: "계정 목록 증적 미제출", Severity: "medium"}}
		return base
	}

	violators := 0
	for _, record := range records {
		if isAccountViolation(record, rule) {
			violators++
		}
	}

	thresholdPct := rule.JudgmentLogic.ViolationThresholdPct
	violationPct := float64(violators) / float64(len(records)) * 100

	if violationPct > thresholdPct {
		base.Verdict = "미준수"
		base.Violations = []grc.Violation{{
			Description: fmt.Sprintf("위반 계정 %d건 (%.1f%%), 임계값 %.0f%%", violators, violationPct, thresholdPct),
			Severity:    "high",
		}}
	} else {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{fmt.Sprintf("위반 계정 %d건 (%.1f%%) — 임계값 %.0f%% 이하", violators, violationPct, thresholdPct)}
	}
	return base
}

func evaluateCodePattern(rule Rule, evidenceData []any, base grc.RuleResult) grc.RuleResult {
	var codeText string
	for _, d := range evidenceData {
		if s, ok := d.(string); ok {
			codeText += s + "\n"
		}
	}

	if codeText == "" {
		base.Verdict = grc.VerdictNOT_MET
		base.SkipReason = "코드 증적 없음"
		base.Reason = "코드 파일 증적 미제출"
		base.Violations = []grc.Violation{{Description: "코드 파일 증적 미제출", Severity: "medium"}}
		return base
	}

	// Check for required keywords from identification_keywords.
	matchCount := 0
	var matched []string
	codeLower := strings.ToLower(codeText)
	for _, kw := range rule.Keywords {
		if strings.Contains(codeLower, strings.ToLower(kw)) {
			matchCount++
			matched = append(matched, kw)
		}
	}

	minPatterns := rule.JudgmentLogic.MinPatterns
	if minPatterns == 0 {
		minPatterns = 2
	}

	if matchCount >= minPatterns {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{fmt.Sprintf("코드 패턴 %d개 매칭 (%s)", matchCount, strings.Join(matched, ", "))}
	} else {
		base.Verdict = "미준수"
		base.Violations = []grc.Violation{{
			Description: fmt.Sprintf("코드 패턴 %d개만 매칭 (최소 %d개 필요)", matchCount, minPatterns),
			Severity:    "high",
		}}
	}
	return base
}

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

// flattenMap recursively extracts nested map values into a single-level map.
// e.g. {"PasswordPolicy": {"MinimumPasswordLength": 10}} → {"PasswordPolicy": {...}, "MinimumPasswordLength": 10}
func flattenMap(m map[string]any) map[string]any {
	result := make(map[string]any)
	for k, v := range m {
		result[k] = v
		if nested, ok := v.(map[string]any); ok {
			for nk, nv := range flattenMap(nested) {
				if _, exists := result[nk]; !exists {
					result[nk] = nv
				}
			}
		}
	}
	return result
}

func compareValues(actual any, op string, expected any) bool {
	// Bool-like 동등성: Enabled/true/yes ↔ Disabled/false/no
	actualBool, actualIsBool := toBoolLike(actual)
	expectedBool, expectedIsBool := toBoolLike(expected)
	if actualIsBool && expectedIsBool {
		switch op {
		case "==":
			return actualBool == expectedBool
		case "!=":
			return actualBool != expectedBool
		}
	}

	actualF, actualOk := toFloat64(actual)
	expectedF, expectedOk := toFloat64(expected)

	if actualOk && expectedOk {
		switch op {
		case "==":
			return actualF == expectedF
		case "!=":
			return actualF != expectedF
		case "<":
			return actualF < expectedF
		case "<=":
			return actualF <= expectedF
		case ">":
			return actualF > expectedF
		case ">=":
			return actualF >= expectedF
		}
	}

	// String comparison.
	actualStr := fmt.Sprintf("%v", actual)
	expectedStr := fmt.Sprintf("%v", expected)
	switch op {
	case "==":
		return strings.EqualFold(actualStr, expectedStr)
	case "!=":
		return !strings.EqualFold(actualStr, expectedStr)
	}
	return false
}

// toBoolLike는 Enabled/Disabled/true/false/yes/no를 bool로 매핑합니다.
func toBoolLike(v any) (bool, bool) {
	if b, ok := v.(bool); ok {
		return b, true
	}
	s := strings.ToLower(fmt.Sprintf("%v", v))
	switch s {
	case "true", "enabled", "yes":
		return true, true
	case "false", "disabled", "no":
		return false, true
	}
	return false, false
}

func toFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(n, 64)
		return f, err == nil
	case bool:
		if n {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

func isAccountViolation(record map[string]string, rule Rule) bool {
	// Check compliance indicators: a record is a violation if it fails any indicator.
	for _, ind := range rule.ComplianceIndicators {
		if ind.Field != "" && ind.Op != "" {
			if actual, ok := record[ind.Field]; ok {
				if !compareValues(actual, ind.Op, ind.Value) {
					return true
				}
			}
		}
		if ind.Pattern != "" {
			for _, val := range record {
				if strings.Contains(strings.ToLower(val), strings.ToLower(ind.Pattern)) {
					return false // compliance pattern matched → not a violation
				}
			}
		}
	}
	return false
}

func aggregateSummary(results []grc.RuleResult, evidenceCount int) grc.Summary {
	s := grc.Summary{
		TotalRules:        len(results),
		EvidenceCollected: evidenceCount,
	}
	for _, r := range results {
		switch grc.NormalizeVerdict(r.Verdict) {
		case grc.VerdictMET:
			s.Passed++
		case grc.VerdictNOT_MET:
			s.Failed++
		case grc.VerdictNEEDS_REVIEW, grc.VerdictINDETERMINATE, grc.VerdictNO_DATA:
			s.NeedsReview++
		case grc.VerdictSKIPPED, grc.VerdictNA, grc.VerdictREPORT:
			// 해당없음/보고서형은 합격률 분모 제외 — skipped 버킷으로 집계
			s.Skipped++
		}
	}
	return s
}

func generateRecommendations(results []grc.RuleResult, ruleset *Ruleset) []grc.Recommendation {
	var recs []grc.Recommendation
	for _, r := range results {
		if grc.NormalizeVerdict(r.Verdict) != grc.VerdictNOT_MET {
			continue
		}
		// Find the rule in ruleset to get legal_basis.
		var action, reference string
		for _, rule := range ruleset.Rules {
			if rule.RuleID == r.RuleID {
				// Build action from violations.
				if len(r.Violations) > 0 {
					parts := make([]string, 0, len(r.Violations))
					for _, v := range r.Violations {
						if v.Description != "" {
							parts = append(parts, v.Description)
						}
					}
					action = "개선 필요: " + strings.Join(parts, "; ")
				} else {
					action = fmt.Sprintf("룰 %s (%s) 미준수 항목 개선 필요", rule.RuleID, rule.Name)
				}
				if src := formatEvidenceSourcesForRecommendation(r.EvidenceSources); src != "" {
					action = fmt.Sprintf("다음 Kubernetes 구성에서 확인됨 [%s]. %s", src, action)
				}
				// Get legal reference.
				for _, lr := range ruleset.LegalRefs {
					reference = fmt.Sprintf("%s %s", lr.Law, lr.Article)
					break
				}
				break
			}
		}
		recs = append(recs, grc.Recommendation{
			RuleID:    r.RuleID,
			Action:    action,
			Reference: reference,
		})
	}
	return recs
}

// ─────────────────────────────────────────────
// Pod Graph → Unified Check Pipeline
// ─────────────────────────────────────────────

// CreatePodGraphCheck creates a compliance check from K8s pod graph data.
// Returns immediately with check_id; evaluation runs asynchronously.
func (s *GRCService) CreatePodGraphCheck(ctx context.Context, companyID string, pgReq PodGraphRequest) (*grc.Check, error) {
	// Validate pod rulesets exist.
	rulesets := s.rulesetStore.LoadAll()
	if len(rulesets) == 0 {
		return nil, &GRCError{Code: "NO_POD_RULESETS", Message: "Pod 룰셋이 로드되지 않았습니다", HTTPStatus: 500}
	}

	checkID := GenerateJobID()
	now := time.Now().UTC()

	chk := &grc.Check{
		CheckID:     checkID,
		CompanyID:   companyID,
		ISMSPItemID: "pod-graph",
		Status:      "queued",
		ProgressPct: 0,
		AutoCollect: false,
		SubmittedAt: now,
		CheckSource: "pod_graph",
	}

	if err := s.repo.CreateCheck(ctx, chk); err != nil {
		return nil, fmt.Errorf("check 생성 실패: %w", err)
	}

	// Build synthetic evidence files from K8s resources.
	syntheticList := buildSyntheticEvidenceList(pgReq)
	podName, podNS := extractPodMeta(pgReq.Pod)
	jobDir := filepath.Join(s.storagePath, companyID, checkID)
	if err := os.MkdirAll(jobDir, 0o755); err != nil {
		return nil, fmt.Errorf("storage directory 생성 실패: %w", err)
	}

	for _, se := range syntheticList {
		// Serialize to disk.
		jsonBytes, err := json.MarshalIndent(se.Data, "", "  ")
		if err != nil {
			log.Printf("[pod-graph-check] marshal %s failed: %v", se.Filename, err)
			continue
		}
		filePath := filepath.Join(jobDir, se.Filename)
		if err := os.WriteFile(filePath, jsonBytes, 0o644); err != nil {
			log.Printf("[pod-graph-check] write %s failed: %v", se.Filename, err)
			continue
		}

		// Compute content hash.
		h := sha256.Sum256(jsonBytes)
		contentHash := hex.EncodeToString(h[:])

		ef := &grc.EvidenceFile{
			CheckID:       checkID,
			Filename:      se.Filename,
			EvidenceType:  "pod_graph",
			System:        "AWS EKS",
			Description:   fmt.Sprintf("Pod %s/%s — %s %s", podNS, podName, se.ResourceType, se.Filename),
			StoragePath:   filePath,
			FileSizeBytes: int64(len(jsonBytes)),
			K8sSource:     se.K8sSource,
			ContentHash:   contentHash,
		}
		if err := s.repo.InsertEvidenceFile(ctx, ef); err != nil {
			log.Printf("[pod-graph-check] insert evidence %s failed: %v", se.Filename, err)
		}
	}

	// Launch async worker.
	go s.runPodGraphWorker(checkID, pgReq)

	return chk, nil
}

func (s *GRCService) runPodGraphWorker(checkID string, pgReq PodGraphRequest) {
	ctx := context.Background()

	if err := s.repo.UpdateCheckStarted(ctx, checkID); err != nil {
		log.Printf("[pod-graph-worker] failed to mark check started: %s: %v", checkID, err)
		return
	}

	result, err := s.processPodGraphCheck(ctx, checkID, pgReq)
	if err != nil {
		log.Printf("[pod-graph-worker] check %s failed: %v", checkID, err)
		errDetail := &grc.ErrorDetail{
			Code:    "INTERNAL_ERROR",
			Message: err.Error(),
		}
		if ge, ok := err.(*GRCError); ok {
			errDetail.Code = ge.Code
			errDetail.Message = ge.Message
		}
		_ = s.repo.UpdateCheckFailed(ctx, checkID, errDetail)
		return
	}

	if err := s.repo.SaveCheckResult(ctx, result); err != nil {
		log.Printf("[pod-graph-worker] failed to save result: %s: %v", checkID, err)
		_ = s.repo.UpdateCheckFailed(ctx, checkID, &grc.ErrorDetail{Code: "INTERNAL_ERROR", Message: "결과 저장 실패"})
	}
}

func (s *GRCService) processPodGraphCheck(ctx context.Context, checkID string, pgReq PodGraphRequest) (*grc.ComplianceCheckResult, error) {
	rulesets := s.rulesetStore.LoadAll()
	if len(rulesets) == 0 {
		return nil, &GRCError{Code: "NO_POD_RULESETS", Message: "Pod 룰셋이 로드되지 않았습니다", HTTPStatus: 500}
	}

	// Step 1: Load evidence files + textualize.
	_ = s.repo.UpdateCheckProgress(ctx, checkID, 10)
	evidenceFiles, err := s.repo.ListEvidenceFiles(ctx, checkID)
	if err != nil {
		return nil, fmt.Errorf("evidence 로드 실패: %w", err)
	}

	// Step 2: Textualize each K8s resource and store as extracted_text.
	_ = s.repo.UpdateCheckProgress(ctx, checkID, 20)
	syntheticList := buildSyntheticEvidenceList(pgReq)
	typeByFilename := make(map[string]string)
	dataByFilename := make(map[string]map[string]any)
	for _, se := range syntheticList {
		typeByFilename[se.Filename] = se.ResourceType
		dataByFilename[se.Filename] = se.Data
	}

	for _, ef := range evidenceFiles {
		resType := typeByFilename[ef.Filename]
		data := dataByFilename[ef.Filename]
		if data == nil {
			continue
		}
		text := textualizePodResource(resType, data)
		if text != "" {
			_ = s.repo.UpdateEvidenceExtractedText(ctx, checkID, ef.Filename, text)
		}
	}

	// Step 3: Structured evaluation (k8s_native — 임베딩 없음).
	_ = s.repo.UpdateCheckProgress(ctx, checkID, 40)

	// Step 4: Structured evaluation using existing rule evaluators.
	var allEvidenceFilenames []string
	for _, ef := range evidenceFiles {
		allEvidenceFilenames = append(allEvidenceFilenames, ef.Filename)
	}

	var ruleResults []grc.RuleResult
	for _, rs := range rulesets {
		for _, rule := range rs.Rules {
			podResult := evaluatePodRule(rule, rs.Item.ID, rs.Item.Name, pgReq)
			rr := convertPodRuleResult(podResult, checkID, allEvidenceFilenames)
			// k8s_native: 구조적 판정만, 임베딩 없음
			ruleResults = append(ruleResults, rr)
		}
	}

	// Step 6: Aggregate.
	_ = s.repo.UpdateCheckProgress(ctx, checkID, 90)
	summary := aggregateSummary(ruleResults, len(evidenceFiles))

	// Compute overall verdict and severity.
	podName, podNS := extractPodMeta(pgReq.Pod)
	verdict := "준수"
	severity := "low"
	for _, rr := range ruleResults {
		if rr.Verdict == "미준수" {
			verdict = "미준수"
			for _, v := range rr.Violations {
				if severityRank(v.Severity) > severityRank(severity) {
					severity = v.Severity
				}
			}
		} else if rr.Verdict == "검토필요" && verdict != "미준수" {
			verdict = "검토필요"
		}
	}

	summary.SummaryText = fmt.Sprintf("Pod Graph 점검 (pod=%s ns=%s): %d개 룰 중 통과 %d / 미준수 %d / 검토필요 %d / 스킵 %d",
		podName, podNS, summary.TotalRules, summary.Passed, summary.Failed, summary.NeedsReview, summary.Skipped)

	// Generate recommendations from all rulesets.
	var recommendations []grc.Recommendation
	for _, rs := range rulesets {
		recs := generateRecommendations(ruleResults, rs)
		recommendations = append(recommendations, recs...)
	}

	return &grc.ComplianceCheckResult{
		CheckID:         checkID,
		ISMSPItemID:     "pod-graph",
		ItemName:        "Pod Graph 점검",
		Verdict:         verdict,
		Severity:        severity,
		CompletedAt:     time.Now().UTC(),
		Summary:         summary,
		RuleResults:     ruleResults,
		Recommendations: recommendations,
	}, nil
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// ─────────────────────────────────────────────
// GRCError
// ─────────────────────────────────────────────

type GRCError struct {
	Code       string
	Message    string
	HTTPStatus int
}

func (e *GRCError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}
