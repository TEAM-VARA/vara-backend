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
	"strconv"
	"strings"
	"time"

	"github.com/vara/backend/internal/domain/grc"
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
		return nil, &GRCError{Code: "INVALID_REQUEST", Message: "company_id 필수", HTTPStatus: 400}
	}
	if req.ClusterName == "" {
		return nil, &GRCError{Code: "INVALID_REQUEST", Message: "cluster_name 필수", HTTPStatus: 400}
	}
	if s.clusterRepo == nil {
		return nil, &GRCError{Code: "NOT_CONFIGURED", Message: "cluster reader repo not configured", HTTPStatus: 500}
	}

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
		assets map[string]*grc.ViolatedAsset
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
				JudgmentMode:      "auto",
			}
			it.ruleResults = append(it.ruleResults, grr)

			// If failed, record the pod as a violated asset
			if rr.Verdict == "미준수" {
				assetKey := fmt.Sprintf("Pod/%s/%s", pod.Namespace, pod.Name)
				if a, ok := it.assets[assetKey]; ok {
					a.ViolatedRules = append(a.ViolatedRules, rr.RuleID)
				} else {
					it.assets[assetKey] = &grc.ViolatedAsset{
						Kind:          "Pod",
						Name:          pod.Name,
						Namespace:     pod.Namespace,
						ViolatedRules: []string{rr.RuleID},
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
		it.ruleResults = append(it.ruleResults, fr)

		// If finding matched (potential issue), record affected resources
		if fr.Verdict == "검토필요" || fr.Verdict == "미준수" {
			for _, ar := range fr.AffectedResources {
				assetKey := fmt.Sprintf("%s/%s/%s", ar.Kind, ar.Namespace, ar.Name)
				if a, ok := it.assets[assetKey]; ok {
					a.ViolatedRules = append(a.ViolatedRules, fr.RuleID)
				} else {
					it.assets[assetKey] = &grc.ViolatedAsset{
						Kind:          ar.Kind,
						Name:          ar.Name,
						Namespace:     ar.Namespace,
						ViolatedRules: []string{fr.RuleID},
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
		TotalPods:   totalPods,
	}

	for itemID, it := range items {
		item := grc.ItemComplianceResult{
			ISMSPItemID: itemID,
			ItemName:    it.itemName,
			TotalRules:  len(it.ruleResults),
			RuleResults: it.ruleResults,
		}

		for _, rr := range it.ruleResults {
			switch rr.Verdict {
			case "준수":
				item.Passed++
			case "미준수":
				item.Failed++
			case "검토필요":
				item.NeedsReview++
			default: // skipped 등
				item.Skipped++
			}
		}

		// Determine item-level verdict
		if item.Failed > 0 {
			item.Verdict = "미준수"
		} else if item.NeedsReview > 0 {
			item.Verdict = "검토필요"
		} else {
			item.Verdict = "준수"
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
		case "준수":
			result.CompliantItems++
		case "미준수":
			result.NonCompliantItems++
		case "검토필요":
			result.NeedsReviewItems++
		}
	}

	log.Printf("[cluster-compliance] done: %d items, %d compliant, %d non-compliant, %d needs-review",
		result.TotalItems, result.CompliantItems, result.NonCompliantItems, result.NeedsReviewItems)

	return result, nil
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
	items, _, err := s.repo.ListFindingClusterSummaries(ctx, companyID, 1, 1)
	if err != nil {
		return nil, err
	}
	// Find the one matching clusterName
	for i := range items {
		if items[i].ClusterName == clusterName {
			return &items[i], nil
		}
	}
	// Try broader search with larger page
	items, _, err = s.repo.ListFindingClusterSummaries(ctx, companyID, 1, 200)
	if err != nil {
		return nil, err
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

	// Load latest cluster summary
	summary, err := s.GetLatestFindingClusterSummary(ctx, companyID, clusterName)
	if err != nil {
		// No summary yet is ok — return empty result
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
	// If no pod graph eval exists yet, rule_compliance stays zero-valued (acceptable).

	return result, nil
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

	// Validate file count matches metadata count.
	if len(files) != len(metadataList) {
		return nil, &GRCError{Code: "INVALID_EVIDENCE_METADATA", Message: "files와 evidence_metadata 길이 불일치", HTTPStatus: 400}
	}

	// Validate file count limits.
	if len(files) == 0 || len(files) > grc.MaxFileCount {
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
func (s *GRCService) UploadGuideline(
	ctx context.Context,
	companyID, ismspItemID string,
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
	guidelineDir := filepath.Join(s.storagePath, companyID, "guidelines", ismspItemID)
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

	// Insert into DB.
	if err := s.repo.InsertGuideline(ctx, g); err != nil {
		// Duplicate check (unique constraint).
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			return nil, &GRCError{Code: "DUPLICATE_GUIDELINE", Message: fmt.Sprintf("동일 지침 파일 이미 존재: %s", fh.Filename), HTTPStatus: 409}
		}
		return nil, fmt.Errorf("지침 DB 저장 실패: %w", err)
	}

	log.Printf("[grc-guideline] uploaded %s for %s/%s (id=%d, text=%d chars, emb=%d dims)",
		fh.Filename, companyID, ismspItemID, g.ID, len(g.ExtractedText), len(g.Embedding))

	return g, nil
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

func (s *GRCService) runWorker(checkID string) {
	ctx := context.Background()

	if err := s.repo.UpdateCheckStarted(ctx, checkID); err != nil {
		log.Printf("[grc-worker] failed to mark check started: %s: %v", checkID, err)
		return
	}

	result, err := s.processCheck(ctx, checkID)
	if err != nil {
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

	embByFile, errEmb := s.repo.ListEvidenceEmbeddingsForCheck(ctx, checkID)
	if errEmb != nil {
		log.Printf("[grc-embed] reload evidence vectors: %v", errEmb)
		embByFile = nil
	}

	// Step 2: Evaluate each rule.
	var ruleResults []grc.RuleResult
	for i, rule := range ruleset.Rules {
		matched := matchEvidenceToRule(evidenceFiles, rule, evidenceStore)
		var result grc.RuleResult

		// GL (guideline RAG) rules don't need evidence files — their "evidence"
		// is the DB guideline text passed via dbGuidelines. Let them through.
		isGuidelineRAG := rule.JudgmentLogic.Type == "semantic_match" &&
			rule.JudgmentLogic.Method == "llm_rag_entailment"

		if len(matched) == 0 && !isGuidelineRAG {
			result = grc.RuleResult{
				RuleID:        rule.RuleID,
				Verdict:       "skipped",
				SkipReason:    "증적 미제출",
				EvidenceFiles: []string{},
			}
		} else if len(matched) == 0 && isGuidelineRAG {
			// Guideline RAG: no evidence files needed, evaluate directly.
			result = s.evaluateRule(ctx, rule, nil, nil, dbGuidelines)
		} else {
			filenames := make([]string, len(matched))
			var extractedData []any
			for j, ef := range matched {
				filenames[j] = ef.Filename
				if d, ok := evidenceStore[ef.Filename]; ok {
					extractedData = append(extractedData, d)
				}
			}

			result = s.evaluateRule(ctx, rule, extractedData, filenames, dbGuidelines)
			result.EvidenceSources = evidenceAttributionsFromFiles(matched)
			result = s.applyGuidelineEmbedding(rule, matched, embByFile, dbGuidelines, result)
		}

		ruleResults = append(ruleResults, result)
		pct := 40 + (i+1)*50/len(ruleset.Rules)
		_ = s.repo.UpdateCheckProgress(ctx, checkID, pct)
	}

	// Step 3: Aggregate results.
	_ = s.repo.UpdateCheckProgress(ctx, checkID, 95)
	summary := aggregateSummary(ruleResults, len(evidenceFiles))
	summary.SummaryText = fmt.Sprintf("ISMS-P %s (%s) 점검 결과: %d개 룰 중 통과 %d / 미준수 %d / 검토필요 %d / 스킵 %d",
		chk.ISMSPItemID, ruleset.Item.Name,
		summary.TotalRules, summary.Passed, summary.Failed, summary.NeedsReview, summary.Skipped)

	verdict := "준수"
	severity := "low"
	for _, r := range ruleResults {
		if r.Verdict == "미준수" {
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
		} else if r.Verdict == "검토필요" && verdict != "미준수" {
			verdict = "검토필요"
		}
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

func (s *GRCService) evaluateRule(ctx context.Context, rule Rule, evidenceData []any, filenames []string, dbGuidelines []grc.Guideline) grc.RuleResult {
	base := grc.RuleResult{
		RuleID:        rule.RuleID,
		EvidenceFiles: filenames,
	}

	switch rule.JudgmentLogic.Type {
	case "structured_match", "manual_evidence_match", "hybrid_match":
		return evaluateStructured(rule, evidenceData, base)
	case "semantic_match":
		return s.evaluateSemantic(ctx, rule, evidenceData, base, dbGuidelines)
	case "regex_match":
		return evaluateRegex(rule, evidenceData, base)
	case "aggregated_statistics":
		return evaluateAggregated(rule, evidenceData, base)
	case "code_pattern_match":
		return evaluateCodePattern(rule, evidenceData, base)
	default:
		base.Verdict = "skipped"
		base.SkipReason = fmt.Sprintf("지원하지 않는 judgment_logic type: %s", rule.JudgmentLogic.Type)
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

func (s *GRCService) evaluateSemantic(ctx context.Context, rule Rule, evidenceData []any, base grc.RuleResult, dbGuidelines []grc.Guideline) grc.RuleResult {
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
		return s.evaluateLLMRAGEntailment(ctx, rule, dbGuidelines, evidenceData, base)
	case "vlm_behavioral_analysis":
		return evaluateOCRKeywordMatch(rule, evidenceData, base)
	default:
		return evaluateKeywordMatch(rule, textContent, base)
	}
}

func evaluateKeywordMatch(rule Rule, text string, base grc.RuleResult) grc.RuleResult {
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
		base.Verdict = "준수"
		base.MatchedIndicators = []string{fmt.Sprintf("식별 키워드 %d개 매칭 (%s)", matchCount, strings.Join(matched, ", "))}
	} else {
		base.Verdict = "미준수"
		base.Violations = []grc.Violation{{
			Description: fmt.Sprintf("식별 키워드 %d개만 매칭 (최소 %d개 필요)", matchCount, minMatches),
			Severity:    "medium",
		}}
	}
	return base
}

func evaluateElementCoverage(rule Rule, text string, base grc.RuleResult) grc.RuleResult {
	if rule.RequiredContentElements == nil {
		base.Verdict = "skipped"
		base.SkipReason = "required_content_elements 정의 없음"
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
		base.Verdict = "미준수"
		base.Violations = missing
		base.MatchedIndicators = matched
	} else {
		base.Verdict = "준수"
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
		base.Verdict = "skipped"
		base.SkipReason = "이미지 증적 없음"
		return base
	}

	text := allText.String()
	if strings.TrimSpace(text) == "" {
		base.Verdict = "skipped"
		base.SkipReason = "OCR 텍스트 추출 실패 (Tesseract 미설치 또는 텍스트 인식 불가)"
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
		base.Verdict = "skipped"
		base.SkipReason = "구조화된 레코드 없음"
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
		base.Verdict = "skipped"
		base.SkipReason = "코드 증적 없음"
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
		switch r.Verdict {
		case "준수":
			s.Passed++
		case "미준수":
			s.Failed++
		case "검토필요":
			s.NeedsReview++
		case "skipped":
			s.Skipped++
		}
	}
	return s
}

func generateRecommendations(results []grc.RuleResult, ruleset *Ruleset) []grc.Recommendation {
	var recs []grc.Recommendation
	for _, r := range results {
		if r.Verdict != "미준수" {
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
