package grc

import (
	"encoding/json"
	"strings"
	"time"
)

// ── 통합 체크 모델 (기존 Job + ComplianceScan 병합) ──

// Check is the unified compliance check model.
// Stored in grc_checks table.
type Check struct {
	CheckID        string     `json:"check_id"`
	CompanyID      string     `json:"company_id"`
	ISMSPItemID    string     `json:"isms_p_item_id"`
	RulesetVersion string     `json:"ruleset_version,omitempty"`
	Status         string     `json:"status"`       // queued | running | completed | failed
	ProgressPct    int        `json:"progress_pct"`
	AutoCollect    bool       `json:"auto_collect"`
	SubmittedAt    time.Time  `json:"submitted_at"`
	StartedAt      *time.Time `json:"started_at,omitempty"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`

	// Result (populated on completion)
	Verdict       string `json:"verdict,omitempty"`       // 준수 | 미준수
	Severity      string `json:"severity,omitempty"`      // critical | high | medium | low
	SummaryText   string `json:"summary_text,omitempty"`
	TotalRules    int    `json:"total_rules,omitempty"`
	PassedRules   int    `json:"passed_rules,omitempty"`
	FailedRules   int    `json:"failed_rules,omitempty"`
	SkippedRules  int    `json:"skipped_rules,omitempty"`
	EvidenceCount int    `json:"evidence_count,omitempty"`

	// Source type: "file" (evidence upload) | "pod_graph" (K8s pod graph)
	CheckSource string `json:"check_source,omitempty"`

	// 이 체크에서 참조한 지침 ID 목록
	GuidelineIDs []int64 `json:"guideline_ids,omitempty"`

	// Error (populated on failure)
	Error *ErrorDetail `json:"error,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ── 증적 ──

// K8sSource identifies where an evidence file was collected in Kubernetes (optional).
// Submit via evidence_metadata[].k8s_source so results can cite cluster/namespace/pod/service/container.
type K8sSource struct {
	ClusterName   string `json:"cluster_name,omitempty"`
	Namespace     string `json:"namespace,omitempty"`
	ResourceKind  string `json:"resource_kind,omitempty"` // Pod, Service, ...
	ResourceName  string `json:"resource_name,omitempty"`
	ContainerName string `json:"container_name,omitempty"`
}

// HasAny returns true if any K8s attribution field is set.
func (k K8sSource) HasAny() bool {
	return k.ClusterName != "" || k.Namespace != "" || k.ResourceKind != "" || k.ResourceName != "" || k.ContainerName != ""
}

// EvidenceAttribution is one evidence file plus optional K8s context (API / DB snapshot).
type EvidenceAttribution struct {
	Filename  string    `json:"filename"`
	K8sSource K8sSource `json:"k8s_source,omitempty"`
}

// EvidenceMetadata is per-file metadata submitted with the check request.
type EvidenceMetadata struct {
	Filename      string   `json:"filename"`
	EvidenceType  string   `json:"evidence_type"`
	System        string   `json:"system,omitempty"`
	Description   string   `json:"description,omitempty"`
	TargetRuleIDs []string  `json:"target_rule_ids,omitempty"`
	K8sSource     K8sSource `json:"k8s_source,omitempty"`
}

// EvidenceFile is the DB record for an uploaded evidence file.
type EvidenceFile struct {
	ID            int64     `json:"id"`
	CheckID       string    `json:"check_id"`
	Filename      string    `json:"filename"`
	EvidenceType  string    `json:"evidence_type"`
	System        string    `json:"system,omitempty"`
	Description   string    `json:"description,omitempty"`
	StoragePath   string    `json:"-"`
	FileSizeBytes int64     `json:"file_size_bytes"`
	TargetRuleIDs []string  `json:"target_rule_ids,omitempty"`
	K8sSource     K8sSource `json:"k8s_source,omitempty"`
	ExtractedText string    `json:"-"`
	ContentHash   string    `json:"-"`
	CreatedAt     time.Time `json:"created_at"`

	// Embedding fields (populated after extraction).
	GuidelineText      string    `json:"-"`
	EvidenceEmbedding  []float32 `json:"-"`
	GuidelineEmbedding []float32 `json:"-"`
}

// ── 룰 평가 결과 ──

// RuleResult holds the evaluation result for a single rule (auto or manual).
// RuleResult is a single rule evaluation outcome.
type RuleResult struct {
	ID                int64       `json:"-"`
	CheckID           string      `json:"-"`
	RuleID            string      `json:"rule_id"`
	ISMSPItemID       string      `json:"isms_p_item_id,omitempty"`
	CheckCategory     string      `json:"check_category"`
	EvidenceType      string      `json:"evidence_type"`
	System            string      `json:"system"`
	Verdict           string                `json:"verdict"` // 준수 | 미준수 | skipped (auto); "" (manual)
	EvidenceFiles     []string              `json:"evidence_files"`
	EvidenceSources   []EvidenceAttribution `json:"evidence_sources,omitempty"`
	MatchedIndicators []string              `json:"matched_indicators,omitempty"`
	Violations          []Violation           `json:"violations,omitempty"`
	SkipReason          string                `json:"skip_reason,omitempty"`
	FailMessage         string                `json:"fail_message,omitempty"`
	Remediation         string                `json:"remediation,omitempty"`
	EmbeddingSimilarity *float64              `json:"embedding_similarity,omitempty"`

	// ── Enhanced verdict metadata ──
	Reason        string          `json:"reason,omitempty"`
	MissingInputs json.RawMessage `json:"missing_inputs,omitempty"`
	EvidenceData  json.RawMessage `json:"evidence_data,omitempty"`
	Layer         string          `json:"layer,omitempty"`

	// ── 결함 귀속 스코프 / fan-out 투영 (cluster·account 결함을 pod에 표시하되 점수는 1회) ──
	Scope       string   `json:"scope,omitempty"`        // pod | pod_chain | cluster | account
	CanonicalID string   `json:"canonical_id,omitempty"` // 점수 dedup distinct 키
	Inherited   bool     `json:"inherited,omitempty"`    // true=상속(클러스터/계정 공통) 결함, pod 직접 책임 아님
	OwnerHint   string   `json:"owner_hint,omitempty"`   // 조치 주체 (workload | cluster-admin | account-admin)
	AffectedPods []string `json:"affected_pods,omitempty"` // 이 결함이 걸리는 pod (blast-radius). count는 1.

	// ── 통합 manual 판정 필드 ──
	// judgment_mode: "auto" (기본값, 기존 R-rule) | "manual" (기존 F-finding)
	JudgmentMode          string          `json:"judgment_mode,omitempty"`
	VerdictType           string          `json:"verdict_type,omitempty"` // compliant_indicator | potential_finding | needs_review
	Matched               bool            `json:"matched"`                // manual 룰: 조건 매칭 여부; auto 룰: 무시
	Observation           string          `json:"observation,omitempty"`
	Evidence              map[string]any  `json:"evidence,omitempty"`
	AffectedResources     []AffectedResource `json:"affected_resources,omitempty"`
	ManualCheckAreas      json.RawMessage `json:"manual_check_areas,omitempty"`
	AdditionalReviewItems json.RawMessage `json:"additional_review_items,omitempty"`
	AutomationCoverage    json.RawMessage `json:"automation_coverage,omitempty"`
	AlternativeControls   json.RawMessage `json:"alternative_controls,omitempty"`
	ComplianceMappings    json.RawMessage `json:"compliance_mappings,omitempty"`
	KisaDefectCaseRefs    json.RawMessage `json:"kisa_defect_case_refs,omitempty"`
	AffectedCount         int             `json:"affected_count,omitempty"`
	AffectedPassCount     int             `json:"affected_pass_count,omitempty"`
	AffectedFailCount     int             `json:"affected_fail_count,omitempty"`
	Deferred              bool            `json:"deferred,omitempty"`
	DeferredReason        string          `json:"deferred_reason,omitempty"`
	OffclusterSatisfactionConditions json.RawMessage `json:"offcluster_satisfaction_conditions,omitempty"`
}

// Violation describes a single compliance failure.
type Violation struct {
	ID           int64     `json:"-"`
	RuleResultID int64     `json:"-"`
	Field        string    `json:"field,omitempty"`
	Pattern      string    `json:"pattern,omitempty"`
	Expected     any       `json:"expected,omitempty"`
	Actual       any       `json:"actual,omitempty"`
	Description  string    `json:"description"`
	Severity     string    `json:"severity"`                  // low | medium | high | critical
	K8sSource    K8sSource `json:"k8s_source,omitempty"`      // 위반 자원 위치
}

// ── 권고사항 ──

// Recommendation suggests an action for a failed rule.
type Recommendation struct {
	ID        int64  `json:"-"`
	CheckID   string `json:"-"`
	RuleID    string `json:"rule_id"`
	Action    string `json:"action"`
	Reference string `json:"reference"`
}

// ── 요약 ──

// Summary is the result summary stats for API response.
type Summary struct {
	TotalRules        int    `json:"total_rules"`
	Passed            int    `json:"passed"`
	Failed            int    `json:"failed"`
	NeedsReview       int    `json:"needs_review"`
	Skipped           int    `json:"skipped"`
	EvidenceCollected int    `json:"evidence_collected"`
	SummaryText       string `json:"summary_text,omitempty"`
}

// ── 내부 워커 결과 (DB 저장 전 in-memory 구조) ──

// ComplianceCheckResult is the worker output before persistence.
type ComplianceCheckResult struct {
	CheckID         string
	ISMSPItemID     string
	ItemName        string
	RulesetVersion  string
	Verdict         string
	Severity        string
	CompletedAt     time.Time
	Summary         Summary
	RuleResults     []RuleResult
	Recommendations []Recommendation
}

// ── API 응답 ──

// CheckDetailResponse is the full API response for GET /checks/:check_id.
type CheckDetailResponse struct {
	CheckID        string           `json:"check_id"`
	CompanyID      string           `json:"company_id"`
	ISMSPItemID    string           `json:"isms_p_item_id"`
	RulesetVersion string           `json:"ruleset_version,omitempty"`
	Status         string           `json:"status"`
	ProgressPct    int              `json:"progress_pct,omitempty"`
	Verdict        string           `json:"verdict,omitempty"`
	Severity       string           `json:"severity,omitempty"`
	SubmittedAt    time.Time        `json:"submitted_at"`
	StartedAt      *time.Time       `json:"started_at,omitempty"`
	CompletedAt    *time.Time       `json:"completed_at,omitempty"`
	Summary        *Summary         `json:"summary,omitempty"`
	RuleResults    []RuleResult     `json:"rule_results,omitempty"`
	Recommendations []Recommendation `json:"recommendations,omitempty"`
	Error          *ErrorDetail     `json:"error,omitempty"`
}

// CheckListItem is a summary for list responses.
type CheckListItem struct {
	CheckID       string     `json:"check_id"`
	CompanyID     string     `json:"company_id"`
	ISMSPItemID   string     `json:"isms_p_item_id"`
	Status        string     `json:"status"`
	Verdict       string     `json:"verdict,omitempty"`
	Severity      string     `json:"severity,omitempty"`
	TotalRules    int        `json:"total_rules,omitempty"`
	PassedRules   int        `json:"passed_rules,omitempty"`
	FailedRules   int        `json:"failed_rules,omitempty"`
	SkippedRules  int        `json:"skipped_rules,omitempty"`
	EvidenceCount int        `json:"evidence_count,omitempty"`
	SubmittedAt   time.Time  `json:"submitted_at"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
}

// Pagination is the pagination metadata for list responses.
type Pagination struct {
	Page       int `json:"page"`
	PageSize   int `json:"page_size"`
	TotalCount int `json:"total_count"`
	TotalPages int `json:"total_pages"`
}

// EvidenceListItem is for the evidence list API response.
type EvidenceListItem struct {
	ID               int64     `json:"id"`
	Filename         string    `json:"filename"`
	EvidenceType     string    `json:"evidence_type"`
	System           string    `json:"system,omitempty"`
	Description      string    `json:"description,omitempty"`
	FileSizeBytes    int64     `json:"file_size_bytes"`
	TargetRuleIDs    []string  `json:"target_rule_ids,omitempty"`
	K8sSource        K8sSource `json:"k8s_source,omitempty"`
	HasExtractedText bool      `json:"has_extracted_text"`
	CreatedAt        time.Time `json:"created_at"`
}

// ── 지침 (회사 내부 정책 문서) ──

// Guideline is a company internal policy document (PDF).
// ISMSPItemID가 nil이면 회사 공용 지침 (모든 항목에서 사용).
type Guideline struct {
	ID            int64     `json:"id"`
	CompanyID     string    `json:"company_id"`
	ISMSPItemID   *string   `json:"isms_p_item_id"`
	Filename      string    `json:"filename"`
	StoragePath   string    `json:"-"`
	FileSizeBytes int64     `json:"file_size_bytes"`
	ContentHash   string    `json:"-"`
	ExtractedText string    `json:"-"`
	Embedding     []float32 `json:"-"`
	Version       int       `json:"version"`
	UploadedAt    time.Time `json:"uploaded_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// GuidelineListItem is a summary for guideline list API responses.
type GuidelineListItem struct {
	ID               int64     `json:"id"`
	CompanyID        string    `json:"company_id"`
	ISMSPItemID      *string   `json:"isms_p_item_id"`
	Filename         string    `json:"filename"`
	FileSizeBytes    int64     `json:"file_size_bytes"`
	HasExtractedText bool      `json:"has_extracted_text"`
	HasEmbedding     bool      `json:"has_embedding"`
	Version          int       `json:"version"`
	UploadedAt       time.Time `json:"uploaded_at"`
}

// GLCheckTarget represents a (company_id, isms_p_item_id) pair that has at least one
// guideline with extracted text, making it eligible for automated GL-layer evaluation.
type GLCheckTarget struct {
	CompanyID   string
	ISMSPItemID string
}

// ── 클라우드 환경 정보 ──

// CloudEnvironment represents a Kubernetes resource stored for GRC compliance matching.
type CloudEnvironment struct {
	ID            int64          `json:"id"`
	CompanyID     string         `json:"company_id"`
	CheckID       string         `json:"check_id,omitempty"`
	ResourceType  string         `json:"resource_type"`
	ResourceName  string         `json:"resource_name"`
	Namespace     string         `json:"namespace,omitempty"`
	ClusterName   string         `json:"cluster_name,omitempty"`
	RawData       map[string]any `json:"raw_data"`
	ExtractedText string         `json:"extracted_text,omitempty"`
	Embedding     []float32      `json:"-"`
	CreatedAt     time.Time      `json:"created_at"`
}

// CloudEnvListItem is for list API responses (without raw_data and embedding).
type CloudEnvListItem struct {
	ID            int64     `json:"id"`
	CompanyID     string    `json:"company_id"`
	CheckID       string    `json:"check_id,omitempty"`
	ResourceType  string    `json:"resource_type"`
	ResourceName  string    `json:"resource_name"`
	Namespace     string    `json:"namespace,omitempty"`
	ClusterName   string    `json:"cluster_name,omitempty"`
	HasEmbedding  bool      `json:"has_embedding"`
	CreatedAt     time.Time `json:"created_at"`
}

// ── Pod 그래프 평가 결과 ──

// PodGraphEvalListItem is for the pod graph evaluation list API response.
type PodGraphEvalListItem struct {
	ID             int64     `json:"id"`
	CompanyID      string    `json:"company_id"`
	ClusterName    string    `json:"cluster_name,omitempty"`
	PodName        string    `json:"pod_name"`
	Namespace      string    `json:"namespace,omitempty"`
	OverallVerdict string    `json:"overall_verdict"`
	TotalRules     int       `json:"total_rules"`
	Passed         int       `json:"passed"`
	Failed         int       `json:"failed"`
	NeedsReview    int       `json:"needs_review"`
	Skipped        int       `json:"skipped"`
	CreatedAt      time.Time `json:"created_at"`
}

// AffectedResource is a K8s resource affected by a manual rule evaluation.
type AffectedResource struct {
	Kind      string `json:"kind"`                // Pod | ServiceAccount | Namespace | Ingress | Service | Node
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// FindingClusterResult is the API response for cluster-wide manual rule evaluation.
type FindingClusterResult struct {
	ID             int64          `json:"id"`
	CompanyID      string         `json:"company_id"`
	ClusterName    string         `json:"cluster_name"`
	Namespace      string         `json:"namespace,omitempty"`
	SnapshotAt     string         `json:"snapshot_at"`
	EvaluatedAt    string         `json:"evaluated_at"`
	TotalFindings  int            `json:"total_findings"`
	MatchedCount   int            `json:"matched_count"`
	UnmatchedCount int            `json:"unmatched_count"`
	ByVerdict      map[string]int `json:"by_verdict"`
	Findings       []RuleResult   `json:"findings"`
}

// ── 통합 클러스터 컴플라이언스 (전체 페이지: ISMS-P 항목별 위반 자산) ──

// ViolatedRuleInfo holds a violated rule with its fail message and remediation.
type ViolatedRuleInfo struct {
	RuleID      string `json:"rule_id"`
	FailMessage string `json:"fail_message,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// ViolatedAsset is a K8s asset that violates one or more rules under an ISMS-P item.
type ViolatedAsset struct {
	Kind          string             `json:"kind"`                    // Pod | ServiceAccount | Namespace | Ingress | Service | Node
	Name          string             `json:"name"`
	Namespace     string             `json:"namespace,omitempty"`
	ViolatedRules []ViolatedRuleInfo `json:"violated_rules"`
}

// ItemLayers groups rule results by evaluation layer.
type ItemLayers struct {
	GL     []RuleResult `json:"gl,omitempty"`     // 정책 (Guideline) rules
	R      []RuleResult `json:"r,omitempty"`      // 기술 (K8s native) rules — 승격/deferred 포함
	F      []RuleResult `json:"f,omitempty"`      // 보조 (Finding/Manual) — F 흡수 후 잔여 없음; 하위호환
	Report []RuleResult `json:"report,omitempty"` // 인벤토리/방증 리포트 — 합격률 분모 제외
}

// CompliantRule is a passed (MET/준수) rule surfaced in the overview so users
// can see which checks passed, not only violations.
type CompliantRule struct {
	RuleID string `json:"rule_id"`
	Name   string `json:"name,omitempty"`
	Layer  string `json:"layer,omitempty"`
}

// ItemComplianceResult holds compliance results for a single ISMS-P item.
type ItemComplianceResult struct {
	ISMSPItemID    string          `json:"isms_p_item_id"`
	ItemName       string          `json:"item_name"`
	Verdict        string          `json:"verdict"`
	Note           string          `json:"note,omitempty"`
	TotalRules     int             `json:"total_rules"`
	Passed         int             `json:"passed"`
	Failed         int             `json:"failed"`
	NeedsReview    int             `json:"needs_review"`
	NoData         int             `json:"no_data,omitempty"`
	Indeterminate  int             `json:"indeterminate,omitempty"`
	NotApplicable  int             `json:"not_applicable,omitempty"` // 해당없음 (vacuous pass — 준수와 분리)
	Skipped        int             `json:"skipped"`
	ViolatedAssetCount int              `json:"violated_asset_count,omitempty"`
	ViolatedAssets     []ViolatedAsset  `json:"violated_assets,omitempty"`
	RuleResults        []RuleResult     `json:"rule_results,omitempty"`
	CompliantRules     []CompliantRule  `json:"compliant_rules,omitempty"` // 통과(준수) 룰 목록 (id+name)
	Layers         *ItemLayers     `json:"layers,omitempty"`
}

// ClusterComplianceResult is the unified response for cluster-wide compliance.
// Merges R-rules (per-pod auto) + F-rules (cluster-wide manual) grouped by ISMS-P item.
type ClusterComplianceResult struct {
	CompanyID          string                 `json:"company_id"`
	ClusterName        string                 `json:"cluster_name"`
	SnapshotAt         string                 `json:"snapshot_at"`
	EvaluatedAt        string                 `json:"evaluated_at"`
	DurationMs         int64                  `json:"duration_ms"`
	TotalItems         int                    `json:"total_items"`
	CompliantItems     int                    `json:"compliant_items"`
	NonCompliantItems  int                    `json:"non_compliant_items"`
	NeedsReviewItems   int                    `json:"needs_review_items"`
	NoDataItems        int                    `json:"no_data_items,omitempty"`
	IndeterminateItems int                    `json:"indeterminate_items,omitempty"`
	NotApplicableItems int                    `json:"not_applicable_items,omitempty"` // 항목 전체가 해당없음
	TotalRules         int                    `json:"total_rules"`
	TotalPods          int                    `json:"total_pods"`
	Items              []ItemComplianceResult `json:"items"`
}

// ── 에러 ──

// ErrorDetail describes an error that occurred during processing.
type ErrorDetail struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

// ── 상수 / 허용값 ──

var AllowedEvidenceTypes = map[string]bool{
	"정책_문서_존재":       true,
	"정책_문서_충실도":      true,
	"정책_시스템_설정":      true,
	"사용자_화면_강제화":     true,
	"변경주기_준수":        true,
	"임시_비밀번호_강제_변경":  true,
	"저장_형태":          true,
	"인증수단":           true,
	"manual_evidence":  true,
	"pod_graph":        true,
}

var AllowedFileExtensions = map[string]bool{
	".pdf":  true,
	".png":  true,
	".jpg":  true,
	".jpeg": true,
	".webp": true,
	".json": true,
	".yaml": true,
	".yml":  true,
	".csv":  true,
	".txt":  true,
}

const (
	MaxFileSize  = 50 * 1024 * 1024  // 50MB per file
	MaxTotalSize = 200 * 1024 * 1024 // 200MB total
	MaxFileCount = 50
)

// ── Verdict Enum ──

const (
	VerdictMET           = "MET"           // 충족/준수
	VerdictNOT_MET       = "NOT_MET"       // 미충족/미준수 (실제 위반)
	VerdictNO_DATA       = "NO_DATA"       // 평가불가 (데이터 미수집)
	VerdictINDETERMINATE = "INDETERMINATE" // 확인불가
	VerdictNEEDS_REVIEW  = "NEEDS_REVIEW"  // 검토필요
	VerdictSKIPPED       = "SKIPPED"       // 건너뜀
	VerdictNA            = "N_A"           // 해당없음 (점검 대상 리소스 부재 — vacuous pass, 준수와 분리 집계)
	VerdictREPORT        = "REPORT"        // 보고서형 (정보 제공 — 합격률 분모 제외)
)

// ── Rule Layer Tags ──

const (
	LayerGL     = "GL"     // 정책 (Guideline)
	LayerR      = "R"      // 기술 (Runtime/K8s native)
	LayerF      = "F"      // 보조 (Finding/Manual) — 흡수 완료 후 잔여 없음; 하위호환 보존
	LayerReport = "REPORT" // 인벤토리/방증 리포트 — verdict 없음, 합격률 분모 제외
)

// NormalizeVerdict maps legacy Korean verdict strings to the new enum.
func NormalizeVerdict(v string) string {
	switch v {
	case "준수", "MET":
		return VerdictMET
	case "미준수", "NOT_MET":
		return VerdictNOT_MET
	case "검토필요", "NEEDS_REVIEW":
		return VerdictNEEDS_REVIEW
	case "NO_DATA":
		return VerdictNO_DATA
	case "INDETERMINATE":
		return VerdictINDETERMINATE
	case "skip", "skipped", "SKIPPED":
		return VerdictSKIPPED
	case "해당없음", "N_A", "N/A":
		return VerdictNA
	case "REPORT":
		return VerdictREPORT
	default:
		return v
	}
}

// LegacyVerdict maps the new enum back to legacy Korean strings for backward compatibility.
func LegacyVerdict(v string) string {
	switch v {
	case VerdictMET:
		return "준수"
	case VerdictNOT_MET:
		return "미준수"
	case VerdictNEEDS_REVIEW:
		return "검토필요"
	case VerdictNO_DATA:
		return "평가불가"
	case VerdictINDETERMINATE:
		return "확인불가"
	case VerdictSKIPPED:
		return "skipped"
	case VerdictNA:
		return "해당없음"
	case VerdictREPORT:
		return "정보"
	default:
		return v
	}
}

// RuleLayer returns the layer tag for a rule_id. (R/GL/F)
func RuleLayer(ruleID string) string {
	if len(ruleID) > 0 && ruleID[0] == 'F' {
		return LayerF
	}
	if strings.Contains(ruleID, "-GL") {
		return LayerGL
	}
	return LayerR
}
