package grc

import "time"

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

// RuleResult holds the evaluation result for a single rule.
type RuleResult struct {
	ID                int64       `json:"-"`
	CheckID           string      `json:"-"`
	RuleID            string      `json:"rule_id"`
	CheckCategory     string      `json:"check_category"`
	EvidenceType      string      `json:"evidence_type"`
	System            string      `json:"system"`
	Verdict           string                `json:"verdict"` // 준수 | 미준수 | skipped
	EvidenceFiles     []string              `json:"evidence_files"`
	EvidenceSources   []EvidenceAttribution `json:"evidence_sources,omitempty"`
	MatchedIndicators []string              `json:"matched_indicators,omitempty"`
	Violations        []Violation           `json:"violations,omitempty"`
	SkipReason        string                `json:"skip_reason,omitempty"`
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
