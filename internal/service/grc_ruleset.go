package service

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/vara/backend/internal/domain/grc"
)

// ManualCheckOutput is attached to R-rules that absorbed a former F-finding rule (Stage 2).
// It carries manual-check context (ARI/MCA/AC/KDC) to be surfaced alongside the R verdict.
// COV(automation_coverage)는 도구 자기평가 메타스탯이므로 흡수하지 않는다.
type ManualCheckOutput struct {
	// AppliesWhen controls when this output is exposed in results.
	// "fail"   = R이 미준수일 때만 노출 (potential_finding 출신)
	// "always" = 항상 노출 (needs_review / additional_evidence 출신)
	AppliesWhen string `json:"applies_when,omitempty"`

	// AbsorbedFrom is the original F-rule ID that was absorbed into this R-rule.
	AbsorbedFrom string `json:"absorbed_from,omitempty"`

	AdditionalReviewItems            []string        `json:"additional_review_items,omitempty"`
	ManualCheckAreas                 []string        `json:"manual_check_areas,omitempty"`
	AlternativeControls              []string        `json:"alternative_controls,omitempty"`
	KisaDefectCaseRefs               json.RawMessage `json:"kisa_defect_case_refs,omitempty"`
	ComplianceMappings               json.RawMessage `json:"compliance_mappings,omitempty"`
	OffclusterSatisfactionConditions []string        `json:"offcluster_satisfaction_conditions,omitempty"`
	ExceptionNamespaces              []string        `json:"exception_namespaces,omitempty"`
}

// ManualRuleMeta holds F-finding-specific metadata for manual judgment rules.
type ManualRuleMeta struct {
	TargetResource                   string          `json:"target_resource,omitempty"`
	RequiredData                     []string        `json:"required_data,omitempty"`
	Condition                        json.RawMessage `json:"condition"`
	ComplianceMappings               json.RawMessage `json:"compliance_mappings,omitempty"`
	KisaDefectCaseRefs               json.RawMessage `json:"kisa_defect_case_refs,omitempty"`
	AdditionalReviewItems            []string        `json:"additional_review_items,omitempty"`
	ManualCheckAreas                 []string        `json:"manual_check_areas,omitempty"`
	AutomationCoverage               json.RawMessage `json:"automation_coverage,omitempty"`
	AlternativeControls              json.RawMessage `json:"alternative_controls,omitempty"`
	ExceptionConditions              json.RawMessage `json:"exception_conditions,omitempty"`
	OffclusterSatisfactionConditions []string        `json:"offcluster_satisfaction_conditions,omitempty"`
	K8sOnlyCheck                     bool            `json:"k8s_only_check,omitempty"`
	Deferred                         bool            `json:"deferred,omitempty"`
	DeferredReason                   string          `json:"deferred_reason,omitempty"`
}

// Ruleset is the top-level structure of an ISMS-P ruleset JSON file (schema 4.0.0).
type Ruleset struct {
	SchemaVersion string           `json:"schema_version"`
	ISMSPRevision string           `json:"isms_p_revision"`
	Item          RulesetItem      `json:"item"`
	LegalRefs     []LegalReference `json:"legal_references"`
	Rules         []Rule           `json:"rules"`
	EvalStrategy  EvalStrategy     `json:"evaluation_strategy"`
}

type RulesetItem struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	CategoryPath string `json:"category_path"`
	Description  string `json:"description"`
}

type LegalReference struct {
	Law     string `json:"law"`
	Article string `json:"article"`
	Summary string `json:"summary"`
}

// Rule represents a single compliance check rule.
//
// judgment_source:
//   - "text_extraction": 지침 문서 점검 (GL — RAG/임베딩)
//   - "k8s_api" / "k8s_native": 클러스터 자동측정 (Pod 평가기 대상)
//   - "evidence_upload": 업로드 증적 점검 (OS/AD/IAM 설정 캡처, 화면, 코드 등 —
//     K8s 측정 대상 아님; 2.5.4 R-03~15처럼 잘못 k8s_api로 분류돼 있던 룰의 정정 값)
//
// extraction_method: "rag" | "api" | "manual"
type Rule struct {
	RuleID           string                      `json:"rule_id"`
	Name             string                      `json:"name,omitempty"`
	JudgmentSource   string                      `json:"judgment_source"`   // "text_extraction" | "k8s_api" | "k8s_native" | "evidence_upload"
	ExtractionMethod string                      `json:"extraction_method"` // "rag" | "api" | "manual"

	// ── 결함 귀속 스코프 (cluster/account fan-out + dedup) ──
	// risk_scope: 결함의 평가/점수 귀속 단위. fanout: 표시 시 영향 pod 투영 범위.
	// 미지정 시 RuleRiskScope()가 rule_id로 추론(SG/aws→account, 그 외 pod).
	RiskScope string `json:"risk_scope,omitempty"` // pod | pod_chain | cluster | account
	Fanout    string `json:"fanout,omitempty"`     // self | asset_consumers | all_pods_in_cluster | all_pods_in_account | nodes_pods

	// 검색/식별 키워드 (text_extraction 룰에서 사용)
	Keywords             []string                    `json:"keywords,omitempty"`
	ComplianceIndicators []Indicator                 `json:"compliance_indicators,omitempty"`
	JudgmentLogic        JudgmentLogic               `json:"judgment_logic"`
	RequiredContentElements map[string][]ContentElement `json:"required_content_elements,omitempty"`

	// k8s_api 룰 전용
	SecretPatterns  []SecretPattern `json:"secret_patterns,omitempty"`
	AuthAnnotations []string        `json:"auth_annotations,omitempty"`
	ExceptionCheck  *ExceptionCheck `json:"exception_check,omitempty"`
	ActivatesOnPass []ActivationRule `json:"activates_on_pass,omitempty"`

	// F-룰 (extraction_method: "manual") 전용
	VerdictType string          `json:"verdict_type,omitempty"` // potential_finding | needs_review
	ManualMeta  *ManualRuleMeta `json:"manual_meta,omitempty"`

	// ── Stage 2: F→R 흡수/승격/리포트/deferred 분류 플래그 ──

	// ManualCheckOutput: 이 R룰이 흡수한 F룰의 수동점검 출력 메타데이터.
	// applies_when 규칙대로 R 결과에 부착된다.
	ManualCheckOutput *ManualCheckOutput `json:"manual_check_output,omitempty"`

	// PromotedFrom: 원래 F룰이었으나 자동화 가능하여 R룰로 승격된 경우 원 F룰 ID.
	// 해당 룰은 Layer=R로 처리되며 합격률 분모에 포함된다.
	PromotedFrom string `json:"promoted_from,omitempty"`

	// ReclassifiedFrom: verdict 없는 인벤토리/방증 출력으로 재분류된 경우 원 F룰 ID.
	// OutputType="report"와 함께 사용. 합격률 분모 제외.
	ReclassifiedFrom string `json:"reclassified_from,omitempty"`

	// DeferredFrom: eBPF 등 파이프라인 미연동으로 보류 처리된 경우 원 F룰 ID.
	// manual_meta.deferred=true와 함께 사용. 합격률 분모 제외.
	DeferredFrom string `json:"deferred_from,omitempty"`

	// OutputType: "report" = 인벤토리/방증 리포트형 출력 (합격률 분모 제외).
	OutputType string `json:"output_type,omitempty"`
}

// IsManual returns true if this rule requires manual judgment (F-finding).
func (r *Rule) IsManual() bool { return r.ExtractionMethod == "manual" }

// IsFindingRule reports whether the rule should be evaluated by the finding
// (ClusterSnapshot) engine. manual 룰뿐 아니라, aws_api 계정스코프 룰(SG/CloudTrail/KMS)은
// extraction_method="api"라 IsManual()엔 안 걸리지만 manual_meta.condition.operator로
// dispatch되므로 여기서 포함한다. (이게 없으면 SG/CloudTrail/KMS가 평가 자체가 안 됨)
func (r *Rule) IsFindingRule() bool {
	if r.IsManual() {
		return true
	}
	return r.JudgmentSource == "aws_api" && r.ManualMeta != nil && len(r.ManualMeta.Condition) > 0
}

// RiskScopeOf returns the rule's risk_scope, inferring a default from rule_id when
// unset: SG/aws_api rules → account, others → pod (pod_chain은 명시 태깅 필요).
func (r *Rule) RiskScopeOf() string {
	if r.RiskScope != "" {
		return r.RiskScope
	}
	if strings.Contains(r.RuleID, "-SG") || r.JudgmentSource == "aws_api" {
		return grc.ScopeAccount
	}
	return grc.ScopePod
}

// FanoutOf returns the rule's fanout mode, defaulting per scope when unset.
func (r *Rule) FanoutOf() string {
	if r.Fanout != "" {
		return r.Fanout
	}
	switch r.RiskScopeOf() {
	case grc.ScopeCluster:
		return grc.FanoutAllPodsCluster
	case grc.ScopeAccount:
		return grc.FanoutAllPodsAccount
	default:
		return grc.FanoutSelf
	}
}

// IsTextExtraction returns true if this rule checks guideline/policy documents.
func (r *Rule) IsTextExtraction() bool { return r.JudgmentSource == "text_extraction" }

// IsK8sAPI returns true if this rule checks cloud/infrastructure environment.
func (r *Rule) IsK8sAPI() bool { return r.JudgmentSource == "k8s_api" }

// SecretPattern is a regex pattern for detecting plaintext secrets.
type SecretPattern struct {
	Name  string `json:"name"`
	Regex string `json:"regex"`
}

// ExceptionCheck defines system namespaces and annotations that exempt a Pod from a rule.
type ExceptionCheck struct {
	Annotation       string   `json:"annotation"`
	SystemNamespaces []string `json:"system_namespaces"`
}

// ActivationRule defines conditional rule activation based on compliance results.
type ActivationRule struct {
	Condition string   `json:"condition"`
	Require   []string `json:"require"`
	Note      string   `json:"note"`
}

type Indicator struct {
	Field       string `json:"field,omitempty"`
	Op          string `json:"op,omitempty"`
	Value       any    `json:"value,omitempty"`
	Unit        string `json:"unit,omitempty"`
	Pattern     string `json:"pattern,omitempty"`
	Type        string `json:"type,omitempty"`
	Description string `json:"description,omitempty"`
}

type ContentElement struct {
	ID            string   `json:"id"`
	Description   string   `json:"description"`
	MatchKeywords []string `json:"match_keywords"`
	LegalBasis    string   `json:"legal_basis,omitempty"`
}

// JudgmentLogic controls how the evaluation engine processes a rule.
type JudgmentLogic struct {
	Type                  string  `json:"type"`                             // "structured_match" | "semantic_match"
	Method                string  `json:"method,omitempty"`                 // "rag_entailment" etc.
	Aggregation           string  `json:"aggregation,omitempty"`
	MinPassRatio          float64 `json:"min_pass_ratio,omitempty"`
	SimilarityThreshold   float64 `json:"similarity_threshold,omitempty"`
	RequiredCoveragePct   int     `json:"required_coverage_pct,omitempty"`
	MinKeywordMatches     int     `json:"min_keyword_matches,omitempty"`
	ViolationThresholdPct float64 `json:"violation_threshold_pct,omitempty"`
	MinComplianceSignals  int     `json:"min_compliance_signals,omitempty"`
	MinPatterns           int     `json:"min_patterns,omitempty"`
	MaxViolations         int     `json:"max_violations,omitempty"`
	SampleSizeMin         int     `json:"sample_size_min,omitempty"`
}

type EvalStrategy struct {
	OverallVerdictLogic string `json:"overall_verdict_logic"`
	Description         string `json:"description"`
}

// ── RulesetStore ──

// RulesetStore loads and caches rulesets from disk.
// Schema 4.0.0: 항목당 파일 1개 (isms_p_{item}.json).
type RulesetStore struct {
	basePath string
	mu       sync.RWMutex
	cache    map[string]*Ruleset
}

func NewRulesetStore(basePath string) *RulesetStore {
	return &RulesetStore{
		basePath: basePath,
		cache:    make(map[string]*Ruleset),
	}
}

// stripBOM removes a leading UTF-8 BOM (EF BB BF) if present; no-op otherwise.
// 일부 출시 isms_p_*.json이 BOM과 함께 저장돼 있는데 Go encoding/json은 BOM을
// "invalid character 'ï'"로 거부하므로, 파싱 전에 모든 로드 경로에서 제거한다.
func stripBOM(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return data[3:]
	}
	return data
}

// Load loads a ruleset by ISMS-P item ID (e.g. "2.5.5").
func (s *RulesetStore) Load(itemID string) (*Ruleset, error) {
	s.mu.RLock()
	if rs, ok := s.cache[itemID]; ok {
		s.mu.RUnlock()
		return rs, nil
	}
	s.mu.RUnlock()

	// v4.0.0 파일 우선, 레거시 fallback
	filenames := []string{
		fmt.Sprintf("isms_p_%s.json", itemID),
		fmt.Sprintf("isms_p_%s_ruleset.json", itemID),
	}

	var data []byte
	var err error
	for _, filename := range filenames {
		for _, p := range s.searchPaths(filename) {
			data, err = os.ReadFile(p)
			if err == nil {
				goto found
			}
		}
	}
	return nil, fmt.Errorf("ruleset file not found for item %s: %w", itemID, err)

found:
	var rs Ruleset
	if err := json.Unmarshal(stripBOM(data), &rs); err != nil {
		return nil, fmt.Errorf("failed to parse ruleset %s: %w", itemID, err)
	}

	s.mu.Lock()
	s.cache[itemID] = &rs
	s.mu.Unlock()

	return &rs, nil
}

// searchPaths returns candidate file paths for a given filename.
func (s *RulesetStore) searchPaths(filename string) []string {
	paths := []string{
		filepath.Join(s.basePath, filename),
	}
	if envPath := os.Getenv("RULESET_PATH"); envPath != "" {
		paths = append([]string{filepath.Join(envPath, filename)}, paths...)
	}
	paths = append(paths, filename)
	return paths
}

// searchDirs returns directories to scan for ruleset files.
func (s *RulesetStore) searchDirs() []string {
	dirs := []string{s.basePath}
	if envPath := os.Getenv("RULESET_PATH"); envPath != "" {
		dirs = append(dirs, envPath)
	}
	dirs = append(dirs, ".")
	return dirs
}

// LoadAll loads all rulesets from disk.
// Unified rulesets (isms_p_X.json) are loaded first; if a pod ruleset
// (isms_p_X_pod_ruleset.json) exists for the same item, its rules are
// merged so that both guideline and k8s_native rules are available.
func (s *RulesetStore) LoadAll() []*Ruleset {
	seen := map[string]*Ruleset{}
	var rulesets []*Ruleset

	for _, dir := range s.searchDirs() {
		matches, _ := filepath.Glob(filepath.Join(dir, "isms_p_*.json"))
		for _, m := range matches {
			data, err := os.ReadFile(m)
			if err != nil {
				continue
			}
			var rs Ruleset
			if err := json.Unmarshal(stripBOM(data), &rs); err != nil || rs.Item.ID == "" {
				continue
			}
			if existing, ok := seen[rs.Item.ID]; ok {
				// Merge rules from the second file (e.g. pod_ruleset) into the first
				existing.Rules = append(existing.Rules, rs.Rules...)
				continue
			}
			stored := rs
			seen[rs.Item.ID] = &stored
			s.mu.Lock()
			s.cache[rs.Item.ID] = &stored
			s.mu.Unlock()
			rulesets = append(rulesets, &stored)
		}
	}
	return rulesets
}

// ListItems returns summary info for all available rulesets.
func (s *RulesetStore) ListItems() ([]RulesetSummary, error) {
	rulesets := s.LoadAll()
	items := make([]RulesetSummary, 0, len(rulesets))
	for _, rs := range rulesets {
		items = append(items, RulesetSummary{
			ISMSPItemID:   rs.Item.ID,
			Name:          rs.Item.Name,
			CategoryPath:  rs.Item.CategoryPath,
			RuleCount:     len(rs.Rules),
			ISMSPRevision: rs.ISMSPRevision,
		})
	}
	return items, nil
}

// GetRaw returns the raw JSON bytes for a ruleset file.
func (s *RulesetStore) GetRaw(itemID string) (json.RawMessage, error) {
	filenames := []string{
		fmt.Sprintf("isms_p_%s.json", itemID),
		fmt.Sprintf("isms_p_%s_ruleset.json", itemID),
	}
	for _, filename := range filenames {
		for _, p := range s.searchPaths(filename) {
			data, err := os.ReadFile(p)
			if err == nil {
				return json.RawMessage(stripBOM(data)), nil
			}
		}
	}
	return nil, fmt.Errorf("ruleset file not found for item %s", itemID)
}

type RulesetSummary struct {
	ISMSPItemID   string `json:"isms_p_item_id"`
	Name          string `json:"name"`
	CategoryPath  string `json:"category_path"`
	RuleCount     int    `json:"rule_count"`
	ISMSPRevision string `json:"isms_p_revision"`
}
