package service

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Ruleset is the top-level structure of an ISMS-P ruleset JSON file.
type Ruleset struct {
	SchemaVersion string           `json:"schema_version"`
	ISMSPRevision string           `json:"isms_p_revision"`
	GeneratedFor  string           `json:"generated_for"`
	Module        string           `json:"module,omitempty"` // "pod-graph" for Pod rulesets
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

type Rule struct {
	RuleID                  string                      `json:"rule_id"`
	Name                    string                      `json:"name,omitempty"`
	JudgmentSource          string                      `json:"judgment_source,omitempty"` // "k8s_native" | "document" | ""
	CheckCategory           string                      `json:"check_category"`
	EvidenceType            string                      `json:"evidence_type"`
	System                  string                      `json:"system"`
	RelatedCheckpoints      []string                    `json:"related_checkpoints"`
	EvidenceFormat          string                      `json:"evidence_format"`
	ExtractionMethod        string                      `json:"extraction_method"`
	AutoCollectable         bool                        `json:"auto_collectable"`
	IdentificationKeywords  []string                    `json:"identification_keywords"`
	ComplianceIndicators    []Indicator                 `json:"compliance_indicators"`
	DeficiencyIndicators    []Indicator                 `json:"deficiency_indicators"`
	JudgementLogic          JudgementLogic              `json:"judgement_logic"`
	RequiredContentElements map[string][]ContentElement `json:"required_content_elements,omitempty"`

	// Pod-graph specific fields (schema 3.0.0-pod)
	DataSources     []DataSource    `json:"data_sources,omitempty"`
	SecretPatterns  []SecretPattern `json:"secret_patterns,omitempty"`
	AuthAnnotations []string        `json:"auth_annotations,omitempty"`
	ExceptionCheck  *ExceptionCheck `json:"exception_check,omitempty"`
	ActivatesOnPass []ActivationRule `json:"activates_on_pass,omitempty"`
	Report          []string        `json:"report,omitempty"`
}

// DataSource describes a K8s API data source for Pod-graph rules.
type DataSource struct {
	ResourceType string   `json:"resource_type"`
	APIEndpoint  string   `json:"api_endpoint"`
	Fields       []string `json:"fields"`
	PythonClient string   `json:"python_client"`
}

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

type JudgementLogic struct {
	Type                 string  `json:"type"`
	Method               string  `json:"method,omitempty"`
	Aggregation          string  `json:"aggregation,omitempty"`
	MinPassRatio         float64 `json:"min_pass_ratio,omitempty"`
	SimilarityThreshold  float64 `json:"similarity_threshold,omitempty"`
	RequiredCoveragePct  int     `json:"required_coverage_pct,omitempty"`
	MinKeywordMatches    int     `json:"min_keyword_matches,omitempty"`
	AnyDeficiencyFails   bool    `json:"any_deficiency_fails,omitempty"`
	ViolationThresholdPct float64 `json:"violation_threshold_pct,omitempty"`
	MinComplianceSignals int     `json:"min_compliance_signals,omitempty"`
	MinPatterns          int     `json:"min_patterns,omitempty"`
	MaxViolations        int     `json:"max_violations,omitempty"`
	SampleSizeMin        int     `json:"sample_size_min,omitempty"`
}

type EvalStrategy struct {
	OverallVerdictLogic string `json:"overall_verdict_logic"`
	Description         string `json:"description"`
}

// RulesetStore loads and caches rulesets from disk.
type RulesetStore struct {
	basePath string
	mu       sync.RWMutex
	cache    map[string]*Ruleset // keyed by item ID, e.g. "2.5.4"
}

func NewRulesetStore(basePath string) *RulesetStore {
	return &RulesetStore{
		basePath: basePath,
		cache:    make(map[string]*Ruleset),
	}
}

func (s *RulesetStore) Load(itemID string) (*Ruleset, error) {
	s.mu.RLock()
	if rs, ok := s.cache[itemID]; ok {
		s.mu.RUnlock()
		return rs, nil
	}
	s.mu.RUnlock()

	// Try unified (4.0.0) file first, then legacy document-only file.
	filenames := []string{
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
	if err := json.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("failed to parse ruleset %s: %w", itemID, err)
	}

	s.mu.Lock()
	s.cache[itemID] = &rs
	s.mu.Unlock()

	return &rs, nil
}

// LoadUnified loads the unified ruleset (schema 4.0.0) for an item.
// If a unified file exists, it returns that. Otherwise it merges rules from
// the document ruleset and pod ruleset into a single Ruleset.
func (s *RulesetStore) LoadUnified(itemID string) (*Ruleset, error) {
	cacheKey := "unified:" + itemID
	s.mu.RLock()
	if rs, ok := s.cache[cacheKey]; ok {
		s.mu.RUnlock()
		return rs, nil
	}
	s.mu.RUnlock()

	// Try loading unified file (schema 4.0.0).
	docRS, docErr := s.Load(itemID)

	// If it's already a unified schema, return directly.
	if docErr == nil && docRS.SchemaVersion == "4.0.0" {
		s.mu.Lock()
		s.cache[cacheKey] = docRS
		s.mu.Unlock()
		return docRS, nil
	}

	// Otherwise, merge document + pod rulesets.
	podRS, podErr := s.LoadPod(itemID)

	if docErr != nil && podErr != nil {
		return nil, fmt.Errorf("no ruleset found for item %s", itemID)
	}

	// Build merged ruleset.
	merged := &Ruleset{
		SchemaVersion: "4.0.0-merged",
	}

	if docRS != nil {
		merged.Item = docRS.Item
		merged.ISMSPRevision = docRS.ISMSPRevision
		merged.LegalRefs = docRS.LegalRefs
		merged.EvalStrategy = docRS.EvalStrategy
		for _, r := range docRS.Rules {
			if r.JudgmentSource == "" {
				r.JudgmentSource = "document"
			}
			merged.Rules = append(merged.Rules, r)
		}
	}

	if podRS != nil {
		if merged.Item.ID == "" {
			merged.Item = podRS.Item
			merged.ISMSPRevision = podRS.ISMSPRevision
			merged.LegalRefs = podRS.LegalRefs
			merged.EvalStrategy = podRS.EvalStrategy
		}
		for _, r := range podRS.Rules {
			if r.JudgmentSource == "" {
				r.JudgmentSource = "k8s_native"
			}
			merged.Rules = append(merged.Rules, r)
		}
	}

	s.mu.Lock()
	s.cache[cacheKey] = merged
	s.mu.Unlock()

	return merged, nil
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

// LoadAll loads all unified rulesets (merging pod + document for each item).
func (s *RulesetStore) LoadAll() []*Ruleset {
	seen := map[string]bool{}
	var rulesets []*Ruleset

	// Find all item IDs from both document and pod rulesets.
	for _, dir := range s.searchDirs() {
		// Document rulesets: isms_p_*_ruleset.json
		matches, _ := filepath.Glob(filepath.Join(dir, "isms_p_*_ruleset.json"))
		for _, m := range matches {
			base := filepath.Base(m)
			// Skip pod rulesets in this pass.
			if len(base) > 16 && base[len(base)-16:] == "pod_ruleset.json" {
				continue
			}
			data, err := os.ReadFile(m)
			if err != nil {
				continue
			}
			var rs Ruleset
			if err := json.Unmarshal(data, &rs); err != nil || rs.Item.ID == "" {
				continue
			}
			if seen[rs.Item.ID] {
				continue
			}
			seen[rs.Item.ID] = true

			unified, err := s.LoadUnified(rs.Item.ID)
			if err != nil {
				continue
			}
			rulesets = append(rulesets, unified)
		}

		// Pod rulesets: isms_p_*_pod_ruleset.json (catch items with no document ruleset)
		podMatches, _ := filepath.Glob(filepath.Join(dir, "isms_p_*_pod_ruleset.json"))
		for _, m := range podMatches {
			data, err := os.ReadFile(m)
			if err != nil {
				continue
			}
			var rs Ruleset
			if err := json.Unmarshal(data, &rs); err != nil || rs.Item.ID == "" {
				continue
			}
			if seen[rs.Item.ID] {
				continue
			}
			seen[rs.Item.ID] = true

			unified, err := s.LoadUnified(rs.Item.ID)
			if err != nil {
				continue
			}
			rulesets = append(rulesets, unified)
		}
	}
	return rulesets
}

// ListItems returns summary info for all available rulesets.
func (s *RulesetStore) ListItems() ([]RulesetSummary, error) {
	dirs := s.searchDirs()

	seen := map[string]bool{}
	var items []RulesetSummary

	for _, dir := range dirs {
		matches, _ := filepath.Glob(filepath.Join(dir, "isms_p_*_ruleset.json"))
		for _, m := range matches {
			data, err := os.ReadFile(m)
			if err != nil {
				continue
			}
			var rs Ruleset
			if err := json.Unmarshal(data, &rs); err != nil {
				continue
			}
			if seen[rs.Item.ID] {
				continue
			}
			seen[rs.Item.ID] = true

			// Cache it while we're at it.
			s.mu.Lock()
			s.cache[rs.Item.ID] = &rs
			s.mu.Unlock()

			items = append(items, RulesetSummary{
				ISMSPItemID:   rs.Item.ID,
				Name:          rs.Item.Name,
				CategoryPath:  rs.Item.CategoryPath,
				RuleCount:     len(rs.Rules),
				ISMSPRevision: rs.ISMSPRevision,
			})
		}
	}
	return items, nil
}

// GetRaw returns the raw JSON bytes for a ruleset file.
func (s *RulesetStore) GetRaw(itemID string) (json.RawMessage, error) {
	filename := fmt.Sprintf("isms_p_%s_ruleset.json", itemID)
	for _, p := range s.searchPaths(filename) {
		data, err := os.ReadFile(p)
		if err == nil {
			return json.RawMessage(data), nil
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
	Module        string `json:"module,omitempty"`
}

// ── Pod Ruleset Methods ──

// LoadPod loads a Pod-graph ruleset by ISMS-P item ID (e.g. "2.6.1").
func (s *RulesetStore) LoadPod(itemID string) (*Ruleset, error) {
	cacheKey := "pod:" + itemID
	s.mu.RLock()
	if rs, ok := s.cache[cacheKey]; ok {
		s.mu.RUnlock()
		return rs, nil
	}
	s.mu.RUnlock()

	filename := fmt.Sprintf("isms_p_%s_pod_ruleset.json", itemID)

	var data []byte
	var err error
	for _, p := range s.searchPaths(filename) {
		data, err = os.ReadFile(p)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("pod ruleset file not found for item %s: %w", itemID, err)
	}

	var rs Ruleset
	if err := json.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("failed to parse pod ruleset %s: %w", itemID, err)
	}

	s.mu.Lock()
	s.cache[cacheKey] = &rs
	s.mu.Unlock()

	return &rs, nil
}

// LoadAllPodRulesets scans for all Pod-graph ruleset files and returns them.
func (s *RulesetStore) LoadAllPodRulesets() []*Ruleset {
	dirs := []string{s.basePath}
	if envPath := os.Getenv("RULESET_PATH"); envPath != "" {
		dirs = append(dirs, envPath)
	}
	dirs = append(dirs, ".")

	seen := map[string]bool{}
	var rulesets []*Ruleset

	for _, dir := range dirs {
		matches, _ := filepath.Glob(filepath.Join(dir, "isms_p_*_pod_ruleset.json"))
		for _, m := range matches {
			data, err := os.ReadFile(m)
			if err != nil {
				continue
			}
			var rs Ruleset
			if err := json.Unmarshal(data, &rs); err != nil {
				continue
			}
			if seen[rs.Item.ID] {
				continue
			}
			seen[rs.Item.ID] = true

			stored := rs
			cacheKey := "pod:" + rs.Item.ID
			s.mu.Lock()
			s.cache[cacheKey] = &stored
			s.mu.Unlock()

			rulesets = append(rulesets, &stored)
		}
	}
	return rulesets
}

// ListPodItems returns summary info for all available Pod-graph rulesets.
func (s *RulesetStore) ListPodItems() ([]RulesetSummary, error) {
	rulesets := s.LoadAllPodRulesets()
	items := make([]RulesetSummary, 0, len(rulesets))
	for _, rs := range rulesets {
		items = append(items, RulesetSummary{
			ISMSPItemID:   rs.Item.ID,
			Name:          rs.Item.Name,
			CategoryPath:  rs.Item.CategoryPath,
			RuleCount:     len(rs.Rules),
			ISMSPRevision: rs.ISMSPRevision,
			Module:        rs.Module,
		})
	}
	return items, nil
}

// GetPodRaw returns the raw JSON bytes for a Pod-graph ruleset file.
func (s *RulesetStore) GetPodRaw(itemID string) (json.RawMessage, error) {
	filename := fmt.Sprintf("isms_p_%s_pod_ruleset.json", itemID)
	for _, p := range s.searchPaths(filename) {
		data, err := os.ReadFile(p)
		if err == nil {
			return json.RawMessage(data), nil
		}
	}
	return nil, fmt.Errorf("pod ruleset file not found for item %s", itemID)
}
