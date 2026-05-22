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
	RuleID                  string                   `json:"rule_id"`
	CheckCategory           string                   `json:"check_category"`
	EvidenceType            string                   `json:"evidence_type"`
	System                  string                   `json:"system"`
	RelatedCheckpoints      []string                 `json:"related_checkpoints"`
	EvidenceFormat          string                   `json:"evidence_format"`
	ExtractionMethod        string                   `json:"extraction_method"`
	AutoCollectable         bool                     `json:"auto_collectable"`
	IdentificationKeywords  []string                 `json:"identification_keywords"`
	ComplianceIndicators    []Indicator              `json:"compliance_indicators"`
	DeficiencyIndicators    []Indicator              `json:"deficiency_indicators"`
	JudgementLogic          JudgementLogic           `json:"judgement_logic"`
	RequiredContentElements map[string][]ContentElement `json:"required_content_elements,omitempty"`
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

	filename := fmt.Sprintf("isms_p_%s_ruleset.json", itemID)

	// Try multiple paths: RULESET_PATH env, basePath, project root.
	paths := []string{
		filepath.Join(s.basePath, filename),
	}
	if envPath := os.Getenv("RULESET_PATH"); envPath != "" {
		paths = append([]string{filepath.Join(envPath, filename)}, paths...)
	}
	// Also try project root (where the file currently is).
	paths = append(paths, filename)

	var data []byte
	var err error
	for _, p := range paths {
		data, err = os.ReadFile(p)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("ruleset file not found for item %s: %w", itemID, err)
	}

	var rs Ruleset
	if err := json.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("failed to parse ruleset %s: %w", itemID, err)
	}

	s.mu.Lock()
	s.cache[itemID] = &rs
	s.mu.Unlock()

	return &rs, nil
}

// ListItems returns summary info for all available rulesets.
func (s *RulesetStore) ListItems() ([]RulesetSummary, error) {
	// Scan basePath and RULESET_PATH for ruleset files.
	dirs := []string{s.basePath}
	if envPath := os.Getenv("RULESET_PATH"); envPath != "" {
		dirs = append(dirs, envPath)
	}
	// Also scan current directory.
	dirs = append(dirs, ".")

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
	paths := []string{
		filepath.Join(s.basePath, filename),
	}
	if envPath := os.Getenv("RULESET_PATH"); envPath != "" {
		paths = append([]string{filepath.Join(envPath, filename)}, paths...)
	}
	paths = append(paths, filename)

	for _, p := range paths {
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
}
