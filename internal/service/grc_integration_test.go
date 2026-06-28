package service

import (
	"strings"
	"testing"

	"github.com/vara/backend/internal/domain/grc"
)

// ── toBoolLike ──

func TestToBoolLike(t *testing.T) {
	tests := []struct {
		input    any
		wantBool bool
		wantOK   bool
	}{
		{true, true, true},
		{false, false, true},
		{"true", true, true},
		{"True", true, true},
		{"Enabled", true, true},
		{"enabled", true, true},
		{"yes", true, true},
		{"false", false, true},
		{"Disabled", false, true},
		{"disabled", false, true},
		{"no", false, true},
		{"maybe", false, false},
		{42, false, false},
		{"STRONG", false, false},
	}
	for _, tt := range tests {
		b, ok := toBoolLike(tt.input)
		if ok != tt.wantOK {
			t.Errorf("toBoolLike(%v): ok = %v, want %v", tt.input, ok, tt.wantOK)
		}
		if ok && b != tt.wantBool {
			t.Errorf("toBoolLike(%v): bool = %v, want %v", tt.input, b, tt.wantBool)
		}
	}
}

// ── compareValues extended: bool-like equality ──

func TestCompareValues_BoolLikeEquality(t *testing.T) {
	tests := []struct {
		actual   any
		op       string
		expected any
		want     bool
	}{
		{"Enabled", "==", true, true},
		{"Disabled", "==", true, false},
		{"Enabled", "!=", false, true},
		{"Disabled", "!=", false, false},
		{true, "==", "Enabled", true},
		{false, "==", "Disabled", true},
		{"yes", "==", true, true},
		{"no", "==", false, true},
	}
	for _, tt := range tests {
		got := compareValues(tt.actual, tt.op, tt.expected)
		if got != tt.want {
			t.Errorf("compareValues(%v, %q, %v) = %v, want %v", tt.actual, tt.op, tt.expected, got, tt.want)
		}
	}
}

// ── matchEvidenceToRule with K8sSource ──
// NOTE: check_category 기반 매칭은 Rule에서 제거됨. K8sSource 보존은 target_rule_ids
// 경로 테스트(TestMatchEvidenceToRule_TargetRuleIDs_K8sSource)가 커버한다.

func TestMatchEvidenceToRule_TargetRuleIDs_K8sSource(t *testing.T) {
	files := []grc.EvidenceFile{
		{
			Filename:      "svc.yaml",
			EvidenceType:  "정책_시스템_설정",
			TargetRuleIDs: []string{"R005"},
			K8sSource: grc.K8sSource{
				Namespace:    "default",
				ResourceKind: "Service",
				ResourceName: "api-svc",
			},
		},
	}
	rule := Rule{RuleID: "R005"}
	matched := matchEvidenceToRule(files, rule, nil)
	if len(matched) != 1 {
		t.Fatalf("matched len = %d", len(matched))
	}
	if matched[0].K8sSource.ResourceName != "api-svc" {
		t.Error("K8sSource not preserved through target_rule_ids matching")
	}
}

// ── evidenceAttributionsFromFiles → generateRecommendations flow ──

func TestEndToEnd_K8sAttributionInRecommendation(t *testing.T) {
	// Simulate the full flow: evidence files → rule evaluation → recommendations

	// 1. Create evidence files with K8s sources
	files := []grc.EvidenceFile{
		{
			Filename:     "iam.json",
			EvidenceType: "정책_시스템_설정",
			K8sSource: grc.K8sSource{
				ClusterName:  "prod-eks",
				Namespace:    "auth",
				ResourceKind: "ConfigMap",
				ResourceName: "iam-config",
			},
		},
	}

	// 2. Build EvidenceSources
	srcs := evidenceAttributionsFromFiles(files)
	if len(srcs) != 1 {
		t.Fatalf("sources len = %d", len(srcs))
	}

	// 3. Create a non-compliant rule result with evidence sources
	ruleResults := []grc.RuleResult{
		{
			RuleID:          "R005",
			Verdict:         "미준수",
			EvidenceFiles:   []string{"iam.json"},
			EvidenceSources: srcs,
			Violations: []grc.Violation{
				{Description: "비밀번호 최소 길이 8자로 설정 (10자 필요)", Severity: "high"},
			},
		},
	}

	// 4. Generate recommendations
	ruleset := &Ruleset{
		Rules: []Rule{
			{RuleID: "R005"},
		},
		LegalRefs: []LegalReference{
			{Law: "개인정보의 안전성 확보조치 기준", Article: "제5조제5항"},
		},
	}
	recs := generateRecommendations(ruleResults, ruleset)

	// 5. Verify
	if len(recs) != 1 {
		t.Fatalf("recommendations len = %d", len(recs))
	}
	rec := recs[0]
	if rec.RuleID != "R005" {
		t.Errorf("rule_id = %q", rec.RuleID)
	}
	if !strings.Contains(rec.Action, "Kubernetes") {
		t.Errorf("missing Kubernetes prefix: %s", rec.Action)
	}
	if !strings.Contains(rec.Action, "prod-eks") {
		t.Errorf("missing cluster name: %s", rec.Action)
	}
	if !strings.Contains(rec.Action, "ConfigMap/iam-config") {
		t.Errorf("missing resource: %s", rec.Action)
	}
	if !strings.Contains(rec.Action, "비밀번호 최소 길이") {
		t.Errorf("missing violation detail: %s", rec.Action)
	}
	if rec.Reference == "" {
		t.Error("reference should not be empty")
	}
}

// ── aggregateSummary with verdict distribution ──

func TestAggregateSummary_AllPassed(t *testing.T) {
	results := []grc.RuleResult{
		{Verdict: "준수"},
		{Verdict: "준수"},
		{Verdict: "준수"},
	}
	s := aggregateSummary(results, 3)
	if s.TotalRules != 3 || s.Passed != 3 || s.Failed != 0 || s.Skipped != 0 {
		t.Errorf("got %+v", s)
	}
}

func TestAggregateSummary_AllFailed(t *testing.T) {
	results := []grc.RuleResult{
		{Verdict: "미준수"},
		{Verdict: "미준수"},
	}
	s := aggregateSummary(results, 2)
	if s.Failed != 2 || s.Passed != 0 {
		t.Errorf("got %+v", s)
	}
}

func TestAggregateSummary_AllSkipped(t *testing.T) {
	results := []grc.RuleResult{
		{Verdict: "skipped"},
		{Verdict: "skipped"},
	}
	s := aggregateSummary(results, 0)
	if s.Skipped != 2 || s.Passed != 0 || s.Failed != 0 {
		t.Errorf("got %+v", s)
	}
}

func TestAggregateSummary_Empty(t *testing.T) {
	s := aggregateSummary(nil, 0)
	if s.TotalRules != 0 {
		t.Errorf("got %+v", s)
	}
}

// ── isAccountViolation ──

func TestIsAccountViolation_FieldMatch(t *testing.T) {
	record := map[string]string{"days_since_change": "200"}
	rule := Rule{
		ComplianceIndicators: []Indicator{
			{Field: "days_since_change", Op: ">", Value: float64(180)},
		},
	}
	if !isAccountViolation(record, rule) {
		t.Error("expected violation: 200 > 180")
	}
}

func TestIsAccountViolation_FieldNoMatch(t *testing.T) {
	record := map[string]string{"days_since_change": "30"}
	rule := Rule{
		ComplianceIndicators: []Indicator{
			{Field: "days_since_change", Op: ">", Value: float64(180)},
		},
	}
	if isAccountViolation(record, rule) {
		t.Error("should not be violation: 30 < 180")
	}
}

func TestIsAccountViolation_PatternMatch(t *testing.T) {
	record := map[string]string{"status": "inactive_user"}
	rule := Rule{
		ComplianceIndicators: []Indicator{
			{Pattern: "inactive"},
		},
	}
	if !isAccountViolation(record, rule) {
		t.Error("expected pattern match violation")
	}
}

// ── envOrDefault ──

func TestEnvOrDefault(t *testing.T) {
	// When env is not set, should return default
	got := envOrDefault("GRC_TEST_NONEXISTENT_KEY_12345", "fallback")
	if got != "fallback" {
		t.Errorf("got %q, want 'fallback'", got)
	}
}

// ── GenerateJobID uniqueness ──

func TestGenerateJobID_UniqueOver100(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := GenerateJobID()
		if seen[id] {
			t.Fatalf("duplicate ID at iteration %d: %s", i, id)
		}
		seen[id] = true
	}
}

func TestGenerateJobID_Format(t *testing.T) {
	for i := 0; i < 10; i++ {
		id := GenerateJobID()
		if len(id) != 13 {
			t.Errorf("id length = %d, want 13", len(id))
		}
		if !strings.HasPrefix(id, "ck_") {
			t.Errorf("id prefix = %q, want ck_", id[:3])
		}
		// Body should be alphanumeric
		body := id[3:]
		for _, c := range body {
			if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
				t.Errorf("non-alphanumeric char in id body: %c", c)
			}
		}
	}
}

// ── flattenMap extended ──

func TestFlattenMap_DeepNesting(t *testing.T) {
	m := map[string]any{
		"L1": map[string]any{
			"L2": map[string]any{
				"L3": "deep_value",
			},
		},
	}
	flat := flattenMap(m)
	if flat["L3"] != "deep_value" {
		t.Errorf("L3 = %v, want deep_value", flat["L3"])
	}
	if _, ok := flat["L1"]; !ok {
		t.Error("L1 should still exist")
	}
}

func TestFlattenMap_NoNesting(t *testing.T) {
	m := map[string]any{"a": 1, "b": "two"}
	flat := flattenMap(m)
	if flat["a"] != 1 || flat["b"] != "two" {
		t.Errorf("got %v", flat)
	}
}

func TestFlattenMap_KeyConflict(t *testing.T) {
	// When a nested key conflicts with a top-level key, top-level wins
	m := map[string]any{
		"X": "top",
		"nested": map[string]any{
			"X": "deep",
		},
	}
	flat := flattenMap(m)
	if flat["X"] != "top" {
		t.Errorf("X = %v, want 'top' (top-level should win)", flat["X"])
	}
}
