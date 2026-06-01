package service

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRulesetStoreLoad(t *testing.T) {
	// Find the ruleset file relative to project root.
	// Tests may run from different directories, try multiple paths.
	paths := []string{
		"../../isms_p_2.5.4_ruleset.json",
		"../../rulesets/isms_p_2.5.4_ruleset.json",
	}

	var basePath string
	for _, p := range paths {
		abs, _ := filepath.Abs(p)
		dir := filepath.Dir(abs)
		if _, err := os.Stat(abs); err == nil {
			basePath = dir
			break
		}
	}
	if basePath == "" {
		t.Skip("ruleset file not found, skipping test")
	}

	store := NewRulesetStore(basePath)
	rs, err := store.Load("2.5.4")
	if err != nil {
		t.Fatalf("Load(2.5.4) failed: %v", err)
	}

	if rs.Item.ID != "2.5.4" {
		t.Errorf("item.id = %q, want 2.5.4", rs.Item.ID)
	}
	if rs.Item.Name != "비밀번호 관리" {
		t.Errorf("item.name = %q, want 비밀번호 관리", rs.Item.Name)
	}
	if len(rs.Rules) != 15 {
		t.Errorf("rules count = %d, want 15", len(rs.Rules))
	}
	if rs.ISMSPRevision != "2023.11" {
		t.Errorf("isms_p_revision = %q, want 2023.11", rs.ISMSPRevision)
	}
}

func TestRulesetStoreLoadUnsupported(t *testing.T) {
	store := NewRulesetStore("nonexistent_dir")
	_, err := store.Load("9.9.9")
	if err == nil {
		t.Error("expected error for unsupported item, got nil")
	}
}

func TestRulesetRuleIDs(t *testing.T) {
	paths := []string{
		"../../isms_p_2.5.4_ruleset.json",
		"../../rulesets/isms_p_2.5.4_ruleset.json",
	}

	var basePath string
	for _, p := range paths {
		abs, _ := filepath.Abs(p)
		dir := filepath.Dir(abs)
		if _, err := os.Stat(abs); err == nil {
			basePath = dir
			break
		}
	}
	if basePath == "" {
		t.Skip("ruleset file not found")
	}

	store := NewRulesetStore(basePath)
	rs, err := store.Load("2.5.4")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	expectedIDs := []string{
		"2.5.4-R001", "2.5.4-R002", "2.5.4-R003", "2.5.4-R004", "2.5.4-R005",
		"2.5.4-R006", "2.5.4-R007", "2.5.4-R008", "2.5.4-R009", "2.5.4-R010",
		"2.5.4-R011", "2.5.4-R012", "2.5.4-R013", "2.5.4-R014", "2.5.4-R015",
	}

	for i, expected := range expectedIDs {
		if i >= len(rs.Rules) {
			t.Fatalf("only %d rules, expected at least %d", len(rs.Rules), i+1)
		}
		if rs.Rules[i].RuleID != expected {
			t.Errorf("rules[%d].rule_id = %q, want %q", i, rs.Rules[i].RuleID, expected)
		}
	}
}

func TestRulesetCheckCategories(t *testing.T) {
	paths := []string{
		"../../isms_p_2.5.4_ruleset.json",
		"../../rulesets/isms_p_2.5.4_ruleset.json",
	}

	var basePath string
	for _, p := range paths {
		abs, _ := filepath.Abs(p)
		dir := filepath.Dir(abs)
		if _, err := os.Stat(abs); err == nil {
			basePath = dir
			break
		}
	}
	if basePath == "" {
		t.Skip("ruleset file not found")
	}

	store := NewRulesetStore(basePath)
	rs, _ := store.Load("2.5.4")

	expectedCategories := map[string]bool{
		"정책_문서_존재":      true,
		"정책_문서_충실도":     true,
		"정책_시스템_설정":     true,
		"사용자_화면_강제화":    true,
		"변경주기_준수":       true,
		"임시_비밀번호_강제_변경": true,
		"저장_형태":         true,
		"인증수단":          true,
	}

	for _, rule := range rs.Rules {
		if !expectedCategories[rule.CheckCategory] {
			t.Errorf("unexpected check_category %q in rule %s", rule.CheckCategory, rule.RuleID)
		}
	}
}

func TestRulesetJudgementLogicTypes(t *testing.T) {
	paths := []string{
		"../../isms_p_2.5.4_ruleset.json",
		"../../rulesets/isms_p_2.5.4_ruleset.json",
	}

	var basePath string
	for _, p := range paths {
		abs, _ := filepath.Abs(p)
		dir := filepath.Dir(abs)
		if _, err := os.Stat(abs); err == nil {
			basePath = dir
			break
		}
	}
	if basePath == "" {
		t.Skip("ruleset file not found")
	}

	store := NewRulesetStore(basePath)
	rs, _ := store.Load("2.5.4")

	validTypes := map[string]bool{
		"structured_match":    true,
		"semantic_match":      true,
		"regex_match":         true,
		"aggregated_statistics": true,
		"code_pattern_match":  true,
	}

	for _, rule := range rs.Rules {
		if !validTypes[rule.JudgementLogic.Type] {
			t.Errorf("unexpected judgement_logic.type %q in rule %s", rule.JudgementLogic.Type, rule.RuleID)
		}
	}
}

func TestRulesetStoreGetRaw(t *testing.T) {
	paths := []string{
		"../../isms_p_2.5.4_ruleset.json",
		"../../rulesets/isms_p_2.5.4_ruleset.json",
	}

	var basePath string
	for _, p := range paths {
		abs, _ := filepath.Abs(p)
		dir := filepath.Dir(abs)
		if _, err := os.Stat(abs); err == nil {
			basePath = dir
			break
		}
	}
	if basePath == "" {
		t.Skip("ruleset file not found")
	}

	store := NewRulesetStore(basePath)
	raw, err := store.GetRaw("2.5.4")
	if err != nil {
		t.Fatalf("GetRaw(2.5.4) failed: %v", err)
	}
	if len(raw) == 0 {
		t.Error("GetRaw returned empty data")
	}
	// Verify it's valid JSON.
	if raw[0] != '{' {
		t.Errorf("raw data doesn't start with '{': starts with %q", string(raw[0]))
	}
}

func TestRulesetStoreCaching(t *testing.T) {
	paths := []string{
		"../../isms_p_2.5.4_ruleset.json",
		"../../rulesets/isms_p_2.5.4_ruleset.json",
	}

	var basePath string
	for _, p := range paths {
		abs, _ := filepath.Abs(p)
		dir := filepath.Dir(abs)
		if _, err := os.Stat(abs); err == nil {
			basePath = dir
			break
		}
	}
	if basePath == "" {
		t.Skip("ruleset file not found")
	}

	store := NewRulesetStore(basePath)

	// First load.
	rs1, err := store.Load("2.5.4")
	if err != nil {
		t.Fatalf("first Load failed: %v", err)
	}

	// Second load should return cached version (same pointer).
	rs2, err := store.Load("2.5.4")
	if err != nil {
		t.Fatalf("second Load failed: %v", err)
	}

	if rs1 != rs2 {
		t.Error("expected cached ruleset to return same pointer")
	}
}
