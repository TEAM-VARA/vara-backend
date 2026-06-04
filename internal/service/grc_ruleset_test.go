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
		"../../rulesets/isms_p_2.5.4.json",
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
	if len(rs.Rules) != 23 {
		t.Errorf("rules count = %d, want 23", len(rs.Rules))
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
		"../../rulesets/isms_p_2.5.4.json",
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
		"R-2.5.4-01", "R-2.5.4-02", "R-2.5.4-03", "R-2.5.4-04", "R-2.5.4-05",
		"R-2.5.4-06", "R-2.5.4-07", "R-2.5.4-08", "R-2.5.4-09", "R-2.5.4-10",
		"R-2.5.4-11", "R-2.5.4-12", "R-2.5.4-13", "R-2.5.4-14", "R-2.5.4-15",
		"R-2.5.4-GL01", "R-2.5.4-GL02", "R-2.5.4-GL03", "R-2.5.4-GL04",
		"R-2.5.4-GL05", "R-2.5.4-GL06", "R-2.5.4-GL07", "R-2.5.4-GL08",
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

func TestRulesetJudgmentLogicTypes(t *testing.T) {
	paths := []string{
		"../../rulesets/isms_p_2.5.4.json",
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
		if !validTypes[rule.JudgmentLogic.Type] {
			t.Errorf("unexpected judgement_logic.type %q in rule %s", rule.JudgmentLogic.Type, rule.RuleID)
		}
	}
}

func TestRulesetStoreGetRaw(t *testing.T) {
	paths := []string{
		"../../rulesets/isms_p_2.5.4.json",
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
		"../../rulesets/isms_p_2.5.4.json",
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
