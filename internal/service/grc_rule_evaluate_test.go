package service

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"
)

func rulesetDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	// internal/service -> repo root
	root := filepath.Join(filepath.Dir(file), "..", "..")
	return filepath.Join(root, "rulesets")
}

func TestEvaluateRuleWithEvidence_structuredFromJSONMap(t *testing.T) {
	s := &GRCService{
		rulesetStore: NewRulesetStore(rulesetDir(t)),
	}
	ctx := context.Background()
	// 2.5.4-R005: IAM password policy structured fields.
	payload := map[string]any{
		"MinimumPasswordLength":       12.0,
		"RequireUppercaseCharacters":  true,
		"RequireLowercaseCharacters":  true,
		"RequireNumbers":              true,
		"RequireSymbols":              true,
		"MaxPasswordAge":              90.0,
		"PasswordReusePrevention":     5.0,
	}
	res, err := s.EvaluateRuleWithEvidence(ctx, "R-2.5.4-05", payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != "준수" {
		t.Fatalf("verdict=%q violations=%+v", res.Verdict, res.Violations)
	}
	if VerdictPassFail(res.Verdict) != "PASS" {
		t.Fatalf("VerdictPassFail=%q", VerdictPassFail(res.Verdict))
	}
}
