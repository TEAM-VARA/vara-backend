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

func TestEvaluateRuleWithEvidence_semanticFromJSONMap(t *testing.T) {
	s := &GRCService{
		rulesetStore: NewRulesetStore(rulesetDir(t)),
	}
	ctx := context.Background()
	// 2.2.1-R007: structured EKS audit fields (see ISMS-P_룰_테스트데이터_JSON_1 / normalizer).
	payload := map[string]any{
		"audit_log_enabled":    true,
		"log_types":            []any{"api", "audit", "authenticator"},
		"log_retention_days":   365.0,
		"dashboard_url":        "https://dash.example",
		"monitored_users":        []any{"a@b.com"},
		"sample_audit_events":    []any{},
	}
	res, err := s.EvaluateRuleWithEvidence(ctx, "R-2.2.1-07", payload, nil)
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
