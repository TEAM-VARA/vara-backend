package service

import (
	"context"
	"encoding/json"
	"testing"
)

const sampleFixtureJSON = `{
  "rule_id": "R-2.2.1-07",
  "compliant": {
    "description": "audit ok",
    "data": {
      "audit_log_enabled": true,
      "log_types": ["api", "audit", "authenticator", "controllerManager", "scheduler"],
      "log_retention_days": 365,
      "dashboard_url": "https://datadog.example.com/dash"
    },
    "expected_result": "PASS"
  },
  "non_compliant": {
    "description": "audit off",
    "data": {
      "audit_log_enabled": false,
      "log_types": [],
      "log_retention_days": 0,
      "dashboard_url": null
    },
    "expected_result": "FAIL"
  }
}`

func TestRuleFixtureFile_roundTrip(t *testing.T) {
	var f RuleFixtureFile
	if err := json.Unmarshal([]byte(sampleFixtureJSON), &f); err != nil {
		t.Fatal(err)
	}
	if f.RuleID != "R-2.2.1-07" {
		t.Fatalf("rule_id=%q", f.RuleID)
	}
	s := &GRCService{rulesetStore: NewRulesetStore(rulesetDir(t))}
	ctx := context.Background()
	ft := EffectiveFixtureType(f)

	for _, tc := range []struct {
		name   string
		sc     FixtureScenario
		expect string
	}{
		{"compliant", f.Compliant, "PASS"},
		{"non_compliant", f.NonCompliant, "FAIL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := EvidencePayloadFromScenario(ft, tc.sc)
			if err != nil {
				t.Fatal(err)
			}
			res, err := s.EvaluateRuleWithEvidence(ctx, f.RuleID, payload, nil)
			if err != nil {
				t.Fatal(err)
			}
			got := VerdictPassFail(res.Verdict)
			if got != tc.expect {
				t.Fatalf("expected %s got %s (verdict=%q)", tc.expect, got, res.Verdict)
			}
		})
	}
}
