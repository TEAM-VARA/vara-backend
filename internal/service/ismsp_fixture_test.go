package service

import (
	"context"
	"encoding/json"
	"testing"
)

const sampleFixtureJSON = `{
  "rule_id": "R-2.5.4-05",
  "compliant": {
    "description": "IAM password policy compliant",
    "data": {
      "MinimumPasswordLength": 12,
      "RequireUppercaseCharacters": true,
      "RequireLowercaseCharacters": true,
      "RequireNumbers": true,
      "RequireSymbols": true,
      "MaxPasswordAge": 90,
      "PasswordReusePrevention": 5
    },
    "expected_result": "PASS"
  },
  "non_compliant": {
    "description": "IAM password policy too weak",
    "data": {
      "MinimumPasswordLength": 6,
      "RequireUppercaseCharacters": false,
      "RequireLowercaseCharacters": false,
      "RequireNumbers": false,
      "RequireSymbols": false,
      "MaxPasswordAge": 0,
      "PasswordReusePrevention": 0
    },
    "expected_result": "FAIL"
  }
}`

func TestRuleFixtureFile_roundTrip(t *testing.T) {
	var f RuleFixtureFile
	if err := json.Unmarshal([]byte(sampleFixtureJSON), &f); err != nil {
		t.Fatal(err)
	}
	if f.RuleID != "R-2.5.4-05" {
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
