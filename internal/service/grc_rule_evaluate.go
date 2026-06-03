package service

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vara/backend/internal/domain/grc"
)

// VerdictPassFail maps internal verdicts to fixture / API style tokens.
func VerdictPassFail(verdict string) string {
	switch verdict {
	case "준수":
		return "PASS"
	case "미준수":
		return "FAIL"
	case "skipped":
		return "SKIP"
	default:
		return verdict
	}
}

// CanonicalEvidenceForRule shapes fixture or API input like extractEvidence output.
//   - structured_match: keep top-level JSON objects as map[string]any (merged by evaluateStructured).
//   - semantic / regex / aggregated / code_pattern: JSON objects are marshaled to a string so
//     keyword and regex matchers see log/policy text (EKS audit exports, etc.).
func CanonicalEvidenceForRule(rule Rule, payload any) []any {
	switch rule.JudgmentLogic.Type {
	case "structured_match":
		if m, ok := payload.(map[string]any); ok {
			return []any{m}
		}
	default:
		if m, ok := payload.(map[string]any); ok {
			b, err := json.Marshal(m)
			if err == nil {
				return []any{string(b)}
			}
		}
	}
	return []any{payload}
}

// EvaluateRuleWithEvidence evaluates one rule outside the async check worker (fixtures, EKS batch jobs).
// ruleRef may be R-2.2.1-07 or 2.2.1-R007. ctx is reserved for future repo-backed evaluation hooks.
func (s *GRCService) EvaluateRuleWithEvidence(ctx context.Context, ruleRef string, evidencePayload any, filenames []string) (grc.RuleResult, error) {
	_ = ctx
	if s == nil || s.rulesetStore == nil {
		return grc.RuleResult{}, fmt.Errorf("GRCService or ruleset store is nil")
	}
	itemID, canonRuleID, err := ResolveItemAndRuleID(ruleRef)
	if err != nil {
		return grc.RuleResult{}, err
	}
	rs, err := s.rulesetStore.Load(itemID)
	if err != nil {
		return grc.RuleResult{}, err
	}
	rule, err := findRuleInRuleset(rs, canonRuleID)
	if err != nil {
		return grc.RuleResult{}, err
	}
	if m, ok := evidencePayload.(map[string]any); ok {
		NormalizeRuleFixtureEvidence(canonRuleID, m)
	}
	if len(filenames) == 0 {
		filenames = []string{"inline"}
	}
	data := CanonicalEvidenceForRule(*rule, evidencePayload)
	return s.evaluateRule(ctx, *rule, data, filenames, nil), nil
}
