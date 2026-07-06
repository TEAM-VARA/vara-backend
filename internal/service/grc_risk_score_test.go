package service

import (
	"testing"

	"github.com/vara/backend/internal/domain/scoring"
)

// TestISMSPRiskAddend: accumulateISMSPRisk / ApplyISMSPToFinalScore 로직 단위테스트 (DB 불필요).
// 가중치는 실제 코드 기준 상=3 / 중=2 / 하=1 (grc_risk_score.go: ismspSeverityWeight).
func TestISMSPRiskAddend(t *testing.T) {
	b := &ISMSPRiskBreakdown{Rules: []ISMSPRiskRuleHit{}}
	seen := map[string]bool{}

	accumulateISMSPRisk(b, seen, "R-2.10.2-01", "미준수", false) // 상 +3 (hostNetwork)
	accumulateISMSPRisk(b, seen, "R-2.6.1-02", "미준수", false)  // 중 +2 (NetworkPolicy)
	accumulateISMSPRisk(b, seen, "R-2.6.7-01", "미준수", false)  // 중 +2 (egress)
	accumulateISMSPRisk(b, seen, "R-2.10.2-01", "미준수", false) // 중복 → rule-once 무시
	accumulateISMSPRisk(b, seen, "R-2.5.5-01", "준수", false)    // 준수 → 무시
	accumulateISMSPRisk(b, seen, "R-2.10.5-01", "미준수", false) // severity맵에 없음 → 무시

	if b.Addend != 7 || b.CountHigh != 1 || b.CountMedium != 2 {
		t.Fatalf("addend=%v high=%d med=%d, want 7/1/2", b.Addend, b.CountHigh, b.CountMedium)
	}
	if b.CountLow != 0 {
		t.Fatalf("low=%d, want 0", b.CountLow)
	}
	if len(b.Rules) != 3 {
		t.Fatalf("rules=%d, want 3", len(b.Rules))
	}

	res := &scoring.Result{FinalScore: 60}
	ApplyISMSPToFinalScore(res, b.Addend) // 60 + 7
	if res.FinalScore != 67 {
		t.Fatalf("final=%v, want 67", res.FinalScore)
	}
}

// TestISMSPRiskAddend_NormalizePODVariant: -POD- 변형 rule_id가 표준 rule_id로 정규화되는지.
func TestISMSPRiskAddend_NormalizePODVariant(t *testing.T) {
	b := &ISMSPRiskBreakdown{Rules: []ISMSPRiskRuleHit{}}
	seen := map[string]bool{}

	accumulateISMSPRisk(b, seen, "R-2.10.2-POD-01", "미준수", false) // → R-2.10.2-01 상 +3
	accumulateISMSPRisk(b, seen, "R-2.10.2-01", "미준수", true)     // 정규화 후 동일 → rule-once 무시

	if b.Addend != 3 || len(b.Rules) != 1 {
		t.Fatalf("addend=%v rules=%d, want 3/1", b.Addend, len(b.Rules))
	}
	if b.Rules[0].RuleID != "R-2.10.2-01" {
		t.Fatalf("ruleID=%q, want R-2.10.2-01", b.Rules[0].RuleID)
	}
}

// TestApplyISMSPToFinalScore_CapAt100: 100 상한 처리.
func TestApplyISMSPToFinalScore_CapAt100(t *testing.T) {
	res := &scoring.Result{FinalScore: 98}
	ApplyISMSPToFinalScore(res, 7) // 105 → 100
	if res.FinalScore != 100 {
		t.Fatalf("final=%v, want 100 (capped)", res.FinalScore)
	}

	// addend<=0 이면 변화 없음
	res2 := &scoring.Result{FinalScore: 50}
	ApplyISMSPToFinalScore(res2, 0)
	if res2.FinalScore != 50 {
		t.Fatalf("final=%v, want 50 (no change)", res2.FinalScore)
	}
}
