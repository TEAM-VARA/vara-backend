package service

import (
	"testing"

	"github.com/vara/backend/internal/domain/grc"
)

// projectFindingsLayer는 verdict_type 보유 룰만 layers.f로 복사하고,
// verdict를 대문자 enum으로 정규화하며, r 원본은 건드리지 않아야 한다.
func TestProjectFindingsLayer(t *testing.T) {
	items := []grc.ItemComplianceResult{
		{
			ISMSPItemID: "2.6.1",
			Layers: &grc.ItemLayers{
				R: []grc.RuleResult{
					// finding (verdict_type 보유) — 한글 verdict → 정규화 대상
					{RuleID: "R-2.6.1-SG01", VerdictType: "potential_finding", Verdict: "미준수"},
					// 순수 기술 룰 (verdict_type 없음) — 투영 제외
					{RuleID: "R-2.6.1-01", Verdict: grc.VerdictMET},
				},
			},
		},
		{
			ISMSPItemID: "2.6.7",
			Layers: &grc.ItemLayers{
				R: []grc.RuleResult{
					{RuleID: "R-2.6.7-02", VerdictType: "compliant_indicator", Verdict: grc.VerdictMET},
				},
			},
		},
		{
			// Layers == nil 항목은 패닉 없이 스킵
			ISMSPItemID: "2.9.1",
		},
	}

	projectFindingsLayer(items)

	// item 2.6.1: finding 1건만 f로 투영, verdict 정규화
	f := items[0].Layers.F
	if len(f) != 1 {
		t.Fatalf("item[0] layers.f = %d건, 기대 1건 (verdict_type 룰만)", len(f))
	}
	if f[0].RuleID != "R-2.6.1-SG01" {
		t.Errorf("투영된 rule_id = %q, 기대 R-2.6.1-SG01", f[0].RuleID)
	}
	if f[0].Verdict != grc.VerdictNOT_MET {
		t.Errorf("f verdict = %q, 기대 %q (대문자 enum 정규화)", f[0].Verdict, grc.VerdictNOT_MET)
	}

	// r 원본은 보존(verdict 미변경): 같은 룰의 r 쪽은 여전히 한글
	if items[0].Layers.R[0].Verdict != "미준수" {
		t.Errorf("r 원본 verdict가 변경됨: %q (표시 전용 복사여야 함)", items[0].Layers.R[0].Verdict)
	}

	// item 2.6.7: compliant_indicator finding 투영
	if len(items[1].Layers.F) != 1 || items[1].Layers.F[0].Verdict != grc.VerdictMET {
		t.Errorf("item[1] layers.f 투영 실패: %+v", items[1].Layers.F)
	}

	// Layers == nil 항목은 그대로 nil
	if items[2].Layers != nil {
		t.Errorf("item[2] Layers는 nil 유지여야 함")
	}
}
