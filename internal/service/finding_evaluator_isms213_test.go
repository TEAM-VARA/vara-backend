package service

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/vara/backend/internal/domain/grc"
	"github.com/vara/backend/internal/repository/postgres"
)

// isms213RulesetDir returns the repo's rulesets directory.
func isms213RulesetDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	return filepath.Join(root, "rulesets")
}

// 출시본 isms_p_2.1.3.json이 파싱되고, 가이드라인 룰(GL01/GL02)이 보존됨을
// end-to-end로 확인한다 (JSON 스키마 회귀 가드).
// R-2.1.3-01/02는 shipping 룰셋에 없다(LBL 흡수/제외). 평가 로직은
// TestRuleISMSP213_01_Coverage_* / TestRuleISMSP213_02_AdmissionPolicy_NoData가 별도 커버한다.
func TestRuleISMSP213_ShippedRulesetEndToEnd(t *testing.T) {
	store := NewRulesetStore(isms213RulesetDir(t))
	rs, err := store.Load("2.1.3")
	if err != nil {
		t.Fatalf("Load(2.1.3) failed: %v", err)
	}

	byID := map[string]Rule{}
	for _, r := range rs.Rules {
		byID[r.RuleID] = r
	}
	for _, want := range []string{"R-2.1.3-GL01", "R-2.1.3-GL02"} {
		if _, ok := byID[want]; !ok {
			t.Fatalf("ruleset missing rule %q (rules: %d)", want, len(rs.Rules))
		}
	}
	// R-2.1.3-02는 출시 룰셋에서 제외되었다 — 재유입 방지 가드.
	if _, ok := byID["R-2.1.3-02"]; ok {
		t.Fatalf("R-2.1.3-02 should not be shipped in the 2.1.3 ruleset")
	}
}

// rawCond marshals a condition map into a json.RawMessage for ManualRuleMeta.Condition.
func rawCond(t *testing.T, cond map[string]any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(cond)
	if err != nil {
		t.Fatalf("marshal condition: %v", err)
	}
	return b
}

func pod(ns, name string, labels, annotations map[string]string) postgres.ClusterPodRow {
	l, _ := json.Marshal(labels)
	a, _ := json.Marshal(annotations)
	return postgres.ClusterPodRow{
		Namespace:   ns,
		Name:        name,
		Labels:      l,
		Annotations: a,
	}
}

// R-2.1.3-01: 후보 키가 하나도 없는 워크로드가 있으면 NEEDS_REVIEW로 잡히고
// missing 목록이 결과에 나온다. 라벨 존재만으로 무조건 PASS 처리하지 않는다.
func TestRuleISMSP213_01_Coverage_MissingIsNeedsReview(t *testing.T) {
	rule := Rule{
		RuleID:           "R-2.1.3-01",
		JudgmentSource:   "k8s_api",
		ExtractionMethod: "manual",
		VerdictType:      "potential_finding",
		ManualMeta: &ManualRuleMeta{
			Condition: rawCond(t, map[string]any{
				"operator": "any_owner_indicator_exists",
				"fields":   []string{"labels.team", "labels.owner", "annotations.owner-team"},
			}),
			AdditionalReviewItems: []string{
				"책임자 라벨이 없는 워크로드를 외부 CMDB/ITSM·Git CODEOWNERS와 대조해 책임소재 확정",
			},
		},
		ManualCheckOutput: &ManualCheckOutput{AppliesWhen: "always"},
	}

	snap := &ClusterSnapshot{
		Pods: []postgres.ClusterPodRow{
			pod("app", "web-abc", map[string]string{"team": "payments"}, nil), // 책임자 있음
			pod("app", "worker-xyz", map[string]string{"app": "worker"}, nil), // 후보 키 전무 → 누락
		},
	}

	rr := evaluateSingleManualRule(rule, snap)

	if rr.Verdict != grc.VerdictNEEDS_REVIEW {
		t.Fatalf("verdict = %q, want NEEDS_REVIEW", rr.Verdict)
	}
	if mc, _ := rr.Evidence["missing_count"].(int); mc != 1 {
		t.Fatalf("missing_count = %v, want 1", rr.Evidence["missing_count"])
	}
	if list, _ := rr.Evidence["missing_list"].(string); !strings.Contains(list, "worker-xyz") {
		t.Fatalf("missing_list = %q, want it to contain worker-xyz", list)
	}
	if len(rr.AffectedResources) != 1 || rr.AffectedResources[0].Name != "worker-xyz" {
		t.Fatalf("affected resources = %+v, want [worker-xyz]", rr.AffectedResources)
	}
	// applies_when=always → 라벨이 있어도 외부 대조 안내가 노출되도록 review item 보존.
	if len(rr.AdditionalReviewItems) == 0 {
		t.Fatalf("expected additional_review_items to be present (always-on CMDB 대조 안내)")
	}
}

// R-2.1.3-01: 후보 키가 전부 채워지면 MET이되, 자기증명을 넘어 외부 대조 안내(always)는 유지.
func TestRuleISMSP213_01_Coverage_AllPresentIsMet(t *testing.T) {
	rule := Rule{
		RuleID:           "R-2.1.3-01",
		JudgmentSource:   "k8s_api",
		ExtractionMethod: "manual",
		VerdictType:      "potential_finding",
		ManualMeta: &ManualRuleMeta{
			Condition: rawCond(t, map[string]any{
				"operator": "any_owner_indicator_exists",
				"fields":   []string{"labels.team", "labels.owner"},
			}),
			AdditionalReviewItems: []string{"책임자 라벨 값을 외부 CMDB/CODEOWNERS와 대조"},
		},
		ManualCheckOutput: &ManualCheckOutput{AppliesWhen: "always"},
	}

	snap := &ClusterSnapshot{
		Pods: []postgres.ClusterPodRow{
			pod("app", "web-abc", map[string]string{"team": "payments"}, nil),
			pod("app", "api-def", map[string]string{"owner": "alice"}, nil),
		},
	}

	rr := evaluateSingleManualRule(rule, snap)

	if rr.Verdict != grc.VerdictMET {
		t.Fatalf("verdict = %q, want MET", rr.Verdict)
	}
	if mc, _ := rr.Evidence["missing_count"].(int); mc != 0 {
		t.Fatalf("missing_count = %v, want 0", rr.Evidence["missing_count"])
	}
	if len(rr.AdditionalReviewItems) == 0 {
		t.Fatalf("expected always-on CMDB 대조 안내 even when MET")
	}
}
