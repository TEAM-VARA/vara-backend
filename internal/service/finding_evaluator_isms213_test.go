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

// 출시본 isms_p_2.1.3.json이 파싱되고, R-2.1.3-01/02가 operator로 디스패치되며,
// 기존 GL01/GL02가 보존됨을 end-to-end로 확인한다 (JSON 스키마 회귀 가드).
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
	// R-2.1.3-01은 LBL로 흡수되어 shipping 룰셋에 없다(2.5.4가 -03부터 시작하는 것과 동일 패턴).
	// R-01 평가 로직은 TestRuleISMSP213_01_Coverage_MissingIsNeedsReview가 별도 커버한다.
	for _, want := range []string{"R-2.1.3-02", "R-2.1.3-GL01", "R-2.1.3-GL02"} {
		if _, ok := byID[want]; !ok {
			t.Fatalf("ruleset missing rule %q (rules: %d)", want, len(rs.Rules))
		}
	}
	if pf := byID["R-2.1.3-02"].PromotedFrom; pf != "LBL-2.1.3-02" {
		t.Fatalf("R-2.1.3-02 promoted_from = %q, want LBL-2.1.3-02", pf)
	}

	snap := &ClusterSnapshot{
		Pods: []postgres.ClusterPodRow{
			pod("app", "web-abc", map[string]string{"app": "web"}, nil), // 후보 키 전무 → 누락
		},
	}

	// R-2.1.3-02: admission 정책 미수집 → NO_DATA (준수 거짓 보고 금지).
	r02 := evaluateSingleManualRule(byID["R-2.1.3-02"], snap)
	if r02.Verdict != grc.VerdictNO_DATA {
		t.Fatalf("R-2.1.3-02 verdict = %q, want NO_DATA", r02.Verdict)
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

// R-2.1.3-02: Kyverno/Gatekeeper 미수집 상태에서 NO_DATA로 떨어지고
// "강제 정책 미수집" 사유가 남는다. 라벨 강제 여부를 "준수"로 거짓 보고하지 않는다.
func TestRuleISMSP213_02_AdmissionPolicy_NoData(t *testing.T) {
	rule := Rule{
		RuleID:           "R-2.1.3-02",
		JudgmentSource:   "k8s_api",
		ExtractionMethod: "manual",
		VerdictType:      "potential_finding",
		PromotedFrom:     "LBL-2.1.3-02",
		ManualMeta: &ManualRuleMeta{
			Condition: rawCond(t, map[string]any{
				"operator":            "required_label_policy_enforced",
				"required_label_keys": []string{"team", "owner", "cost-center"},
				"policy_kinds":        []string{"ClusterPolicy", "K8sRequiredLabels"},
			}),
		},
	}

	// 라벨이 전부 붙어 있는 클러스터라도 "강제"가 입증되지 않으면 준수로 보고하면 안 된다.
	snap := &ClusterSnapshot{
		Pods: []postgres.ClusterPodRow{
			pod("app", "web-abc", map[string]string{"team": "payments", "owner": "alice", "cost-center": "cc1"}, nil),
		},
	}

	rr := evaluateSingleManualRule(rule, snap)

	if rr.Verdict != grc.VerdictNO_DATA {
		t.Fatalf("verdict = %q, want NO_DATA", rr.Verdict)
	}
	if dp, ok := rr.Evidence["data_provided"].(bool); !ok || dp {
		t.Fatalf("evidence data_provided = %v, want false", rr.Evidence["data_provided"])
	}
	if !strings.Contains(rr.Observation, "미수집") {
		t.Fatalf("observation = %q, want it to mention 미수집", rr.Observation)
	}
}
