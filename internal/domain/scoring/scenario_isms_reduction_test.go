package scoring

import "testing"

// ISMS-P 가산 차감: 보완 버킷 ↔ 룰 매핑(strict), 그룹 부착, net:isolation/SG 신규항목,
// 비대상 룰 제외, Δ=Σweight. (rrApprox는 scenario_riskreduction_test.go)
func TestAttachISMSReductions(t *testing.T) {
	// 베이스 set: remediation_items_test.go와 동일 샘플 — cve:image / rbac:sa:ci-sa / mount:pod 그룹 생성.
	// NetworkIsolationNone는 false라 net:isolation 항목은 없음 → fallback 생성 경로도 함께 검증.
	in := RemediationInput{
		RiskScore: 93, ImpactScore: 100, Toxic: 1.0,
		GlobalImage: 90,
		CVEs: []CVEItem{
			{ID: "CVE-A", Score: 90, Severity: "critical"},
			{ID: "CVE-B", Score: 75},
			{ID: "CVE-C", Score: 40},
		},
		Exposed: true, ExposedVia: "Service(LoadBalancer)",
		RBAC: 40, Network: 30, Mount: 30,
		AllPerms: []PermItem{
			{Verb: "*", Resource: "*"},
			{Verb: "get", Resource: "secrets"},
			{Verb: "create", Resource: "pods/exec"},
		},
		PrivilegedContainers: []string{"app"},
		HostPathVolumes:      []string{"data"},
		SAName:               "ci-sa",
	}
	set := BuildRemediationItems(in)

	// fired: 점수 가산된 ISMS 룰 (직접+상속). 비대상 R-2.7.1-02 포함 → 무시되어야.
	fired := []ISMSRuleHit{
		{RuleID: "R-2.10.8-04", Severity: "상", Weight: 3},   // → cve:image
		{RuleID: "R-2.5.5-01", Severity: "상", Weight: 3},    // → rbac:sa
		{RuleID: "R-2.5.5-02", Severity: "상", Weight: 3},    // → rbac:sa
		{RuleID: "R-2.5.5-08", Severity: "중", Weight: 2},    // → rbac:sa (워크로드 create 권한, 합 8)
		{RuleID: "R-2.10.2-01", Severity: "상", Weight: 3},   // → mount:pod
		{RuleID: "R-2.6.1-02", Severity: "중", Weight: 2},    // → net:isolation
		{RuleID: "R-2.6.1-SG01", Severity: "상", Weight: 3},  // → sg:inbound-open (신규)
		{RuleID: "R-2.6.6-01", Severity: "상", Weight: 3},    // → sg:remote-port (신규)
		{RuleID: "R-2.10.3-SG01", Severity: "상", Weight: 3}, // → sg:sensitive-port (신규)
		{RuleID: "R-2.7.1-02", Severity: "상", Weight: 3},    // 비대상(암호화) → 무시
	}
	addend := 30.0 // 전체 가산 합(eligible 27 + 비대상 3) — 상3/중2/하1

	AttachISMSReductions(&set, fired, "ci-sa", addend, 93)

	grp := map[string]RemediationItem{}
	for _, g := range set.Groups {
		grp[g.ID] = g
	}
	item := map[string]RemediationItem{}
	for _, it := range set.Items {
		item[it.ID] = it
	}

	// ── 그룹 부착(근본원인 완전 제거 시) ──
	if g := grp["cve:image"]; g.ISMSReduction == nil || !rrApprox(g.ISMSReduction.Delta, 3) || g.ISMSReduction.Axis != AxisRisk {
		t.Errorf("cve:image ISMS Δ=%v (want 3/risk)", ismsDelta(g))
	} else if !rrApprox(g.ISMSReduction.Before, 30) || !rrApprox(g.ISMSReduction.After, 27) {
		t.Errorf("cve:image ISMS before/after=%v/%v (want 30/27)", g.ISMSReduction.Before, g.ISMSReduction.After)
	}
	if g := grp["rbac:sa:ci-sa"]; g.ISMSReduction == nil || !rrApprox(g.ISMSReduction.Delta, 8) {
		t.Errorf("rbac:sa ISMS Δ=%v (want 8 = 2.5.5-01+02 + 2.6.3-01 = 3+3+2)", ismsDelta(g))
	} else if len(g.ISMSRules) != 3 {
		t.Errorf("rbac:sa ISMS rules=%d (want 3)", len(g.ISMSRules))
	}
	if g := grp["mount:pod"]; g.ISMSReduction == nil || !rrApprox(g.ISMSReduction.Delta, 3) {
		t.Errorf("mount:pod ISMS Δ=%v (want 3)", ismsDelta(g))
	}

	// ── net:isolation 항목 fallback 생성(베이스에 없었음) ──
	if it := item["net:isolation"]; it.ISMSReduction == nil || !rrApprox(it.ISMSReduction.Delta, 2) {
		t.Errorf("net:isolation ISMS Δ=%v (want 2 = 2.6.1-02 = 2)", ismsDelta(it))
	} else if it.RiskReduction.Delta != 0 {
		t.Errorf("net:isolation native Δ=%v (want 0 — 점수 영향 없음)", it.RiskReduction.Delta)
	}

	// ── SG 신규 항목(각 3, native 0) ──
	for _, id := range []string{"sg:inbound-open", "sg:remote-port", "sg:sensitive-port"} {
		it, ok := item[id]
		if !ok {
			t.Errorf("%s 항목 미생성", id)
			continue
		}
		if it.ISMSReduction == nil || !rrApprox(it.ISMSReduction.Delta, 3) {
			t.Errorf("%s ISMS Δ=%v (want 3)", id, ismsDelta(it))
		}
		if it.RiskReduction.Delta != 0 {
			t.Errorf("%s native Δ=%v (want 0)", id, it.RiskReduction.Delta)
		}
	}

	// ── 비대상 룰(R-2.7.1-02)은 어디에도 안 붙음 ──
	for _, it := range append(append([]RemediationItem{}, set.Items...), set.Groups...) {
		for _, r := range it.ISMSRules {
			if r.RuleID == "R-2.7.1-02" {
				t.Errorf("비대상 R-2.7.1-02가 %s에 부착됨", it.ID)
			}
		}
	}

	// ── 개별 CVE/권한/mount 항목에는 ISMS 차감이 붙지 않음(잔여) ──
	for _, id := range []string{"cve:CVE-A", "rbac:get:secrets", "mount:privileged:app"} {
		if it := item[id]; it.ISMSReduction != nil {
			t.Errorf("개별 항목 %s에 ISMS 차감이 붙음(want nil — 그룹에만)", id)
		}
	}
}

func ismsDelta(it RemediationItem) interface{} {
	if it.ISMSReduction == nil {
		return "nil"
	}
	return it.ISMSReduction.Delta
}
