package scoring

import "testing"

// granular 보완 항목: 항목별 remove-one 재계산 + Δ=0 사유 + 그룹 누적. (rrApprox는 scenario_riskreduction_test.go)
func TestBuildRemediationItems(t *testing.T) {
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

	byID := map[string]RemediationItem{}
	for _, it := range set.Items {
		byID[it.ID] = it
	}
	grp := map[string]RemediationItem{}
	for _, g := range set.Groups {
		grp[g.ID] = g
	}

	// ── CVE (risk 축) — 총감소가능량 63을 점수 비례 배분(sum=205): 90/75/40 ──
	if it := byID["cve:CVE-A"]; !rrApprox(it.RiskReduction.Delta, 27.66) || it.RiskReduction.Axis != AxisRisk {
		t.Errorf("CVE-A: Δ=%v axis=%s (want 27.66/risk)", it.RiskReduction.Delta, it.RiskReduction.Axis)
	}
	if it := byID["cve:CVE-B"]; !rrApprox(it.RiskReduction.Delta, 23.05) || it.ZeroReason != "" {
		t.Errorf("CVE-B: Δ=%v reason=%q (want 23.05 + no reason)", it.RiskReduction.Delta, it.ZeroReason)
	}
	if it := byID["cve:CVE-C"]; !rrApprox(it.RiskReduction.Delta, 12.29) {
		t.Errorf("CVE-C: Δ=%v (want 12.29)", it.RiskReduction.Delta)
	}
	// 개별 delta 합 = 그룹(전체 패치) delta
	if g := grp["cve:image"]; !rrApprox(g.RiskReduction.Delta, 63) {
		t.Errorf("cve group Δ=%v want 63", g.RiskReduction.Delta)
	}

	// ── 노출 (risk 축) ──
	if it := byID["net:exposure"]; !rrApprox(it.RiskReduction.Delta, 30) {
		t.Errorf("exposure Δ=%v want 30", it.RiskReduction.Delta)
	}

	// ── RBAC (impact 축) ──
	if it := byID["rbac:*:*"]; !rrApprox(it.RiskReduction.Delta, 10) || it.RiskReduction.Axis != AxisImpact {
		t.Errorf("cluster-admin: Δ=%v axis=%s (want 10/impact)", it.RiskReduction.Delta, it.RiskReduction.Axis)
	}
	if it := byID["rbac:get:secrets"]; it.RiskReduction.Delta != 0 || it.ZeroReason == "" {
		t.Errorf("secrets(상위 포함): Δ=%v reason=%q (want 0 + 사유)", it.RiskReduction.Delta, it.ZeroReason)
	}
	if g := grp["rbac:sa:ci-sa"]; !rrApprox(g.RiskReduction.Delta, 40) {
		t.Errorf("rbac group Δ=%v want 40", g.RiskReduction.Delta)
	}

	// ── Mount (impact 축) — privileged·hostPath 둘 다 → 하나만 빼면 30 유지(Δ0) ──
	if it := byID["mount:privileged:app"]; it.RiskReduction.Delta != 0 || it.ZeroReason == "" {
		t.Errorf("privileged(hostPath 잔존): Δ=%v reason=%q (want 0 + 사유)", it.RiskReduction.Delta, it.ZeroReason)
	}
	if g := grp["mount:pod"]; !rrApprox(g.RiskReduction.Delta, 30) {
		t.Errorf("mount group Δ=%v want 30", g.RiskReduction.Delta)
	}
}
