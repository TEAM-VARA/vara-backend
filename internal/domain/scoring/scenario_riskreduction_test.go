package scoring

import "testing"

func rrApprox(a, b float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < 0.01
}

// risk 축(Final) = (0.7×Global + 0.3×노출[0/100]) × Toxic. attack_path 제외.
func TestRiskInputs_Score(t *testing.T) {
	r := RiskInputs{GlobalImage: 90, Exposed: true, Toxic: 1.0}
	// 0.7×90 + 0.3×100 = 63 + 30 = 93
	if got := r.Score(); !rrApprox(got, 93.0) {
		t.Fatalf("risk Score = %v, want 93.0", got)
	}
	r.Exposed = false // 노출 0
	if got := r.Score(); !rrApprox(got, 63.0) {
		t.Errorf("risk Score(미노출) = %v, want 63.0", got)
	}
}

// risk 축 보완 delta: CVE 패치·노출 차단만 risk를 내린다.
func TestRiskReduction_RiskAxis(t *testing.T) {
	cur := RiskInputs{GlobalImage: 90, Exposed: true, Toxic: 1.0}
	before := cur.Score() // 93.0

	cve := cur
	cve.GlobalImage = 0
	if d := before - cve.Score(); !rrApprox(d, 63.0) { // 0.7×90
		t.Errorf("CVE 패치 Δrisk = %v, want 63.0", d)
	}
	exp := cur
	exp.Exposed = false
	if d := before - exp.Score(); !rrApprox(d, 30.0) { // 0.3×100
		t.Errorf("노출 차단 Δrisk = %v, want 30.0", d)
	}
}

// impact 축(attack_path) = RBAC + Net + Mount. RBAC·Mount·net 보완이 내린다.
func TestImpactInputs_Score(t *testing.T) {
	i := ImpactInputs{RBAC: 30, Network: 30, Mount: 30}
	if got := i.Score(); !rrApprox(got, 90.0) {
		t.Fatalf("impact Score = %v, want 90.0", got)
	}
	// 합이 100 초과면 clamp
	if got := (ImpactInputs{RBAC: 40, Network: 30, Mount: 40}).Score(); !rrApprox(got, 100.0) {
		t.Errorf("impact clamp = %v, want 100.0", got)
	}
}

func TestRiskReduction_ImpactAxis(t *testing.T) {
	cur := ImpactInputs{RBAC: 30, Network: 30, Mount: 30}
	before := cur.Score() // 90

	rbac := cur
	rbac.RBAC = 25 // secrets→exec
	if d := before - rbac.Score(); !rrApprox(d, 5.0) {
		t.Errorf("RBAC 30→25 Δimpact = %v, want 5.0", d)
	}
	net := cur
	net.Network = 0 // default-deny
	if d := before - net.Score(); !rrApprox(d, 30.0) {
		t.Errorf("default-deny Δimpact = %v, want 30.0", d)
	}
}

// Toxic 곱셈 + clamp 비선형(risk 축): 단순 빼기면 틀린다.
func TestRiskReduction_ToxicClampNonlinear(t *testing.T) {
	cur := RiskInputs{GlobalImage: 90, Exposed: true, Toxic: 1.5}
	before := cur.Score() // (63+30)×1.5=139.5 → clamp 100
	if !rrApprox(before, 100) {
		t.Fatalf("before(toxic1.5) = %v, want 100(clamp)", before)
	}
	cve := cur
	cve.GlobalImage = 0
	delta := before - cve.Score() // after = 30×1.5=45 → delta 55
	if !rrApprox(delta, 55.0) {
		t.Errorf("CVE delta(toxic1.5) = %v, want 55.0(clamp 압축)", delta)
	}
}
