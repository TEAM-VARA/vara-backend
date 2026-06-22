package scoring

// ============================================================================
// 보완 적용 시 점수 하락량(remediation delta) — 2축 모델
//
// 현재 점수 체계는 두 점수로 분리돼 있다(final_scoring_repo.go가 attack_path를 제외하고
// exposure_scores만 Final에 넣음):
//
//	risk(=Final, likelihood) = (0.7×Global_CVE + 0.3×노출[0/100]) × Toxic   ← CVE·노출만
//	impact(=attack_path)     = RBAC + Network + Mount  (0~100)              ← RBAC·Mount·net
//
// 따라서 보완은 자기가 속한 "축"의 점수만 내린다:
//	CVE 패치·외부노출 차단        → risk 축
//	RBAC·Mount·network isolation → impact 축
//
// "빼기"가 아니라 재계산(현재 vs 그 항목 제거 후)이라 MAX/tier·Toxic 비선형을 정확히 반영한다.
// ============================================================================

// 보완이 내리는 점수 축.
const (
	AxisRisk   = "risk"   // likelihood: CVE + 노출 (= Final/risk_score)
	AxisImpact = "impact" // attack_path: RBAC + Network + Mount
)

// RiskReduction — 이 보완 적용 시 점수 변화. delta = before - after (>= 0).
type RiskReduction struct {
	Axis   string  `json:"axis"`   // risk | impact (어느 점수를 내리나)
	Before float64 `json:"before"` // 현재 점수
	After  float64 `json:"after"`  // 보완 후 점수
	Delta  float64 `json:"delta"`  // 하락량
}

// RiskInputs — risk_score(Final) 재계산용. attack_path 제외, 노출은 0/100.
//
//	Final = (0.7×Global + 0.3×노출[0/100]) × Toxic    (final_scoring_repo.go 와 동일)
type RiskInputs struct {
	GlobalImage float64 // 이미지 CVE 최댓값 (0~100)
	Exposed     bool    // 외부 노출 → 100, 아니면 0
	Toxic       float64 // 배수 (>=1.0)
}

// Score — 기존 ComputeFinalScore 그대로 재사용(노출을 0/100으로 넘김).
func (r RiskInputs) Score() float64 {
	exposure := 0.0
	if r.Exposed {
		exposure = 100.0
	}
	final, _, _ := ComputeFinalScore(r.GlobalImage, exposure, r.Toxic)
	return final
}

// ImpactInputs — attack_path(영향) 점수 재계산용 = RBAC + Network + Mount (0~100).
type ImpactInputs struct {
	RBAC    int // 0~40
	Network int // 0~30
	Mount   int // 0~30
}

// Score — attack_path total (0~100 clamp).
func (i ImpactInputs) Score() float64 {
	v := i.RBAC + i.Network + i.Mount
	if v > AttackPathMaxTotal {
		v = AttackPathMaxTotal
	}
	if v < 0 {
		v = 0
	}
	return float64(v)
}
