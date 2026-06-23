package service

import (
	"context"

	"github.com/vara/backend/internal/domain/scoring"
)

// attachRiskReductions — 각 보완(ScenarioMitigation)에 "적용 시 점수 하락량"(risk_reduction)을
// 2축으로 채운다.
//
//	risk 축  (Final = likelihood) : CVE 패치 · 외부노출 차단(9005)
//	impact 축 (attack_path)       : RBAC · Mount · network isolation(9034)
//
// final_scoring_repo가 attack_path를 Final에서 제외하므로(노출 0/100만 사용), RBAC/Mount/net
// 보완은 risk가 아니라 impact(attack_path) 점수를 내린다. delta는 "빼기"가 아니라 재계산
// (현재 vs 그 항목 제거 후)이라 MAX/tier·Toxic 비선형을 정확히 반영한다.
//
// 한계: RBAC 점수가 5단계(cluster-admin/wildcard/secrets/exec/read)뿐이라, 그 level을 결정하지
// 않는 RBAC 보완(webhook/backdoor/events 등)은 impact delta=0이 된다. 권한별 가중치로 RBAC
// 점수를 세분화하면 해소된다.
func (s *ScenarioService) attachRiskReductions(ctx context.Context, cluster, podUID string, res *scoring.PodScenarioResult) {
	if s.attackPath == nil || s.finalScore == nil || res == nil {
		return
	}
	ap, err := s.attackPath.GetByPodUID(ctx, cluster, podUID)
	if err != nil || ap == nil {
		return // 점수 정보 없으면 risk_reduction 생략(nil)
	}
	fin, ferr := s.finalScore.GetByPodUID(ctx, cluster, podUID)
	if ferr != nil || fin == nil {
		return
	}
	exposed := false
	if s.exposure != nil {
		if ex, eerr := s.exposure.GetByPodUID(ctx, cluster, podUID); eerr == nil && ex != nil {
			exposed = ex.Exposed
		}
	}

	curRisk := scoring.RiskInputs{GlobalImage: fin.GlobalImageScore, Exposed: exposed, Toxic: fin.ToxicMultiplier}
	curImpact := scoring.ImpactInputs{RBAC: ap.RBACScore, Network: ap.NetworkScore, Mount: ap.MountScore}

	riskShown := res.RiskScore  // 페이지에 보이는 risk_score(=fin.FinalScore)
	riskCalc := curRisk.Score() // 재계산 기준(내부 일관성용)
	impactBefore := curImpact.Score()

	// risk 축 RiskReduction (Toxic·clamp 때문에 표시값-재계산값 분리)
	riskRR := func(afterScore float64) *scoring.RiskReduction {
		delta := riskCalc - afterScore
		if delta < 0 {
			delta = 0
		}
		af := riskShown - delta
		if af < 0 {
			af = 0
		}
		return &scoring.RiskReduction{
			Axis: scoring.AxisRisk, Before: scoring.RoundTo2(riskShown),
			After: scoring.RoundTo2(af), Delta: scoring.RoundTo2(delta),
		}
	}
	// impact 축 RiskReduction (정수 합산이라 표시-재계산 차이 없음)
	impactRR := func(afterScore float64) *scoring.RiskReduction {
		delta := impactBefore - afterScore
		if delta < 0 {
			delta = 0
		}
		return &scoring.RiskReduction{
			Axis: scoring.AxisImpact, Before: scoring.RoundTo2(impactBefore),
			After: scoring.RoundTo2(afterScore), Delta: scoring.RoundTo2(delta),
		}
	}

	// MS-TA9034(NetworkPolicy)는 연결되는 Pod마다 한 항목씩 쪼개져 있을 수 있다. 격리 점수는
	// "이 Pod에 default-deny가 적용되는가"의 전부-아니면-전무(none→deny_all)라 연결 1건씩 더해지는 게
	// 아니다. 따라서 네트워크 격리 하락량은 9034 항목 중 첫 1건에만 붙여 중복 합산을 막는다.
	netRRDone := false
	for i := range res.Mitigations {
		m := &res.Mitigations[i]
		switch {
		case m.Bucket == "VULN": // CVE 패치(이미지 업그레이드) → Global 0
			after := curRisk
			after.GlobalImage = 0
			m.RiskReduction = riskRR(after.Score())
		case m.Bucket == "NET" && m.MSTA == "MS-TA9005": // 외부노출 차단
			after := curRisk
			after.Exposed = false
			m.RiskReduction = riskRR(after.Score())
		case m.Bucket == "NET" && m.MSTA == "MS-TA9034": // default-deny NetworkPolicy
			if netRRDone {
				break // 연결별로 쪼갠 나머지 항목은 격리 하락량을 중복으로 싣지 않는다.
			}
			netRRDone = true
			after := curImpact
			after.Network = scoring.ComputeNetworkScore(scoring.NetworkIsolationDenyAll)
			m.RiskReduction = impactRR(after.Score())
		case m.Bucket == "RBAC":
			after := curImpact
			after.RBAC = rbacScoreWithout(ap, m.MSTA)
			m.RiskReduction = impactRR(after.Score())
		case m.Bucket == "MOUNT":
			after := curImpact
			after.Mount = mountScoreWithout(ap.MountDetails, m.MSTA)
			m.RiskReduction = impactRR(after.Score())
		}
	}
}

// rbacScoreWithout — 이 보완이 회수하는 RBAC 신호를 뺀, 남은 신호 중 최고 level 점수.
// VARA RBAC level enum에 매핑되는 신호만 점수에 영향(그 외 보완은 현재값 유지 → delta=0).
func rbacScoreWithout(ap *scoring.AttackPathResult, fixedMSTA string) int {
	d := ap.RBACDetails
	best := 0
	consider := func(active bool, removedBy string, val int) {
		if active && fixedMSTA != removedBy && val > best {
			best = val
		}
	}
	consider(d.IsClusterAdmin, "MS-TA9019", scoring.ComputeRBACScore(scoring.RBACLevelClusterAdmin))    // 40
	consider(d.HasWildcard, "—", scoring.ComputeRBACScore(scoring.RBACLevelWildcard))                   // 35 (단독 보완 없음 → 잔존)
	consider(d.HasSecretsAccess, "MS-TA9025", scoring.ComputeRBACScore(scoring.RBACLevelSecretsAccess)) // 30
	consider(d.HasPodExec, "MS-TA9006", scoring.ComputeRBACScore(scoring.RBACLevelPodExec))             // 25
	if best > ap.RBACScore {
		return ap.RBACScore
	}
	return best
}

// mountScoreWithout — 해당 securityContext/volume 신호를 끄고 Mount 점수를 재산정.
// 같은 tier(30)를 만드는 다른 신호가 남으면 점수가 안 떨어진다(ComputeMountScore가 처리).
func mountScoreWithout(md scoring.MountDetails, fixedMSTA string) int {
	switch fixedMSTA {
	case "MS-TA9018": // privileged 제거
		md.HasPrivileged = false
	case "MS-TA9013": // writable hostPath 제거
		md.HasHostPath = false
	}
	return scoring.ComputeMountScore(md)
}
