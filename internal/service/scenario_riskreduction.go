package service

import (
	"context"

	"github.com/vara/backend/internal/domain/scoring"
)

// attachRiskReductions — 각 보완(ScenarioMitigation)에 "적용 시 하락량"(risk_reduction)을
// 2축으로 채운다.
//
//	risk 축  (Final = likelihood)        : CVE 패치 · 외부노출 차단(9005)
//	blast 축 (전파 총위험도 total_risk)   : RBAC(측면이동) · NetworkPolicy(9034) · Mount(노드 공유)
//
// CVE·노출은 risk_score(Final)를 내리고, RBAC/Network/Mount는 blast_risk(blast_pair_risk.total_risk)를
// 내린다. blast 하락은 "그 보완이 닫는 채널(rbac/network/host)을 이 Pod의 나가는 엣지에서 0으로 두고
// reach 재계산"이다(scenario_blastreduction.go). delta는 "빼기"가 아니라 재계산이라 멀티홉 전파를
// 정확히 반영한다. NetworkPolicy(9034)만 대상 Pod별로 끊어 연결 단위 하락을 보인다.
//
// 한계: blast_edges 채널 확률이 사전계산값이라 RBAC technique끼리 세분 구분은 못 한다(모두 같은 rbac
// 채널 차단으로 처리). br(blastReducer)는 BuildForPod에서 1회 로드해 넘긴다.
func (s *ScenarioService) attachRiskReductions(ctx context.Context, cluster, podUID string, res *scoring.PodScenarioResult, br *blastReducer) {
	if s.finalScore == nil || res == nil {
		return
	}
	fin, ferr := s.finalScore.GetByPodUID(ctx, cluster, podUID)
	if ferr != nil || fin == nil {
		return // 점수 정보 없으면 risk_reduction 생략(nil)
	}
	exposed := false
	if s.exposure != nil {
		if ex, eerr := s.exposure.GetByPodUID(ctx, cluster, podUID); eerr == nil && ex != nil {
			exposed = ex.Exposed
		}
	}

	curRisk := scoring.RiskInputs{GlobalImage: fin.GlobalImageScore, Exposed: exposed, Toxic: fin.ToxicMultiplier}
	riskShown := res.RiskScore  // 페이지에 보이는 risk_score(= 저장 final_score)
	riskCalc := curRisk.Score() // 재계산 기준(내부 일관성용)

	// risk 축 RiskReduction (Toxic·clamp 때문에 표시값-재계산값 분리). CVE·외부노출만 risk 축.
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

	for i := range res.Mitigations {
		m := &res.Mitigations[i]
		switch {
		case m.Bucket == "VULN": // CVE 패치(이미지 업그레이드) → Global 0 (risk 축)
			after := curRisk
			after.GlobalImage = 0
			m.RiskReduction = riskRR(after.Score())
		case m.Bucket == "NET" && m.MSTA == "MS-TA9005": // 외부노출 차단 (risk 축)
			after := curRisk
			after.Exposed = false
			m.RiskReduction = riskRR(after.Score())
		case m.Bucket == "NET" && m.MSTA == "MS-TA9034": // default-deny NetworkPolicy (blast: network 채널)
			// 연결별로 쪼갠 항목이면 m.Target(대상 Pod 이름)으로 그 연결만 끊는다. 빈 값이면 이 Pod egress 전체.
			m.RiskReduction = br.closeChannel(blastChannelNetwork, m.Target)
		case m.Bucket == "RBAC": // 권한 회수 (blast: rbac=측면이동 채널)
			m.RiskReduction = br.closeChannel(blastChannelRBAC, "")
		case m.Bucket == "MOUNT": // privileged/hostPath 제거 (blast: host=노드 공유 채널)
			m.RiskReduction = br.closeChannel(blastChannelHost, "")
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
