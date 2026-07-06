package service

import (
	"context"
	"fmt"

	"github.com/vara/backend/internal/domain/scoring"
	"github.com/vara/backend/internal/repository/postgres"
)

// breakdownISMSPAddender는 Breakdown에 ISMS-P 가산 내역을 표기하기 위한 최소 인터페이스다.
// *GRCService가 이를 만족한다. nil이면(미주입) ISMS-P 섹션은 생략된다 — 기존 동작 불변.
type breakdownISMSPAddender interface {
	ComputePodISMSPAddend(ctx context.Context, companyID, clusterName, namespace, podName string) *ISMSPRiskBreakdown
}

// BreakdownService는 Final Score의 구성 근거를 조립합니다.
type BreakdownService struct {
	finalRepo  *postgres.FinalScoringRepo
	globalRepo *postgres.GlobalScoringRepo
	localRepo  *postgres.LocalScoringRepo
	toxicRepo  *postgres.ToxicRepo
	ismsp      breakdownISMSPAddender // ISMS-P 가산 제공자(선택) — 미주입 시 섹션 생략
}

func NewBreakdownService(
	finalRepo *postgres.FinalScoringRepo,
	globalRepo *postgres.GlobalScoringRepo,
	localRepo *postgres.LocalScoringRepo,
	toxicRepo *postgres.ToxicRepo,
) *BreakdownService {
	return &BreakdownService{
		finalRepo:  finalRepo,
		globalRepo: globalRepo,
		localRepo:  localRepo,
		toxicRepo:  toxicRepo,
	}
}

// SetISMSPAddender는 ISMS-P 미준수 가산 제공자를 주입한다(server 부팅 시 grcSvc 주입).
// 주입되면 GetBreakdown 응답에 ISMS-P 가산 섹션을 포함하고 formula에 가산을 표기한다.
func (s *BreakdownService) SetISMSPAddender(a breakdownISMSPAddender) {
	s.ismsp = a
}

func (s *BreakdownService) GetBreakdown(ctx context.Context, clusterName, podUID string) (*scoring.ScoreBreakdown, error) {
	// 1. Final (숫자 분해)
	f, err := s.finalRepo.GetByPodUID(ctx, clusterName, podUID)
	if err != nil {
		return nil, fmt.Errorf("get final: %w", err)
	}
	if f == nil {
		return nil, nil
	}

	// ── ISMS-P 미준수 가산 내역 ──
	// FinalScore(=f.FinalScore)에는 가산이 이미 포함되어 저장돼 있다. 여기서는 그 내역을
	// 분해해 표기하기 위해 동일 입력(company_id="" + cluster + 원본 pod_name)으로 재계산한다.
	// (final compute 경로와 같은 인자 — final_scores.pod_name은 정규화 전 원본 키)
	var ismspSection *scoring.BreakdownISMSP
	var ismspAddend float64
	if s.ismsp != nil {
		if bdISMSP := s.ismsp.ComputePodISMSPAddend(ctx, "", clusterName, f.PodNamespace, f.PodName); bdISMSP != nil && bdISMSP.Addend > 0 {
			ismspAddend = bdISMSP.Addend
			ismspSection = buildISMSPSection(bdISMSP)
		}
	}

	// cap 전 원값 재계산 — Global/Exposure/Toxic 기반 base 점수(가산 전).
	// 공식: (Global × 0.7 + Exposure × 0.3) × Toxic  (Attack Path는 Risk Score에서 제외)
	rawBase := (f.GlobalImageScore*0.7 + f.LocalScore*0.3) * f.ToxicMultiplier
	baseScore := rawBase
	if baseScore > 100 {
		baseScore = 100
	}
	// formula는 base → (있으면) ISMS-P 가산 → 최종(f.FinalScore) 순서로 투명하게 표기한다.
	// 가산이 없으면 base = f.FinalScore라 종전과 동일한 한 줄이 된다.
	baseExpr := fmt.Sprintf("(%.2f × 0.7 + %.2f × 0.3) × %.2f", f.GlobalImageScore, f.LocalScore, f.ToxicMultiplier)
	var formula string
	switch {
	case rawBase > 100 && ismspAddend > 0:
		formula = fmt.Sprintf("%s = %.2f → 상한 적용 %.2f  +  ISMS-P 미준수 %.2f  =  %.2f",
			baseExpr, rawBase, baseScore, ismspAddend, f.FinalScore)
	case rawBase > 100:
		formula = fmt.Sprintf("%s = %.2f → 상한 적용 %.2f", baseExpr, rawBase, f.FinalScore)
	case ismspAddend > 0:
		formula = fmt.Sprintf("%s = %.2f  +  ISMS-P 미준수 %.2f  =  %.2f",
			baseExpr, baseScore, ismspAddend, f.FinalScore)
	default:
		formula = fmt.Sprintf("%s = %.2f", baseExpr, f.FinalScore)
	}

	// 원점수(clamp 전, ISMS-P 가산 포함)와 상한 여부 — FE ⓘ 툴팁용.
	rawFinal := rawBase + ismspAddend
	bd := &scoring.ScoreBreakdown{
		PodUID:        f.PodUID,
		PodName:       scoring.NormalizePodName(f.PodName),
		FinalScore:    f.FinalScore,
		RiskLevel:     f.RiskLevel,
		RiskLabel:     riskLabelKR(f.RiskLevel),
		RawFinalScore: rawFinal,
		Capped:        rawFinal > f.FinalScore+0.01,
		ISMSP:         ismspSection,
		Formula:       formula,
	}

	// 2. Global section
	bd.Global = scoring.BreakdownSection{
		Label:          "Global Score",
		RawScore:       f.GlobalImageScore,
		Weight:         0.7,
		Contribution:   f.GlobalContribution,
		Description:    descGlobal,
		Interpretation: interpretGlobal(f.GlobalImageScore, f.UsedTopCVE),
	}
	if f.UsedTopCVE != "" {
		if cve, err := s.globalRepo.GetByCVEID(ctx, f.UsedTopCVE); err == nil && cve != nil {
			// CVSS 결측 보완 출처를 해석 문구에도 반영(API 소비자용). 배지는 FE가 구조화 필드로 렌더.
			cvssInterp := interpretCVSS(cve.CVSSScore)
			switch cve.ImputationSource {
			case "ai":
				cvssInterp += fmt.Sprintf(" · NVD 결측 → AI 추정(신뢰도 %.0f%%), 점수엔 신뢰도만큼만 반영", cve.ImputationConfidence*100)
			case "osv":
				cvssInterp += " · NVD 결측 → OSV 출처값 사용"
			}
			bd.Global.Factors = []scoring.BreakdownFactor{
				{
					Name:                 "CVSS",
					Value:                fmt.Sprintf("%.1f (%s)", cve.CVSSScore, cve.CVSSSeverity),
					Description:          descCVSS,
					Interpretation:       cvssInterp,
					Imputed:              cve.CVSSImputed,
					ImputationSource:     cve.ImputationSource,
					ImputationConfidence: cve.ImputationConfidence,
				},
				{
					Name:           "EPSS",
					Value:          fmt.Sprintf("%.1f%%", cve.EPSSScore*100),
					Description:    descEPSS,
					Interpretation: interpretEPSS(cve.EPSSScore),
				},
				{
					Name:           "KEV",
					Value:          kevValue(cve.InKEV),
					Description:    descKEV,
					Interpretation: interpretKEV(cve.InKEV),
				},
				{
					Name:           "ExploitDB",
					Value:          exploitDBValue(cve.InExploitDB),
					Description:    descExploitDB,
					Interpretation: interpretExploitDB(cve.InExploitDB),
				},
				{
					Name:           "SSVC",
					Value:          cve.SSVCExploitation,
					Description:    descSSVC,
					Interpretation: interpretSSVC(cve.SSVCExploitation),
				},
			}
		}
	}

	// 3. Exposure section (구 Local — attack_path 제외, 인터넷 노출만)
	bd.Local = scoring.BreakdownSection{
		Label:        "Exposure Score",
		RawScore:     f.LocalScore, // 0/100 (노출 여부)
		Weight:       0.3,
		Contribution: f.LocalContribution,
		Description:  descLocal,
	}
	if loc, err := s.localRepo.GetByPodUID(ctx, clusterName, podUID); err == nil && loc != nil {
		bd.Local.Interpretation = interpretLocal(loc.LocalScore, loc.Exposed, loc.AttackPathLevel)
		bd.Local.Factors = []scoring.BreakdownFactor{
			{
				Name:           "Exposure",
				Value:          exposureValue(loc.Exposed, loc.ExposureScoreRaw),
				Description:    descExposure,
				Interpretation: interpretExposure(loc.Exposed),
			},
			{
				Name:           "Attack Path",
				Value:          fmt.Sprintf("%d (%s)", loc.AttackPathScoreRaw, loc.AttackPathLevel),
				Description:    descAttackPath,
				Interpretation: interpretAttackPath(loc.AttackPathLevel, loc.AttackPathScoreRaw),
			},
		}
	} else {
		bd.Local.Interpretation = interpretLocal(f.LocalScore, false, "Low")
	}

	// 4. Toxic section
	bd.Toxic = scoring.BreakdownSection{
		Label:       "Toxic Multiplier",
		RawScore:    f.ToxicMultiplier,
		Description: descToxic,
	}
	// 룰 카탈로그 rule_id → 설명(왜 위험한지). 매칭된 룰마다 factor 로 붙여 FE 가 카드로 렌더한다.
	toxicDesc := make(map[string]string, len(scoring.AllToxicRules))
	for _, cr := range scoring.AllToxicRules {
		toxicDesc[cr.RuleID] = cr.Description
	}
	var ruleNames []string
	if tox, err := s.toxicRepo.GetByPodUID(ctx, clusterName, podUID); err == nil && tox != nil {
		for _, r := range tox.MatchedRules {
			ruleNames = append(ruleNames, r.Name)
			desc := toxicDesc[r.RuleID]
			if desc == "" {
				desc = r.Reason
			}
			bd.Toxic.Factors = append(bd.Toxic.Factors, scoring.BreakdownFactor{
				Name:           r.Name,
				Value:          fmt.Sprintf("×%.2f", r.Multiplier),
				Description:    desc,
				Interpretation: r.Reason,
			})
		}
	}
	bd.Toxic.Interpretation = interpretToxic(f.ToxicMultiplier, ruleNames)

	return bd, nil
}

// buildISMSPSection은 service의 ISMSPRiskBreakdown을 표시용 scoring.BreakdownISMSP로 변환한다.
func buildISMSPSection(b *ISMSPRiskBreakdown) *scoring.BreakdownISMSP {
	rules := make([]scoring.BreakdownISMSPRule, 0, len(b.Rules))
	for _, r := range b.Rules {
		rules = append(rules, scoring.BreakdownISMSPRule{
			RuleID:    r.RuleID,
			Name:      r.Name,
			ItemID:    r.ItemID,
			ItemName:  r.ItemName,
			Severity:  r.Severity,
			Weight:    r.Weight,
			Inherited: r.Inherited,
		})
	}
	total := b.CountHigh + b.CountMedium + b.CountLow
	return &scoring.BreakdownISMSP{
		Label:       "ISMS-P 미준수 가산",
		Addend:      b.Addend,
		CountHigh:   b.CountHigh,
		CountMedium: b.CountMedium,
		CountLow:    b.CountLow,
		Description: "ISMS-P 미준수(NOT_MET) 항목을 위험도에 가산합니다. severity 상 3 / 중 2 / 하 1점, " +
			"rule_id당 1회. 도구(Kubescape·Security Hub·Trivy·Kyverno) severity 보유 룰만 반영합니다.",
		Interpretation: fmt.Sprintf("미준수 %d건(상 %d·중 %d·하 %d) → 위험도 +%.2f점",
			total, b.CountHigh, b.CountMedium, b.CountLow, b.Addend),
		Rules: rules,
	}
}

func kevValue(in bool) string {
	if in {
		return "등재됨"
	}
	return "미등재"
}

func exploitDBValue(in bool) string {
	if in {
		return "공개 PoC 있음"
	}
	return "없음"
}

func exposureValue(exposed bool, raw int) string {
	if exposed {
		return fmt.Sprintf("%d (노출됨)", raw)
	}
	return fmt.Sprintf("%d (노출 안 됨)", raw)
}
