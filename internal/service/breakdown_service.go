package service

import (
	"context"
	"fmt"

	"github.com/vara/backend/internal/domain/scoring"
	"github.com/vara/backend/internal/repository/postgres"
)

// BreakdownService는 Final Score의 구성 근거를 조립합니다.
type BreakdownService struct {
	finalRepo  *postgres.FinalScoringRepo
	globalRepo *postgres.GlobalScoringRepo
	localRepo  *postgres.LocalScoringRepo
	toxicRepo  *postgres.ToxicRepo
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

func (s *BreakdownService) GetBreakdown(ctx context.Context, clusterName, podUID string) (*scoring.ScoreBreakdown, error) {
	// 1. Final (숫자 분해)
	f, err := s.finalRepo.GetByPodUID(ctx, clusterName, podUID)
	if err != nil {
		return nil, fmt.Errorf("get final: %w", err)
	}
	if f == nil {
		return nil, nil
	}

	// cap 전 원값 재계산 — 상한(100)이 적용된 경우 formula에 투명하게 표기
	// 공식: (Global × 0.7 + Exposure × 0.3) × Toxic  (Attack Path는 Risk Score에서 제외)
	rawFinal := (f.GlobalImageScore*0.7 + f.LocalScore*0.3) * f.ToxicMultiplier
	formula := fmt.Sprintf("(%.2f × 0.7 + %.2f × 0.3) × %.2f = %.2f",
		f.GlobalImageScore, f.LocalScore, f.ToxicMultiplier, f.FinalScore)
	if rawFinal > 100 {
		formula = fmt.Sprintf("(%.2f × 0.7 + %.2f × 0.3) × %.2f = %.2f → 상한 적용 %.2f",
			f.GlobalImageScore, f.LocalScore, f.ToxicMultiplier, rawFinal, f.FinalScore)
	}

	bd := &scoring.ScoreBreakdown{
		PodUID:     f.PodUID,
		PodName:    scoring.NormalizePodName(f.PodName),
		FinalScore: f.FinalScore,
		RiskLevel:  f.RiskLevel,
		RiskLabel:  riskLabelKR(f.RiskLevel),
		Formula:    formula,
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
			bd.Global.Factors = []scoring.BreakdownFactor{
				{
					Name:           "CVSS",
					Value:          fmt.Sprintf("%.1f (%s)", cve.CVSSScore, cve.CVSSSeverity),
					Description:    descCVSS,
					Interpretation: interpretCVSS(cve.CVSSScore),
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
	var ruleNames []string
	if tox, err := s.toxicRepo.GetByPodUID(ctx, clusterName, podUID); err == nil && tox != nil {
		for _, r := range tox.MatchedRules {
			ruleNames = append(ruleNames, r.Name)
		}
	}
	bd.Toxic.Interpretation = interpretToxic(f.ToxicMultiplier, ruleNames)

	return bd, nil
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
