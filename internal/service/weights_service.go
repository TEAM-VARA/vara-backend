package service

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/vara/backend/internal/domain/scoring"
	"github.com/vara/backend/internal/platform/vlm"
	"github.com/vara/backend/internal/repository/postgres"
)

// WeightsService는 Risk Scoring 전역 가중치 조회/갱신 + 변경 시 재계산 + AI 추천을 담당합니다.
type WeightsService struct {
	repo        *postgres.ScoringWeightsRepo
	finalSvc    *FinalScoringService
	toxicSvc    *ToxicService
	vlm         *vlm.Client // AI 가중치 추천(없으면 추천 비활성)
	globalRepo  *postgres.GlobalScoringRepo // Global 가중치 변경 시 cve_global_scores 제자리 재계산
	imgCacheSvc *ImageGlobalCacheService    // 이미지 Global 캐시 재계산
	sbomRepo    *postgres.SBOMRepo          // 재계산 대상 이미지 digest 목록
	cluster     string
}

func NewWeightsService(repo *postgres.ScoringWeightsRepo, finalSvc *FinalScoringService, toxicSvc *ToxicService, vlmClient *vlm.Client, globalRepo *postgres.GlobalScoringRepo, imgCacheSvc *ImageGlobalCacheService, sbomRepo *postgres.SBOMRepo, cluster string) *WeightsService {
	return &WeightsService{repo: repo, finalSvc: finalSvc, toxicSvc: toxicSvc, vlm: vlmClient, globalRepo: globalRepo, imgCacheSvc: imgCacheSvc, sbomRepo: sbomRepo, cluster: cluster}
}

// Get은 현재 가중치를 반환합니다.
func (s *WeightsService) Get(ctx context.Context) (scoring.Weights, error) {
	return s.repo.Get(ctx)
}

// LoadIntoRuntime은 DB 가중치를 전역(CurrentWeights)에 적용합니다. 서버 기동 시 호출.
func (s *WeightsService) LoadIntoRuntime(ctx context.Context) error {
	w, err := s.repo.Get(ctx)
	if err != nil {
		return err
	}
	scoring.SetWeights(w)
	return nil
}

const weightSumTolerance = 0.001

func validateWeights(w scoring.Weights) error {
	if w.FinalGlobal < 0 || w.FinalExposure < 0 ||
		w.GlobalCVSS < 0 || w.GlobalEPSS < 0 || w.GlobalSSVC < 0 {
		return fmt.Errorf("가중치는 음수일 수 없습니다")
	}
	if fs := w.FinalGlobal + w.FinalExposure; math.Abs(fs-1.0) > weightSumTolerance {
		return fmt.Errorf("final 가중치 합이 1.0이어야 합니다 (현재 global+exposure=%.3f)", fs)
	}
	if gs := w.GlobalCVSS + w.GlobalEPSS + w.GlobalSSVC; math.Abs(gs-1.0) > weightSumTolerance {
		return fmt.Errorf("global 가중치 합이 1.0이어야 합니다 (현재 cvss+epss+ssvc=%.3f)", gs)
	}
	if w.ToxicCritical < 1.0 || w.ToxicHigh < 1.0 || w.ToxicMedium < 1.0 {
		return fmt.Errorf("toxic 배수는 1.0 이상이어야 합니다")
	}
	return nil
}

// WeightsUpdateResult는 가중치 갱신 + 재계산 요약입니다.
type WeightsUpdateResult struct {
	Weights         scoring.Weights `json:"weights"`
	ToxicRecomputed int             `json:"toxic_matched"`
	FinalRecomputed int             `json:"final_recomputed"`
	Note            string          `json:"note,omitempty"`
}

// Update는 가중치를 검증·저장·전역적용하고 toxic+final을 즉시 재계산합니다.
//
// Final·Toxic 가중치 변경은 이 재계산으로 즉시 반영됩니다.
// Global 가중치 변경은 캐시된 image_global_scores를 안 건드리므로, 이미지 Global 재계산
// (POST /scoring/global/images/{digest}?force=true 또는 스캔)이 있어야 반영됩니다 → Note로 안내.
func (s *WeightsService) Update(ctx context.Context, w scoring.Weights) (*WeightsUpdateResult, error) {
	if err := validateWeights(w); err != nil {
		return nil, err
	}
	old, _ := s.repo.Get(ctx) // 변경 전 가중치(Global 변경 여부 판단용)
	if err := s.repo.Upsert(ctx, w); err != nil {
		return nil, err
	}
	scoring.SetWeights(w)

	res := &WeightsUpdateResult{Weights: w}

	// Global 가중치(CVSS/EPSS/SSVC)가 바뀐 경우에만 cve/image Global을 제자리 재계산.
	// raw 신호가 이미 저장돼 있어 외부 API 호출 없이 즉시 반영된다.
	globalChanged := old.GlobalCVSS != w.GlobalCVSS || old.GlobalEPSS != w.GlobalEPSS || old.GlobalSSVC != w.GlobalSSVC
	if globalChanged && s.globalRepo != nil {
		if _, err := s.globalRepo.ReweightAll(ctx, w); err != nil {
			fmt.Printf("warn: weights update — cve global reweight failed: %v\n", err)
		}
		// image_global_scores는 Go 루프(이미지별 RecomputeAndStore→ComputeImage) 대신
		// 단일 bulk SQL로 제자리 집계 재계산한다(수만 번 DB 읽기 → 타임아웃 제거).
		if _, err := s.globalRepo.ReweightAllImages(ctx); err != nil {
			fmt.Printf("warn: weights update — image global bulk reweight failed: %v\n", err)
		}
	}

	// Toxic 재계산 (새 배수 반영)
	if s.toxicSvc != nil {
		if tr, err := s.toxicSvc.ComputeForCluster(ctx, s.cluster); err != nil {
			fmt.Printf("warn: weights update — toxic recompute failed: %v\n", err)
		} else if tr != nil {
			res.ToxicRecomputed = tr.MatchedTotal
		}
	}
	// Final 재계산 (새 final 가중치 + 갱신된 toxic 반영)
	if s.finalSvc != nil {
		if fr, err := s.finalSvc.ComputeForCluster(ctx, s.cluster); err != nil {
			fmt.Printf("warn: weights update — final recompute failed: %v\n", err)
		} else if fr != nil {
			res.FinalRecomputed = fr.Computed
		}
	}

	res.Note = "Final·Toxic 가중치는 즉시 반영되었습니다. Global 가중치 변경 시 cve/image Global도 즉시 재계산됩니다."
	return res, nil
}

// ─────────────────────────────────────────────
// AI 추천 가중치 (추천만, 자동 적용 X)
// ─────────────────────────────────────────────

const weightsRecommendSystemPrompt = `너는 컨테이너 보안 플랫폼(VARA)의 Risk Scoring 가중치 튜너다.
점수 모델은 고정이고 아래 8개 가중치 값만 조정해 추천한다.

[Final] Final = (Global × final_weight_global + Local × final_weight_exposure) × Toxic
- final_weight_global: CVE 자체의 본질적 위험 비중
- final_weight_exposure: 배포 환경(인터넷 노출 + 공격경로) 비중
- 제약: 두 값의 합 = 1.0

[Global] Global = (CVSS × global_weight_cvss + EPSS × global_weight_epss + SSVC × global_weight_ssvc) × 100
- global_weight_cvss: 표준 심각도(CVSS)
- global_weight_epss: 악용 확률 예측(EPSS)
- global_weight_ssvc: 실제 악용 관측(KEV/PoC)
- 제약: 세 값의 합 = 1.0

[Toxic] 위험 조합 매칭 시 곱하는 배수(각 1.0 이상, 보통 1.5/1.3/1.2 부근)
- toxic_critical, toxic_high, toxic_medium

규칙:
- 현재값 + 클러스터 통계 + (있으면) 운영자 우선순위를 함께 고려해 보수적으로 제안한다.
- 노출 파드 비중이 높으면 final_weight_exposure를, KEV가 많으면 global_weight_ssvc를 올리는 식으로 통계에 근거한다.
- 합 제약을 지키고 급격한 변화는 피한다.
반드시 아래 JSON만 출력(다른 텍스트 금지):
{"final_weight_global":0.0,"final_weight_exposure":0.0,"global_weight_cvss":0.0,"global_weight_epss":0.0,"global_weight_ssvc":0.0,"toxic_critical":1.0,"toxic_high":1.0,"toxic_medium":1.0,"confidence":0.0,"rationale":"한국어 근거 2~4문장"}`

// llmWeights는 LLM 응답 JSON 파싱용입니다.
type llmWeights struct {
	FinalGlobal   float64 `json:"final_weight_global"`
	FinalExposure float64 `json:"final_weight_exposure"`
	GlobalCVSS    float64 `json:"global_weight_cvss"`
	GlobalEPSS    float64 `json:"global_weight_epss"`
	GlobalSSVC    float64 `json:"global_weight_ssvc"`
	ToxicCritical float64 `json:"toxic_critical"`
	ToxicHigh     float64 `json:"toxic_high"`
	ToxicMedium   float64 `json:"toxic_medium"`
	Confidence    float64 `json:"confidence"`
	Rationale     string  `json:"rationale"`
}

// Recommend는 클러스터 통계 + (선택)운영자 설명을 근거로 AI가 추천 가중치를 생성합니다.
// 자동 적용하지 않고 추천값+근거만 반환합니다. LLM 미설정/실패 시 에러.
func (s *WeightsService) Recommend(ctx context.Context, profile string) (*scoring.WeightsRecommendation, error) {
	if s.vlm == nil || !s.vlm.Available() {
		return nil, fmt.Errorf("AI 추천 비활성: LLM(ANTHROPIC_API_KEY)이 설정되지 않았습니다")
	}

	current, err := s.repo.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("현재 가중치 조회 실패: %w", err)
	}
	posture, _ := s.repo.CollectPosture(ctx, s.cluster) // 부분 통계도 허용

	curJSON, _ := json.Marshal(current)
	postureJSON, _ := json.Marshal(posture)
	profile = strings.TrimSpace(profile)
	profileLine := "(운영자 입력 없음 — 통계만으로 추천)"
	if profile != "" {
		profileLine = profile
	}
	user := fmt.Sprintf("## 현재 가중치\n%s\n\n## 클러스터 통계\n%s\n\n## 운영자 우선순위\n%s\n\n위 정보를 바탕으로 추천 가중치를 JSON으로만 출력하라.",
		string(curJSON), string(postureJSON), profileLine)

	aiCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	raw, err := s.vlm.Complete(aiCtx, weightsRecommendSystemPrompt, user, 0.0)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("AI 호출 실패: %w", err)
	}

	// 응답에서 JSON 객체 추출 (rationale에 중괄호 없다고 가정, 첫 { ~ 마지막 })
	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start < 0 || end <= start {
		return nil, fmt.Errorf("AI 응답에서 JSON을 찾지 못했습니다")
	}
	var lw llmWeights
	if err := json.Unmarshal([]byte(raw[start:end+1]), &lw); err != nil {
		return nil, fmt.Errorf("AI 응답 JSON 파싱 실패: %w", err)
	}

	rec := scoring.Weights{
		FinalGlobal:   lw.FinalGlobal,
		FinalExposure: lw.FinalExposure,
		GlobalCVSS:    lw.GlobalCVSS,
		GlobalEPSS:    lw.GlobalEPSS,
		GlobalSSVC:    lw.GlobalSSVC,
		ToxicCritical: lw.ToxicCritical,
		ToxicHigh:     lw.ToxicHigh,
		ToxicMedium:   lw.ToxicMedium,
	}
	normalizeWeights(&rec)
	if err := validateWeights(rec); err != nil {
		return nil, fmt.Errorf("AI 추천값이 제약을 만족하지 못했습니다: %w", err)
	}

	conf := lw.Confidence
	if conf < 0 {
		conf = 0
	} else if conf > 1 {
		conf = 1
	}

	return &scoring.WeightsRecommendation{
		Recommended: rec,
		Current:     current,
		Rationale:   strings.TrimSpace(lw.Rationale),
		Confidence:  conf,
		Posture:     posture,
		Profile:     profile,
		Note:        "추천값입니다. 적용하려면 PUT /api/v1/scoring/weights로 전송하세요. Global 가중치 변경은 이미지 Global 재계산 후 반영됩니다.",
	}, nil
}

// normalizeWeights는 합 제약(Final=1.0, Global=1.0)으로 정규화하고 toxic을 1.0 이상으로 클램프합니다.
// LLM이 약간 어긋난 값을 줘도 validateWeights를 통과하도록 보정합니다.
func normalizeWeights(w *scoring.Weights) {
	if fs := w.FinalGlobal + w.FinalExposure; fs > 0 {
		w.FinalGlobal = round4(w.FinalGlobal / fs)
		w.FinalExposure = round4(1.0 - w.FinalGlobal)
	} else {
		w.FinalGlobal, w.FinalExposure = 0.7, 0.3
	}
	if gs := w.GlobalCVSS + w.GlobalEPSS + w.GlobalSSVC; gs > 0 {
		w.GlobalCVSS = round4(w.GlobalCVSS / gs)
		w.GlobalEPSS = round4(w.GlobalEPSS / gs)
		w.GlobalSSVC = round4(1.0 - w.GlobalCVSS - w.GlobalEPSS)
	} else {
		w.GlobalCVSS, w.GlobalEPSS, w.GlobalSSVC = 0.4, 0.3, 0.3
	}
	if w.ToxicCritical < 1.0 {
		w.ToxicCritical = 1.0
	}
	if w.ToxicHigh < 1.0 {
		w.ToxicHigh = 1.0
	}
	if w.ToxicMedium < 1.0 {
		w.ToxicMedium = 1.0
	}
}

// round4는 표시 오차 정리를 위한 반올림입니다(postgres 패키지와 동일 목적).
func round4(f float64) float64 { return math.Round(f*10000) / 10000 }
