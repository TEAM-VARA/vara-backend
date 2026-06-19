package service

import (
	"context"
	"fmt"
	"math"

	"github.com/vara/backend/internal/domain/scoring"
	"github.com/vara/backend/internal/repository/postgres"
)

// WeightsService는 Risk Scoring 전역 가중치 조회/갱신 + 변경 시 재계산을 담당합니다.
type WeightsService struct {
	repo     *postgres.ScoringWeightsRepo
	finalSvc *FinalScoringService
	toxicSvc *ToxicService
	cluster  string
}

func NewWeightsService(repo *postgres.ScoringWeightsRepo, finalSvc *FinalScoringService, toxicSvc *ToxicService, cluster string) *WeightsService {
	return &WeightsService{repo: repo, finalSvc: finalSvc, toxicSvc: toxicSvc, cluster: cluster}
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
	if err := s.repo.Upsert(ctx, w); err != nil {
		return nil, err
	}
	scoring.SetWeights(w)

	res := &WeightsUpdateResult{Weights: w}

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

	res.Note = "Final·Toxic 가중치는 즉시 반영되었습니다. Global 가중치 변경은 이미지 Global 재계산(force 또는 스캔) 후 반영됩니다."
	return res, nil
}
