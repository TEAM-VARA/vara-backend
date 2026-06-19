package postgres

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vara/backend/internal/domain/scoring"
)

// round4는 REAL(float32) 저장으로 생기는 0.6999999 같은 표시 오차를 정리합니다.
func round4(f float64) float64 { return math.Round(f*10000) / 10000 }

// ScoringWeightsRepo는 Risk Scoring 전역 가중치(scoring_weights 단일행)를 읽고 씁니다.
type ScoringWeightsRepo struct {
	pool *pgxpool.Pool
}

func NewScoringWeightsRepo(pool *pgxpool.Pool) *ScoringWeightsRepo {
	return &ScoringWeightsRepo{pool: pool}
}

// Get은 현재 가중치를 반환합니다. 행이 없으면 DefaultWeights.
func (r *ScoringWeightsRepo) Get(ctx context.Context) (scoring.Weights, error) {
	const q = `
		SELECT final_weight_global, final_weight_exposure,
		       global_weight_cvss, global_weight_epss, global_weight_ssvc,
		       toxic_critical, toxic_high, toxic_medium
		FROM scoring_weights WHERE id = 1`
	var w scoring.Weights
	err := r.pool.QueryRow(ctx, q).Scan(
		&w.FinalGlobal, &w.FinalExposure,
		&w.GlobalCVSS, &w.GlobalEPSS, &w.GlobalSSVC,
		&w.ToxicCritical, &w.ToxicHigh, &w.ToxicMedium,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return scoring.DefaultWeights(), nil
	}
	if err != nil {
		return scoring.DefaultWeights(), fmt.Errorf("get scoring_weights: %w", err)
	}
	// REAL(float32) 저장 오차 정리 (0.6999999 → 0.7)
	w.FinalGlobal, w.FinalExposure = round4(w.FinalGlobal), round4(w.FinalExposure)
	w.GlobalCVSS, w.GlobalEPSS, w.GlobalSSVC = round4(w.GlobalCVSS), round4(w.GlobalEPSS), round4(w.GlobalSSVC)
	w.ToxicCritical, w.ToxicHigh, w.ToxicMedium = round4(w.ToxicCritical), round4(w.ToxicHigh), round4(w.ToxicMedium)
	return w, nil
}

// Upsert는 가중치를 저장합니다 (단일행, updated_at 갱신).
func (r *ScoringWeightsRepo) Upsert(ctx context.Context, w scoring.Weights) error {
	const q = `
		INSERT INTO scoring_weights (
			id, final_weight_global, final_weight_exposure,
			global_weight_cvss, global_weight_epss, global_weight_ssvc,
			toxic_critical, toxic_high, toxic_medium, updated_at
		) VALUES (1, $1,$2,$3,$4,$5,$6,$7,$8, NOW())
		ON CONFLICT (id) DO UPDATE SET
			final_weight_global   = EXCLUDED.final_weight_global,
			final_weight_exposure = EXCLUDED.final_weight_exposure,
			global_weight_cvss    = EXCLUDED.global_weight_cvss,
			global_weight_epss    = EXCLUDED.global_weight_epss,
			global_weight_ssvc    = EXCLUDED.global_weight_ssvc,
			toxic_critical        = EXCLUDED.toxic_critical,
			toxic_high            = EXCLUDED.toxic_high,
			toxic_medium          = EXCLUDED.toxic_medium,
			updated_at            = NOW()`
	_, err := r.pool.Exec(ctx, q,
		w.FinalGlobal, w.FinalExposure,
		w.GlobalCVSS, w.GlobalEPSS, w.GlobalSSVC,
		w.ToxicCritical, w.ToxicHigh, w.ToxicMedium,
	)
	if err != nil {
		return fmt.Errorf("upsert scoring_weights: %w", err)
	}
	return nil
}
