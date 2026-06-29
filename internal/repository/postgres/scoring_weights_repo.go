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
		       toxic_critical, toxic_high, toxic_medium,
		       cut_emergency, cut_warning, cut_caution
		FROM scoring_weights WHERE id = 1`
	var w scoring.Weights
	err := r.pool.QueryRow(ctx, q).Scan(
		&w.FinalGlobal, &w.FinalExposure,
		&w.GlobalCVSS, &w.GlobalEPSS, &w.GlobalSSVC,
		&w.ToxicCritical, &w.ToxicHigh, &w.ToxicMedium,
		&w.CutEmergency, &w.CutWarning, &w.CutCaution,
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
	w.CutEmergency, w.CutWarning, w.CutCaution = round4(w.CutEmergency), round4(w.CutWarning), round4(w.CutCaution)
	return w, nil
}

// CollectPosture는 AI 가중치 추천의 근거로 쓸 클러스터 현황을 집계합니다.
// final/exposure/toxic은 해당 클러스터 최신 snapshot 기준, CVE는 스코어링된 전체 기준.
// 일부 쿼리가 실패해도 가능한 만큼 채워 반환합니다(부분 통계도 추천엔 유용).
func (r *ScoringWeightsRepo) CollectPosture(ctx context.Context, cluster string) (scoring.ClusterPosture, error) {
	p := scoring.ClusterPosture{
		GradeCounts: map[string]int{},
		CVESeverity: map[string]int{},
	}

	// 1) final_scores 등급 분포 (최신 snapshot)
	rows, err := r.pool.Query(ctx, `
		SELECT risk_level, COUNT(*)
		FROM final_scores
		WHERE cluster_name = $1
		  AND snapshot_at = (SELECT MAX(snapshot_at) FROM final_scores WHERE cluster_name = $1)
		GROUP BY risk_level`, cluster)
	if err == nil {
		for rows.Next() {
			var level string
			var n int
			if err := rows.Scan(&level, &n); err == nil {
				p.GradeCounts[level] = n
				p.TotalPods += n
			}
		}
		rows.Close()
	}

	// 2) exposure_scores 노출 파드 수 (최신 snapshot)
	_ = r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FILTER (WHERE exposed)
		FROM exposure_scores
		WHERE cluster_name = $1
		  AND snapshot_at = (SELECT MAX(snapshot_at) FROM exposure_scores WHERE cluster_name = $1)`,
		cluster).Scan(&p.ExposedPods)

	// 3) toxic_results 매칭(배수>1) 파드 수 + 최대 배수 (최신 snapshot)
	_ = r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FILTER (WHERE multiplier > 1.0), COALESCE(MAX(multiplier), 1.0)
		FROM toxic_results
		WHERE cluster_name = $1
		  AND snapshot_at = (SELECT MAX(snapshot_at) FROM toxic_results WHERE cluster_name = $1)`,
		cluster).Scan(&p.ToxicMatchedPods, &p.MaxToxicMultiplier)

	// 4) cve_global_scores 전반 신호 (KEV 수 / 평균 EPSS / 총수)
	_ = r.pool.QueryRow(ctx, `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE in_kev), COALESCE(AVG(epss_score), 0)
		FROM cve_global_scores`).Scan(&p.ScoredCVEs, &p.KevCVEs, &p.AvgEPSS)

	// 5) cve_global_scores 심각도 분포
	srows, err := r.pool.Query(ctx, `
		SELECT COALESCE(NULLIF(cvss_severity, ''), 'UNKNOWN'), COUNT(*)
		FROM cve_global_scores GROUP BY 1`)
	if err == nil {
		for srows.Next() {
			var sev string
			var n int
			if err := srows.Scan(&sev, &n); err == nil {
				p.CVESeverity[sev] = n
			}
		}
		srows.Close()
	}

	return p, nil
}

// Upsert는 가중치를 저장합니다 (단일행, updated_at 갱신).
func (r *ScoringWeightsRepo) Upsert(ctx context.Context, w scoring.Weights) error {
	const q = `
		INSERT INTO scoring_weights (
			id, final_weight_global, final_weight_exposure,
			global_weight_cvss, global_weight_epss, global_weight_ssvc,
			toxic_critical, toxic_high, toxic_medium,
			cut_emergency, cut_warning, cut_caution, updated_at
		) VALUES (1, $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11, NOW())
		ON CONFLICT (id) DO UPDATE SET
			final_weight_global   = EXCLUDED.final_weight_global,
			final_weight_exposure = EXCLUDED.final_weight_exposure,
			global_weight_cvss    = EXCLUDED.global_weight_cvss,
			global_weight_epss    = EXCLUDED.global_weight_epss,
			global_weight_ssvc    = EXCLUDED.global_weight_ssvc,
			toxic_critical        = EXCLUDED.toxic_critical,
			toxic_high            = EXCLUDED.toxic_high,
			toxic_medium          = EXCLUDED.toxic_medium,
			cut_emergency         = EXCLUDED.cut_emergency,
			cut_warning           = EXCLUDED.cut_warning,
			cut_caution           = EXCLUDED.cut_caution,
			updated_at            = NOW()`
	_, err := r.pool.Exec(ctx, q,
		w.FinalGlobal, w.FinalExposure,
		w.GlobalCVSS, w.GlobalEPSS, w.GlobalSSVC,
		w.ToxicCritical, w.ToxicHigh, w.ToxicMedium,
		w.CutEmergency, w.CutWarning, w.CutCaution,
	)
	if err != nil {
		return fmt.Errorf("upsert scoring_weights: %w", err)
	}
	return nil
}
