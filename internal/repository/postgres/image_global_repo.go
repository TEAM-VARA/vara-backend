package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vara/backend/internal/domain/scoring"
)

// ImageGlobalRepo는 image_global_scores 테이블 전용 Repository입니다.
//
// 작업 B-1의 GlobalScoringRepo와는 별개로 운영하여 충돌을 회피합니다.
// (cve_global_scores는 GlobalScoringRepo가 담당)
type ImageGlobalRepo struct {
	pool *pgxpool.Pool
}

// NewImageGlobalRepo는 ImageGlobalRepo를 생성합니다.
func NewImageGlobalRepo(pool *pgxpool.Pool) *ImageGlobalRepo {
	return &ImageGlobalRepo{pool: pool}
}

// Upsert는 image_global_scores에 결과를 저장합니다.
// 같은 image_digest가 있으면 update.
func (r *ImageGlobalRepo) Upsert(ctx context.Context, rec scoring.ImageGlobalRecord) error {
	const q = `
		INSERT INTO image_global_scores (
			image_digest, image,
			cve_count, max_score, avg_score, top_cve,
			critical_count, high_count, medium_count, low_count,
			active_count, poc_count, none_count,
			computed_at, expires_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10,
			$11, $12, $13,
			$14, $15
		)
		ON CONFLICT (image_digest) DO UPDATE SET
			image          = EXCLUDED.image,
			cve_count      = EXCLUDED.cve_count,
			max_score      = EXCLUDED.max_score,
			avg_score      = EXCLUDED.avg_score,
			top_cve        = EXCLUDED.top_cve,
			critical_count = EXCLUDED.critical_count,
			high_count     = EXCLUDED.high_count,
			medium_count   = EXCLUDED.medium_count,
			low_count      = EXCLUDED.low_count,
			active_count   = EXCLUDED.active_count,
			poc_count      = EXCLUDED.poc_count,
			none_count     = EXCLUDED.none_count,
			computed_at    = EXCLUDED.computed_at,
			expires_at     = EXCLUDED.expires_at
	`

	_, err := r.pool.Exec(ctx, q,
		rec.ImageDigest, rec.Image,
		rec.CVECount, rec.MaxScore, rec.AvgScore, nilIfEmpty(rec.TopCVE),
		rec.CriticalCount, rec.HighCount, rec.MediumCount, rec.LowCount,
		rec.ActiveCount, rec.POCCount, rec.NoneCount,
		rec.ComputedAt, rec.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("upsert image_global_scores: %w", err)
	}
	return nil
}

// GetByDigest는 image_digest로 이미지 점수를 조회합니다.
//   - 없으면 (nil, nil)
//   - 캐시 만료 여부는 호출자가 결정 (expires_at 비교)
func (r *ImageGlobalRepo) GetByDigest(ctx context.Context, imageDigest string) (*scoring.ImageGlobalRecord, error) {
	var rec scoring.ImageGlobalRecord
	var topCVE *string

	err := r.pool.QueryRow(ctx,
		`SELECT 
			image_digest, image,
			cve_count, max_score, avg_score, top_cve,
			critical_count, high_count, medium_count, low_count,
			active_count, poc_count, none_count,
			computed_at, expires_at
		 FROM image_global_scores
		 WHERE image_digest = $1`,
		imageDigest,
	).Scan(
		&rec.ImageDigest, &rec.Image,
		&rec.CVECount, &rec.MaxScore, &rec.AvgScore, &topCVE,
		&rec.CriticalCount, &rec.HighCount, &rec.MediumCount, &rec.LowCount,
		&rec.ActiveCount, &rec.POCCount, &rec.NoneCount,
		&rec.ComputedAt, &rec.ExpiresAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get image_global by digest: %w", err)
	}

	if topCVE != nil {
		rec.TopCVE = *topCVE
	}
	rec.RiskLevel = scoring.ClassifyImageRiskLevel(rec.MaxScore)
	return &rec, nil
}

// IsFresh는 캐시가 유효한지(만료 안 됐는지) 판정합니다.
func (r *ImageGlobalRepo) IsFresh(rec *scoring.ImageGlobalRecord) bool {
	if rec == nil {
		return false
	}
	return time.Now().Before(rec.ExpiresAt)
}

// nilIfEmpty: 빈 문자열을 NULL로 변환.
func nilIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
