package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vara/backend/internal/domain/scoring"
)

// CVEEnrichmentRepo는 CVE 단위 narrative enrichment(설계서 §4)를 cve_enrichment 테이블에
// JSONB로 저장/조회합니다. cve_global_scores(점수)와 분리된 독립 캐시(독립 TTL/무효화).
//
// 캐시 정책:
//   - GetFresh: expires_at > NOW() 인 것만 반환 (만료 시 nil → 호출자가 재추출)
//   - Get     : 만료 무시하고 반환 (디버깅/폴백용)
//   - Upsert  : expires_at = NOW() + EnrichmentTTL 재설정
type CVEEnrichmentRepo struct {
	pool *pgxpool.Pool
}

// NewCVEEnrichmentRepo는 CVEEnrichmentRepo를 생성합니다.
func NewCVEEnrichmentRepo(pool *pgxpool.Pool) *CVEEnrichmentRepo {
	return &CVEEnrichmentRepo{pool: pool}
}

// Upsert는 enrichment object를 저장합니다. expires_at은 NOW() + EnrichmentTTL.
// sourceHash는 advisory 본문+NVD desc 해시(출처 변경 감지용).
func (r *CVEEnrichmentRepo) Upsert(ctx context.Context, e *scoring.CVEEnrichment, sourceHash string) error {
	if e == nil || e.CVEID == "" {
		return fmt.Errorf("cve_enrichment: nil or empty cve_id")
	}
	payload, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal enrichment %s: %w", e.CVEID, err)
	}
	expiresAt := time.Now().Add(scoring.EnrichmentTTL)

	const q = `
		INSERT INTO cve_enrichment (
			cve_id, enrichment, extractor_version, source_hash, computed_at, expires_at
		) VALUES ($1, $2, $3, $4, NOW(), $5)
		ON CONFLICT (cve_id) DO UPDATE SET
			enrichment        = EXCLUDED.enrichment,
			extractor_version = EXCLUDED.extractor_version,
			source_hash       = EXCLUDED.source_hash,
			computed_at       = NOW(),
			expires_at        = EXCLUDED.expires_at
	`
	if _, err := r.pool.Exec(ctx, q, e.CVEID, payload, scoring.EnrichmentExtractorVersion, sourceHash, expiresAt); err != nil {
		return fmt.Errorf("upsert cve_enrichment %s: %w", e.CVEID, err)
	}
	return nil
}

// GetFresh는 만료되지 않았고 현재 extractor_version과 일치하는 enrichment만 반환합니다.
// 없거나 만료/버전 불일치면 nil(에러 아님) → 호출자가 재추출.
func (r *CVEEnrichmentRepo) GetFresh(ctx context.Context, cveID string) (*scoring.CVEEnrichment, error) {
	const q = `
		SELECT enrichment
		FROM cve_enrichment
		WHERE cve_id = $1 AND expires_at > NOW() AND extractor_version = $2
	`
	var payload []byte
	err := r.pool.QueryRow(ctx, q, cveID, scoring.EnrichmentExtractorVersion).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get fresh enrichment %s: %w", cveID, err)
	}
	var e scoring.CVEEnrichment
	if err := json.Unmarshal(payload, &e); err != nil {
		return nil, fmt.Errorf("unmarshal enrichment %s: %w", cveID, err)
	}
	return &e, nil
}
