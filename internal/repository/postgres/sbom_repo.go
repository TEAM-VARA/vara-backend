package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SBOMRepo는 sboms 테이블에 대한 데이터 액세스를 담당합니다.
//
// sboms 테이블 스키마:
//   id            BIGSERIAL PRIMARY KEY
//   image         TEXT NOT NULL
//   image_digest  TEXT NOT NULL
//   raw_data      JSONB                  -- Trivy 자체 JSON 통째로 저장
//   created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
type SBOMRepo struct {
	pool *pgxpool.Pool
}

// NewSBOMRepo는 SBOMRepo를 생성합니다.
func NewSBOMRepo(pool *pgxpool.Pool) *SBOMRepo {
	return &SBOMRepo{pool: pool}
}

// SBOM은 sboms 테이블 한 행을 표현합니다.
type SBOM struct {
	ID          int64
	Image       string
	ImageDigest string
	RawData     json.RawMessage
	CreatedAt   time.Time
}

// Upsert는 SBOM을 저장합니다.
// 같은 image_digest로 이미 존재하면 raw_data를 갱신합니다.
func (r *SBOMRepo) Upsert(ctx context.Context, image, digest string, rawData json.RawMessage) error {
	if image == "" || digest == "" {
		return errors.New("image and digest are required")
	}
	if !json.Valid(rawData) {
		return errors.New("rawData is not valid JSON")
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 기존 row 존재 여부 체크
	var existingID int64
	err = tx.QueryRow(ctx,
		`SELECT id FROM sboms WHERE image_digest = $1 LIMIT 1`,
		digest,
	).Scan(&existingID)

	if errors.Is(err, pgx.ErrNoRows) {
		// INSERT
		_, err = tx.Exec(ctx,
			`INSERT INTO sboms (image, image_digest, raw_data)
			 VALUES ($1, $2, $3)`,
			image, digest, []byte(rawData),
		)
		if err != nil {
			return fmt.Errorf("insert sbom: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("check existing sbom: %w", err)
	} else {
		// UPDATE
		_, err = tx.Exec(ctx,
			`UPDATE sboms SET image = $1, raw_data = $2 WHERE id = $3`,
			image, []byte(rawData), existingID,
		)
		if err != nil {
			return fmt.Errorf("update sbom: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// ExistsByDigest는 해당 digest의 SBOM이 존재하는지 확인합니다.
func (r *SBOMRepo) ExistsByDigest(ctx context.Context, digest string) (bool, error) {
	if digest == "" {
		return false, nil
	}
	var n int
	err := r.pool.QueryRow(ctx,
		`SELECT 1 FROM sboms WHERE image_digest = $1 LIMIT 1`,
		digest,
	).Scan(&n)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("exists by digest: %w", err)
	}
	return true, nil
}

// ListDistinctDigests는 sboms에 등록된 중복 없는 image_digest 전체를 반환합니다.
// 글로벌 점수 자동 갱신(Phase 0)에서 만료 캐시 재계산 대상을 산출하는 데 사용합니다.
func (r *SBOMRepo) ListDistinctDigests(ctx context.Context) ([]string, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT DISTINCT image_digest FROM sboms
		 WHERE image_digest IS NOT NULL AND image_digest != ''`,
	)
	if err != nil {
		return nil, fmt.Errorf("list distinct digests: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, fmt.Errorf("scan digest: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// GetByDigest는 digest로 SBOM을 조회합니다.
// 없으면 (nil, nil) 반환.
func (r *SBOMRepo) GetByDigest(ctx context.Context, digest string) (*SBOM, error) {
	if digest == "" {
		return nil, errors.New("digest is required")
	}

	var s SBOM
	var raw []byte
	err := r.pool.QueryRow(ctx,
		`SELECT id, image, image_digest, raw_data, created_at
		 FROM sboms WHERE image_digest = $1
		 ORDER BY created_at DESC LIMIT 1`,
		digest,
	).Scan(&s.ID, &s.Image, &s.ImageDigest, &raw, &s.CreatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get sbom by digest: %w", err)
	}
	s.RawData = json.RawMessage(raw)
	return &s, nil
}

// ListRecent는 최근 SBOM 목록을 반환합니다 (디버깅/관리용).
func (r *SBOMRepo) ListRecent(ctx context.Context, limit int) ([]SBOM, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := r.pool.Query(ctx,
		`SELECT id, image, image_digest, created_at
		 FROM sboms ORDER BY created_at DESC LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list recent sboms: %w", err)
	}
	defer rows.Close()

	var out []SBOM
	for rows.Next() {
		var s SBOM
		if err := rows.Scan(&s.ID, &s.Image, &s.ImageDigest, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan sbom: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
