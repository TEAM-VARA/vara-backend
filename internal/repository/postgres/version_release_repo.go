package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vara/backend/internal/platform/depsdev"
)

// VersionReleaseRepo는 package_version_releases + depsdev_queries 테이블을 담당합니다.
//
// deps.dev에서 받은 패키지 버전별 릴리스 날짜를 저장/조회합니다.
type VersionReleaseRepo struct {
	pool *pgxpool.Pool
}

func NewVersionReleaseRepo(pool *pgxpool.Pool) *VersionReleaseRepo {
	return &VersionReleaseRepo{pool: pool}
}

// VersionReleaseTTL: deps.dev 결과 신선도 (릴리스 날짜는 잘 안 변하므로 길게).
const VersionReleaseTTL = 7 * 24 * time.Hour

// IsCached는 (system, name)이 최근 TTL 내에 조회됐는지 확인합니다.
func (r *VersionReleaseRepo) IsCached(ctx context.Context, system, name string) (bool, error) {
	var expiresAt time.Time
	err := r.pool.QueryRow(ctx,
		`SELECT expires_at FROM depsdev_queries WHERE system = $1 AND name = $2`,
		system, name,
	).Scan(&expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check depsdev cache: %w", err)
	}
	return time.Now().Before(expiresAt), nil
}

// UpsertVersions는 한 패키지의 버전 릴리스 목록을 일괄 저장하고 조회 캐시를 갱신합니다.
func (r *VersionReleaseRepo) UpsertVersions(ctx context.Context, system, name string, versions []depsdev.VersionRelease) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const q = `
		INSERT INTO package_version_releases (system, name, version, published_at, fetched_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (system, name, version) DO UPDATE SET
			published_at = EXCLUDED.published_at,
			fetched_at   = EXCLUDED.fetched_at
	`
	for _, v := range versions {
		if _, err := tx.Exec(ctx, q, system, name, v.Version, v.PublishedAt); err != nil {
			return fmt.Errorf("upsert version %s@%s: %w", name, v.Version, err)
		}
	}

	// 조회 캐시 갱신 (버전 0개여도 기록 → 재조회 방지)
	now := time.Now()
	if _, err := tx.Exec(ctx,
		`INSERT INTO depsdev_queries (system, name, queried_at, version_count, expires_at)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (system, name) DO UPDATE SET
		   queried_at = EXCLUDED.queried_at,
		   version_count = EXCLUDED.version_count,
		   expires_at = EXCLUDED.expires_at`,
		system, name, now, len(versions), now.Add(VersionReleaseTTL),
	); err != nil {
		return fmt.Errorf("record depsdev query: %w", err)
	}

	return tx.Commit(ctx)
}

// ListVersions는 한 패키지의 저장된 버전 릴리스 목록을 반환합니다 (published_at 오름차순).
func (r *VersionReleaseRepo) ListVersions(ctx context.Context, system, name string) ([]depsdev.VersionRelease, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT version, published_at
		 FROM package_version_releases
		 WHERE system = $1 AND name = $2
		 ORDER BY published_at ASC NULLS LAST`,
		system, name,
	)
	if err != nil {
		return nil, fmt.Errorf("list versions: %w", err)
	}
	defer rows.Close()

	var out []depsdev.VersionRelease
	for rows.Next() {
		var v depsdev.VersionRelease
		if err := rows.Scan(&v.Version, &v.PublishedAt); err != nil {
			return nil, fmt.Errorf("scan version: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// GetReleaseDate는 특정 버전의 릴리스 날짜를 반환합니다 (없으면 nil, nil).
func (r *VersionReleaseRepo) GetReleaseDate(ctx context.Context, system, name, version string) (*time.Time, error) {
	var publishedAt *time.Time
	err := r.pool.QueryRow(ctx,
		`SELECT published_at FROM package_version_releases
		 WHERE system = $1 AND name = $2 AND version = $3`,
		system, name, version,
	).Scan(&publishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get release date: %w", err)
	}
	return publishedAt, nil
}
