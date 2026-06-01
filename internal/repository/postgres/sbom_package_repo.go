package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vara/backend/internal/domain/sbom"
)

// SBOMPackageRepo는 sbom_packages 테이블을 담당합니다.
type SBOMPackageRepo struct {
	pool *pgxpool.Pool
}

func NewSBOMPackageRepo(pool *pgxpool.Pool) *SBOMPackageRepo {
	return &SBOMPackageRepo{pool: pool}
}

// UpsertBatch는 한 이미지의 모든 패키지를 일괄 저장합니다.
// 빈 문자열은 SQL NULLIF로 NULL 변환.
func (r *SBOMPackageRepo) UpsertBatch(ctx context.Context, packages []sbom.SBOMPackage) error {
	if len(packages) == 0 {
		return nil
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const q = `
		INSERT INTO sbom_packages (
			image_digest, purl, name, version, ecosystem,
			arch, src_name, src_version,
			layer_digest, pkg_class, target, licenses
		) VALUES (
			$1, $2, $3, $4, $5,
			NULLIF($6, ''), NULLIF($7, ''), NULLIF($8, ''),
			NULLIF($9, ''), NULLIF($10, ''), NULLIF($11, ''),
			$12
		)
		ON CONFLICT (image_digest, purl) DO UPDATE SET
			name         = EXCLUDED.name,
			version      = EXCLUDED.version,
			ecosystem    = EXCLUDED.ecosystem,
			arch         = EXCLUDED.arch,
			src_name     = EXCLUDED.src_name,
			src_version  = EXCLUDED.src_version,
			layer_digest = EXCLUDED.layer_digest,
			pkg_class    = EXCLUDED.pkg_class,
			target       = EXCLUDED.target,
			licenses     = EXCLUDED.licenses,
			extracted_at = NOW()
	`

	for _, p := range packages {
		_, err := tx.Exec(ctx, q,
			p.ImageDigest, p.PURL, p.Name, p.Version, p.Ecosystem,
			p.Arch, p.SrcName, p.SrcVersion,
			p.LayerDigest, p.PkgClass, p.Target,
			p.Licenses,
		)
		if err != nil {
			return fmt.Errorf("upsert package %s: %w", p.PURL, err)
		}
	}

	return tx.Commit(ctx)
}

// DeleteByImageDigest는 한 이미지의 모든 패키지를 삭제합니다.
func (r *SBOMPackageRepo) DeleteByImageDigest(ctx context.Context, imageDigest string) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM sbom_packages WHERE image_digest = $1`,
		imageDigest,
	)
	if err != nil {
		return fmt.Errorf("delete by digest: %w", err)
	}
	return nil
}

// ListByImageDigest는 한 이미지의 모든 패키지를 반환합니다.
func (r *SBOMPackageRepo) ListByImageDigest(ctx context.Context, imageDigest string) ([]sbom.SBOMPackage, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT image_digest, purl, name, version, ecosystem,
		        COALESCE(arch, ''), COALESCE(src_name, ''), COALESCE(src_version, ''),
		        COALESCE(layer_digest, ''), COALESCE(pkg_class, ''), COALESCE(target, ''),
		        COALESCE(licenses, '{}'::text[])
		 FROM sbom_packages WHERE image_digest = $1
		 ORDER BY ecosystem, name, version`,
		imageDigest,
	)
	if err != nil {
		return nil, fmt.Errorf("list by digest: %w", err)
	}
	defer rows.Close()

	var out []sbom.SBOMPackage
	for rows.Next() {
		var p sbom.SBOMPackage
		err := rows.Scan(
			&p.ImageDigest, &p.PURL, &p.Name, &p.Version, &p.Ecosystem,
			&p.Arch, &p.SrcName, &p.SrcVersion,
			&p.LayerDigest, &p.PkgClass, &p.Target,
			&p.Licenses,
		)
		if err != nil {
			return nil, fmt.Errorf("scan package: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SearchByName은 이름으로 모든 이미지에서 매칭되는 패키지를 찾습니다.
func (r *SBOMPackageRepo) SearchByName(ctx context.Context, name string) ([]sbom.SBOMPackage, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT image_digest, purl, name, version, ecosystem,
		        COALESCE(arch, ''), COALESCE(src_name, ''), COALESCE(src_version, ''),
		        COALESCE(layer_digest, ''), COALESCE(pkg_class, ''), COALESCE(target, ''),
		        COALESCE(licenses, '{}'::text[])
		 FROM sbom_packages WHERE name = $1
		 ORDER BY ecosystem, version`,
		name,
	)
	if err != nil {
		return nil, fmt.Errorf("search by name: %w", err)
	}
	defer rows.Close()

	var out []sbom.SBOMPackage
	for rows.Next() {
		var p sbom.SBOMPackage
		err := rows.Scan(
			&p.ImageDigest, &p.PURL, &p.Name, &p.Version, &p.Ecosystem,
			&p.Arch, &p.SrcName, &p.SrcVersion,
			&p.LayerDigest, &p.PkgClass, &p.Target,
			&p.Licenses,
		)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CountByImageDigest는 한 이미지의 패키지 개수를 반환합니다.
func (r *SBOMPackageRepo) CountByImageDigest(ctx context.Context, imageDigest string) (int, error) {
	var count int
	err := r.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM sbom_packages WHERE image_digest = $1`,
		imageDigest,
	).Scan(&count)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("count by digest: %w", err)
	}
	return count, nil
}
