package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vara/backend/internal/domain/sbom"
)

// PackageVulnerabilityRepo는 package_vulnerabilities + package_osv_queries 테이블을 담당합니다.
type PackageVulnerabilityRepo struct {
	pool *pgxpool.Pool
}

func NewPackageVulnerabilityRepo(pool *pgxpool.Pool) *PackageVulnerabilityRepo {
	return &PackageVulnerabilityRepo{pool: pool}
}

// ─────────────────────────────────────────
// 캐시 조회 (osv 호출 전 체크용)
// ─────────────────────────────────────────

// IsCached returns true if this PURL has been queried recently (within TTL).
func (r *PackageVulnerabilityRepo) IsCached(ctx context.Context, purl string) (bool, error) {
	var expiresAt time.Time
	err := r.pool.QueryRow(ctx,
		`SELECT expires_at FROM package_osv_queries WHERE purl = $1`,
		purl,
	).Scan(&expiresAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check osv cache: %w", err)
	}

	return time.Now().Before(expiresAt), nil
}

// RecordQuery records that a PURL has been queried (even if 0 vulns).
func (r *PackageVulnerabilityRepo) RecordQuery(ctx context.Context, purl string, vulnCount int) error {
	now := time.Now()
	_, err := r.pool.Exec(ctx,
		`INSERT INTO package_osv_queries (purl, queried_at, vuln_count, expires_at)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (purl) DO UPDATE SET
		   queried_at = EXCLUDED.queried_at,
		   vuln_count = EXCLUDED.vuln_count,
		   expires_at = EXCLUDED.expires_at`,
		purl, now, vulnCount, now.Add(sbom.PackageVulnTTL),
	)
	if err != nil {
		return fmt.Errorf("record osv query: %w", err)
	}
	return nil
}

// ─────────────────────────────────────────
// Vulnerability Upsert
// ─────────────────────────────────────────

// UpsertBatch는 한 PURL의 모든 취약점을 일괄 저장합니다.
//
// 같은 (purl, vuln_id)는 update. 트랜잭션 처리.
func (r *PackageVulnerabilityRepo) UpsertBatch(ctx context.Context, vulns []sbom.PackageVulnerability) error {
	if len(vulns) == 0 {
		return nil
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const q = `
		INSERT INTO package_vulnerabilities (
			purl, name, version, ecosystem,
			vuln_id, aliases, summary,
			severity_score, severity_vector, severity_label,
			fetched_at, expires_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, NULLIF($7, ''),
			$8, NULLIF($9, ''), NULLIF($10, ''),
			$11, $12
		)
		ON CONFLICT (purl, vuln_id) DO UPDATE SET
			name            = EXCLUDED.name,
			version         = EXCLUDED.version,
			ecosystem       = EXCLUDED.ecosystem,
			aliases         = EXCLUDED.aliases,
			summary         = EXCLUDED.summary,
			severity_score  = EXCLUDED.severity_score,
			severity_vector = EXCLUDED.severity_vector,
			severity_label  = EXCLUDED.severity_label,
			fetched_at      = EXCLUDED.fetched_at,
			expires_at      = EXCLUDED.expires_at
	`

	for _, v := range vulns {
		var score interface{} = v.SeverityScore
		if v.SeverityScore == 0 {
			score = nil
		}
		_, err := tx.Exec(ctx, q,
			v.PURL, v.Name, v.Version, v.Ecosystem,
			v.VulnID, v.Aliases, v.Summary,
			score, v.SeverityVector, v.SeverityLabel,
			v.FetchedAt, v.ExpiresAt,
		)
		if err != nil {
			return fmt.Errorf("upsert vuln %s: %w", v.VulnID, err)
		}
	}

	return tx.Commit(ctx)
}

// ─────────────────────────────────────────
// 조회
// ─────────────────────────────────────────

// ListByImageDigest는 한 이미지의 모든 패키지에 대한 취약점을 반환합니다.
//
// sbom_packages → package_vulnerabilities JOIN
func (r *PackageVulnerabilityRepo) ListByImageDigest(ctx context.Context, imageDigest string) ([]sbom.PackageVulnerability, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT 
			pv.purl, pv.name, pv.version, pv.ecosystem,
			pv.vuln_id, COALESCE(pv.aliases, '{}'::text[]),
			COALESCE(pv.summary, ''),
			COALESCE(pv.severity_score, 0),
			COALESCE(pv.severity_vector, ''),
			COALESCE(pv.severity_label, ''),
			pv.fetched_at, pv.expires_at
		 FROM package_vulnerabilities pv
		 JOIN sbom_packages sp ON sp.purl = pv.purl
		 WHERE sp.image_digest = $1
		 ORDER BY pv.severity_score DESC NULLS LAST, pv.vuln_id`,
		imageDigest,
	)
	if err != nil {
		return nil, fmt.Errorf("list by image digest: %w", err)
	}
	defer rows.Close()

	return scanVulns(rows)
}

// ListByPURL은 단일 PURL의 모든 취약점을 반환합니다.
func (r *PackageVulnerabilityRepo) ListByPURL(ctx context.Context, purl string) ([]sbom.PackageVulnerability, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT 
			purl, name, version, ecosystem,
			vuln_id, COALESCE(aliases, '{}'::text[]),
			COALESCE(summary, ''),
			COALESCE(severity_score, 0),
			COALESCE(severity_vector, ''),
			COALESCE(severity_label, ''),
			fetched_at, expires_at
		 FROM package_vulnerabilities
		 WHERE purl = $1
		 ORDER BY severity_score DESC NULLS LAST`,
		purl,
	)
	if err != nil {
		return nil, fmt.Errorf("list by purl: %w", err)
	}
	defer rows.Close()

	return scanVulns(rows)
}

// SearchByVulnID는 특정 CVE/GHSA ID로 모든 영향 PURL을 찾습니다.
func (r *PackageVulnerabilityRepo) SearchByVulnID(ctx context.Context, vulnID string) ([]sbom.PackageVulnerability, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT 
			purl, name, version, ecosystem,
			vuln_id, COALESCE(aliases, '{}'::text[]),
			COALESCE(summary, ''),
			COALESCE(severity_score, 0),
			COALESCE(severity_vector, ''),
			COALESCE(severity_label, ''),
			fetched_at, expires_at
		 FROM package_vulnerabilities
		 WHERE vuln_id = $1 OR $1 = ANY(aliases)
		 ORDER BY name, version`,
		vulnID,
	)
	if err != nil {
		return nil, fmt.Errorf("search by vuln id: %w", err)
	}
	defer rows.Close()

	return scanVulns(rows)
}

// DeleteByPURL은 한 PURL의 모든 취약점 기록을 삭제합니다 (재스캔 전 정리).
func (r *PackageVulnerabilityRepo) DeleteByPURL(ctx context.Context, purl string) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM package_vulnerabilities WHERE purl = $1`,
		purl,
	)
	if err != nil {
		return fmt.Errorf("delete by purl: %w", err)
	}
	return nil
}

// ─────────────────────────────────────────
// 공통 scan
// ─────────────────────────────────────────

func scanVulns(rows pgx.Rows) ([]sbom.PackageVulnerability, error) {
	var out []sbom.PackageVulnerability
	for rows.Next() {
		var v sbom.PackageVulnerability
		err := rows.Scan(
			&v.PURL, &v.Name, &v.Version, &v.Ecosystem,
			&v.VulnID, &v.Aliases,
			&v.Summary,
			&v.SeverityScore,
			&v.SeverityVector,
			&v.SeverityLabel,
			&v.FetchedAt, &v.ExpiresAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan vuln: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ─────────────────────────────────────────
// Scheduler 지원 메서드
// ─────────────────────────────────────────

// ListDistinctImageDigests는 sbom_packages에 있는 모든 unique image_digest를 반환합니다.
// VulnScheduler가 스캔할 이미지 목록 조회에 사용됩니다.
func (r *PackageVulnerabilityRepo) ListDistinctImageDigests(ctx context.Context) ([]string, error) {
	const query = `
		SELECT DISTINCT image_digest 
		FROM sbom_packages 
		WHERE image_digest IS NOT NULL AND image_digest != ''
		ORDER BY image_digest
	`
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list image digests: %w", err)
	}
	defer rows.Close()

	var digests []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		digests = append(digests, d)
	}
	return digests, rows.Err()
}

// ListRecentlyAdded는 since 이후로 fetched_at된 vulnerability를 반환합니다.
// severities가 비어있으면 모든 severity 포함.
//
// VulnScheduler가 "이번 스캔에서 새로 추가된 vuln" 식별에 사용.
func (r *PackageVulnerabilityRepo) ListRecentlyAdded(
	ctx context.Context,
	since time.Time,
	severities []string,
) ([]sbom.PackageVulnerability, error) {
	query := `
		SELECT purl, name, version, ecosystem,
		       vuln_id, aliases, summary, 
		       severity_score, severity_vector, severity_label,
		       fetched_at, expires_at
		FROM package_vulnerabilities
		WHERE fetched_at >= $1
	`
	args := []interface{}{since}

	if len(severities) > 0 {
		query += ` AND severity_label = ANY($2)`
		args = append(args, severities)
	}

	query += ` ORDER BY severity_score DESC, vuln_id`

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list recently added: %w", err)
	}
	defer rows.Close()

	return scanVulns(rows)
}
