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
			published_at, modified_at,
			fetched_at, expires_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, NULLIF($7, ''),
			$8, NULLIF($9, ''), NULLIF($10, ''),
			$11, $12,
			$13, $14
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
			published_at    = EXCLUDED.published_at,
			modified_at     = EXCLUDED.modified_at,
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
			v.PublishedAt, v.ModifiedAt,
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
			pv.published_at, pv.modified_at,
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
			published_at, modified_at,
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
			published_at, modified_at,
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

// SearchPodsByVulnID는 vuln_id가 실제로 영향을 주는 Pod 목록을 역추적합니다.
//
// 경로: vuln_id → package_vulnerabilities.purl → sbom_packages.image_digest
//   → sboms.image → cluster_pods.containers[].image (cluster의 최신 snapshot)
//
// 대상은 (A) cluster_pods 최신 스냅샷 기준이며, 시스템 Pod(tetragon/ebs-csi-node)은 제외합니다.
func (r *PackageVulnerabilityRepo) SearchPodsByVulnID(ctx context.Context, clusterName, vulnID string) ([]sbom.AffectedPod, error) {
	rows, err := r.pool.Query(ctx,
		`WITH affected_digests AS (
			SELECT DISTINCT sp.image_digest, pv.name AS pkg_name, pv.version AS pkg_version
			FROM package_vulnerabilities pv
			JOIN sbom_packages sp ON sp.purl = pv.purl
			WHERE pv.vuln_id = $2 OR $2 = ANY(pv.aliases)
		),
		affected_images AS (
			SELECT ad.image_digest, ad.pkg_name, ad.pkg_version, s.image
			FROM affected_digests ad
			JOIN sboms s ON s.image_digest = ad.image_digest
		),
		latest_pods AS (
			SELECT pod_uid, name AS pod_name, namespace,
			       jsonb_array_elements(containers)->>'image' AS pod_image
			FROM cluster_pods
			WHERE cluster_name = $1
			  AND snapshot_at = (SELECT MAX(snapshot_at) FROM cluster_pods WHERE cluster_name = $1)
			  AND name NOT LIKE 'tetragon%'
			  AND name NOT LIKE 'ebs-csi-node%'
		)
		SELECT DISTINCT lp.pod_uid, lp.pod_name, lp.namespace,
		       ai.image_digest, ai.pkg_name, ai.pkg_version
		FROM latest_pods lp
		JOIN affected_images ai ON ai.image = lp.pod_image
		ORDER BY lp.namespace, lp.pod_name`,
		clusterName, vulnID,
	)
	if err != nil {
		return nil, fmt.Errorf("search pods by vuln id: %w", err)
	}
	defer rows.Close()

	var out []sbom.AffectedPod
	for rows.Next() {
		var p sbom.AffectedPod
		if err := rows.Scan(&p.PodUID, &p.PodName, &p.Namespace,
			&p.ImageDigest, &p.PackageName, &p.Version); err != nil {
			return nil, fmt.Errorf("scan affected pod: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetCVETimelineByPod은 한 Pod(최신 스냅샷의 이미지 기준)의 CVE를 published_at 월별로
// 집계해 타임라인을 반환합니다.
//
// 경로: cluster_pods.containers[].image → sboms.image_digest
//   → sbom_packages.purl → package_vulnerabilities (published_at 기준 월별 그룹핑)
//
// 같은 CVE가 여러 패키지에 걸쳐도 vuln_id 기준 1회만 집계합니다.
func (r *PackageVulnerabilityRepo) GetCVETimelineByPod(ctx context.Context, clusterName, podUID string) (*sbom.CVETimelineResponse, error) {
	const q = `
		WITH pod_digests AS (
			SELECT DISTINCT s.image_digest
			FROM cluster_pods cp
			CROSS JOIN LATERAL jsonb_array_elements(cp.containers) c
			JOIN sboms s ON s.image = (c->>'image')
			WHERE cp.cluster_name = $1
			  AND cp.pod_uid = $2
			  AND cp.snapshot_at = (SELECT MAX(snapshot_at) FROM cluster_pods WHERE cluster_name = $1)
		),
		pod_vulns AS (
			-- vuln_id 기준 1회 (대표 published_at/score)
			SELECT DISTINCT ON (pv.vuln_id)
				pv.vuln_id, pv.published_at, COALESCE(pv.severity_score, 0) AS score
			FROM pod_digests pd
			JOIN sbom_packages sp ON sp.image_digest = pd.image_digest
			JOIN package_vulnerabilities pv ON pv.purl = sp.purl
			ORDER BY pv.vuln_id, pv.published_at NULLS LAST
		)
		SELECT
			to_char(date_trunc('month', published_at), 'YYYY-MM') AS month,
			COUNT(*) AS cnt,
			COALESCE(MAX(score), 0) AS max_score,
			COUNT(*) FILTER (WHERE score >= 9.0) AS critical_cnt,
			COUNT(*) FILTER (WHERE score >= 7.0 AND score < 9.0) AS high_cnt
		FROM pod_vulns
		WHERE published_at IS NOT NULL
		GROUP BY 1
		ORDER BY 1
	`
	rows, err := r.pool.Query(ctx, q, clusterName, podUID)
	if err != nil {
		return nil, fmt.Errorf("cve timeline by pod: %w", err)
	}
	defer rows.Close()

	resp := &sbom.CVETimelineResponse{ClusterName: clusterName, PodUID: podUID}
	for rows.Next() {
		var b sbom.CVETimelineBucket
		if err := rows.Scan(&b.Month, &b.Count, &b.MaxScore, &b.CriticalCount, &b.HighCount); err != nil {
			return nil, fmt.Errorf("scan timeline bucket: %w", err)
		}
		resp.Buckets = append(resp.Buckets, b)
		resp.TotalCVEs += b.Count
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// published_at 없는 CVE 수 + first/last 집계 (별도 쿼리, 동일 경로)
	const aggQ = `
		WITH pod_digests AS (
			SELECT DISTINCT s.image_digest
			FROM cluster_pods cp
			CROSS JOIN LATERAL jsonb_array_elements(cp.containers) c
			JOIN sboms s ON s.image = (c->>'image')
			WHERE cp.cluster_name = $1
			  AND cp.pod_uid = $2
			  AND cp.snapshot_at = (SELECT MAX(snapshot_at) FROM cluster_pods WHERE cluster_name = $1)
		),
		pod_vulns AS (
			SELECT DISTINCT ON (pv.vuln_id) pv.vuln_id, pv.published_at
			FROM pod_digests pd
			JOIN sbom_packages sp ON sp.image_digest = pd.image_digest
			JOIN package_vulnerabilities pv ON pv.purl = sp.purl
			ORDER BY pv.vuln_id, pv.published_at NULLS LAST
		)
		SELECT
			COUNT(*) FILTER (WHERE published_at IS NULL) AS without_date,
			MIN(published_at) AS first_seen,
			MAX(published_at) AS last_seen
		FROM pod_vulns
	`
	var firstSeen, lastSeen *time.Time
	if err := r.pool.QueryRow(ctx, aggQ, clusterName, podUID).Scan(&resp.WithoutDate, &firstSeen, &lastSeen); err != nil {
		return nil, fmt.Errorf("cve timeline agg: %w", err)
	}
	resp.FirstSeen = firstSeen
	resp.LastSeen = lastSeen

	return resp, nil
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
			&v.PublishedAt, &v.ModifiedAt,
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
		       vuln_id, COALESCE(aliases, '{}'::text[]), COALESCE(summary, ''),
		       COALESCE(severity_score, 0), COALESCE(severity_vector, ''), COALESCE(severity_label, ''),
		       published_at, modified_at,
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
