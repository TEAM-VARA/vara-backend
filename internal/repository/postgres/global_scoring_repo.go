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

// GlobalScoringRepo는 Global CVE Score를 PostgreSQL에 저장하고,
// SBOM 데이터에서 CVE 목록을 추출합니다.
//
// 캐시 정책:
//   - GetByCVEID: expires_at 검사 없이 그냥 반환 (호출자가 결정)
//   - GetByCVEIDFresh: expires_at 안 지난 것만 반환
//   - Upsert: NOW() + CacheTTL로 expires_at 재설정
type GlobalScoringRepo struct {
	pool *pgxpool.Pool
}

// NewGlobalScoringRepo는 GlobalScoringRepo를 생성합니다.
func NewGlobalScoringRepo(pool *pgxpool.Pool) *GlobalScoringRepo {
	return &GlobalScoringRepo{pool: pool}
}

// ─────────────────────────────────────────
// CVE Global Score 저장/조회
// ─────────────────────────────────────────

// Upsert는 단일 CVE의 Global Score를 저장합니다.
// expires_at은 자동으로 NOW() + CacheTTL.
//
// rawData들은 nil 가능 (선택적). nil이면 raw 컬럼이 NULL.
func (r *GlobalScoringRepo) Upsert(
	ctx context.Context,
	score scoring.GlobalScore,
	rawNVD, rawEPSS, rawKEV, rawExploitDB any,
) error {
	rawNVDJSON, _ := marshalOrNil(rawNVD)
	rawEPSSJSON, _ := marshalOrNil(rawEPSS)
	rawKEVJSON, _ := marshalOrNil(rawKEV)
	rawExploitDBJSON, _ := marshalOrNil(rawExploitDB)

	expiresAt := time.Now().Add(scoring.CacheTTL)

	const q = `
		INSERT INTO cve_global_scores (
			cve_id,
			cvss_score, cvss_severity, cvss_vector, cvss_found,
			epss_score, epss_percentile, epss_found,
			ssvc_exploitation, ssvc_source, in_kev, in_exploitdb,
			global_score,
			cvss_contribution, epss_contribution, ssvc_contribution,
			computed_at, expires_at,
			raw_nvd, raw_epss, raw_kev, raw_exploitdb,
			cvss_imputed, imputation_source, imputation_confidence
		) VALUES (
			$1,
			$2, $3, $4, $5,
			$6, $7, $8,
			$9, $10, $11, $12,
			$13,
			$14, $15, $16,
			NOW(), $17,
			$18, $19, $20, $21,
			$22, $23, $24
		)
		ON CONFLICT (cve_id) DO UPDATE SET
			cvss_score        = EXCLUDED.cvss_score,
			cvss_severity     = EXCLUDED.cvss_severity,
			cvss_vector       = EXCLUDED.cvss_vector,
			cvss_found        = EXCLUDED.cvss_found,
			epss_score        = EXCLUDED.epss_score,
			epss_percentile   = EXCLUDED.epss_percentile,
			epss_found        = EXCLUDED.epss_found,
			ssvc_exploitation = EXCLUDED.ssvc_exploitation,
			ssvc_source       = EXCLUDED.ssvc_source,
			in_kev            = EXCLUDED.in_kev,
			in_exploitdb      = EXCLUDED.in_exploitdb,
			global_score      = EXCLUDED.global_score,
			cvss_contribution = EXCLUDED.cvss_contribution,
			epss_contribution = EXCLUDED.epss_contribution,
			ssvc_contribution = EXCLUDED.ssvc_contribution,
			computed_at       = NOW(),
			expires_at        = EXCLUDED.expires_at,
			raw_nvd           = EXCLUDED.raw_nvd,
			raw_epss          = EXCLUDED.raw_epss,
			raw_kev           = EXCLUDED.raw_kev,
			raw_exploitdb     = EXCLUDED.raw_exploitdb,
			cvss_imputed          = EXCLUDED.cvss_imputed,
			imputation_source     = EXCLUDED.imputation_source,
			imputation_confidence = EXCLUDED.imputation_confidence
	`

	_, err := r.pool.Exec(ctx, q,
		score.CVEID,
		nullableFloat(score.CVSSScore, score.CVSSFound || score.CVSSImputed || score.ImputationSource != ""), score.CVSSSeverity, score.CVSSVector, score.CVSSFound,
		nullableFloat(score.EPSSScore, score.EPSSFound), nullableFloat(score.EPSSPercentile, score.EPSSFound), score.EPSSFound,
		score.SSVCExploitation, score.SSVCSource, score.InKEV, score.InExploitDB,
		score.GlobalScore,
		score.CVSSContribution, score.EPSSContribution, score.SSVCContribution,
		expiresAt,
		rawNVDJSON, rawEPSSJSON, rawKEVJSON, rawExploitDBJSON,
		score.CVSSImputed, score.ImputationSource, score.ImputationConfidence,
	)
	if err != nil {
		return fmt.Errorf("upsert cve_global_scores %s: %w", score.CVEID, err)
	}
	return nil
}

// ReweightAll은 Global 가중치 변경 시 cve_global_scores 전 행을 외부 API 호출 없이
// 제자리(in-place) 재계산합니다. raw 신호(cvss_score, epss_score, ssvc_exploitation,
// imputation_source, imputation_confidence)가 이미 저장돼 있으므로 단일 UPDATE로 충분합니다.
//
// 가중치: $1=w.GlobalCVSS, $2=w.GlobalEPSS, $3=w.GlobalSSVC.
// 영향받은 행 수를 반환합니다.
func (r *GlobalScoringRepo) ReweightAll(ctx context.Context, w scoring.Weights) (int64, error) {
	const q = `
		WITH terms AS (
			SELECT
				cve_id,
				LEAST(GREATEST(COALESCE(cvss_score, 0) / 10.0, 0), 1)
					* CASE WHEN imputation_source = 'ai' THEN COALESCE(imputation_confidence, 1) ELSE 1 END
					* $1                                                              AS cvss_term,
				LEAST(GREATEST(COALESCE(epss_score, 0), 0), 1) * $2                  AS epss_term,
				(CASE ssvc_exploitation
					WHEN 'active' THEN 1.0
					WHEN 'poc'    THEN 0.5
					ELSE 0.0
				END) * $3                                                           AS ssvc_term
			FROM cve_global_scores
		)
		UPDATE cve_global_scores g SET
			cvss_contribution = ROUND((t.cvss_term * 100)::numeric, 2),
			epss_contribution = ROUND((t.epss_term * 100)::numeric, 2),
			ssvc_contribution = ROUND((t.ssvc_term * 100)::numeric, 2),
			global_score      = ROUND(((t.cvss_term + t.epss_term + t.ssvc_term) * 100)::numeric, 2)
		FROM terms t
		WHERE g.cve_id = t.cve_id
	`

	tag, err := r.pool.Exec(ctx, q, w.GlobalCVSS, w.GlobalEPSS, w.GlobalSSVC)
	if err != nil {
		return 0, fmt.Errorf("reweight all cve_global_scores: %w", err)
	}
	return tag.RowsAffected(), nil
}

// GetByCVEID는 단일 CVE의 점수를 조회합니다. 없으면 nil 반환.
func (r *GlobalScoringRepo) GetByCVEID(ctx context.Context, cveID string) (*scoring.GlobalScore, error) {
	return r.getByCVEIDInternal(ctx, cveID, false)
}

// GetByCVEIDFresh는 expires_at이 지나지 않은 경우만 반환합니다.
// 캐시 만료 시 nil 반환 → 호출자가 재계산.
func (r *GlobalScoringRepo) GetByCVEIDFresh(ctx context.Context, cveID string) (*scoring.GlobalScore, error) {
	return r.getByCVEIDInternal(ctx, cveID, true)
}

func (r *GlobalScoringRepo) getByCVEIDInternal(ctx context.Context, cveID string, freshOnly bool) (*scoring.GlobalScore, error) {
	q := `
		SELECT
			cve_id,
			COALESCE(cvss_score, 0), COALESCE(cvss_severity, ''), COALESCE(cvss_vector, ''), cvss_found,
			COALESCE(epss_score, 0), COALESCE(epss_percentile, 0), epss_found,
			ssvc_exploitation, ssvc_source, in_kev, in_exploitdb,
			global_score, cvss_contribution, epss_contribution, ssvc_contribution,
			computed_at, expires_at,
			COALESCE(cvss_imputed, false), COALESCE(imputation_source, ''), COALESCE(imputation_confidence, 0)
		FROM cve_global_scores
		WHERE cve_id = $1
	`
	if freshOnly {
		q += " AND expires_at > NOW()"
	}

	var s scoring.GlobalScore
	err := r.pool.QueryRow(ctx, q, cveID).Scan(
		&s.CVEID,
		&s.CVSSScore, &s.CVSSSeverity, &s.CVSSVector, &s.CVSSFound,
		&s.EPSSScore, &s.EPSSPercentile, &s.EPSSFound,
		&s.SSVCExploitation, &s.SSVCSource, &s.InKEV, &s.InExploitDB,
		&s.GlobalScore, &s.CVSSContribution, &s.EPSSContribution, &s.SSVCContribution,
		&s.ComputedAt, &s.ExpiresAt,
		&s.CVSSImputed, &s.ImputationSource, &s.ImputationConfidence,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get cve %s: %w", cveID, err)
	}
	return &s, nil
}

// ─────────────────────────────────────────
// 이미지의 CVE 목록 추출 (sboms 테이블에서)
// ─────────────────────────────────────────

// CVEFromSBOM은 sboms.raw_data에서 추출한 CVE 한 건입니다.
type CVEFromSBOM struct {
	CVEID            string
	Severity         string
	PkgName          string
	InstalledVersion string
	FixedVersion     string
}

// ListCVEsByImageDigest는 sboms.raw_data에서 CVE 목록을 추출합니다.
// trivy JSON 형식 가정.
//
// sboms.raw_data 구조:
//   {
//     "Results": [
//       {
//         "Vulnerabilities": [
//           { "VulnerabilityID": "CVE-...", "Severity": "...", "PkgName": "...", ... }
//         ]
//       }
//     ]
//   }
//
// 중복 CVE는 제거 (같은 이미지에 같은 CVE가 여러 패키지에서 나올 수 있음).
func (r *GlobalScoringRepo) ListCVEsByImageDigest(ctx context.Context, imageDigest string) ([]CVEFromSBOM, error) {
	// CVE 목록 = Trivy SBOM(sboms.raw_data) ∪ OSV(package_vulnerabilities).
	// Trivy는 이미지 스캔 시점에 고정된 취약점, OSV는 매시간 갱신되는 신규 취약점.
	// 둘을 합쳐야 신규 OSV CVE가 이미지 Global 점수(최댓값)에 반영된다.
	// OSV vuln_id가 CVE-*면 그대로, 아니면 aliases의 CVE-*를 사용(NVD 스코어링 가능 대상만).
	// CVE ID 기준 dedup(같은 CVE가 양쪽/여러 패키지에 있을 수 있음).
	const q = `
		SELECT DISTINCT ON (cve_id)
			cve_id, severity, pkg_name, installed_version, fixed_version
		FROM (
			-- Trivy SBOM CVEs
			SELECT
				vuln->>'VulnerabilityID'                AS cve_id,
				COALESCE(vuln->>'Severity', '')         AS severity,
				COALESCE(vuln->>'PkgName', '')          AS pkg_name,
				COALESCE(vuln->>'InstalledVersion', '') AS installed_version,
				COALESCE(vuln->>'FixedVersion', '')     AS fixed_version
			FROM sboms,
			     jsonb_array_elements(raw_data->'Results') AS result,
			     jsonb_array_elements(COALESCE(result->'Vulnerabilities', '[]'::jsonb)) AS vuln
			WHERE image_digest = $1
			  AND raw_data IS NOT NULL
			  AND raw_data::text != 'null'
			  AND vuln->>'VulnerabilityID' IS NOT NULL
			  AND vuln->>'VulnerabilityID' != ''

			UNION ALL

			-- OSV CVEs (package_vulnerabilities → 같은 image_digest의 sbom_packages)
			SELECT
				CASE
					WHEN pv.vuln_id LIKE 'CVE-%' THEN pv.vuln_id
					ELSE (SELECT a FROM unnest(pv.aliases) AS a WHERE a LIKE 'CVE-%' LIMIT 1)
				END                            AS cve_id,
				''                             AS severity,
				''                             AS pkg_name,
				''                             AS installed_version,
				COALESCE(pv.fixed_version, '') AS fixed_version
			FROM package_vulnerabilities pv
			JOIN sbom_packages sp ON sp.purl = pv.purl
			WHERE sp.image_digest = $1
			  AND pv.withdrawn_at IS NULL
		) merged
		WHERE cve_id LIKE 'CVE-%'
		ORDER BY cve_id
	`

	rows, err := r.pool.Query(ctx, q, imageDigest)
	if err != nil {
		return nil, fmt.Errorf("list cves for image %s: %w", imageDigest, err)
	}
	defer rows.Close()

	var out []CVEFromSBOM
	for rows.Next() {
		var c CVEFromSBOM
		if err := rows.Scan(&c.CVEID, &c.Severity, &c.PkgName, &c.InstalledVersion, &c.FixedVersion); err != nil {
			return nil, fmt.Errorf("scan cve: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetImageByDigest는 sboms 테이블에서 이미지 이름을 조회합니다.
func (r *GlobalScoringRepo) GetImageByDigest(ctx context.Context, imageDigest string) (string, error) {
	var image string
	err := r.pool.QueryRow(ctx,
		`SELECT image FROM sboms WHERE image_digest = $1 LIMIT 1`,
		imageDigest,
	).Scan(&image)

	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get image by digest: %w", err)
	}
	return image, nil
}

// ─────────────────────────────────────────
// 헬퍼
// ─────────────────────────────────────────

// marshalOrNil은 nil 입력 시 NULL 처리.
func marshalOrNil(v any) ([]byte, error) {
	if v == nil {
		return nil, nil
	}
	return json.Marshal(v)
}

// nullableFloat은 found=false면 nil 반환 (NULL 저장).
func nullableFloat(v float64, found bool) any {
	if !found {
		return nil
	}
	return v
}
