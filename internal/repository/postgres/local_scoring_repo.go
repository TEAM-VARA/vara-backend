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

// LocalScoringRepo는 Local Score 계산에 필요한 두 원본 점수(exposure, attack_path)를
// 조회하고, 통합 결과를 local_scores 테이블에 저장합니다.
//
// 의존 테이블:
//   - exposure_scores       (작업 C-1)
//   - attack_path_scores    (작업 B-2c)
//   - cluster_pods          (Pod 목록 — 두 점수가 모두 없을 수도 있는 Pod 확인용)
//
// 시점 정책: 각 점수 테이블의 cluster별 최신 snapshot을 독립적으로 조회
type LocalScoringRepo struct {
	pool *pgxpool.Pool
}

// NewLocalScoringRepo는 LocalScoringRepo를 생성합니다.
func NewLocalScoringRepo(pool *pgxpool.Pool) *LocalScoringRepo {
	return &LocalScoringRepo{pool: pool}
}

// ─────────────────────────────────────────
// 조회용 DTO
// ─────────────────────────────────────────

// PodSourceScores는 단일 Pod의 두 원본 점수를 묶은 결과입니다.
type PodSourceScores struct {
	PodUID       string
	PodName      string
	PodNamespace string

	// exposure (없으면 false / 0)
	HasExposure        bool
	Exposed            bool
	ExposureScoreRaw   int
	ExposureSnapshotAt time.Time

	// attack_path (없으면 false / 0)
	HasAttackPath        bool
	AttackPathScoreRaw   int
	AttackPathLevel      string
	AttackPathSnapshotAt time.Time
}

// ─────────────────────────────────────────
// 원본 점수 일괄 조회
// ─────────────────────────────────────────

// LoadSourceScores는 클러스터의 모든 Pod에 대해 exposure + attack_path 점수를 조회합니다.
//
// 전략:
//  1. cluster_pods의 최신 snapshot에서 Pod 목록 로드 (기준)
//  2. exposure_scores의 각 Pod 최신 점수 조회 (LEFT JOIN)
//  3. attack_path_scores의 각 Pod 최신 점수 조회 (LEFT JOIN)
//
// Pod이 두 점수 중 하나라도 없으면 그 부분은 0으로 처리하고 missing 카운터 증가.
func (r *LocalScoringRepo) LoadSourceScores(ctx context.Context, clusterName string) ([]PodSourceScores, error) {
	// 1. cluster_pods 최신 snapshot 조회
	var podsSnapshot *time.Time
	err := r.pool.QueryRow(ctx,
		`SELECT MAX(snapshot_at) FROM cluster_pods WHERE cluster_name = $1`,
		clusterName,
	).Scan(&podsSnapshot)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("find pods snapshot: %w", err)
	}
	if podsSnapshot == nil {
		return nil, fmt.Errorf("no pods found for cluster %s", clusterName)
	}

	// 2. Pod 목록 + exposure + attack_path 한번에 LEFT JOIN
	//    각 점수의 가장 최근 row (snapshot_at DESC 첫 row)를 LATERAL로 가져옴
	query := `
		SELECT 
			p.pod_uid,
			p.name AS pod_name,
			p.namespace AS pod_namespace,

			-- exposure
			es.exposed,
			score,
			es.snapshot_at AS exposure_snapshot_at,

			-- attack_path
			aps.total_score,
			aps.snapshot_at AS attack_path_snapshot_at,
			CASE
				WHEN aps.total_score >= 70 THEN 'High'
				WHEN aps.total_score >= 40 THEN 'Medium'
				WHEN aps.total_score > 0 THEN 'Low'
				WHEN aps.total_score = 0 THEN 'Minimal'
				ELSE NULL
			END AS attack_path_level

		FROM cluster_pods p

		LEFT JOIN LATERAL (
			SELECT exposed, snapshot_at
			FROM exposure_scores
			WHERE cluster_name = $1 AND pod_uid = p.pod_uid
			ORDER BY snapshot_at DESC LIMIT 1
		) es ON TRUE

		LEFT JOIN LATERAL (
			SELECT total_score, snapshot_at
			FROM attack_path_scores
			WHERE cluster_name = $1 AND pod_uid = p.pod_uid
			ORDER BY snapshot_at DESC LIMIT 1
		) aps ON TRUE

		WHERE p.cluster_name = $1 AND p.snapshot_at = $2
	`

	rows, err := r.pool.Query(ctx, query, clusterName, *podsSnapshot)
	if err != nil {
		return nil, fmt.Errorf("load source scores: %w", err)
	}
	defer rows.Close()

	var out []PodSourceScores
	for rows.Next() {
		var s PodSourceScores
		var exposed *bool
		var exposureRaw *int
		var exposureSnap *time.Time
		var apRaw *int
		var apSnap *time.Time
		var apLevel *string

		err := rows.Scan(
			&s.PodUID, &s.PodName, &s.PodNamespace,
			&exposed, &exposureRaw, &exposureSnap,
			&apRaw, &apSnap, &apLevel,
		)
		if err != nil {
			return nil, fmt.Errorf("scan source: %w", err)
		}

		if exposed != nil && exposureRaw != nil {
			s.HasExposure = true
			s.Exposed = *exposed
			s.ExposureScoreRaw = *exposureRaw
			if exposureSnap != nil {
				s.ExposureSnapshotAt = *exposureSnap
			}
		}

		if apRaw != nil {
			s.HasAttackPath = true
			s.AttackPathScoreRaw = *apRaw
			if apLevel != nil {
				s.AttackPathLevel = *apLevel
			}
			if apSnap != nil {
				s.AttackPathSnapshotAt = *apSnap
			}
		}

		out = append(out, s)
	}
	return out, rows.Err()
}

// ─────────────────────────────────────────
// 결과 저장
// ─────────────────────────────────────────

// UpsertBatch는 local_scores에 batch로 저장합니다.
func (r *LocalScoringRepo) UpsertBatch(ctx context.Context, results []scoring.LocalScoreResult) error {
	if len(results) == 0 {
		return nil
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const q = `
		INSERT INTO local_scores (
			cluster_name, pod_uid, pod_name, pod_namespace,
			local_score, exposure_contribution, attack_path_contribution,
			exposure_score_raw, attack_path_score_raw,
			exposed, attack_path_level, local_level,
			snapshot_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
		)
		ON CONFLICT (cluster_name, pod_uid, snapshot_at) DO UPDATE SET
			pod_name                 = EXCLUDED.pod_name,
			pod_namespace            = EXCLUDED.pod_namespace,
			local_score              = EXCLUDED.local_score,
			exposure_contribution    = EXCLUDED.exposure_contribution,
			attack_path_contribution = EXCLUDED.attack_path_contribution,
			exposure_score_raw       = EXCLUDED.exposure_score_raw,
			attack_path_score_raw    = EXCLUDED.attack_path_score_raw,
			exposed                  = EXCLUDED.exposed,
			attack_path_level        = EXCLUDED.attack_path_level,
			local_level              = EXCLUDED.local_level,
			computed_at              = NOW()
	`

	for _, res := range results {
		_, err := tx.Exec(ctx, q,
			res.ClusterName, res.PodUID, res.PodName, res.PodNamespace,
			res.LocalScore, res.ExposureContribution, res.AttackPathContribution,
			res.ExposureScoreRaw, res.AttackPathScoreRaw,
			res.Exposed, res.AttackPathLevel, res.LocalLevel,
			res.SnapshotAt,
		)
		if err != nil {
			return fmt.Errorf("upsert pod %s: %w", res.PodUID, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// GetByPodUID는 단일 Pod의 최근 결과를 조회합니다.
func (r *LocalScoringRepo) GetByPodUID(ctx context.Context, clusterName, podUID string) (*scoring.LocalScoreResult, error) {
	var res scoring.LocalScoreResult

	err := r.pool.QueryRow(ctx,
		`SELECT 
			cluster_name, pod_uid, pod_name, pod_namespace,
			local_score, exposure_contribution, attack_path_contribution,
			exposure_score_raw, attack_path_score_raw,
			exposed, attack_path_level, local_level,
			snapshot_at, computed_at
		 FROM local_scores
		 WHERE cluster_name = $1 AND pod_uid = $2
		 ORDER BY snapshot_at DESC LIMIT 1`,
		clusterName, podUID,
	).Scan(
		&res.ClusterName, &res.PodUID, &res.PodName, &res.PodNamespace,
		&res.LocalScore, &res.ExposureContribution, &res.AttackPathContribution,
		&res.ExposureScoreRaw, &res.AttackPathScoreRaw,
		&res.Exposed, &res.AttackPathLevel, &res.LocalLevel,
		&res.SnapshotAt, &res.ComputedAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get by pod uid: %w", err)
	}

	return &res, nil
}

// ListByCluster는 클러스터의 최신 결과를 모두 반환합니다.
func (r *LocalScoringRepo) ListByCluster(ctx context.Context, clusterName string) ([]scoring.LocalScoreResult, error) {
	var latestSnapshot *time.Time
	err := r.pool.QueryRow(ctx,
		`SELECT MAX(snapshot_at) FROM local_scores WHERE cluster_name = $1`,
		clusterName,
	).Scan(&latestSnapshot)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("get latest snapshot: %w", err)
	}
	if latestSnapshot == nil {
		return []scoring.LocalScoreResult{}, nil
	}

	rows, err := r.pool.Query(ctx,
		`SELECT 
			cluster_name, pod_uid, pod_name, pod_namespace,
			local_score, exposure_contribution, attack_path_contribution,
			exposure_score_raw, attack_path_score_raw,
			exposed, attack_path_level, local_level,
			snapshot_at, computed_at
		 FROM local_scores
		 WHERE cluster_name = $1 AND snapshot_at = $2
		 ORDER BY local_score DESC, pod_namespace, pod_name`,
		clusterName, *latestSnapshot,
	)
	if err != nil {
		return nil, fmt.Errorf("list by cluster: %w", err)
	}
	defer rows.Close()

	var out []scoring.LocalScoreResult
	for rows.Next() {
		var res scoring.LocalScoreResult
		err := rows.Scan(
			&res.ClusterName, &res.PodUID, &res.PodName, &res.PodNamespace,
			&res.LocalScore, &res.ExposureContribution, &res.AttackPathContribution,
			&res.ExposureScoreRaw, &res.AttackPathScoreRaw,
			&res.Exposed, &res.AttackPathLevel, &res.LocalLevel,
			&res.SnapshotAt, &res.ComputedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan result: %w", err)
		}
		out = append(out, res)
	}
	return out, rows.Err()
}
