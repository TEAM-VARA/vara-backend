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

// FinalScoringRepo는 Final Score 계산에 필요한 모든 입력을 조회하고,
// 결과를 final_scores 테이블에 저장합니다.
//
// 조회 흐름 (한 Pod 단위):
//  1. cluster_pods.containers[].image → tag 목록 추출
//  2. sboms.image = tag로 image_digest 추출
//  3. image_global_scores.image_digest로 max_score 조회
//  4. local_scores.pod_uid로 local_score 조회
//  5. 가장 위험한 컨테이너 이미지 채택 → 통합
type FinalScoringRepo struct {
	pool *pgxpool.Pool
}

func NewFinalScoringRepo(pool *pgxpool.Pool) *FinalScoringRepo {
	return &FinalScoringRepo{pool: pool}
}

// LatestSnapshotAt: 이 클러스터의 최신 배치 snapshot_at. 행 없으면 ok=false(폴백).
func (r *FinalScoringRepo) LatestSnapshotAt(ctx context.Context, cluster string) (time.Time, bool, error) {
	var t *time.Time
	if err := r.pool.QueryRow(ctx,
		`SELECT MAX(snapshot_at) FROM final_scores WHERE cluster_name=$1`, cluster).Scan(&t); err != nil {
		return time.Time{}, false, fmt.Errorf("latest snapshot: %w", err)
	}
	if t == nil {
		return time.Time{}, false, nil
	}
	return *t, true, nil
}

// ─────────────────────────────────────────
// 조회용 DTO
// ─────────────────────────────────────────

// PodFinalInput은 Final Score 계산에 필요한 단일 Pod의 정보입니다.
type PodFinalInput struct {
	PodUID       string
	PodName      string
	PodNamespace string

	// 컨테이너 이미지 + 해당 이미지의 global score (없으면 nil)
	Containers []ContainerImageScore

	// Local Score (없으면 nil)
	HasLocal        bool
	LocalScore      float64
	LocalSnapshotAt time.Time
	PodSnapshotAt   time.Time
}

// ContainerImageScore는 한 컨테이너의 image + global score 매핑입니다.
type ContainerImageScore struct {
	ImageTag    string // "nginx:1.14.0"
	ImageDigest string // "sha256:..." (없으면 "")
	HasSBOM     bool
	HasGlobal   bool

	// image_global_scores 값 (없으면 zero)
	MaxScore float64
	TopCVE   string
}

// ─────────────────────────────────────────
// 일괄 로드
// ─────────────────────────────────────────

// LoadInputsForCluster는 클러스터의 모든 Pod에 대해 Final Score 계산 입력을 로드합니다.
//
// 단일 쿼리에서 모두 처리:
//  1. cluster_pods 최신 snapshot
//  2. jsonb_array_elements로 컨테이너 펼침
//  3. sboms LEFT JOIN으로 image_digest 추출
//  4. image_global_scores LEFT JOIN으로 max_score
//  5. local_scores LEFT JOIN (LATERAL, 최신 snapshot)
//
// 결과를 Pod 단위로 집계.
func (r *FinalScoringRepo) LoadInputsForCluster(ctx context.Context, clusterName string) ([]PodFinalInput, error) {
	// 1. cluster_pods 최신 snapshot
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

	// 2. Pod + container + image 조인
	//
	// containers는 JSONB 배열, 펼쳐서 image 추출.
	// sboms.image = container image tag로 LEFT JOIN
	// image_global_scores.image_digest로 LEFT JOIN
	// local_scores는 Pod 단위라 별도 LATERAL
	query := `
		SELECT 
			p.pod_uid,
			p.name AS pod_name,
			p.namespace AS pod_namespace,
			p.snapshot_at AS pod_snapshot_at,

			c.value->>'image' AS container_image_tag,
			s.image_digest,
			igs.max_score AS image_max_score,
			igs.top_cve AS image_top_cve,

			ls.local_score,
			ls.snapshot_at AS local_snapshot_at
		FROM cluster_pods p
		LEFT JOIN LATERAL jsonb_array_elements(p.containers) AS c ON TRUE
		LEFT JOIN sboms s ON s.image = c.value->>'image'
		LEFT JOIN image_global_scores igs ON igs.image_digest = s.image_digest
		LEFT JOIN LATERAL (
			-- Risk Score 2번째 인자 = 인터넷 노출(0/100). attack_path 제외로 local_scores 대신 exposure_scores 사용.
			SELECT CASE WHEN exposed THEN 100.0 ELSE 0.0 END AS local_score, snapshot_at
			FROM exposure_scores
			WHERE cluster_name = $1 AND pod_uid = p.pod_uid
			ORDER BY snapshot_at DESC LIMIT 1
		) ls ON TRUE
		WHERE p.cluster_name = $1 AND p.snapshot_at = $2
		ORDER BY p.pod_uid
	`

	rows, err := r.pool.Query(ctx, query, clusterName, *podsSnapshot)
	if err != nil {
		return nil, fmt.Errorf("load final inputs: %w", err)
	}
	defer rows.Close()

	// Pod 단위 집계 (같은 pod_uid가 여러 row로 나옴 — 컨테이너 펼치기 때문)
	podMap := make(map[string]*PodFinalInput)
	order := []string{} // 등장 순서 보존

	for rows.Next() {
		var (
			podUID, podName, podNamespace string
			podSnap                       time.Time
			containerImageTag             *string
			imageDigest                   *string
			imageMaxScore                 *float64
			imageTopCVE                   *string
			localScore                    *float64
			localSnap                     *time.Time
		)

		err := rows.Scan(
			&podUID, &podName, &podNamespace, &podSnap,
			&containerImageTag, &imageDigest, &imageMaxScore, &imageTopCVE,
			&localScore, &localSnap,
		)
		if err != nil {
			return nil, fmt.Errorf("scan final input row: %w", err)
		}

		// Pod 신규 등장 시 초기화
		input, exists := podMap[podUID]
		if !exists {
			input = &PodFinalInput{
				PodUID:        podUID,
				PodName:       podName,
				PodNamespace:  podNamespace,
				PodSnapshotAt: podSnap,
			}
			podMap[podUID] = input
			order = append(order, podUID)

			// local 점수 (Pod 단위이므로 첫 row에서만 설정)
			if localScore != nil {
				input.HasLocal = true
				input.LocalScore = *localScore
				if localSnap != nil {
					input.LocalSnapshotAt = *localSnap
				}
			}
		}

		// 컨테이너 정보 추가
		if containerImageTag != nil {
			c := ContainerImageScore{
				ImageTag: *containerImageTag,
			}
			if imageDigest != nil {
				c.ImageDigest = *imageDigest
				c.HasSBOM = true
			}
			if imageMaxScore != nil {
				c.MaxScore = *imageMaxScore
				c.HasGlobal = true
			}
			if imageTopCVE != nil {
				c.TopCVE = *imageTopCVE
			}
			input.Containers = append(input.Containers, c)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// 순서 보존하여 반환
	out := make([]PodFinalInput, 0, len(order))
	for _, uid := range order {
		out = append(out, *podMap[uid])
	}

	return out, nil
}

// LoadInputByPodUID는 단일 Pod의 final score 입력을 조회합니다.
// 컨테이너 펼치기로 row가 여러 개 나올 수 있어 집계 필요.
// Pod가 없으면 nil 반환.
func (r *FinalScoringRepo) LoadInputByPodUID(
	ctx context.Context,
	clusterName, podUID string,
) (*PodFinalInput, error) {
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

	// LoadInputsForCluster와 동일 SQL + pod_uid 필터
	query := `
		SELECT
			p.pod_uid,
			p.name AS pod_name,
			p.namespace AS pod_namespace,
			p.snapshot_at AS pod_snapshot_at,

			c.value->>'image' AS container_image_tag,
			s.image_digest,
			igs.max_score AS image_max_score,
			igs.top_cve AS image_top_cve,

			ls.local_score,
			ls.snapshot_at AS local_snapshot_at
		FROM cluster_pods p
		LEFT JOIN LATERAL jsonb_array_elements(p.containers) AS c ON TRUE
		LEFT JOIN sboms s ON s.image = c.value->>'image'
		LEFT JOIN image_global_scores igs ON igs.image_digest = s.image_digest
		LEFT JOIN LATERAL (
			-- Risk Score 2번째 인자 = 인터넷 노출(0/100). attack_path 제외로 local_scores 대신 exposure_scores 사용.
			SELECT CASE WHEN exposed THEN 100.0 ELSE 0.0 END AS local_score, snapshot_at
			FROM exposure_scores
			WHERE cluster_name = $1 AND pod_uid = p.pod_uid
			ORDER BY snapshot_at DESC LIMIT 1
		) ls ON TRUE
		WHERE p.cluster_name = $1 AND p.snapshot_at = $2 AND p.pod_uid = $3
	`

	rows, err := r.pool.Query(ctx, query, clusterName, *podsSnapshot, podUID)
	if err != nil {
		return nil, fmt.Errorf("load final input by uid: %w", err)
	}
	defer rows.Close()

	var input *PodFinalInput

	for rows.Next() {
		var (
			retPodUID, podName, podNamespace string
			podSnap                          time.Time
			containerImageTag                *string
			imageDigest                      *string
			imageMaxScore                    *float64
			imageTopCVE                      *string
			localScore                       *float64
			localSnap                        *time.Time
		)

		err := rows.Scan(
			&retPodUID, &podName, &podNamespace, &podSnap,
			&containerImageTag, &imageDigest, &imageMaxScore, &imageTopCVE,
			&localScore, &localSnap,
		)
		if err != nil {
			return nil, fmt.Errorf("scan final input row: %w", err)
		}

		// 첫 row에서만 Pod 초기화 (이후 row는 컨테이너만 추가)
		if input == nil {
			input = &PodFinalInput{
				PodUID:        retPodUID,
				PodName:       podName,
				PodNamespace:  podNamespace,
				PodSnapshotAt: podSnap,
			}
			if localScore != nil {
				input.HasLocal = true
				input.LocalScore = *localScore
				if localSnap != nil {
					input.LocalSnapshotAt = *localSnap
				}
			}
		}

		// 컨테이너 정보 추가
		if containerImageTag != nil {
			c := ContainerImageScore{
				ImageTag: *containerImageTag,
			}
			if imageDigest != nil {
				c.ImageDigest = *imageDigest
				c.HasSBOM = true
			}
			if imageMaxScore != nil {
				c.MaxScore = *imageMaxScore
				c.HasGlobal = true
			}
			if imageTopCVE != nil {
				c.TopCVE = *imageTopCVE
			}
			input.Containers = append(input.Containers, c)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return input, nil
}

// ─────────────────────────────────────────
// 저장
// ─────────────────────────────────────────

// UpsertBatch는 final_scores에 batch로 저장합니다.
func (r *FinalScoringRepo) UpsertBatch(ctx context.Context, results []scoring.FinalScoreResult) error {
	if len(results) == 0 {
		return nil
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const q = `
		INSERT INTO final_scores (
			cluster_name, pod_uid, pod_name, pod_namespace,
			final_score, risk_level,
			global_contribution, local_contribution, toxic_multiplier,
			global_image_score, local_score,
			used_image_digest, used_image_tag, used_top_cve,
			missing_global_image, missing_local, missing_sbom,
			snapshot_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
		)
		ON CONFLICT (cluster_name, pod_uid, snapshot_at) DO UPDATE SET
			pod_name             = EXCLUDED.pod_name,
			pod_namespace        = EXCLUDED.pod_namespace,
			final_score          = EXCLUDED.final_score,
			risk_level           = EXCLUDED.risk_level,
			global_contribution  = EXCLUDED.global_contribution,
			local_contribution   = EXCLUDED.local_contribution,
			toxic_multiplier     = EXCLUDED.toxic_multiplier,
			global_image_score   = EXCLUDED.global_image_score,
			local_score          = EXCLUDED.local_score,
			used_image_digest    = EXCLUDED.used_image_digest,
			used_image_tag       = EXCLUDED.used_image_tag,
			used_top_cve         = EXCLUDED.used_top_cve,
			missing_global_image = EXCLUDED.missing_global_image,
			missing_local        = EXCLUDED.missing_local,
			missing_sbom         = EXCLUDED.missing_sbom,
			computed_at          = NOW()
	`

	for _, res := range results {
		_, err := tx.Exec(ctx, q,
			res.ClusterName, res.PodUID, res.PodName, res.PodNamespace,
			res.FinalScore, res.RiskLevel,
			res.GlobalContribution, res.LocalContribution, res.ToxicMultiplier,
			res.GlobalImageScore, res.LocalScore,
			nilIfEmptyStr(res.UsedImageDigest), nilIfEmptyStr(res.UsedImageTag), nilIfEmptyStr(res.UsedTopCVE),
			res.MissingGlobalImage, res.MissingLocal, res.MissingSBOM,
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

// GetByPodUID는 단일 Pod의 최근 결과를 반환합니다.
func (r *FinalScoringRepo) GetByPodUID(ctx context.Context, clusterName, podUID string) (*scoring.FinalScoreResult, error) {
	var res scoring.FinalScoreResult
	var digest, tag, topCVE *string

	err := r.pool.QueryRow(ctx,
		`SELECT 
			cluster_name, pod_uid, pod_name, pod_namespace,
			final_score, risk_level,
			global_contribution, local_contribution, toxic_multiplier,
			global_image_score, local_score,
			used_image_digest, used_image_tag, used_top_cve,
			missing_global_image, missing_local, missing_sbom,
			snapshot_at, computed_at
		 FROM final_scores
		 WHERE cluster_name = $1 AND pod_uid = $2
		 ORDER BY snapshot_at DESC LIMIT 1`,
		clusterName, podUID,
	).Scan(
		&res.ClusterName, &res.PodUID, &res.PodName, &res.PodNamespace,
		&res.FinalScore, &res.RiskLevel,
		&res.GlobalContribution, &res.LocalContribution, &res.ToxicMultiplier,
		&res.GlobalImageScore, &res.LocalScore,
		&digest, &tag, &topCVE,
		&res.MissingGlobalImage, &res.MissingLocal, &res.MissingSBOM,
		&res.SnapshotAt, &res.ComputedAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get by pod uid: %w", err)
	}

	if digest != nil {
		res.UsedImageDigest = *digest
	}
	if tag != nil {
		res.UsedImageTag = *tag
	}
	if topCVE != nil {
		res.UsedTopCVE = *topCVE
	}

	return &res, nil
}

// ListClusterNames는 final_scores에 존재하는 모든 cluster_name을 반환합니다(전체 재계산 스크립트용).
func (r *FinalScoringRepo) ListClusterNames(ctx context.Context) ([]string, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT DISTINCT cluster_name FROM final_scores ORDER BY cluster_name`)
	if err != nil {
		return nil, fmt.Errorf("list cluster names: %w", err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan cluster name: %w", err)
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

// ListByCluster는 클러스터의 최신 결과를 모두 반환합니다.
func (r *FinalScoringRepo) ListByCluster(ctx context.Context, clusterName string) ([]scoring.FinalScoreResult, error) {
	var latest *time.Time
	err := r.pool.QueryRow(ctx,
		`SELECT MAX(snapshot_at) FROM final_scores WHERE cluster_name = $1`,
		clusterName,
	).Scan(&latest)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("get latest snapshot: %w", err)
	}
	if latest == nil {
		return []scoring.FinalScoreResult{}, nil
	}

	rows, err := r.pool.Query(ctx,
		`SELECT 
			cluster_name, pod_uid, pod_name, pod_namespace,
			final_score, risk_level,
			global_contribution, local_contribution, toxic_multiplier,
			global_image_score, local_score,
			used_image_digest, used_image_tag, used_top_cve,
			missing_global_image, missing_local, missing_sbom,
			snapshot_at, computed_at
		 FROM final_scores
		 WHERE cluster_name = $1 AND snapshot_at = $2
		 ORDER BY final_score DESC, pod_namespace, pod_name`,
		clusterName, *latest,
	)
	if err != nil {
		return nil, fmt.Errorf("list by cluster: %w", err)
	}
	defer rows.Close()

	var out []scoring.FinalScoreResult
	for rows.Next() {
		var res scoring.FinalScoreResult
		var digest, tag, topCVE *string

		err := rows.Scan(
			&res.ClusterName, &res.PodUID, &res.PodName, &res.PodNamespace,
			&res.FinalScore, &res.RiskLevel,
			&res.GlobalContribution, &res.LocalContribution, &res.ToxicMultiplier,
			&res.GlobalImageScore, &res.LocalScore,
			&digest, &tag, &topCVE,
			&res.MissingGlobalImage, &res.MissingLocal, &res.MissingSBOM,
			&res.SnapshotAt, &res.ComputedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan result: %w", err)
		}

		if digest != nil {
			res.UsedImageDigest = *digest
		}
		if tag != nil {
			res.UsedImageTag = *tag
		}
		if topCVE != nil {
			res.UsedTopCVE = *topCVE
		}
		out = append(out, res)
	}
	return out, rows.Err()
}

// nilIfEmptyStr: 빈 문자열을 NULL로 변환.
func nilIfEmptyStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
