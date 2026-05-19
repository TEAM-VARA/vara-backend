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

// ToxicRepo는 Toxic Combination 평가에 필요한 신호를 수집하고
// 결과를 toxic_results 테이블에 저장합니다.
//
// 데이터 소스:
//   - exposure_scores (externally_exposed)
//   - attack_path_scores (cluster_admin, secret_access, no_network_policy)
//   - cluster_pods.containers (privileged, host_network, no_resource_limits)
//   - image_global_scores (has_critical_cve, has_high_cve, has_kev/poc)
type ToxicRepo struct {
	pool *pgxpool.Pool
}

func NewToxicRepo(pool *pgxpool.Pool) *ToxicRepo {
	return &ToxicRepo{pool: pool}
}

// PodToxicSignals는 신호 + 메타데이터를 묶은 입력 단위입니다.
type PodToxicSignals struct {
	PodUID       string
	PodName      string
	PodNamespace string
	SnapshotAt   time.Time
	Signals      scoring.ToxicSignals
}

// ─────────────────────────────────────────
// 신호 일괄 수집
// ─────────────────────────────────────────

// LoadSignalsForCluster는 클러스터의 모든 Pod에 대해 토픽 신호를 수집합니다.
//
// 단일 쿼리에서 다중 LATERAL JOIN으로 처리:
//   - exposure_scores 최신 (Pod별 최신)
//   - attack_path_scores 최신
//   - cluster_pods.containers JSONB 분석
//   - image_global_scores 통해 CVE 메트릭
func (r *ToxicRepo) LoadSignalsForCluster(ctx context.Context, clusterName string) ([]PodToxicSignals, error) {
	// 1. cluster_pods 최신 snapshot
	var podsSnapshot *time.Time
	err := r.pool.QueryRow(ctx,
		`SELECT MAX(snapshot_at) FROM cluster_pods WHERE cluster_name = $1`,
		clusterName,
	).Scan(&podsSnapshot)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("get pods snapshot: %w", err)
	}
	if podsSnapshot == nil {
		return nil, fmt.Errorf("no pods found for cluster %s", clusterName)
	}

	// 2. Pod별 신호를 모두 가져오는 쿼리.
	//
	//	   exposure / attack_path / cve 메트릭은 LATERAL JOIN으로
	//	   각 Pod별 최신 한 행만 가져옴.
	query := `
		WITH latest_pods AS (
			SELECT pod_uid, name, namespace, snapshot_at, host_network, containers
			FROM cluster_pods
			WHERE cluster_name = $1 AND snapshot_at = $2
		),
		image_metrics AS (
			SELECT 
				p.pod_uid,
				BOOL_OR(igs.active_count > 0) AS has_kev,
				BOOL_OR(igs.critical_count > 0) AS has_critical,
				BOOL_OR(igs.high_count > 0 OR igs.critical_count > 0) AS has_high
			FROM latest_pods p
			LEFT JOIN LATERAL jsonb_array_elements(p.containers) AS c ON TRUE
			LEFT JOIN sboms s ON s.image = c->>'image'
			LEFT JOIN image_global_scores igs ON igs.image_digest = s.image_digest
			GROUP BY p.pod_uid
		)
		SELECT 
			p.pod_uid, p.name, p.namespace, p.snapshot_at, p.host_network, p.containers,
			COALESCE(es.exposed, false) AS exposed,
			COALESCE(aps.role_severity, '') AS role_severity,
			COALESCE(aps.scope, '') AS scope,
			COALESCE(aps.network_score, 0) AS network_score,
			COALESCE(im.has_kev, false) AS has_kev,
			COALESCE(im.has_critical, false) AS has_critical,
			COALESCE(im.has_high, false) AS has_high
		FROM latest_pods p
		LEFT JOIN LATERAL (
			SELECT exposed FROM exposure_scores
			WHERE cluster_name = $1 AND pod_uid = p.pod_uid
			ORDER BY snapshot_at DESC LIMIT 1
		) es ON TRUE
		LEFT JOIN LATERAL (
			SELECT role_severity, scope, network_score FROM attack_path_scores
			WHERE cluster_name = $1 AND pod_uid = p.pod_uid
			ORDER BY snapshot_at DESC LIMIT 1
		) aps ON TRUE
		LEFT JOIN image_metrics im ON im.pod_uid = p.pod_uid
		ORDER BY p.pod_uid
	`

	rows, err := r.pool.Query(ctx, query, clusterName, *podsSnapshot)
	if err != nil {
		return nil, fmt.Errorf("load toxic signals: %w", err)
	}
	defer rows.Close()

	var out []PodToxicSignals
	for rows.Next() {
		var (
			podUID, podName, podNamespace string
			snapAt                        time.Time
			hostNetwork                   bool
			containersJSON                []byte
			exposed                       bool
			roleSeverity, scope           string
			networkScore                  int
			hasKEV, hasCritical, hasHigh  bool
		)

		err := rows.Scan(
			&podUID, &podName, &podNamespace, &snapAt, &hostNetwork, &containersJSON,
			&exposed, &roleSeverity, &scope, &networkScore,
			&hasKEV, &hasCritical, &hasHigh,
		)
		if err != nil {
			return nil, fmt.Errorf("scan signals: %w", err)
		}

		// 컨테이너 JSONB 분석
		privileged, noLimits := analyzeContainers(containersJSON)

		// 신호 구성
		sig := scoring.ToxicSignals{
			ExternallyExposed: exposed,
			ClusterAdmin:      isClusterAdmin(roleSeverity),
			SecretAccess:      hasSecretAccess(scope),
			NoNetworkPolicy:   networkScore >= 30, // 작업 B-2c 기준: 격리 없음
			Privileged:        privileged,
			HostNetwork:       hostNetwork,
			NoResourceLimits:  noLimits,
			HasKEVCVE:         hasKEV,
			HasCriticalCVE:    hasCritical,
			HasHighCVE:        hasHigh,
			HasActiveOrPOC:    hasKEV, // POC만은 ExploitDB 데이터 필요 — 작업 B-1의 SSVC=poc 카운트 없으면 KEV로 대체
		}

		out = append(out, PodToxicSignals{
			PodUID:       podUID,
			PodName:      podName,
			PodNamespace: podNamespace,
			SnapshotAt:   snapAt,
			Signals:      sig,
		})
	}

	return out, rows.Err()
}

// ─────────────────────────────────────────
// 컨테이너 JSONB 분석
// ─────────────────────────────────────────

// containerJSON 표현 (예상):
//	[
//	  {
//	    "image": "nginx:1.14.0",
//	    "security_context": {"privileged": true, "run_as_user": 0},
//	    "resources": {"limits": {"cpu": "500m"}, "requests": {...}}
//	  }
//	]
type containerLite struct {
	Image           string         `json:"image"`
	SecurityContext map[string]any `json:"security_context,omitempty"`
	Resources       map[string]any `json:"resources,omitempty"`
}

// analyzeContainers는 containers JSONB를 분석하여:
//   - 하나라도 privileged: true 면 privileged=true
//   - 하나라도 resources.limits가 비어있으면 noLimits=true
func analyzeContainers(raw []byte) (privileged, noLimits bool) {
	if len(raw) == 0 {
		return false, true
	}
	var containers []containerLite
	if err := json.Unmarshal(raw, &containers); err != nil {
		return false, false
	}
	if len(containers) == 0 {
		return false, true
	}

	for _, c := range containers {
		// privileged
		if c.SecurityContext != nil {
			if v, ok := c.SecurityContext["privileged"].(bool); ok && v {
				privileged = true
			}
		}
		// limits 누락
		if c.Resources == nil {
			noLimits = true
			continue
		}
		limits, ok := c.Resources["limits"].(map[string]any)
		if !ok || len(limits) == 0 {
			noLimits = true
		}
	}
	return
}

// ─────────────────────────────────────────
// attack_path_scores 신호 매핑
// ─────────────────────────────────────────
//
// 작업 B-2c에서 정한 role_severity / scope 값을 토픽 신호로 매핑.

func isClusterAdmin(roleSeverity string) bool {
	// 작업 B-2c에서 cluster-admin은 role_severity = "cluster-admin"
	// 또는 점수 70+ 또는 scope = "wildcard"
	return roleSeverity == "cluster-admin" || roleSeverity == "wildcard"
}

func hasSecretAccess(scope string) bool {
	// 작업 B-2c에서 scope에 "secret" 포함 시 secret 접근
	if scope == "" {
		return false
	}
	for _, s := range []string{"secret", "secret-access", "secrets", "secrets-access"} {
		if scope == s {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────
// 저장
// ─────────────────────────────────────────

// UpsertBatch는 toxic_results에 배치 저장합니다.
func (r *ToxicRepo) UpsertBatch(ctx context.Context, clusterName string, results []scoring.ToxicResult) error {
	if len(results) == 0 {
		return nil
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const q = `
		INSERT INTO toxic_results (
			cluster_name, pod_uid, pod_name, pod_namespace,
			multiplier, matched_rules, signals, snapshot_at
		) VALUES (
			$1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8
		)
		ON CONFLICT (cluster_name, pod_uid, snapshot_at) DO UPDATE SET
			pod_name      = EXCLUDED.pod_name,
			pod_namespace = EXCLUDED.pod_namespace,
			multiplier    = EXCLUDED.multiplier,
			matched_rules = EXCLUDED.matched_rules,
			signals       = EXCLUDED.signals,
			computed_at   = NOW()
	`

	for _, res := range results {
		matchedJSON, _ := json.Marshal(res.MatchedRules)
		signalsJSON, _ := json.Marshal(res.Signals)

		_, err := tx.Exec(ctx, q,
			clusterName, res.PodUID, res.PodName, res.PodNamespace,
			res.Multiplier, string(matchedJSON), string(signalsJSON), res.SnapshotAt,
		)
		if err != nil {
			return fmt.Errorf("upsert toxic for pod %s: %w", res.PodUID, err)
		}
	}

	return tx.Commit(ctx)
}

// ─────────────────────────────────────────
// 조회
// ─────────────────────────────────────────

// GetByPodUID는 단일 Pod의 최근 결과를 반환합니다.
func (r *ToxicRepo) GetByPodUID(ctx context.Context, clusterName, podUID string) (*scoring.ToxicResult, error) {
	var res scoring.ToxicResult
	var matchedJSON, signalsJSON []byte

	err := r.pool.QueryRow(ctx,
		`SELECT cluster_name, pod_uid, pod_name, pod_namespace,
		        multiplier, matched_rules, signals, snapshot_at, computed_at
		 FROM toxic_results
		 WHERE cluster_name = $1 AND pod_uid = $2
		 ORDER BY snapshot_at DESC LIMIT 1`,
		clusterName, podUID,
	).Scan(
		&res.ClusterName, &res.PodUID, &res.PodName, &res.PodNamespace,
		&res.Multiplier, &matchedJSON, &signalsJSON, &res.SnapshotAt, &res.ComputedAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get toxic by pod: %w", err)
	}

	_ = json.Unmarshal(matchedJSON, &res.MatchedRules)
	_ = json.Unmarshal(signalsJSON, &res.Signals)
	return &res, nil
}

// ListByCluster는 클러스터의 최신 결과를 모두 반환합니다.
func (r *ToxicRepo) ListByCluster(ctx context.Context, clusterName string) ([]scoring.ToxicResult, error) {
	var latest *time.Time
	err := r.pool.QueryRow(ctx,
		`SELECT MAX(snapshot_at) FROM toxic_results WHERE cluster_name = $1`,
		clusterName,
	).Scan(&latest)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("get latest: %w", err)
	}
	if latest == nil {
		return []scoring.ToxicResult{}, nil
	}

	rows, err := r.pool.Query(ctx,
		`SELECT cluster_name, pod_uid, pod_name, pod_namespace,
		        multiplier, matched_rules, signals, snapshot_at, computed_at
		 FROM toxic_results
		 WHERE cluster_name = $1 AND snapshot_at = $2
		 ORDER BY multiplier DESC, pod_namespace, pod_name`,
		clusterName, *latest,
	)
	if err != nil {
		return nil, fmt.Errorf("list toxic by cluster: %w", err)
	}
	defer rows.Close()

	var out []scoring.ToxicResult
	for rows.Next() {
		var res scoring.ToxicResult
		var matchedJSON, signalsJSON []byte
		err := rows.Scan(
			&res.ClusterName, &res.PodUID, &res.PodName, &res.PodNamespace,
			&res.Multiplier, &matchedJSON, &signalsJSON, &res.SnapshotAt, &res.ComputedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan toxic: %w", err)
		}
		_ = json.Unmarshal(matchedJSON, &res.MatchedRules)
		_ = json.Unmarshal(signalsJSON, &res.Signals)
		out = append(out, res)
	}
	return out, rows.Err()
}

// GetMultiplier는 단일 Pod의 multiplier만 반환합니다. (FinalScoringService용)
// 결과가 없으면 1.0 반환.
func (r *ToxicRepo) GetMultiplier(ctx context.Context, clusterName, podUID string) (float64, error) {
	var mult float64
	err := r.pool.QueryRow(ctx,
		`SELECT multiplier
		 FROM toxic_results
		 WHERE cluster_name = $1 AND pod_uid = $2
		 ORDER BY snapshot_at DESC LIMIT 1`,
		clusterName, podUID,
	).Scan(&mult)

	if errors.Is(err, pgx.ErrNoRows) {
		return 1.0, nil
	}
	if err != nil {
		return 1.0, fmt.Errorf("get toxic multiplier: %w", err)
	}
	return mult, nil
}

// LoadMultipliersForCluster는 클러스터의 모든 Pod에 대한 multiplier를 일괄 조회합니다.
// FinalScoringService에서 한 번에 모든 Pod의 multiplier를 가져갈 때 사용.
//
// 반환: map[pod_uid] -> multiplier (없는 Pod은 키 없음, 호출자가 1.0으로 처리)
func (r *ToxicRepo) LoadMultipliersForCluster(ctx context.Context, clusterName string) (map[string]float64, error) {
	var latest *time.Time
	err := r.pool.QueryRow(ctx,
		`SELECT MAX(snapshot_at) FROM toxic_results WHERE cluster_name = $1`,
		clusterName,
	).Scan(&latest)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("get latest: %w", err)
	}
	if latest == nil {
		return map[string]float64{}, nil
	}

	rows, err := r.pool.Query(ctx,
		`SELECT pod_uid, multiplier FROM toxic_results
		 WHERE cluster_name = $1 AND snapshot_at = $2`,
		clusterName, *latest,
	)
	if err != nil {
		return nil, fmt.Errorf("load multipliers: %w", err)
	}
	defer rows.Close()

	out := make(map[string]float64)
	for rows.Next() {
		var uid string
		var m float64
		if err := rows.Scan(&uid, &m); err != nil {
			return nil, err
		}
		out[uid] = m
	}
	return out, rows.Err()
}
