package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vara/backend/internal/domain/scoring"
)

// ToxicRepo는 Toxic Combination 평가에 필요한 신호를 수집하고
// 결과를 toxic_results 테이블에 저장합니다.
//
// 신호 임계값 (vara-test-cluster 데이터 기준 조정 v2):
//
//	cluster_admin   : rbac_score >= 60 (작업 B-2c wildcard/admin 수준)
//	secret_access   : rbac_score >= 50 AND details에 'secret' 또는 'wildcard'
//	no_network_policy: network_score >= 30 (단독 매칭 약화 목적, 조합에서만 효과)
type ToxicRepo struct {
	pool *pgxpool.Pool
}

func NewToxicRepo(pool *pgxpool.Pool) *ToxicRepo {
	return &ToxicRepo{pool: pool}
}

type PodToxicSignals struct {
	PodUID       string
	PodName      string
	PodNamespace string
	SnapshotAt   time.Time
	Signals      scoring.ToxicSignals
}

func (r *ToxicRepo) LoadSignalsForCluster(ctx context.Context, clusterName string) ([]PodToxicSignals, error) {
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

	query := `
		WITH latest_pods AS (
			SELECT pod_uid, name, namespace, snapshot_at, containers
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
			p.pod_uid, p.name, p.namespace, p.snapshot_at, p.containers,
			COALESCE(es.exposed, false) AS exposed,
			COALESCE(aps.rbac_score, 0) AS rbac_score,
			COALESCE(aps.network_score, 0) AS network_score,
			COALESCE(aps.mount_score, 0) AS mount_score,
			COALESCE(aps.rbac_details::text, '{}') AS rbac_details_text,
			COALESCE(aps.mount_details::text, '{}') AS mount_details_text,
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
			SELECT rbac_score, network_score, mount_score, rbac_details, mount_details
			FROM attack_path_scores
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
			podUID, podName, podNamespace       string
			snapAt                              time.Time
			containersJSON                      []byte
			exposed                             bool
			rbacScore, networkScore, mountScore int
			rbacDetailsText, mountDetailsText   string
			hasKEV, hasCritical, hasHigh        bool
		)

		err := rows.Scan(
			&podUID, &podName, &podNamespace, &snapAt, &containersJSON,
			&exposed,
			&rbacScore, &networkScore, &mountScore,
			&rbacDetailsText, &mountDetailsText,
			&hasKEV, &hasCritical, &hasHigh,
		)
		if err != nil {
			return nil, fmt.Errorf("scan signals: %w", err)
		}

		privileged, noLimits, hostNet := analyzeContainers(containersJSON)

		// 신호 판단 v2 (점수 기반, JSONB는 보조)
		clusterAdmin := rbacScore >= 60

		secretAccess := false
		if rbacScore >= 50 || mountScore >= 30 {
			lowText := strings.ToLower(rbacDetailsText + " " + mountDetailsText)
			if strings.Contains(lowText, "secret") || strings.Contains(lowText, "wildcard") {
				secretAccess = true
			}
		}

		sig := scoring.ToxicSignals{
			ExternallyExposed: exposed,
			ClusterAdmin:      clusterAdmin,
			SecretAccess:      secretAccess,
			NoNetworkPolicy:   networkScore >= 30,
			Privileged:        privileged,
			HostNetwork:       hostNet,
			NoResourceLimits:  noLimits,
			HasKEVCVE:         hasKEV,
			HasCriticalCVE:    hasCritical,
			HasHighCVE:        hasHigh,
			HasActiveOrPOC:    hasKEV,
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

type containerLite struct {
	Image           string         `json:"image"`
	SecurityContext map[string]any `json:"security_context,omitempty"`
	Resources       map[string]any `json:"resources,omitempty"`
	HostNetwork     bool           `json:"host_network,omitempty"`
}

func analyzeContainers(raw []byte) (privileged, noLimits, hostNet bool) {
	if len(raw) == 0 {
		return false, true, false
	}
	var containers []containerLite
	if err := json.Unmarshal(raw, &containers); err != nil {
		return false, false, false
	}
	if len(containers) == 0 {
		return false, true, false
	}

	for _, c := range containers {
		if c.SecurityContext != nil {
			if v, ok := c.SecurityContext["privileged"].(bool); ok && v {
				privileged = true
			}
		}
		if c.Resources == nil {
			noLimits = true
		} else {
			limits, ok := c.Resources["limits"].(map[string]any)
			if !ok || len(limits) == 0 {
				noLimits = true
			}
		}
		if c.HostNetwork {
			hostNet = true
		}
	}
	return
}

// ─────────────────────────────────────────
// 저장
// ─────────────────────────────────────────

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

func (r *ToxicRepo) GetMultiplier(ctx context.Context, clusterName, podUID string) (float64, error) {
	var mult float64
	err := r.pool.QueryRow(ctx,
		`SELECT multiplier FROM toxic_results
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
