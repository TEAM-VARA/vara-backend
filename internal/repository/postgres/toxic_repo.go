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
// 데이터 소스 (실제 스키마 반영):
//   - exposure_scores.exposed → externally_exposed
//   - attack_path_scores.rbac_score / network_score / mount_score
//   - attack_path_scores.rbac_details / mount_details (JSONB)
//   - cluster_pods.containers (privileged, no_resource_limits)
//   - image_global_scores.{active, critical, high}_count
//
// 주의: cluster_pods에 host_network 컬럼 없음 → 신호 false 고정.
//
//	추후 컨테이너 JSONB나 Pod 메타에서 추출 가능.
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

	// 2. Pod별 신호 모두 가져오기
	//
	// 주의: cluster_pods에 host_network 컬럼 없음 → 제거
	//       attack_path_scores는 score + details JSONB로 구성됨
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
			COALESCE(aps.rbac_details, '{}'::jsonb) AS rbac_details,
			COALESCE(aps.mount_details, '{}'::jsonb) AS mount_details,
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
			rbacDetailsJSON, mountDetailsJSON   []byte
			hasKEV, hasCritical, hasHigh        bool
		)

		err := rows.Scan(
			&podUID, &podName, &podNamespace, &snapAt, &containersJSON,
			&exposed,
			&rbacScore, &networkScore, &mountScore,
			&rbacDetailsJSON, &mountDetailsJSON,
			&hasKEV, &hasCritical, &hasHigh,
		)
		if err != nil {
			return nil, fmt.Errorf("scan signals: %w", err)
		}

		// 컨테이너 JSONB 분석
		privileged, noLimits, hostNet := analyzeContainers(containersJSON)

		// rbac/mount details JSONB 분석
		clusterAdmin := isClusterAdminFromDetails(rbacScore, rbacDetailsJSON)
		secretAccess := hasSecretAccessFromDetails(rbacScore, mountScore, rbacDetailsJSON, mountDetailsJSON)

		// 신호 구성
		sig := scoring.ToxicSignals{
			ExternallyExposed: exposed,
			ClusterAdmin:      clusterAdmin,
			SecretAccess:      secretAccess,
			NoNetworkPolicy:   networkScore >= 30, // 작업 B-2c: 격리 없음
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

// containerLite는 cluster_pods.containers의 한 원소 일부입니다.
//
// 예시 컨테이너 JSONB (가정):
//
//	{
//	  "image": "nginx:1.14.0",
//	  "security_context": {"privileged": true, "run_as_user": 0},
//	  "resources": {"limits": {"cpu": "500m"}, "requests": {...}},
//	  "host_network": true                          // 또는 다른 위치
//	}
//
// 실제 형식이 다르면 신호가 false로 나올 수 있음.
// hostNetwork는 보통 Pod-level이지만 데이터에 없으면 false 폴백.
type containerLite struct {
	Image           string         `json:"image"`
	SecurityContext map[string]any `json:"security_context,omitempty"`
	Resources       map[string]any `json:"resources,omitempty"`
	HostNetwork     bool           `json:"host_network,omitempty"`
}

// analyzeContainers는 containers JSONB를 분석하여 신호를 추출합니다.
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
		// privileged
		if c.SecurityContext != nil {
			if v, ok := c.SecurityContext["privileged"].(bool); ok && v {
				privileged = true
			}
		}
		// limits 누락
		if c.Resources == nil {
			noLimits = true
		} else {
			limits, ok := c.Resources["limits"].(map[string]any)
			if !ok || len(limits) == 0 {
				noLimits = true
			}
		}
		// host network (컨테이너에 있을 수도, 없을 수도)
		if c.HostNetwork {
			hostNet = true
		}
	}
	return
}

// ─────────────────────────────────────────
// attack_path_scores 신호 추출 (details JSONB 활용)
// ─────────────────────────────────────────

// isClusterAdminFromDetails는 RBAC score + details에서 cluster-admin 여부를 판단합니다.
//
// 작업 B-2c에서 rbac_score = 70은 cluster-admin/wildcard 권한 점수.
//   - rbac_score >= 70 → cluster-admin 거의 확실
//   - rbac_details JSONB에 'cluster-admin' 또는 'wildcard' 문자열 포함 시 확정
func isClusterAdminFromDetails(rbacScore int, rbacDetails []byte) bool {
	// 점수 기반 1차 판단 (작업 B-2c에서 65~70이 cluster-admin/wildcard)
	if rbacScore >= 65 {
		return true
	}
	// JSONB 텍스트 검색 (details에 명시적 표시가 있을 수도)
	if len(rbacDetails) > 0 {
		text := string(rbacDetails)
		for _, keyword := range []string{"cluster-admin", "cluster_admin", "wildcard", "ClusterAdmin"} {
			if jsonContainsKeyword(text, keyword) {
				return true
			}
		}
	}
	return false
}

// hasSecretAccessFromDetails는 RBAC + Mount details에서 secret 접근 가능 여부를 판단합니다.
//
// 작업 B-2c에서:
//   - rbac_score 60+ = secret-access 등 민감 권한
//   - mount_score > 0 = secret/configmap 마운트 등
func hasSecretAccessFromDetails(rbacScore, mountScore int, rbacDetails, mountDetails []byte) bool {
	// 점수 기반 1차 판단
	if rbacScore >= 60 || mountScore >= 20 {
		// 보조 확인: 텍스트에 secret 키워드 있는지
		combined := string(rbacDetails) + string(mountDetails)
		if combined == "" {
			return rbacScore >= 60 || mountScore >= 30
		}
		for _, keyword := range []string{"secret", "Secret"} {
			if jsonContainsKeyword(combined, keyword) {
				return true
			}
		}
		// 키워드 없어도 점수 매우 높으면 인정
		return rbacScore >= 65 || mountScore >= 40
	}
	return false
}

// jsonContainsKeyword는 JSONB 텍스트에 키워드가 들어 있는지 확인합니다.
// (정밀 파싱 대신 substring 검사 — JSON key/value 양쪽 다 잡힘)
func jsonContainsKeyword(text, keyword string) bool {
	return len(text) >= len(keyword) && indexOf(text, keyword) >= 0
}

func indexOf(s, sub string) int {
	n := len(s)
	m := len(sub)
	if m == 0 {
		return 0
	}
	for i := 0; i+m <= n; i++ {
		if s[i:i+m] == sub {
			return i
		}
	}
	return -1
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
