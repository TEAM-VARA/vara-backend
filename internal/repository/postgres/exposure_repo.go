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

// ExposureRepo는 인터넷 노출 계산에 필요한 데이터를 조회하고,
// 계산 결과를 exposure_scores 테이블에 저장합니다.
//
// 데이터 소스:
//   - cluster_pods (snapshot 기반 시계열)
//   - cluster_services (snapshot 기반 시계열)
//   - cluster_ingresses (snapshot 기반 시계열)
//
// 각 테이블의 snapshot_at은 독립적으로 갱신됩니다.
// (Pod는 30초마다, Service는 1분마다, Ingress는 1분마다 수집)
// 따라서 "최신 snapshot"은 테이블별로 다를 수 있습니다.
//
// 본 Repo는 각 테이블의 최신 snapshot을 독립적으로 조회합니다.
type ExposureRepo struct {
	pool *pgxpool.Pool
}

// NewExposureRepo는 ExposureRepo를 생성합니다.
func NewExposureRepo(pool *pgxpool.Pool) *ExposureRepo {
	return &ExposureRepo{pool: pool}
}

// ─────────────────────────────────────────
// 조회용 DTO (cluster_* 테이블 raw 표현)
// ─────────────────────────────────────────

// PodSnapshot은 cluster_pods 한 행입니다.
type PodSnapshot struct {
	PodUID    string
	Name      string
	Namespace string
	PodIP     string
	Labels    map[string]string
}

// ServiceSnapshot은 cluster_services 한 행입니다.
type ServiceSnapshot struct {
	Name      string
	Namespace string
	Type      string
	Selector  map[string]string
}

// IngressSnapshot은 cluster_ingresses의 (host, backend service) 매핑 한 건입니다.
type IngressSnapshot struct {
	Name        string
	Namespace   string
	Host        string
	ServiceName string
}

// ─────────────────────────────────────────
// 각 테이블의 최신 snapshot_at 조회 (독립적)
// ─────────────────────────────────────────

// GetLatestPodsSnapshot은 cluster_pods의 최신 snapshot_at을 반환합니다.
// 없으면 에러 반환 (Pod 데이터는 반드시 있어야 함).
func (r *ExposureRepo) GetLatestPodsSnapshot(ctx context.Context, clusterName string) (time.Time, error) {
	var t *time.Time
	err := r.pool.QueryRow(ctx,
		`SELECT MAX(snapshot_at) FROM cluster_pods WHERE cluster_name = $1`,
		clusterName,
	).Scan(&t)

	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, fmt.Errorf("get latest pods snapshot: %w", err)
	}
	if t == nil || t.IsZero() {
		return time.Time{}, fmt.Errorf("no pods snapshot found for cluster %s", clusterName)
	}
	return *t, nil
}

// GetLatestServicesSnapshot은 cluster_services의 최신 snapshot_at을 반환합니다.
// Service가 하나도 없는 클러스터는 드물어요 (kubernetes Service는 기본 존재).
// 없으면 zero time 반환 (에러 아님).
func (r *ExposureRepo) GetLatestServicesSnapshot(ctx context.Context, clusterName string) (time.Time, error) {
	var t *time.Time
	err := r.pool.QueryRow(ctx,
		`SELECT MAX(snapshot_at) FROM cluster_services WHERE cluster_name = $1`,
		clusterName,
	).Scan(&t)

	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, fmt.Errorf("get latest services snapshot: %w", err)
	}
	if t == nil {
		return time.Time{}, nil
	}
	return *t, nil
}

// GetLatestIngressesSnapshot은 cluster_ingresses의 최신 snapshot_at을 반환합니다.
// Ingress가 없는 클러스터도 흔합니다.
// 없으면 zero time 반환 (에러 아님).
func (r *ExposureRepo) GetLatestIngressesSnapshot(ctx context.Context, clusterName string) (time.Time, error) {
	var t *time.Time
	err := r.pool.QueryRow(ctx,
		`SELECT MAX(snapshot_at) FROM cluster_ingresses WHERE cluster_name = $1`,
		clusterName,
	).Scan(&t)

	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, fmt.Errorf("get latest ingresses snapshot: %w", err)
	}
	if t == nil {
		return time.Time{}, nil
	}
	return *t, nil
}

// ─────────────────────────────────────────
// 데이터 조회
// ─────────────────────────────────────────

// ListPodsAtSnapshot은 특정 snapshot의 모든 Pod을 반환합니다.
func (r *ExposureRepo) ListPodsAtSnapshot(ctx context.Context, clusterName string, snapshotAt time.Time) ([]PodSnapshot, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT pod_uid, name, namespace,
		        COALESCE(pod_ip, '') AS pod_ip,
		        COALESCE(labels, '{}'::jsonb)
		 FROM cluster_pods
		 WHERE cluster_name = $1 AND snapshot_at = $2`,
		clusterName, snapshotAt,
	)
	if err != nil {
		return nil, fmt.Errorf("query pods: %w", err)
	}
	defer rows.Close()

	var out []PodSnapshot
	for rows.Next() {
		var p PodSnapshot
		var labelsRaw []byte
		if err := rows.Scan(&p.PodUID, &p.Name, &p.Namespace, &p.PodIP, &labelsRaw); err != nil {
			return nil, fmt.Errorf("scan pod: %w", err)
		}
		if len(labelsRaw) > 0 {
			_ = json.Unmarshal(labelsRaw, &p.Labels)
		}
		if p.Labels == nil {
			p.Labels = map[string]string{}
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListServicesAtSnapshot은 특정 snapshot의 모든 Service를 반환합니다.
// snapshot이 zero time이면 빈 리스트 반환.
func (r *ExposureRepo) ListServicesAtSnapshot(ctx context.Context, clusterName string, snapshotAt time.Time) ([]ServiceSnapshot, error) {
	if snapshotAt.IsZero() {
		return []ServiceSnapshot{}, nil
	}
	rows, err := r.pool.Query(ctx,
		`SELECT name, namespace, COALESCE(type, ''), COALESCE(selector, '{}'::jsonb)
		 FROM cluster_services
		 WHERE cluster_name = $1 AND snapshot_at = $2`,
		clusterName, snapshotAt,
	)
	if err != nil {
		return nil, fmt.Errorf("query services: %w", err)
	}
	defer rows.Close()

	var out []ServiceSnapshot
	for rows.Next() {
		var s ServiceSnapshot
		var selectorRaw []byte
		if err := rows.Scan(&s.Name, &s.Namespace, &s.Type, &selectorRaw); err != nil {
			return nil, fmt.Errorf("scan service: %w", err)
		}
		if len(selectorRaw) > 0 {
			_ = json.Unmarshal(selectorRaw, &s.Selector)
		}
		if s.Selector == nil {
			s.Selector = map[string]string{}
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ListIngressBackendsAtSnapshot은 특정 snapshot의 Ingress backend 매핑을
// 펼쳐서 반환합니다. snapshot이 zero time이면 빈 리스트 반환.
func (r *ExposureRepo) ListIngressBackendsAtSnapshot(ctx context.Context, clusterName string, snapshotAt time.Time) ([]IngressSnapshot, error) {
	if snapshotAt.IsZero() {
		return []IngressSnapshot{}, nil
	}
	query := `
		SELECT
			ing.name,
			ing.namespace,
			COALESCE(rule->>'host', '') AS host,
			COALESCE(path->>'service_name', '') AS service_name
		FROM cluster_ingresses ing,
		     jsonb_array_elements(ing.rules) AS rule,
		     jsonb_array_elements(COALESCE(rule->'paths', '[]'::jsonb)) AS path
		WHERE ing.cluster_name = $1
		  AND ing.snapshot_at = $2
		  AND COALESCE(path->>'service_name', '') <> ''
	`
	rows, err := r.pool.Query(ctx, query, clusterName, snapshotAt)
	if err != nil {
		return nil, fmt.Errorf("query ingresses: %w", err)
	}
	defer rows.Close()

	var out []IngressSnapshot
	for rows.Next() {
		var ig IngressSnapshot
		if err := rows.Scan(&ig.Name, &ig.Namespace, &ig.Host, &ig.ServiceName); err != nil {
			return nil, fmt.Errorf("scan ingress: %w", err)
		}
		out = append(out, ig)
	}
	return out, rows.Err()
}

// ─────────────────────────────────────────
// 저장
// ─────────────────────────────────────────

// UpsertExposureBatch는 여러 결과를 배치로 저장합니다.
func (r *ExposureRepo) UpsertExposureBatch(ctx context.Context, results []scoring.ExposureResult) error {
	if len(results) == 0 {
		return nil
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const q = `
		INSERT INTO exposure_scores (
			cluster_name, pod_uid, pod_name, pod_namespace,
			exposed, score,
			matched_services, matched_ingresses,
			snapshot_at,
			runtime_actually_accessed, runtime_external_traffic_count, runtime_details
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		)
		ON CONFLICT (cluster_name, pod_uid, snapshot_at) DO UPDATE SET
			pod_name                       = EXCLUDED.pod_name,
			pod_namespace                  = EXCLUDED.pod_namespace,
			exposed                        = EXCLUDED.exposed,
			score                          = EXCLUDED.score,
			matched_services               = EXCLUDED.matched_services,
			matched_ingresses              = EXCLUDED.matched_ingresses,
			runtime_actually_accessed      = EXCLUDED.runtime_actually_accessed,
			runtime_external_traffic_count = EXCLUDED.runtime_external_traffic_count,
			runtime_details                = EXCLUDED.runtime_details,
			computed_at                    = NOW()
	`

	for _, result := range results {
		matchedServicesJSON, _ := json.Marshal(result.MatchedServices)
		if matchedServicesJSON == nil {
			matchedServicesJSON = []byte("[]")
		}
		matchedIngressesJSON, _ := json.Marshal(result.MatchedIngresses)
		if matchedIngressesJSON == nil {
			matchedIngressesJSON = []byte("[]")
		}

		// nullable JSONB — nil이면 NULL
		var runtimeDetailsJSON []byte
		if result.RuntimeDetails != nil {
			runtimeDetailsJSON, _ = json.Marshal(result.RuntimeDetails)
		}

		_, err := tx.Exec(ctx, q,
			result.ClusterName, result.PodUID, result.PodName, result.PodNamespace,
			result.Exposed, result.Score,
			matchedServicesJSON, matchedIngressesJSON,
			result.SnapshotAt,
			result.RuntimeActuallyAccessed, result.RuntimeExternalTrafficCount, runtimeDetailsJSON,
		)
		if err != nil {
			return fmt.Errorf("upsert pod %s: %w", result.PodUID, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// GetByPodUID는 단일 Pod의 최근 결과를 조회합니다.
func (r *ExposureRepo) GetByPodUID(ctx context.Context, clusterName, podUID string) (*scoring.ExposureResult, error) {
	var result scoring.ExposureResult
	var matchedServicesRaw, matchedIngressesRaw []byte

	err := r.pool.QueryRow(ctx,
		`SELECT cluster_name, pod_uid, pod_name, pod_namespace,
		        exposed, score,
		        matched_services, matched_ingresses,
		        snapshot_at, computed_at
		 FROM exposure_scores
		 WHERE cluster_name = $1 AND pod_uid = $2
		 ORDER BY snapshot_at DESC LIMIT 1`,
		clusterName, podUID,
	).Scan(
		&result.ClusterName, &result.PodUID, &result.PodName, &result.PodNamespace,
		&result.Exposed, &result.Score,
		&matchedServicesRaw, &matchedIngressesRaw,
		&result.SnapshotAt, &result.ComputedAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get by pod uid: %w", err)
	}

	if len(matchedServicesRaw) > 0 {
		_ = json.Unmarshal(matchedServicesRaw, &result.MatchedServices)
	}
	if len(matchedIngressesRaw) > 0 {
		_ = json.Unmarshal(matchedIngressesRaw, &result.MatchedIngresses)
	}

	return &result, nil
}

// ListByCluster는 클러스터의 최신 snapshot 결과를 모두 반환합니다.
func (r *ExposureRepo) ListByCluster(ctx context.Context, clusterName string) ([]scoring.ExposureResult, error) {
	var latestSnapshot *time.Time
	err := r.pool.QueryRow(ctx,
		`SELECT MAX(snapshot_at) FROM exposure_scores WHERE cluster_name = $1`,
		clusterName,
	).Scan(&latestSnapshot)

	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("get latest snapshot: %w", err)
	}
	if latestSnapshot == nil {
		return []scoring.ExposureResult{}, nil
	}

	rows, err := r.pool.Query(ctx,
		`SELECT cluster_name, pod_uid, pod_name, pod_namespace,
		        exposed, score,
		        matched_services, matched_ingresses,
		        snapshot_at, computed_at
		 FROM exposure_scores
		 WHERE cluster_name = $1 AND snapshot_at = $2
		 ORDER BY exposed DESC, pod_namespace, pod_name`,
		clusterName, *latestSnapshot,
	)
	if err != nil {
		return nil, fmt.Errorf("list by cluster: %w", err)
	}
	defer rows.Close()

	var out []scoring.ExposureResult
	for rows.Next() {
		var result scoring.ExposureResult
		var matchedServicesRaw, matchedIngressesRaw []byte

		err := rows.Scan(
			&result.ClusterName, &result.PodUID, &result.PodName, &result.PodNamespace,
			&result.Exposed, &result.Score,
			&matchedServicesRaw, &matchedIngressesRaw,
			&result.SnapshotAt, &result.ComputedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan result: %w", err)
		}

		if len(matchedServicesRaw) > 0 {
			_ = json.Unmarshal(matchedServicesRaw, &result.MatchedServices)
		}
		if len(matchedIngressesRaw) > 0 {
			_ = json.Unmarshal(matchedIngressesRaw, &result.MatchedIngresses)
		}

		out = append(out, result)
	}
	return out, rows.Err()
}
