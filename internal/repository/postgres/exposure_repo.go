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
// 조회 데이터:
//   - 최신 snapshot의 cluster_pods
//   - 최신 snapshot의 cluster_services
//   - 최신 snapshot의 cluster_ingresses
//
// 저장 데이터:
//   - exposure_scores (Pod별 판정 결과)
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
	Labels    map[string]string
}

// ServiceSnapshot은 cluster_services 한 행입니다.
type ServiceSnapshot struct {
	Name      string
	Namespace string
	Type      string
	Selector  map[string]string
}

// IngressSnapshot은 cluster_ingresses 한 행에서 추출한
// (host, backend service) 매핑 한 건입니다.
//
// 하나의 Ingress가 여러 host/path/backend를 가질 수 있으므로,
// 본 구조체는 펼쳐진 형태입니다.
type IngressSnapshot struct {
	Name        string
	Namespace   string
	Host        string
	ServiceName string // backend service name
}

// ─────────────────────────────────────────
// 조회 메서드
// ─────────────────────────────────────────

// GetLatestSnapshotAt은 cluster_pods의 최신 snapshot_at을 반환합니다.
// 인터넷 노출 계산 시점에 어느 스냅샷을 기준으로 할지 결정합니다.
func (r *ExposureRepo) GetLatestSnapshotAt(ctx context.Context, clusterName string) (time.Time, error) {
	var snapshotAt time.Time
	err := r.pool.QueryRow(ctx,
		`SELECT MAX(snapshot_at)
		 FROM cluster_pods
		 WHERE cluster_name = $1`,
		clusterName,
	).Scan(&snapshotAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, fmt.Errorf("no snapshots found for cluster %s", clusterName)
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("get latest snapshot: %w", err)
	}
	if snapshotAt.IsZero() {
		return time.Time{}, fmt.Errorf("no snapshots found for cluster %s", clusterName)
	}
	return snapshotAt, nil
}

// ListPodsAtSnapshot은 특정 snapshot의 모든 Pod을 반환합니다.
func (r *ExposureRepo) ListPodsAtSnapshot(ctx context.Context, clusterName string, snapshotAt time.Time) ([]PodSnapshot, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT pod_uid, name, namespace, COALESCE(labels, '{}'::jsonb)
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
		if err := rows.Scan(&p.PodUID, &p.Name, &p.Namespace, &labelsRaw); err != nil {
			return nil, fmt.Errorf("scan pod: %w", err)
		}
		// labels JSONB → map[string]string
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
func (r *ExposureRepo) ListServicesAtSnapshot(ctx context.Context, clusterName string, snapshotAt time.Time) ([]ServiceSnapshot, error) {
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

// ListIngressBackendsAtSnapshot은 특정 snapshot의 Ingress에서
// (Service 매핑) 정보를 펼쳐서 반환합니다.
//
// 하나의 Ingress가 N개 host * M개 path를 가질 수 있으므로
// 각 path별 backend service를 한 row로 펼칩니다.
//
// cluster_ingresses.rules JSONB 구조:
//
//	[
//	  {
//	    "host": "example.com",
//	    "paths": [
//	      {"path": "/", "service_name": "nginx-svc", "service_port": 80}
//	    ]
//	  }
//	]
func (r *ExposureRepo) ListIngressBackendsAtSnapshot(ctx context.Context, clusterName string, snapshotAt time.Time) ([]IngressSnapshot, error) {
	// jsonb_path_query로 host + service_name 펼치기
	// 일부 Ingress는 host가 없을 수 있음 (default backend) → COALESCE
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
// 저장 메서드
// ─────────────────────────────────────────

// UpsertExposureResult는 단일 Pod의 계산 결과를 저장합니다.
// 같은 (cluster_name, pod_uid, snapshot_at)이면 갱신합니다.
func (r *ExposureRepo) UpsertExposureResult(ctx context.Context, result scoring.ExposureResult) error {
	matchedServicesJSON, _ := json.Marshal(result.MatchedServices)
	if matchedServicesJSON == nil {
		matchedServicesJSON = []byte("[]")
	}
	matchedIngressesJSON, _ := json.Marshal(result.MatchedIngresses)
	if matchedIngressesJSON == nil {
		matchedIngressesJSON = []byte("[]")
	}

	_, err := r.pool.Exec(ctx,
		`INSERT INTO exposure_scores (
			cluster_name, pod_uid, pod_name, pod_namespace,
			exposed, score,
			matched_services, matched_ingresses,
			snapshot_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9
		)
		ON CONFLICT (cluster_name, pod_uid, snapshot_at) DO UPDATE SET
			pod_name          = EXCLUDED.pod_name,
			pod_namespace     = EXCLUDED.pod_namespace,
			exposed           = EXCLUDED.exposed,
			score             = EXCLUDED.score,
			matched_services  = EXCLUDED.matched_services,
			matched_ingresses = EXCLUDED.matched_ingresses,
			computed_at       = NOW()`,
		result.ClusterName, result.PodUID, result.PodName, result.PodNamespace,
		result.Exposed, result.Score,
		matchedServicesJSON, matchedIngressesJSON,
		result.SnapshotAt,
	)
	if err != nil {
		return fmt.Errorf("upsert exposure result: %w", err)
	}
	return nil
}

// UpsertExposureBatch는 여러 결과를 배치로 저장합니다.
// 트랜잭션으로 묶어서 일관성 보장.
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
			snapshot_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9
		)
		ON CONFLICT (cluster_name, pod_uid, snapshot_at) DO UPDATE SET
			pod_name          = EXCLUDED.pod_name,
			pod_namespace     = EXCLUDED.pod_namespace,
			exposed           = EXCLUDED.exposed,
			score             = EXCLUDED.score,
			matched_services  = EXCLUDED.matched_services,
			matched_ingresses = EXCLUDED.matched_ingresses,
			computed_at       = NOW()
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

		_, err := tx.Exec(ctx, q,
			result.ClusterName, result.PodUID, result.PodName, result.PodNamespace,
			result.Exposed, result.Score,
			matchedServicesJSON, matchedIngressesJSON,
			result.SnapshotAt,
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
// 같은 Pod에 여러 snapshot 결과가 있으면 가장 최근 것 반환.
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
	// 가장 최근 snapshot_at 찾기
	var latestSnapshot time.Time
	err := r.pool.QueryRow(ctx,
		`SELECT MAX(snapshot_at) FROM exposure_scores WHERE cluster_name = $1`,
		clusterName,
	).Scan(&latestSnapshot)

	if errors.Is(err, pgx.ErrNoRows) || latestSnapshot.IsZero() {
		return []scoring.ExposureResult{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get latest snapshot: %w", err)
	}

	rows, err := r.pool.Query(ctx,
		`SELECT cluster_name, pod_uid, pod_name, pod_namespace,
		        exposed, score,
		        matched_services, matched_ingresses,
		        snapshot_at, computed_at
		 FROM exposure_scores
		 WHERE cluster_name = $1 AND snapshot_at = $2
		 ORDER BY exposed DESC, pod_namespace, pod_name`,
		clusterName, latestSnapshot,
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
