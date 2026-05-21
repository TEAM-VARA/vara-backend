package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vara/backend/internal/domain/edge"
)

// ────────────────────────────────────────────────────
// EdgesRepo — edges 테이블 CRUD + ebpf_network_flows 집계
// ────────────────────────────────────────────────────

type EdgesRepo struct {
	pool *pgxpool.Pool
}

func NewEdgesRepo(pool *pgxpool.Pool) *EdgesRepo {
	return &EdgesRepo{pool: pool}
}

// ────────────────────────────────────────────────────
// 핵심 — ebpf_network_flows를 edges로 집계
// ────────────────────────────────────────────────────

// AggregatedEdge — 집계 쿼리 결과 (raw)
type AggregatedEdge struct {
	SourcePodUID    string
	SourceName      string
	SourceNamespace string
	TargetPodUID    string
	TargetName      string
	TargetNamespace string
	Weight          int
	FirstSeenAt     time.Time
	LastSeenAt      time.Time
}

// AggregateFromEBPFFlows — ebpf_network_flows를 GROUP BY로 집계
//
// 처리 단계:
//   1. ebpf_network_flows에서 최근 windowMinutes 분 데이터 가져옴
//   2. src_pod_id → cluster_pods로 source Pod uid/name/namespace 매핑
//   3. dst_ip → cluster_pods.pod_ip로 target Pod uid/name/namespace 매핑
//   4. 매칭 실패 (외부 IP 등)는 제외
//   5. excludePatterns에 해당하는 Pod 제외 (자기 자신)
//   6. GROUP BY (src_pod_uid, target_pod_uid) → weight 집계
//
// 입력:
//   clusterName        : 분석 대상 클러스터
//   windowMinutes      : 시간 윈도우 (분)
//   excludePatterns    : 제외할 src_pod_id prefix (예: "default/vara-ebpf-agent-")
//
// 반환:
//   집계된 edges (Pod-to-Pod 쌍별로 1개)
//   처리한 raw flow 수
//   매칭/제외로 스킵된 flow 수
func (r *EdgesRepo) AggregateFromEBPFFlows(
	ctx context.Context,
	clusterName string,
	windowMinutes int,
	excludePatterns []string,
) ([]AggregatedEdge, int, int, error) {
	since := time.Now().Add(-time.Duration(windowMinutes) * time.Minute)

	// cluster_pods 최신 snapshot
	const podsSnapshotSQL = `
		SELECT MAX(snapshot_at) FROM cluster_pods WHERE cluster_name = $1
	`
	var podsSnapshot *time.Time
	if err := r.pool.QueryRow(ctx, podsSnapshotSQL, clusterName).Scan(&podsSnapshot); err != nil {
		return nil, 0, 0, fmt.Errorf("get pods snapshot: %w", err)
	}
	if podsSnapshot == nil {
		// cluster_pods 데이터 자체가 없음
		return nil, 0, 0, nil
	}

	// 메인 집계 쿼리
	// - src_pods : src_pod_id (namespace/name) 로 매칭
	// - dst_pods : dst_ip = pod_ip 로 매칭
	// - 둘 다 매칭된 경우만 edges 생성 (Pod-to-Pod)
	// - 제외 패턴 적용 (src_pod_id LIKE ANY(...))
	const aggregateSQL = `
		WITH window_flows AS (
			SELECT
				src_pod_id,
				src_ip,
				dst_ip,
				timestamp
			FROM ebpf_network_flows
			WHERE cluster_name = $1
			  AND timestamp >= $2
			  AND src_pod_id IS NOT NULL
			  AND src_pod_id != ''
		),
		-- src_pod_id ("namespace/name") → cluster_pods 매칭
		flows_with_src AS (
			SELECT
				wf.src_pod_id,
				wf.src_ip,
				wf.dst_ip,
				wf.timestamp,
				sp.pod_uid AS src_pod_uid,
				sp.name AS src_name,
				sp.namespace AS src_namespace
			FROM window_flows wf
			JOIN cluster_pods sp 
			  ON sp.cluster_name = $1
			  AND sp.snapshot_at = $3
			  AND wf.src_pod_id = sp.namespace || '/' || sp.name
		),
		-- dst_ip → cluster_pods.pod_ip 매칭
		flows_with_dst AS (
			SELECT
				fws.*,
				dp.pod_uid AS dst_pod_uid,
				dp.name AS dst_name,
				dp.namespace AS dst_namespace
			FROM flows_with_src fws
			JOIN cluster_pods dp
			  ON dp.cluster_name = $1
			  AND dp.snapshot_at = $3
			  AND dp.pod_ip = fws.dst_ip
			  AND dp.pod_ip != ''
		)
		SELECT
			src_pod_uid, src_name, src_namespace,
			dst_pod_uid, dst_name, dst_namespace,
			COUNT(*) AS weight,
			MIN(timestamp) AS first_seen_at,
			MAX(timestamp) AS last_seen_at
		FROM flows_with_dst
		WHERE src_pod_uid != dst_pod_uid  -- 자기 자신과의 통신 제외
		GROUP BY src_pod_uid, src_name, src_namespace,
		         dst_pod_uid, dst_name, dst_namespace
	`

	rows, err := r.pool.Query(ctx, aggregateSQL, clusterName, since, *podsSnapshot)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("aggregate query: %w", err)
	}
	defer rows.Close()

	var edges []AggregatedEdge
	for rows.Next() {
		var e AggregatedEdge
		if err := rows.Scan(
			&e.SourcePodUID, &e.SourceName, &e.SourceNamespace,
			&e.TargetPodUID, &e.TargetName, &e.TargetNamespace,
			&e.Weight, &e.FirstSeenAt, &e.LastSeenAt,
		); err != nil {
			return nil, 0, 0, fmt.Errorf("scan edge: %w", err)
		}

		// 제외 패턴 적용 (src 기준)
		// excludePatterns 예: "default/vara-ebpf-agent-"
		srcKey := e.SourceNamespace + "/" + e.SourceName
		dstKey := e.TargetNamespace + "/" + e.TargetName
		if matchesAnyPrefix(srcKey, excludePatterns) || matchesAnyPrefix(dstKey, excludePatterns) {
			continue
		}

		edges = append(edges, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, 0, fmt.Errorf("rows error: %w", err)
	}

	// 전체 처리한 flow 수 + 스킵된 수 (디버깅용)
	processedFlows, skippedFlows, err := r.countFlows(ctx, clusterName, since, *podsSnapshot)
	if err != nil {
		// 통계는 실패해도 무시 (메인 결과는 OK)
		fmt.Printf("warn: count flows: %v\n", err)
	}

	return edges, processedFlows, skippedFlows, nil
}

// matchesAnyPrefix — Pod 키가 제외 패턴 중 하나와 매칭하는지
func matchesAnyPrefix(podKey string, patterns []string) bool {
	for _, p := range patterns {
		if len(podKey) >= len(p) && podKey[:len(p)] == p {
			return true
		}
	}
	return false
}

// countFlows — 처리 통계 (성공/스킵)
func (r *EdgesRepo) countFlows(
	ctx context.Context,
	clusterName string,
	since time.Time,
	podsSnapshot time.Time,
) (processed, skipped int, err error) {
	const sql = `
		WITH window_flows AS (
			SELECT src_pod_id, dst_ip
			FROM ebpf_network_flows
			WHERE cluster_name = $1 AND timestamp >= $2
		),
		matched AS (
			SELECT wf.*
			FROM window_flows wf
			JOIN cluster_pods sp 
			  ON sp.cluster_name = $1 AND sp.snapshot_at = $3
			  AND wf.src_pod_id = sp.namespace || '/' || sp.name
			JOIN cluster_pods dp
			  ON dp.cluster_name = $1 AND dp.snapshot_at = $3
			  AND dp.pod_ip = wf.dst_ip
		)
		SELECT
			(SELECT COUNT(*) FROM window_flows) AS total,
			(SELECT COUNT(*) FROM matched) AS matched_count
	`
	var total, matched int
	if err := r.pool.QueryRow(ctx, sql, clusterName, since, podsSnapshot).Scan(&total, &matched); err != nil {
		return 0, 0, err
	}
	return matched, total - matched, nil
}

// ────────────────────────────────────────────────────
// Upsert 결과 저장
// ────────────────────────────────────────────────────

// UpsertEdges — edges 일괄 저장 (snapshot_at 기준 upsert)
//
// 같은 (cluster, src, dst, layer, snapshot_at)이면 UPDATE,
// 다르면 INSERT.
func (r *EdgesRepo) UpsertEdges(
	ctx context.Context,
	clusterName string,
	layer string,
	snapshotAt time.Time,
	aggregated []AggregatedEdge,
) error {
	if len(aggregated) == 0 {
		return nil
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	trafficWeight := edge.LayerWeight(layer)

	const q = `
		INSERT INTO edges (
			cluster_name,
			source_pod_uid, target_pod_uid, layer,
			weight, traffic_weight,
			source_name, source_namespace,
			target_name, target_namespace,
			first_seen_at, last_seen_at,
			snapshot_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
		)
		ON CONFLICT (cluster_name, source_pod_uid, target_pod_uid, layer, snapshot_at) 
		DO UPDATE SET
			weight           = EXCLUDED.weight,
			traffic_weight   = EXCLUDED.traffic_weight,
			source_name      = EXCLUDED.source_name,
			source_namespace = EXCLUDED.source_namespace,
			target_name      = EXCLUDED.target_name,
			target_namespace = EXCLUDED.target_namespace,
			first_seen_at    = LEAST(edges.first_seen_at, EXCLUDED.first_seen_at),
			last_seen_at     = GREATEST(edges.last_seen_at, EXCLUDED.last_seen_at),
			computed_at      = NOW()
	`

	for _, e := range aggregated {
		_, err := tx.Exec(ctx, q,
			clusterName,
			e.SourcePodUID, e.TargetPodUID, layer,
			e.Weight, trafficWeight,
			e.SourceName, e.SourceNamespace,
			e.TargetName, e.TargetNamespace,
			e.FirstSeenAt, e.LastSeenAt,
			snapshotAt,
		)
		if err != nil {
			return fmt.Errorf("upsert edge %s→%s: %w", e.SourcePodUID, e.TargetPodUID, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// ────────────────────────────────────────────────────
// 조회
// ────────────────────────────────────────────────────

// ListByCluster — 클러스터의 모든 edges (최신 snapshot)
func (r *EdgesRepo) ListByCluster(ctx context.Context, clusterName string) ([]edge.Edge, error) {
	const q = `
		WITH latest AS (
			SELECT MAX(snapshot_at) AS snap FROM edges WHERE cluster_name = $1
		)
		SELECT 
			id, cluster_name,
			source_pod_uid, target_pod_uid, layer,
			weight, traffic_weight,
			COALESCE(source_name, ''), COALESCE(source_namespace, ''),
			COALESCE(target_name, ''), COALESCE(target_namespace, ''),
			first_seen_at, last_seen_at,
			snapshot_at, computed_at
		FROM edges, latest
		WHERE cluster_name = $1
		  AND snapshot_at = latest.snap
		ORDER BY weight DESC
	`

	rows, err := r.pool.Query(ctx, q, clusterName)
	if err != nil {
		return nil, fmt.Errorf("list edges: %w", err)
	}
	defer rows.Close()

	var out []edge.Edge
	for rows.Next() {
		var e edge.Edge
		if err := rows.Scan(
			&e.ID, &e.ClusterName,
			&e.Source, &e.Target, &e.Layer,
			&e.Weight, &e.TrafficWeight,
			&e.SourceName, &e.SourceNamespace,
			&e.TargetName, &e.TargetNamespace,
			&e.FirstSeenAt, &e.LastSeenAt,
			&e.SnapshotAt, &e.ComputedAt,
		); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		e.DisplayID = edge.FormatDisplayID(e.ID)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListByPod — 특정 Pod이 source 또는 target인 edges
func (r *EdgesRepo) ListByPod(ctx context.Context, clusterName, podUID string) ([]edge.Edge, error) {
	const q = `
		WITH latest AS (
			SELECT MAX(snapshot_at) AS snap FROM edges WHERE cluster_name = $1
		)
		SELECT 
			id, cluster_name,
			source_pod_uid, target_pod_uid, layer,
			weight, traffic_weight,
			COALESCE(source_name, ''), COALESCE(source_namespace, ''),
			COALESCE(target_name, ''), COALESCE(target_namespace, ''),
			first_seen_at, last_seen_at,
			snapshot_at, computed_at
		FROM edges, latest
		WHERE cluster_name = $1
		  AND snapshot_at = latest.snap
		  AND (source_pod_uid = $2 OR target_pod_uid = $2)
		ORDER BY weight DESC
	`

	rows, err := r.pool.Query(ctx, q, clusterName, podUID)
	if err != nil {
		return nil, fmt.Errorf("list edges by pod: %w", err)
	}
	defer rows.Close()

	var out []edge.Edge
	for rows.Next() {
		var e edge.Edge
		if err := rows.Scan(
			&e.ID, &e.ClusterName,
			&e.Source, &e.Target, &e.Layer,
			&e.Weight, &e.TrafficWeight,
			&e.SourceName, &e.SourceNamespace,
			&e.TargetName, &e.TargetNamespace,
			&e.FirstSeenAt, &e.LastSeenAt,
			&e.SnapshotAt, &e.ComputedAt,
		); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		e.DisplayID = edge.FormatDisplayID(e.ID)
		out = append(out, e)
	}
	return out, rows.Err()
}
