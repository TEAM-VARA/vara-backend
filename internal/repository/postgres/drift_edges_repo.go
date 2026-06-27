package postgres

import (
	"context"
	"fmt"
	"os"
	"time"
)

// ComputeDriftEdges : NetworkPolicy(선언) vs 실제 통신(eBPF) 위반을
// edges 테이블에 layer='drift', edge_type='violates' 로 적재한다.
//
//   "dst 파드가 어떤 NetworkPolicy의 보호 대상인데,
//    src 파드가 그 정책 허용목록(ingress.from)에 없는 실제 통신" = drift.
//
// - pod_uid 기준 (topology 노드가 pod_uid 라서 그래프에 바로 매칭됨).
// - dst_port < 32768 : 임시포트(응답 방향) 제외, listen 포트만 inbound 로 인정.
// - snapshot_at = NOW() : 다른 Compute*Edges 와 동일. DeleteEdgesBefore(start)에
//   안 쓸리려면 start 이후 시각이어야 함.
// - 매 사이클 layer='drift' 전체 선삭제 후 재적재 (Replace).
func (r *EdgesRepo) ComputeDriftEdges(ctx context.Context, clusterName string) (int64, error) {
	snapAt := time.Now()

	// 1) 이전 사이클 drift 엣지 제거 (layer 한정 — 다른 layer 안 건드림)
	if _, err := r.pool.Exec(ctx,
		`DELETE FROM edges WHERE cluster_name = $1 AND layer = 'drift'`,
		clusterName,
	); err != nil {
		return 0, fmt.Errorf("delete old drift edges: %w", err)
	}

	// 2) 위반 계산 → edges 적재
	const q = `
		WITH latest_np AS (
			SELECT name, namespace, pod_selector, ingress_rules
			FROM cluster_network_policies
			WHERE cluster_name = $1
			  AND snapshot_at = (SELECT MAX(snapshot_at) FROM cluster_network_policies WHERE cluster_name = $1)
		),
		latest_pods AS (
			SELECT pod_uid, name AS pod_name, namespace AS pod_namespace, labels
			FROM cluster_pods
			WHERE cluster_name = $1
			  AND snapshot_at = (SELECT MAX(snapshot_at) FROM cluster_pods WHERE cluster_name = $1)
		),
		target_pods AS (   -- 정책이 보호하는 파드 (dst 후보)
			SELECT np.name AS policy_name, np.namespace,
			       p.pod_uid AS dst_uid, p.pod_name AS dst_name, p.pod_namespace AS dst_ns
			FROM latest_np np
			JOIN latest_pods p
			  ON p.pod_namespace = np.namespace
			 AND p.labels @> COALESCE(np.pod_selector->'matchLabels', '{}'::jsonb)
		),
		allowed_src AS (   -- 정책이 허용하는 src (rule·from 전부 펼침)
			SELECT np.name AS policy_name, np.namespace, p.pod_uid AS ok_src_uid
			FROM latest_np np
			CROSS JOIN LATERAL jsonb_array_elements(COALESCE(np.ingress_rules, '[]'::jsonb)) AS rule
			CROSS JOIN LATERAL jsonb_array_elements(COALESCE(rule->'from', '[]'::jsonb))      AS frm
			JOIN latest_pods p
			  ON p.labels @> (frm->'pod_selector'->'matchLabels')
		),
		-- flow(파드이름)를 uid 로 번역하면서 위반만 추림
		violations AS (
			SELECT
				src.pod_uid       AS source_pod_uid,
				src.pod_name      AS source_name,
				src.pod_namespace AS source_namespace,
				t.dst_uid         AS target_pod_uid,
				t.dst_name        AS target_name,
				t.dst_ns          AS target_namespace,
				t.policy_name     AS policy_name,
				SUM(f.flow_count) AS flow_count
			FROM ebpf_flow_agg f
			JOIN target_pods t
			  ON f.dst_pod_id = t.dst_ns || '/' || t.dst_name
			JOIN latest_pods src
			  ON f.src_pod_id = src.pod_namespace || '/' || src.pod_name
			WHERE f.cluster_name = $1
			  AND f.minute_bucket > NOW() - INTERVAL '30 minutes'
			  AND f.dst_port < 32768
			  AND NOT EXISTS (
				SELECT 1 FROM allowed_src a
				WHERE a.policy_name = t.policy_name
				  AND a.ok_src_uid = src.pod_uid
			  )
			GROUP BY src.pod_uid, src.pod_name, src.pod_namespace,
			         t.dst_uid, t.dst_name, t.dst_ns, t.policy_name
		)
		INSERT INTO edges (
			cluster_name,
			source_pod_uid, target_pod_uid,
			source_name, source_namespace,
			target_name, target_namespace,
			source_kind, target_kind,
			target_type, target_service_name, target_ip,
			layer, edge_type, mode,
			weight, traffic_weight, total_bytes,
			snapshot_at, computed_at
		)
		SELECT
			$1,
			v.source_pod_uid, v.target_pod_uid,
			v.source_name, v.source_namespace,
			v.target_name, v.target_namespace,
			'pod', 'pod',
			'pod', NULL, NULL,
			'drift', 'violates', 'observed',
			1, v.flow_count::real, 0,
			$2::timestamptz, NOW()
		FROM violations v
		ON CONFLICT DO NOTHING
	`
	tag, err := r.pool.Exec(ctx, q, clusterName, snapAt)
	if err != nil {
		return 0, fmt.Errorf("insert drift edges: %w", err)
	}

	// 데모용 drift 시드: DEMO_DRIFT_SEED=true 일 때만, 실재하는 두 파드 사이에 drift 엣지 1건 고정.
	// (매 사이클 재삽입되어 항상 보임. env 끄면 다음 사이클 drift 전삭제로 자동 제거. 끝점이 실재 파드라 dangling 없음.)
	if os.Getenv("DEMO_DRIFT_SEED") == "true" {
		const seed = `
			WITH lp AS (
				SELECT pod_uid, name, namespace FROM cluster_pods
				WHERE cluster_name=$1
				  AND snapshot_at=(SELECT MAX(snapshot_at) FROM cluster_pods WHERE cluster_name=$1)
				  AND name NOT LIKE 'tetragon%' AND name NOT LIKE 'ebs-csi-node%' AND namespace <> 'default'
			),
			dst AS (
				SELECT pod_uid,name,namespace FROM lp
				ORDER BY (name LIKE 'ts-inside-payment-service%') DESC, (name LIKE 'ts-payment-service%') DESC, name
				LIMIT 1
			),
			src AS (
				SELECT p.pod_uid,p.name,p.namespace,
				       ROW_NUMBER() OVER (ORDER BY (p.name LIKE 'ts-gateway-service%') DESC,
				                                   (p.name LIKE 'ts-order-service%') DESC, p.name) AS rn
				FROM lp p, dst WHERE p.pod_uid <> dst.pod_uid
			)
			INSERT INTO edges (
				cluster_name, source_pod_uid, target_pod_uid,
				source_name, source_namespace, target_name, target_namespace,
				source_kind, target_kind, target_type, target_service_name, target_ip,
				layer, edge_type, mode, weight, traffic_weight, total_bytes,
				snapshot_at, computed_at
			)
			SELECT $1, src.pod_uid, dst.pod_uid, src.name, src.namespace, dst.name, dst.namespace,
				'pod','pod','pod','demo-drift-seed',NULL,
				'drift','violates','observed', 1, 1.0, 0, $2::timestamptz, NOW()
			FROM src, dst
			WHERE src.rn <= 2
			ON CONFLICT DO NOTHING`
		if _, err := r.pool.Exec(ctx, seed, clusterName, snapAt); err != nil {
			fmt.Printf("warn: demo drift seed failed: %v\n", err)
		}
	}

	return tag.RowsAffected(), nil
}
