package postgres

import (
	"context"
	"fmt"
	"time"
)

// DriftFeedItem : NetworkPolicy(선언) vs 실제 통신(eBPF) 위반 1건.
// 파드 단위로 내보냄 (FE 그래프 노드가 파드 단위라 그대로 매칭).
type DriftFeedItem struct {
	SrcPod     string    `json:"src_pod"`     // 위반한 출발 파드 "ns/pod"
	DstPod     string    `json:"dst_pod"`     // 정책이 보호하는 도착 파드 "ns/pod"
	DstPort    int       `json:"dst_port"`    // 도착 listen 포트
	PolicyName string    `json:"policy_name"` // 어긴 NetworkPolicy 이름
	FlowCount  int64     `json:"flow_count"`  // 그 위반 통신 누적 횟수
	LastSeen   time.Time `json:"last_seen"`   // 마지막 위반 시각
}

// QueryDriftFeed : 정책 위반(drift) 조회.
//   "dst 파드가 어떤 NetworkPolicy의 보호 대상인데,
//    src 파드가 그 정책의 허용목록(ingress.from)에 없는 실제 통신" = drift.
//
// 키는 cluster_name 으로 통일 (network_policies/pods 엔 customer_id 가 없음).
// dst_port < 32768 : 임시포트(응답 방향) 제외, listen 포트만 inbound 로 인정.
func (r *EbpfRepo) QueryDriftFeed(
	ctx context.Context, clusterName string, since time.Time, limit int,
) ([]DriftFeedItem, error) {
	const q = `
		WITH latest_np AS (
			SELECT name, namespace, pod_selector, ingress_rules
			FROM cluster_network_policies
			WHERE cluster_name = $1
			  AND snapshot_at = (
				SELECT max(snapshot_at) FROM cluster_network_policies WHERE cluster_name = $1
			  )
		),
		latest_pods AS (
			SELECT name, namespace, labels
			FROM cluster_pods
			WHERE cluster_name = $1
			  AND snapshot_at = (
				SELECT max(snapshot_at) FROM cluster_pods WHERE cluster_name = $1
			  )
		),
		target_pods AS (
			SELECT np.name AS policy_name, np.namespace, p.name AS dst_pod
			FROM latest_np np
			JOIN latest_pods p
			  ON p.namespace = np.namespace
			 AND p.labels @> (np.pod_selector -> 'matchLabels')
		),
		allowed_src AS (
			SELECT np.name AS policy_name, np.namespace, p.name AS ok_src
			FROM latest_np np
			CROSS JOIN LATERAL jsonb_array_elements(COALESCE(np.ingress_rules, '[]'::jsonb)) AS rule
			CROSS JOIN LATERAL jsonb_array_elements(COALESCE(rule->'from', '[]'::jsonb))      AS frm
			JOIN latest_pods p
			  ON p.namespace = np.namespace
			 AND p.labels @> (frm -> 'pod_selector' -> 'matchLabels')
		)
		SELECT
			f.src_pod_id,
			f.dst_pod_id,
			f.dst_port,
			t.policy_name,
			COALESCE(sum(f.flow_count), 0) AS flow_count,
			max(f.last_seen)               AS last_seen
		FROM ebpf_flow_agg f
		JOIN target_pods t
		  ON f.dst_pod_id = t.namespace || '/' || t.dst_pod
		WHERE f.cluster_name = $1
		  AND f.minute_bucket > $2
		  AND f.dst_port < 32768
		  AND NOT EXISTS (
			SELECT 1 FROM allowed_src a
			WHERE a.policy_name = t.policy_name
			  AND f.src_pod_id = a.namespace || '/' || a.ok_src
		  )
		GROUP BY f.src_pod_id, f.dst_pod_id, f.dst_port, t.policy_name
		ORDER BY last_seen DESC
		LIMIT $3
	`
	rows, err := r.pg.Query(ctx, q, clusterName, since, limit)
	if err != nil {
		return nil, fmt.Errorf("query drift feed: %w", err)
	}
	defer rows.Close()

	items := make([]DriftFeedItem, 0)
	for rows.Next() {
		var it DriftFeedItem
		if err := rows.Scan(
			&it.SrcPod, &it.DstPod, &it.DstPort,
			&it.PolicyName, &it.FlowCount, &it.LastSeen,
		); err != nil {
			return nil, fmt.Errorf("scan drift feed: %w", err)
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iter: %w", err)
	}
	return items, nil
}
