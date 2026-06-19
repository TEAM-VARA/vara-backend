package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vara/backend/internal/blastedge"
)

// BlastEdgesRepo — blast_edges 테이블 적재 + 입력 로딩.
// 엣지 계산 자체는 internal/blastedge(순수 로직), 여기는 DB I/O만.
// 설계: docs/blast-channels-spec.md (§8 = blast_edges)
type BlastEdgesRepo struct {
	pool *pgxpool.Pool
}

func NewBlastEdgesRepo(pool *pgxpool.Pool) *BlastEdgesRepo {
	return &BlastEdgesRepo{pool: pool}
}

// LoadPods — cluster_pods 최신 snapshot의 pod facts + final_scores 기반 B.Risk를 적재.
//
// B.Risk = final_scores.final_score / 100  (0~1).
// 주의: final_score는 준서형 Risk Score를 그대로 사용 — attack-path 제거 작업이
// 완료되면 순수 likelihood가 된다(그 전까진 impact가 약간 섞인 값).
//
// v1 단순화:
//   - HostPath = false (privileged-only 탈출 신호; 민감경로 hostPath는 추후)
//   - HasSAToken = true (automount 기본 true 가정; automount=false 탐지는 추후)
func (r *BlastEdgesRepo) LoadPods(ctx context.Context, cluster string) (map[string]blastedge.PodFact, time.Time, error) {
	var snap *time.Time
	if err := r.pool.QueryRow(ctx,
		`SELECT MAX(snapshot_at) FROM cluster_pods WHERE cluster_name = $1`, cluster,
	).Scan(&snap); err != nil {
		return nil, time.Time{}, fmt.Errorf("blast: latest pod snapshot: %w", err)
	}
	if snap == nil {
		return map[string]blastedge.PodFact{}, time.Time{}, nil
	}

	rows, err := r.pool.Query(ctx, `
		SELECT p.pod_uid, p.name, p.namespace,
		       COALESCE(p.node, ''), COALESCE(p.phase, ''),
		       COALESCE(p.service_account, ''),
		       COALESCE(p.containers, '[]'::jsonb),
		       COALESCE(f.final_score, 0)
		FROM cluster_pods p
		LEFT JOIN final_scores f
		       ON f.cluster_name = p.cluster_name
		      AND f.pod_uid      = p.pod_uid
		      AND f.snapshot_at  = (SELECT MAX(snapshot_at) FROM final_scores WHERE cluster_name = p.cluster_name)
		WHERE p.cluster_name = $1 AND p.snapshot_at = $2`,
		cluster, *snap,
	)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("blast: load pods: %w", err)
	}
	defer rows.Close()

	out := map[string]blastedge.PodFact{}
	for rows.Next() {
		var uid, name, ns, node, phase, sa string
		var containersRaw []byte
		var finalScore float64
		if err := rows.Scan(&uid, &name, &ns, &node, &phase, &sa, &containersRaw, &finalScore); err != nil {
			return nil, time.Time{}, fmt.Errorf("blast: scan pod: %w", err)
		}

		saName := sa
		if saName == "" {
			saName = "default"
		}

		privileged := false
		for _, c := range parseContainers(containersRaw) { // attack_path_repo.go 재사용
			if c.Privileged {
				privileged = true
				break
			}
		}

		risk := finalScore / 100.0
		if risk < 0 {
			risk = 0
		} else if risk > 1 {
			risk = 1
		}

		out[uid] = blastedge.PodFact{
			UID:         uid,
			Name:        name,
			Namespace:   ns,
			Node:        node,
			Running:     phase == "Running",
			SANamespace: ns,
			SAName:      saName,
			Privileged:  privileged,
			HostPath:    false, // v1: privileged-only
			HasSAToken:  true,  // v1: automount 기본 true 가정
			Risk:        risk,
		}
	}
	return out, *snap, rows.Err()
}

// LoadPerms — rbac_sa_permissions(최종 권한)을 "saNamespace/saName" → []Perm 로 적재.
// (escalation-aware final 권한집합. value(B)용 initial은 v1에서 불필요.)
func (r *BlastEdgesRepo) LoadPerms(ctx context.Context, cluster string) (map[string][]blastedge.Perm, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT sa_namespace, sa_name, api_group, resource, verb, namespace, resource_name
		FROM rbac_sa_permissions
		WHERE cluster_name = $1`,
		cluster,
	)
	if err != nil {
		return nil, fmt.Errorf("blast: load perms: %w", err)
	}
	defer rows.Close()

	out := map[string][]blastedge.Perm{}
	for rows.Next() {
		var saNS, saName, apiGroup, resource, verb string
		var nsp, rn *string
		if err := rows.Scan(&saNS, &saName, &apiGroup, &resource, &verb, &nsp, &rn); err != nil {
			return nil, fmt.Errorf("blast: scan perm: %w", err)
		}
		key := saNS + "/" + saName
		out[key] = append(out[key], blastedge.Perm{
			APIGroup:     apiGroup,
			Resource:     resource,
			Verb:         verb,
			Namespace:    nsp,
			ResourceName: rn,
		})
	}
	return out, rows.Err()
}

// LoadObservedFlows — 관측된 pod→pod 네트워크 연결을 edges 테이블에서 가져온다.
// eBPF를 직접 집계하지 않고, Phase 1 ComputeNetworkEdges가 이미 적재한
// edge_type='connects_to' ∧ mode='observed' 행(최신 snapshot)을 재사용한다. directed src→dst.
func (r *BlastEdgesRepo) LoadObservedFlows(ctx context.Context, cluster string) ([]blastedge.Flow, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT source_pod_uid, target_pod_uid
		FROM edges
		WHERE cluster_name = $1
		  AND edge_type = 'connects_to'
		  AND mode = 'observed'
		  AND snapshot_at = (
		      SELECT MAX(snapshot_at) FROM edges
		      WHERE cluster_name = $1 AND edge_type = 'connects_to' AND mode = 'observed'
		  )`,
		cluster,
	)
	if err != nil {
		return nil, fmt.Errorf("blast: load observed flows: %w", err)
	}
	defer rows.Close()

	var out []blastedge.Flow
	for rows.Next() {
		var src, dst string
		if err := rows.Scan(&src, &dst); err != nil {
			return nil, fmt.Errorf("blast: scan flow: %w", err)
		}
		if src == "" || dst == "" || src == dst {
			continue
		}
		out = append(out, blastedge.Flow{SrcUID: src, DstUID: dst})
	}
	return out, rows.Err()
}

// BlastOutEdge — source pod 1개의 outgoing 전파 엣지 1건 (시나리오용 읽기 뷰).
type BlastOutEdge struct {
	TargetPodUID    string
	TargetName      string
	TargetNamespace string
	WinChannel      string // host | rbac | network
	Reason          string
	PEdge           float64
}

// GetOutgoingBySource — 한 source pod에서 나가는 전파 엣지를 최신 snapshot 기준으로 읽는다.
// p_edge 내림차순(강한 엣지 우선)으로 반환. 결과 없으면 빈 슬라이스.
// 공격 시나리오의 outgoing(전파) 섹션을 구성하는 데 쓴다. (idx_blast_edges_source 사용)
func (r *BlastEdgesRepo) GetOutgoingBySource(ctx context.Context, cluster, sourcePodUID string) ([]BlastOutEdge, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT target_pod_uid, COALESCE(target_name, ''), COALESCE(target_namespace, ''),
		       win_channel, COALESCE(reason, ''), p_edge
		FROM blast_edges
		WHERE cluster_name = $1 AND source_pod_uid = $2
		  AND snapshot_at = (
		      SELECT MAX(snapshot_at) FROM blast_edges WHERE cluster_name = $1
		  )
		ORDER BY p_edge DESC`,
		cluster, sourcePodUID,
	)
	if err != nil {
		return nil, fmt.Errorf("blast: get outgoing by source: %w", err)
	}
	defer rows.Close()

	var out []BlastOutEdge
	for rows.Next() {
		var e BlastOutEdge
		if err := rows.Scan(&e.TargetPodUID, &e.TargetName, &e.TargetNamespace,
			&e.WinChannel, &e.Reason, &e.PEdge); err != nil {
			return nil, fmt.Errorf("blast: scan outgoing edge: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Replace — 해당 (cluster, snapshot)의 blast_edges를 통째로 교체(삭제 후 일괄 삽입).
// src/dst 표시용 name/namespace는 pods에서 채운다. 적재된 행 수를 반환.
func (r *BlastEdgesRepo) Replace(
	ctx context.Context,
	cluster string,
	snapshot time.Time,
	edges []blastedge.Edge,
	pods map[string]blastedge.PodFact,
) (int, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("blast: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // commit 후엔 no-op

	if _, err := tx.Exec(ctx,
		`DELETE FROM blast_edges WHERE cluster_name = $1 AND snapshot_at = $2`,
		cluster, snapshot,
	); err != nil {
		return 0, fmt.Errorf("blast: delete old: %w", err)
	}

	cols := []string{
		"cluster_name", "source_pod_uid", "target_pod_uid",
		"p_host", "p_rbac", "p_net", "p_edge", "neg_log_p", "win_channel", "reason", "dst_value",
		"source_name", "source_namespace", "target_name", "target_namespace", "snapshot_at",
	}
	data := make([][]any, 0, len(edges))
	for _, e := range edges {
		s := pods[e.SrcUID]
		d := pods[e.DstUID]
		data = append(data, []any{
			cluster, e.SrcUID, e.DstUID,
			e.PHost, e.PRBAC, e.PNet, e.PEdge, e.NegLogP, e.WinChannel, e.Reason, e.DstValue,
			s.Name, s.Namespace, d.Name, d.Namespace, snapshot,
		})
	}

	n, err := tx.CopyFrom(ctx, pgx.Identifier{"blast_edges"}, cols, pgx.CopyFromRows(data))
	if err != nil {
		return 0, fmt.Errorf("blast: copy rows: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("blast: commit: %w", err)
	}
	return int(n), nil
}
