package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ────────────────────────────────────────────────────
// ClusterNodesRepo — cluster_nodes 테이블 조회 전용
//
// 다른 곳에서 노드 IP를 필요로 할 때 (host_network 추론 등)
// 사용하기 위한 가벼운 repository.
// ────────────────────────────────────────────────────

type ClusterNodesRepo struct {
	pg *pgxpool.Pool
}

func NewClusterNodesRepo(pg *pgxpool.Pool) *ClusterNodesRepo {
	return &ClusterNodesRepo{pg: pg}
}

// GetLatestSnapshot — 클러스터의 최신 노드 스냅샷 시각
func (r *ClusterNodesRepo) GetLatestSnapshot(ctx context.Context, clusterName string) (time.Time, error) {
	const q = `
		SELECT MAX(snapshot_at)
		FROM cluster_nodes
		WHERE cluster_name = $1
	`
	var t *time.Time
	err := r.pg.QueryRow(ctx, q, clusterName).Scan(&t)
	if err != nil && err != pgx.ErrNoRows {
		return time.Time{}, fmt.Errorf("get latest nodes snapshot: %w", err)
	}
	if t == nil {
		return time.Time{}, fmt.Errorf("no node snapshots for cluster %s", clusterName)
	}
	return *t, nil
}

// ListNodeIPs — 클러스터의 모든 노드 IP 목록 (host_network 추론용)
//
// 반환: node name → internal_ip
//
// host_network=true 인 Pod은 pod_ip == 노드의 internal_ip 가 되므로
// 이 맵을 cluster_pods.pod_ip와 매칭해서 추론.
func (r *ClusterNodesRepo) ListNodeIPs(
	ctx context.Context,
	clusterName string,
	snapshotAt time.Time,
) (map[string]string, error) {
	const q = `
		SELECT name, internal_ip
		FROM cluster_nodes
		WHERE cluster_name = $1
		  AND snapshot_at = $2
		  AND internal_ip IS NOT NULL
	`
	rows, err := r.pg.Query(ctx, q, clusterName, snapshotAt)
	if err != nil {
		return nil, fmt.Errorf("query node IPs: %w", err)
	}
	defer rows.Close()

	result := make(map[string]string)
	for rows.Next() {
		var name, ip string
		if err := rows.Scan(&name, &ip); err != nil {
			return nil, fmt.Errorf("scan node IP: %w", err)
		}
		result[name] = ip
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}
	return result, nil
}

// NodeIPSet — 노드 IP 집합 (matching 효율화)
type NodeIPSet map[string]struct{}

// ListNodeIPSet — IP 집합으로 반환 (Pod IP가 host인지 빠르게 확인)
//
// 사용 예시:
//   set, _ := repo.ListNodeIPSet(ctx, clusterName, snapshot)
//   if _, isHostNet := set[podIP]; isHostNet { ... }
func (r *ClusterNodesRepo) ListNodeIPSet(
	ctx context.Context,
	clusterName string,
	snapshotAt time.Time,
) (NodeIPSet, error) {
	const q = `
		SELECT internal_ip
		FROM cluster_nodes
		WHERE cluster_name = $1
		  AND snapshot_at = $2
		  AND internal_ip IS NOT NULL
	`
	rows, err := r.pg.Query(ctx, q, clusterName, snapshotAt)
	if err != nil {
		return nil, fmt.Errorf("query node IP set: %w", err)
	}
	defer rows.Close()

	result := make(NodeIPSet)
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		result[ip] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}
	return result, nil
}

// Contains — IP가 노드 IP 집합에 있는지 (host_network 사용 여부)
func (s NodeIPSet) Contains(ip string) bool {
	if ip == "" {
		return false
	}
	_, ok := s[ip]
	return ok
}
