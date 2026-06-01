package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AnalysisCacheRepo는 그래프 분석 사전계산 결과 캐시를 담당합니다.
// (pod_blast_radius, node_centrality, attack_path_cache)
type AnalysisCacheRepo struct {
	pool *pgxpool.Pool
}

func NewAnalysisCacheRepo(pool *pgxpool.Pool) *AnalysisCacheRepo {
	return &AnalysisCacheRepo{pool: pool}
}

// ─────────────────────────────────────────
// Blast Radius
// ─────────────────────────────────────────

type BlastRadiusRow struct {
	PodUID         string         `json:"pod_uid"`
	ReachableCount int            `json:"reachable_count"`
	ReachablePods  []string       `json:"reachable_pods"`
	BlastScore     float64        `json:"blast_score"`
	ByLayer        map[string]int `json:"by_layer"`
}

// UpsertBlastRadiusBatch는 클러스터의 모든 Pod blast radius를 교체합니다.
func (r *AnalysisCacheRepo) UpsertBlastRadiusBatch(ctx context.Context, cluster string, rows []BlastRadiusRow) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// 기존 데이터 삭제 (전체 재계산)
	if _, err := tx.Exec(ctx, `DELETE FROM pod_blast_radius WHERE cluster_name = $1`, cluster); err != nil {
		return fmt.Errorf("delete old blast radius: %w", err)
	}

	for _, row := range rows {
		reachableJSON, _ := json.Marshal(row.ReachablePods)
		byLayerJSON, _ := json.Marshal(row.ByLayer)

		_, err := tx.Exec(ctx, `
			INSERT INTO pod_blast_radius 
				(cluster_name, pod_uid, reachable_count, reachable_pods, blast_score, by_layer, computed_at)
			VALUES ($1, $2, $3, $4, $5, $6, NOW())
		`, cluster, row.PodUID, row.ReachableCount, reachableJSON, row.BlastScore, byLayerJSON)
		if err != nil {
			return fmt.Errorf("insert blast radius for %s: %w", row.PodUID, err)
		}
	}

	return tx.Commit(ctx)
}

// GetBlastRadius는 특정 Pod의 캐시된 blast radius를 반환합니다.
func (r *AnalysisCacheRepo) GetBlastRadius(ctx context.Context, cluster, podUID string) (*BlastRadiusRow, error) {
	const query = `
		SELECT pod_uid, reachable_count, reachable_pods, blast_score, by_layer
		FROM pod_blast_radius
		WHERE cluster_name = $1 AND pod_uid = $2
	`

	var row BlastRadiusRow
	var reachableJSON, byLayerJSON []byte

	err := r.pool.QueryRow(ctx, query, cluster, podUID).Scan(
		&row.PodUID, &row.ReachableCount, &reachableJSON, &row.BlastScore, &byLayerJSON,
	)
	if err != nil {
		return nil, nil // 캐시 miss (에러 아님)
	}

	json.Unmarshal(reachableJSON, &row.ReachablePods)
	json.Unmarshal(byLayerJSON, &row.ByLayer)

	return &row, nil
}

// ─────────────────────────────────────────
// Centrality (PageRank + Betweenness)
// ─────────────────────────────────────────

type CentralityRow struct {
	NodeID      string  `json:"node_id"`
	Label       string  `json:"label"`
	Kind        string  `json:"kind"`
	PageRank    float64 `json:"pagerank"`
	Betweenness float64 `json:"betweenness"`
}

// UpsertCentralityBatch는 클러스터의 모든 노드 중요도를 교체합니다.
func (r *AnalysisCacheRepo) UpsertCentralityBatch(ctx context.Context, cluster string, rows []CentralityRow) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM node_centrality WHERE cluster_name = $1`, cluster); err != nil {
		return fmt.Errorf("delete old centrality: %w", err)
	}

	for _, row := range rows {
		_, err := tx.Exec(ctx, `
			INSERT INTO node_centrality 
				(cluster_name, node_id, label, kind, pagerank, betweenness, computed_at)
			VALUES ($1, $2, $3, $4, $5, $6, NOW())
		`, cluster, row.NodeID, row.Label, row.Kind, row.PageRank, row.Betweenness)
		if err != nil {
			return fmt.Errorf("insert centrality for %s: %w", row.NodeID, err)
		}
	}

	return tx.Commit(ctx)
}

// GetTopByPageRank는 PageRank 상위 N개 노드를 반환합니다.
func (r *AnalysisCacheRepo) GetTopByPageRank(ctx context.Context, cluster string, topN int) ([]CentralityRow, error) {
	return r.getTopBy(ctx, cluster, "pagerank", topN)
}

// GetTopByBetweenness는 Betweenness 상위 N개 노드를 반환합니다.
func (r *AnalysisCacheRepo) GetTopByBetweenness(ctx context.Context, cluster string, topN int) ([]CentralityRow, error) {
	return r.getTopBy(ctx, cluster, "betweenness", topN)
}

func (r *AnalysisCacheRepo) getTopBy(ctx context.Context, cluster, column string, topN int) ([]CentralityRow, error) {
	if topN <= 0 || topN > 200 {
		topN = 20
	}
	// column은 내부 고정값이라 인젝션 안전
	query := fmt.Sprintf(`
		SELECT node_id, label, kind, pagerank, betweenness
		FROM node_centrality
		WHERE cluster_name = $1
		ORDER BY %s DESC
		LIMIT $2
	`, column)

	rows, err := r.pool.Query(ctx, query, cluster, topN)
	if err != nil {
		return nil, fmt.Errorf("get top by %s: %w", column, err)
	}
	defer rows.Close()

	var result []CentralityRow
	for rows.Next() {
		var c CentralityRow
		if err := rows.Scan(&c.NodeID, &c.Label, &c.Kind, &c.PageRank, &c.Betweenness); err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, rows.Err()
}

// ─────────────────────────────────────────
// Attack Path (Dijkstra)
// ─────────────────────────────────────────

type AttackPathRow struct {
	SourceID  string   `json:"source_id"`
	TargetID  string   `json:"target_id"`
	Nodes     []string `json:"nodes"`
	Labels    []string `json:"labels"`
	Layers    []string `json:"layers"`
	TotalCost float64  `json:"total_cost"`
	Hops      int      `json:"hops"`
}

// UpsertAttackPathBatch는 클러스터의 모든 공격 경로를 교체합니다.
func (r *AnalysisCacheRepo) UpsertAttackPathBatch(ctx context.Context, cluster string, rows []AttackPathRow) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM attack_path_cache WHERE cluster_name = $1`, cluster); err != nil {
		return fmt.Errorf("delete old attack paths: %w", err)
	}

	for _, row := range rows {
		nodesJSON, _ := json.Marshal(row.Nodes)
		labelsJSON, _ := json.Marshal(row.Labels)
		layersJSON, _ := json.Marshal(row.Layers)

		_, err := tx.Exec(ctx, `
			INSERT INTO attack_path_cache 
				(cluster_name, source_id, target_id, path_nodes, path_labels, path_layers, total_cost, hops, computed_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
		`, cluster, row.SourceID, row.TargetID, nodesJSON, labelsJSON, layersJSON, row.TotalCost, row.Hops)
		if err != nil {
			return fmt.Errorf("insert attack path %s->%s: %w", row.SourceID, row.TargetID, err)
		}
	}

	return tx.Commit(ctx)
}

// GetAttackPaths는 클러스터의 모든 공격 경로를 cost 오름차순으로 반환합니다.
func (r *AnalysisCacheRepo) GetAttackPaths(ctx context.Context, cluster string) ([]AttackPathRow, error) {
	const query = `
		SELECT source_id, target_id, path_nodes, path_labels, path_layers, total_cost, hops
		FROM attack_path_cache
		WHERE cluster_name = $1
		ORDER BY total_cost ASC
	`

	rows, err := r.pool.Query(ctx, query, cluster)
	if err != nil {
		return nil, fmt.Errorf("get attack paths: %w", err)
	}
	defer rows.Close()

	var result []AttackPathRow
	for rows.Next() {
		var row AttackPathRow
		var nodesJSON, labelsJSON, layersJSON []byte

		if err := rows.Scan(&row.SourceID, &row.TargetID, &nodesJSON, &labelsJSON, &layersJSON, &row.TotalCost, &row.Hops); err != nil {
			return nil, err
		}

		json.Unmarshal(nodesJSON, &row.Nodes)
		json.Unmarshal(labelsJSON, &row.Labels)
		json.Unmarshal(layersJSON, &row.Layers)

		result = append(result, row)
	}
	return result, rows.Err()
}

// LastComputedAt은 마지막 분석 계산 시각을 반환합니다.
func (r *AnalysisCacheRepo) LastComputedAt(ctx context.Context, cluster string) (time.Time, error) {
	var t time.Time
	err := r.pool.QueryRow(ctx, `
		SELECT COALESCE(MAX(computed_at), 'epoch'::timestamptz)
		FROM node_centrality WHERE cluster_name = $1
	`, cluster).Scan(&t)
	return t, err
}
