package postgres

import (
	"context"
	"fmt"
	"sort"    // layers 정렬용
	"strings" // conditions 파싱용
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
//  1. ebpf_network_flows에서 최근 windowMinutes 분 데이터 가져옴
//  2. src_pod_id → cluster_pods로 source Pod uid/name/namespace 매핑
//  3. dst_ip → cluster_pods.pod_ip로 target Pod uid/name/namespace 매핑
//  4. 매칭 실패 (외부 IP 등)는 제외
//  5. excludePatterns에 해당하는 Pod 제외 (자기 자신)
//  6. GROUP BY (src_pod_uid, target_pod_uid) → weight 집계
//
// 입력:
//
//	clusterName        : 분석 대상 클러스터
//	windowMinutes      : 시간 윈도우 (분)
//	excludePatterns    : 제외할 src_pod_id prefix (예: "default/vara-ebpf-agent-")
//
// 반환:
//
//	집계된 edges (Pod-to-Pod 쌍별로 1개)
//	처리한 raw flow 수
//	매칭/제외로 스킵된 flow 수
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
		WITH latest_per_combo AS (
    SELECT DISTINCT ON (layer, edge_type) 
        layer, edge_type, snapshot_at AS snap
    FROM edges 
    WHERE cluster_name = $1
    ORDER BY layer, edge_type, snapshot_at DESC
)
SELECT
    id, cluster_name,
    source_pod_uid,
    COALESCE(target_pod_uid, '')                         AS target_pod_uid,
    layer,
    weight, traffic_weight,
    COALESCE(source_name, ''), COALESCE(source_namespace, ''),
    COALESCE(target_name, ''), COALESCE(target_namespace, ''),
    first_seen_at, last_seen_at,
    snapshot_at, computed_at,
    COALESCE(source_kind, 'pod')                          AS source_kind,
    COALESCE(target_kind, 'pod')                          AS target_kind,
    COALESCE(target_type, 'pod')                          AS target_type,
    COALESCE(target_service_name, '')                     AS target_service_name,
    COALESCE(edge_type, 'can_reach')                      AS edge_type,
    COALESCE(mode, 'observed')                            AS mode,
    COALESCE(total_bytes, 0)                              AS total_bytes
FROM edges e
JOIN latest_per_combo lpc 
  ON e.layer = lpc.layer 
 AND e.edge_type = lpc.edge_type 
 AND e.snapshot_at = lpc.snap
WHERE e.cluster_name = $1
ORDER BY layer, edge_type, weight DESC
	`

	rows, err := r.pool.Query(ctx, q, clusterName)
	if err != nil {
		return nil, fmt.Errorf("list edges: %w", err)
	}
	defer rows.Close()

	out := []edge.Edge{}
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
			&e.SourceKind, &e.TargetKind,
			&e.TargetType, &e.TargetServiceName,
			&e.EdgeType, &e.Mode, &e.TotalBytes,
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
		WITH latest_per_combo AS (
    	SELECT DISTINCT ON (layer, edge_type) 
        layer, edge_type, snapshot_at AS snap
    	FROM edges 
    	WHERE cluster_name = $1
    	ORDER BY layer, edge_type, snapshot_at DESC
		)

		SELECT
			id, cluster_name,
			source_pod_uid,
			COALESCE(target_pod_uid, '')                         AS target_pod_uid,
			layer,
			weight, traffic_weight,
			COALESCE(source_name, ''), COALESCE(source_namespace, ''),
			COALESCE(target_name, ''), COALESCE(target_namespace, ''),
			first_seen_at, last_seen_at,
			snapshot_at, computed_at,
			COALESCE(source_kind, 'pod')                          AS source_kind,
			COALESCE(target_kind, 'pod')                          AS target_kind,
			COALESCE(target_type, 'pod')                          AS target_type,
			COALESCE(target_service_name, '')                     AS target_service_name,
			COALESCE(edge_type, 'can_reach')                      AS edge_type,
			COALESCE(mode, 'observed')                            AS mode,
			COALESCE(total_bytes, 0)                              AS total_bytes
		FROM edges e
		JOIN latest_per_combo lpc 
  		ON e.layer = lpc.layer 
 		AND e.edge_type = lpc.edge_type 
 		AND e.snapshot_at = lpc.snap
		WHERE e.cluster_name = $1
  		AND (e.source_pod_uid = $2 OR e.target_pod_uid = $2)
		ORDER BY layer, edge_type, weight DESC
	`

	rows, err := r.pool.Query(ctx, q, clusterName, podUID)
	if err != nil {
		return nil, fmt.Errorf("list edges by pod: %w", err)
	}
	defer rows.Close()

	out := []edge.Edge{}
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
			&e.SourceKind, &e.TargetKind,
			&e.TargetType, &e.TargetServiceName,
			&e.EdgeType, &e.Mode, &e.TotalBytes,
		); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		e.DisplayID = edge.FormatDisplayID(e.ID)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ────────────────────────────────────────────────────
// 응답 보강용 조회 함수 (Blast Radius PDF 5.1~5.4)
// ────────────────────────────────────────────────────

// ListNodes는 클러스터의 모든 Pod를 NodeView로 반환합니다.
// cluster_pods + final_scores + exposure_scores LATERAL JOIN으로 최신 데이터 조회.
func (r *EdgesRepo) ListNodes(ctx context.Context, clusterName string) ([]edge.NodeView, error) {
	const q = `
		WITH latest_pods AS (
			SELECT MAX(snapshot_at) AS snap
			FROM cluster_pods
			WHERE cluster_name = $1
		)
		SELECT
			p.pod_uid,
			p.name,
			p.namespace,
			COALESCE(p.service_account, '') AS service_account,
			COALESCE(fs.final_score::float8, 0.0) AS risk_score,
			COALESCE(fs.risk_level, 'safe') AS risk_level,
			COALESCE(es.exposed, false) AS is_exposed
		FROM cluster_pods p
		LEFT JOIN LATERAL (
			SELECT final_score, risk_level
			FROM final_scores
			WHERE cluster_name = $1 AND pod_uid = p.pod_uid
			ORDER BY snapshot_at DESC LIMIT 1
		) fs ON TRUE
		LEFT JOIN LATERAL (
			SELECT exposed
			FROM exposure_scores
			WHERE cluster_name = $1 AND pod_uid = p.pod_uid
			ORDER BY snapshot_at DESC LIMIT 1
		) es ON TRUE
		WHERE p.cluster_name = $1 AND p.snapshot_at = (SELECT snap FROM latest_pods)
		ORDER BY fs.final_score DESC NULLS LAST
	`

	rows, err := r.pool.Query(ctx, q, clusterName)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	defer rows.Close()

	out := []edge.NodeView{}
	for rows.Next() {
		var n edge.NodeView
		if err := rows.Scan(
			&n.ID, &n.Name, &n.Namespace, &n.ServiceAccount,
			&n.RiskScore, &n.RiskLevel, &n.IsExposed,
		); err != nil {
			return nil, fmt.Errorf("scan node: %w", err)
		}
		n.Type = "Pod"
		out = append(out, n)
	}
	return out, rows.Err()
}

// ComputeSummary는 클러스터의 risk_level별 카운트를 반환합니다.
// 각 Pod의 가장 최근 final_scores row를 기준으로 카운트.
func (r *EdgesRepo) ComputeSummary(ctx context.Context, clusterName string) (*edge.EdgesSummary, error) {
	const q = `
    WITH latest_pods AS (
        SELECT pod_uid FROM cluster_pods
        WHERE cluster_name = $1
          AND snapshot_at = (SELECT MAX(snapshot_at) FROM cluster_pods WHERE cluster_name = $1)
    ),
    latest_final AS (
        SELECT DISTINCT ON (fs.pod_uid) fs.pod_uid, fs.risk_level
        FROM final_scores fs
        JOIN latest_pods lp ON lp.pod_uid = fs.pod_uid
        WHERE fs.cluster_name = $1
        ORDER BY fs.pod_uid, fs.snapshot_at DESC
    )
    SELECT
        COUNT(*) FILTER (WHERE risk_level = 'emergency') AS emergency,
        COUNT(*) FILTER (WHERE risk_level = 'warning')   AS warning,
        COUNT(*) FILTER (WHERE risk_level = 'caution')   AS caution,
        COUNT(*) FILTER (WHERE risk_level = 'safe')      AS safe,
        COUNT(*) AS total
    FROM latest_final
`

	var s edge.EdgesSummary
	err := r.pool.QueryRow(ctx, q, clusterName).Scan(
		&s.Emergency, &s.Warning, &s.Caution, &s.Safe, &s.Total,
	)
	if err != nil {
		return nil, fmt.Errorf("compute summary: %w", err)
	}
	return &s, nil
}

// ListToxicCombinations는 매칭된 toxic 룰을 layer 조합 형식으로 반환합니다.
// toxic_results.matched_rules를 펼친 후 toxic_rules JOIN.
// rule_id별로 그룹핑 → 매칭된 Pod들이 묶임.
func (r *EdgesRepo) ListToxicCombinations(ctx context.Context, clusterName string) ([]edge.ToxicCombination, error) {
	const q = `
		WITH latest_results AS (
			SELECT DISTINCT ON (pod_uid) pod_uid, matched_rules
			FROM toxic_results
			WHERE cluster_name = $1
			ORDER BY pod_uid, snapshot_at DESC
		),
		exploded AS (
			SELECT pod_uid, jsonb_array_elements_text(matched_rules) AS rule_id
			FROM latest_results
		)
		SELECT
			r.rule_id,
			r.name,
			r.description,
			r.severity,
			r.conditions,
			array_agg(DISTINCT e.pod_uid) AS pod_uids
		FROM exploded e
		JOIN toxic_rules r ON r.rule_id = e.rule_id
		WHERE r.enabled = TRUE
		GROUP BY r.rule_id, r.name, r.description, r.severity, r.conditions
		ORDER BY 
			CASE r.severity
				WHEN 'Critical' THEN 1
				WHEN 'High'     THEN 2
				WHEN 'Medium'   THEN 3
				ELSE 4
			END,
			r.rule_id
	`

	rows, err := r.pool.Query(ctx, q, clusterName)
	if err != nil {
		return nil, fmt.Errorf("list toxic combinations: %w", err)
	}
	defer rows.Close()

	out := []edge.ToxicCombination{}
	for rows.Next() {
		var (
			ruleID, name, description, severity, conditions string
			podUIDs                                         []string
		)
		if err := rows.Scan(&ruleID, &name, &description, &severity, &conditions, &podUIDs); err != nil {
			return nil, fmt.Errorf("scan toxic: %w", err)
		}

		layers := parseToxicConditionsToLayers(conditions)

		// severity 매핑: Critical→emergency, High→warning, Medium→caution
		severityLower := "caution"
		switch strings.ToLower(severity) {
		case "critical":
			severityLower = "emergency"
		case "high":
			severityLower = "warning"
		case "medium":
			severityLower = "caution"
		}

		// ID: tc_{rule_id 소문자 + 언더스코어}
		id := "tc_" + strings.ToLower(strings.ReplaceAll(ruleID, "-", "_"))

		out = append(out, edge.ToxicCombination{
			ID:       id,
			RuleID:   ruleID,
			Title:    name,
			PodIDs:   podUIDs,
			Severity: severityLower,
			Reason:   description,
			Layers:   layers,
		})
	}
	return out, rows.Err()
}

// signalToLayer는 toxic signal 이름을 layer 이름으로 매핑합니다.
func signalToLayer(signal string) string {
	switch signal {
	case "externally_exposed", "no_network_policy":
		return "network"
	case "cluster_admin", "secret_access":
		return "identity"
	case "has_kev_cve", "has_critical_cve", "has_high_cve", "has_active_or_poc":
		return "supply_chain"
	case "privileged", "host_network", "host_pid", "host_ipc", "no_resource_limits":
		return "host"
	}
	return ""
}

// parseToxicConditionsToLayers는 conditions 문자열에서 layer 목록을 추출합니다.
// 예: "externally_exposed AND cluster_admin" → ["identity", "network"] (정렬됨)
func parseToxicConditionsToLayers(conditions string) []string {
	layerSet := make(map[string]bool)

	for _, token := range strings.Fields(conditions) {
		token = strings.TrimSpace(token)
		// 논리 연산자 제외
		if token == "AND" || token == "OR" || token == "NOT" || token == "" {
			continue
		}
		// 괄호 제거
		token = strings.Trim(token, "()")

		if layer := signalToLayer(token); layer != "" {
			layerSet[layer] = true
		}
	}

	layers := make([]string, 0, len(layerSet))
	for l := range layerSet {
		layers = append(layers, l)
	}
	sort.Strings(layers)
	return layers
}

// ComputeIdentityEdges는 RBAC 정보로부터 identity layer edges를 적재합니다.
// 3개 INSERT 실행:
//  1. Pod → SA (assumes)
//  2. SA → Role (binds, namespace-level)
//  3. SA → ClusterRole (binds, cluster-level)
func (r *EdgesRepo) ComputeIdentityEdges(ctx context.Context, clusterName string) (*edge.IdentityComputeResult, error) {
	start := time.Now()
	snapAt := time.Now()

	// ─────────────────────────────────────────────
	// Step 1: Pod → SA (assumes)
	// ─────────────────────────────────────────────
	qAssumes := `
		WITH latest_pods AS (
			SELECT pod_uid, name, namespace, service_account
			FROM cluster_pods
			WHERE cluster_name = $1
			  AND snapshot_at = (SELECT MAX(snapshot_at) FROM cluster_pods WHERE cluster_name = $1)
			  AND service_account IS NOT NULL AND service_account != ''
		)
		INSERT INTO edges (
			cluster_name,
			source_pod_uid, target_pod_uid,
			source_name, source_namespace,
			target_name, target_namespace,
			source_kind, target_kind,
			target_type, target_service_name,
			layer, edge_type, mode,
			weight, traffic_weight,
			snapshot_at, computed_at
		)
		SELECT
			$1,
			pod_uid, NULL,
			name, namespace,
			service_account, namespace,
			'pod', 'service_account',
			'service_account',
			'sa:' || namespace || '/' || service_account,
			'identity', 'assumes', 'declared',
			1, 0.7,
			$2::timestamptz, NOW()
		FROM latest_pods
		ON CONFLICT DO NOTHING
	`
	tag1, err := r.pool.Exec(ctx, qAssumes, clusterName, snapAt)
	if err != nil {
		return nil, fmt.Errorf("insert assumes: %w", err)
	}
	assumesInserted := tag1.RowsAffected()

	// ─────────────────────────────────────────────
	// Step 2: SA → Role (binds, Namespace-level RoleBinding)
	// ─────────────────────────────────────────────
	qBindsRole := `
		WITH latest_rb AS (
			SELECT name, namespace, role_ref, subjects
			FROM cluster_role_bindings
			WHERE cluster_name = $1
			  AND snapshot_at = (SELECT MAX(snapshot_at) FROM cluster_role_bindings WHERE cluster_name = $1)
		)
		INSERT INTO edges (
			cluster_name,
			source_pod_uid, target_pod_uid,
			source_name, source_namespace,
			target_name, target_namespace,
			source_kind, target_kind,
			target_type, target_service_name,
			layer, edge_type, mode,
			weight, traffic_weight,
			snapshot_at, computed_at
		)
		SELECT DISTINCT
			$1,
			'sa:' || COALESCE(subj->>'namespace', rb.namespace) || '/' || (subj->>'name'),
			NULL,
			subj->>'name', COALESCE(subj->>'namespace', rb.namespace),
			rb.role_ref->>'name', rb.namespace,
			'service_account',
			CASE rb.role_ref->>'kind' WHEN 'ClusterRole' THEN 'cluster_role' ELSE 'role' END,
			CASE rb.role_ref->>'kind' WHEN 'ClusterRole' THEN 'cluster_role' ELSE 'role' END,
			CASE rb.role_ref->>'kind'
				WHEN 'ClusterRole' THEN 'crole:' || (rb.role_ref->>'name')
				ELSE 'role:' || rb.namespace || '/' || (rb.role_ref->>'name')
			END,
			'identity', 'binds', 'declared',
			1, 0.7,
			$2::timestamptz, NOW()
		FROM latest_rb rb,
		     jsonb_array_elements(rb.subjects) subj
		WHERE subj->>'kind' = 'ServiceAccount'
		ON CONFLICT DO NOTHING
	`
	tag2, err := r.pool.Exec(ctx, qBindsRole, clusterName, snapAt)
	if err != nil {
		return nil, fmt.Errorf("insert binds(role): %w", err)
	}
	bindsRoleInserted := tag2.RowsAffected()

	// ─────────────────────────────────────────────
	// Step 3: SA → ClusterRole (binds, Cluster-level ClusterRoleBinding)
	// ─────────────────────────────────────────────
	qBindsCRole := `
		WITH latest_crb AS (
			SELECT name, role_ref, subjects
			FROM cluster_cluster_role_bindings
			WHERE cluster_name = $1
			  AND snapshot_at = (SELECT MAX(snapshot_at) FROM cluster_cluster_role_bindings WHERE cluster_name = $1)
		)
		INSERT INTO edges (
			cluster_name,
			source_pod_uid, target_pod_uid,
			source_name, source_namespace,
			target_name, target_namespace,
			source_kind, target_kind,
			target_type, target_service_name,
			layer, edge_type, mode,
			weight, traffic_weight,
			snapshot_at, computed_at
		)
		SELECT DISTINCT
			$1,
			'sa:' || (subj->>'namespace') || '/' || (subj->>'name'),
			NULL,
			subj->>'name', subj->>'namespace',
			crb.role_ref->>'name', '',
			'service_account', 'cluster_role',
			'cluster_role',
			'crole:' || (crb.role_ref->>'name'),
			'identity', 'binds', 'declared',
			1, 0.7,
			$2::timestamptz, NOW()
		FROM latest_crb crb,
		     jsonb_array_elements(crb.subjects) subj
		WHERE subj->>'kind' = 'ServiceAccount'
		  AND subj->>'namespace' IS NOT NULL
		ON CONFLICT DO NOTHING
	`
	tag3, err := r.pool.Exec(ctx, qBindsCRole, clusterName, snapAt)
	if err != nil {
		return nil, fmt.Errorf("insert binds(crole): %w", err)
	}
	bindsCRoleInserted := tag3.RowsAffected()

	return &edge.IdentityComputeResult{
		ClusterName: clusterName,
		Assumes:     int(assumesInserted),
		BindsRole:   int(bindsRoleInserted),
		BindsCRole:  int(bindsCRoleInserted),
		Total:       int(assumesInserted + bindsRoleInserted + bindsCRoleInserted),
		SnapshotAt:  snapAt,
		ComputedAt:  time.Now(),
		DurationMs:  time.Since(start).Milliseconds(),
	}, nil
}

// ComputeSupplyChainEdges는 SBOM/CVE 정보로부터 supply_chain layer edges를 적재합니다.
// 2개 INSERT 실행:
//  1. shares_image: 같은 image_digest 공유하는 Pod 쌍
//  2. shares_cve: 다른 image지만 같은 KEV CVE 공유 (cross-image)
func (r *EdgesRepo) ComputeSupplyChainEdges(ctx context.Context, clusterName string) (*edge.SupplyChainComputeResult, error) {
	start := time.Now()
	snapAt := time.Now()

	// ─────────────────────────────────────────────
	// Step 1: shares_image (같은 이미지)
	// sboms 테이블로 cluster_pods.containers[].image → image_digest 매핑
	// ─────────────────────────────────────────────
	qSharesImage := `
		WITH pod_digests AS (
			SELECT DISTINCT cp.pod_uid, cp.pod_name, cp.pod_namespace, s.image_digest
			FROM (
				SELECT pod_uid, name AS pod_name, namespace AS pod_namespace,
				       jsonb_array_elements(containers)->>'image' AS pod_image
				FROM cluster_pods 
				WHERE cluster_name = $1
				  AND snapshot_at = (SELECT MAX(snapshot_at) FROM cluster_pods WHERE cluster_name = $1)
			) cp
			JOIN sboms s ON s.image = cp.pod_image
		)
		INSERT INTO edges (
			cluster_name,
			source_pod_uid, target_pod_uid,
			source_name, source_namespace,
			target_name, target_namespace,
			source_kind, target_kind,
			target_type, target_service_name,
			layer, edge_type, mode,
			weight, traffic_weight,
			snapshot_at, computed_at
		)
		SELECT
			$1,
			a.pod_uid, b.pod_uid,
			a.pod_name, a.pod_namespace,
			b.pod_name, b.pod_namespace,
			'pod', 'pod',
			'pod',
			'img:' || LEFT(a.image_digest, 19),
			'supply_chain', 'shares_image', 'declared',
			1, 0.6,
			$2::timestamptz, NOW()
		FROM pod_digests a 
		JOIN pod_digests b ON a.image_digest = b.image_digest 
		                  AND a.pod_uid < b.pod_uid
		ON CONFLICT DO NOTHING
	`
	tag1, err := r.pool.Exec(ctx, qSharesImage, clusterName, snapAt)
	if err != nil {
		return nil, fmt.Errorf("insert shares_image: %w", err)
	}
	sharesImageInserted := tag1.RowsAffected()

	// ─────────────────────────────────────────────
	// Step 2: shares_cve (KEV + cross-image)
	// 각 Pod 쌍당 1개 edge, 대표 CVE를 target_service_name에 라벨
	// ─────────────────────────────────────────────
	qSharesCVE := `
		WITH pod_digests AS (
			SELECT DISTINCT cp.pod_uid, cp.pod_name, cp.pod_namespace, s.image_digest
			FROM (
				SELECT pod_uid, name AS pod_name, namespace AS pod_namespace,
				       jsonb_array_elements(containers)->>'image' AS pod_image
				FROM cluster_pods 
				WHERE cluster_name = $1
				  AND snapshot_at = (SELECT MAX(snapshot_at) FROM cluster_pods WHERE cluster_name = $1)
			) cp
			JOIN sboms s ON s.image = cp.pod_image
		),
		pod_cves AS (
			SELECT pd.pod_uid, pd.pod_name, pd.pod_namespace, pd.image_digest, cgs.cve_id
			FROM pod_digests pd
			JOIN sbom_packages sp ON sp.image_digest = pd.image_digest
			JOIN package_vulnerabilities pv ON pv.purl = sp.purl
			JOIN cve_global_scores cgs ON cgs.cve_id = ANY(pv.aliases)
			WHERE cgs.in_kev = TRUE
		),
		pod_pairs AS (
			SELECT 
				a.pod_uid AS pod_a, a.pod_name AS name_a, a.pod_namespace AS ns_a,
				b.pod_uid AS pod_b, b.pod_name AS name_b, b.pod_namespace AS ns_b,
				MIN(a.cve_id) AS representative_cve
			FROM pod_cves a 
			JOIN pod_cves b 
			  ON a.cve_id = b.cve_id 
			 AND a.pod_uid < b.pod_uid
			 AND a.image_digest != b.image_digest
			GROUP BY a.pod_uid, a.pod_name, a.pod_namespace, 
			         b.pod_uid, b.pod_name, b.pod_namespace
		)
		INSERT INTO edges (
			cluster_name,
			source_pod_uid, target_pod_uid,
			source_name, source_namespace,
			target_name, target_namespace,
			source_kind, target_kind,
			target_type, target_service_name,
			layer, edge_type, mode,
			weight, traffic_weight,
			snapshot_at, computed_at
		)
		SELECT 
			$1,
			pod_a, pod_b,
			name_a, ns_a, name_b, ns_b,
			'pod', 'pod', 'pod',
			'cve:' || representative_cve,
			'supply_chain', 'shares_cve', 'declared',
			1, 0.6,
			$2::timestamptz, NOW()
		FROM pod_pairs
		ON CONFLICT DO NOTHING
	`
	tag2, err := r.pool.Exec(ctx, qSharesCVE, clusterName, snapAt)
	if err != nil {
		return nil, fmt.Errorf("insert shares_cve: %w", err)
	}
	sharesCVEInserted := tag2.RowsAffected()

	return &edge.SupplyChainComputeResult{
		ClusterName: clusterName,
		SharesImage: int(sharesImageInserted),
		SharesCVE:   int(sharesCVEInserted),
		Total:       int(sharesImageInserted + sharesCVEInserted),
		SnapshotAt:  snapAt,
		ComputedAt:  time.Now(),
		DurationMs:  time.Since(start).Milliseconds(),
	}, nil
}
