package postgres

import (
	"context"
	"fmt"
	"os"      // EDGE_MIN_FLOWS / EDGE_WINDOW_MINUTES env
	"sort"    // layers 정렬용
	"strconv" // env int 파싱
	"strings" // conditions 파싱용
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vara/backend/internal/domain/edge"
)

// edgeEnvInt는 양의 정수 env를 읽고, 없거나 잘못되면 기본값을 반환한다.
// (connects_to 빈도 임계값·시간 윈도우 튜닝용 — 재기동만으로 조정)
func edgeEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

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
        e.id, e.cluster_name,
        e.source_pod_uid,
        COALESCE(e.target_pod_uid, '')                         AS target_pod_uid,
        e.layer,
        e.weight, e.traffic_weight,
        COALESCE(e.source_name, ''), COALESCE(e.source_namespace, ''),
        COALESCE(e.target_name, ''), COALESCE(e.target_namespace, ''),
        e.first_seen_at, e.last_seen_at,
        e.snapshot_at, e.computed_at,
        COALESCE(e.source_kind, 'pod')                          AS source_kind,
        COALESCE(e.target_kind, 'pod')                          AS target_kind,
        COALESCE(e.target_type, 'pod')                          AS target_type,
        COALESCE(e.target_service_name, '')                     AS target_service_name,
        COALESCE(e.edge_type, 'can_reach')                      AS edge_type,
        COALESCE(e.mode, 'observed')                            AS mode,
        COALESCE(e.total_bytes, 0)                              AS total_bytes
    FROM edges e
    JOIN latest_per_combo lpc 
      ON e.layer = lpc.layer 
     AND e.edge_type = lpc.edge_type 
     AND e.snapshot_at = lpc.snap
    WHERE e.cluster_name = $1
    ORDER BY e.layer, e.edge_type, e.weight DESC
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
        e.id, e.cluster_name,
        e.source_pod_uid,
        COALESCE(e.target_pod_uid, '')                         AS target_pod_uid,
        e.layer,
        e.weight, e.traffic_weight,
        COALESCE(e.source_name, ''), COALESCE(e.source_namespace, ''),
        COALESCE(e.target_name, ''), COALESCE(e.target_namespace, ''),
        e.first_seen_at, e.last_seen_at,
        e.snapshot_at, e.computed_at,
        COALESCE(e.source_kind, 'pod')                          AS source_kind,
        COALESCE(e.target_kind, 'pod')                          AS target_kind,
        COALESCE(e.target_type, 'pod')                          AS target_type,
        COALESCE(e.target_service_name, '')                     AS target_service_name,
        COALESCE(e.edge_type, 'can_reach')                      AS edge_type,
        COALESCE(e.mode, 'observed')                            AS mode,
        COALESCE(e.total_bytes, 0)                              AS total_bytes
    FROM edges e
    JOIN latest_per_combo lpc 
      ON e.layer = lpc.layer 
     AND e.edge_type = lpc.edge_type 
     AND e.snapshot_at = lpc.snap
    WHERE e.cluster_name = $1
      AND (e.source_pod_uid = $2 OR e.target_pod_uid = $2)
    ORDER BY e.layer, e.edge_type, e.weight DESC
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
//  1. Pod → SA (assumes) — 시스템 pod(tetragon/ebs-csi-node) 제외
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
			  AND name NOT LIKE 'tetragon%'
			  AND name NOT LIKE 'ebs-csi-node%'
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
// 1개 INSERT 실행:
//  1. shares_image: 비활성화됨 (아래 참조)
//  2. shares_cve: 다른 image지만 같은 KEV CVE 공유 (cross-image)
func (r *EdgesRepo) ComputeSupplyChainEdges(ctx context.Context, clusterName string) (*edge.SupplyChainComputeResult, error) {
	start := time.Now()
	snapAt := time.Now()

	// ─────────────────────────────────────────────
	// Step 1: shares_image — 비활성화 (2026-06)
	// 사유: 공통 사이드카 이미지 공유로 N² 엣지 폭발 (3,500+)
	// TODO: CVE 허브 노드 구조로 재설계 예정 (실측: 943→41 검증 완료)
	// ─────────────────────────────────────────────
	// qSharesImage := `
	// 	WITH pod_digests AS (
	// 		SELECT DISTINCT cp.pod_uid, cp.pod_name, cp.pod_namespace, s.image_digest
	// 		FROM (
	// 			SELECT pod_uid, name AS pod_name, namespace AS pod_namespace,
	// 			       jsonb_array_elements(containers)->>'image' AS pod_image
	// 			FROM cluster_pods
	// 			WHERE cluster_name = $1
	// 			  AND snapshot_at = (SELECT MAX(snapshot_at) FROM cluster_pods WHERE cluster_name = $1)
	// 		) cp
	// 		JOIN sboms s ON s.image = cp.pod_image
	// 	)
	// 	INSERT INTO edges (
	// 		cluster_name,
	// 		source_pod_uid, target_pod_uid,
	// 		source_name, source_namespace,
	// 		target_name, target_namespace,
	// 		source_kind, target_kind,
	// 		target_type, target_service_name,
	// 		layer, edge_type, mode,
	// 		weight, traffic_weight,
	// 		snapshot_at, computed_at
	// 	)
	// 	SELECT
	// 		$1,
	// 		a.pod_uid, b.pod_uid,
	// 		a.pod_name, a.pod_namespace,
	// 		b.pod_name, b.pod_namespace,
	// 		'pod', 'pod',
	// 		'pod',
	// 		'img:' || LEFT(a.image_digest, 19),
	// 		'supply_chain', 'shares_image', 'declared',
	// 		1, 0.6,
	// 		$2::timestamptz, NOW()
	// 	FROM pod_digests a
	// 	JOIN pod_digests b ON a.image_digest = b.image_digest
	// 	                  AND a.pod_uid < b.pod_uid
	// 	ON CONFLICT DO NOTHING
	// `
	// tag1, err := r.pool.Exec(ctx, qSharesImage, clusterName, snapAt)
	// if err != nil {
	// 	return nil, fmt.Errorf("insert shares_image: %w", err)
	// }
	// sharesImageInserted := tag1.RowsAffected()
	sharesImageInserted := int64(0)

	// ─────────────────────────────────────────────
	// Step 2: shares_cve (KEV + cross-image)
	// 각 Pod 쌍당 1개 edge, 대표 CVE를 target_service_name에 라벨
	// 시스템 pod(tetragon/ebs-csi-node)은 제외
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
				  AND name NOT LIKE 'tetragon%'
				  AND name NOT LIKE 'ebs-csi-node%'
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

// ComputeNetworkEdges는 network layer의 4개 edge_type을 적재합니다.
//  1. selected_by: Service → Pod (labels matching)
//  2. allows:      NetworkPolicy (Pod → Pod)
//  3. routed_by:   Ingress → Service
//  4. connects_to: eBPF 관찰된 pod→pod 통신
//
// 시스템 pod(tetragon/ebs-csi-node)은 제외.
func (r *EdgesRepo) ComputeNetworkEdges(ctx context.Context, clusterName string) (*edge.NetworkComputeResult, error) {
	start := time.Now()
	snapAt := time.Now()

	// ─────────────────────────────────────────────
	// Step 1: selected_by (Service → Pod)
	// ─────────────────────────────────────────────
	qSelectedBy := `
		WITH latest_pods AS (
			SELECT pod_uid, name AS pod_name, namespace AS pod_namespace, labels 
			FROM cluster_pods 
			WHERE cluster_name = $1
			  AND snapshot_at = (SELECT MAX(snapshot_at) FROM cluster_pods WHERE cluster_name = $1)
			  AND name NOT LIKE 'tetragon%'
			  AND name NOT LIKE 'ebs-csi-node%'
		),
		latest_services AS (
			SELECT service_uid, name AS svc_name, namespace AS svc_namespace, selector 
			FROM cluster_services 
			WHERE cluster_name = $1
			  AND snapshot_at = (SELECT MAX(snapshot_at) FROM cluster_services WHERE cluster_name = $1)
			  AND selector IS NOT NULL AND selector != '{}'::jsonb
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
			s.service_uid, p.pod_uid,
			s.svc_name, s.svc_namespace,
			p.pod_name, p.pod_namespace,
			'service', 'pod',
			'pod', NULL,
			'network', 'selected_by', 'declared',
			1, 0.6,
			$2::timestamptz, NOW()
		FROM latest_services s
		JOIN latest_pods p ON p.pod_namespace = s.svc_namespace
                  AND p.labels @> s.selector
		ON CONFLICT DO NOTHING
	`
	tag1, err := r.pool.Exec(ctx, qSelectedBy, clusterName, snapAt)
	if err != nil {
		return nil, fmt.Errorf("insert selected_by: %w", err)
	}

	// ─────────────────────────────────────────────
	// Step 2: allows (NetworkPolicy ingress_rules)
	// 현재 0건이지만 데이터 들어오면 자동 적재
	// ─────────────────────────────────────────────
	qAllows := `
		WITH latest_pods AS (
			SELECT pod_uid, name AS pod_name, namespace AS pod_namespace, labels 
			FROM cluster_pods 
			WHERE cluster_name = $1
			  AND snapshot_at = (SELECT MAX(snapshot_at) FROM cluster_pods WHERE cluster_name = $1)
			  AND name NOT LIKE 'tetragon%'
			  AND name NOT LIKE 'ebs-csi-node%'
		),
		latest_np AS (
			SELECT name, namespace, pod_selector, ingress_rules
			FROM cluster_network_policies
			WHERE cluster_name = $1
			  AND snapshot_at = (SELECT MAX(snapshot_at) FROM cluster_network_policies WHERE cluster_name = $1)
		),
		ingress_pairs AS (
			SELECT 
				target.pod_uid AS target_pod_uid,
				target.pod_name AS target_pod_name,
				target.pod_namespace AS target_pod_namespace,
				source.pod_uid AS source_pod_uid,
				source.pod_name AS source_pod_name,
				source.pod_namespace AS source_pod_namespace
			FROM latest_np np
			JOIN latest_pods target 
			  ON target.pod_namespace = np.namespace 
			 AND target.labels @> COALESCE(np.pod_selector->'matchLabels', '{}'::jsonb)
			CROSS JOIN LATERAL jsonb_array_elements(COALESCE(np.ingress_rules, '[]'::jsonb)) AS ing
			CROSS JOIN LATERAL jsonb_array_elements(COALESCE(ing->'from', '[]'::jsonb)) AS from_rule
			JOIN latest_pods source
			  ON source.labels @> (from_rule->'pod_selector'->'matchLabels')
			 AND source.pod_uid != target.pod_uid
		)
		INSERT INTO edges (
			cluster_name,
			source_pod_uid, target_pod_uid,
			source_name, source_namespace,
			target_name, target_namespace,
			source_kind, target_kind,
			target_type,
			layer, edge_type, mode,
			weight, traffic_weight,
			snapshot_at, computed_at
		)
		SELECT DISTINCT
			$1,
			source_pod_uid, target_pod_uid,
			source_pod_name, source_pod_namespace,
			target_pod_name, target_pod_namespace,
			'pod', 'pod',
			'pod',
			'network', 'allows', 'declared',
			1, 0.6,
			$2::timestamptz, NOW()
		FROM ingress_pairs
		ON CONFLICT DO NOTHING
	`
	tag2, err := r.pool.Exec(ctx, qAllows, clusterName, snapAt)
	if err != nil {
		return nil, fmt.Errorf("insert allows: %w", err)
	}

	// ─────────────────────────────────────────────
	// Step 3: routed_by (Ingress → Service)
	// 현재 0건이지만 데이터 들어오면 자동 적재
	// ─────────────────────────────────────────────
	qRoutedBy := `
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
			ing.ingress_uid, NULL,
			ing.name, ing.namespace,
			path->'backend'->'service'->>'name', ing.namespace,
			'ingress', 'service',
			'service', 'svc:' || ing.namespace || '/' || (path->'backend'->'service'->>'name'),
			'network', 'routed_by', 'declared',
			1, 0.6,
			$2::timestamptz, NOW()
		FROM cluster_ingresses ing,
		     jsonb_array_elements(ing.rules) AS rule,
		     jsonb_array_elements(rule->'http'->'paths') AS path
		WHERE ing.cluster_name = $1
		  AND ing.snapshot_at = (SELECT MAX(snapshot_at) FROM cluster_ingresses WHERE cluster_name = $1)
		  AND path->'backend'->'service'->>'name' IS NOT NULL
		ON CONFLICT DO NOTHING
	`
	tag3, err := r.pool.Exec(ctx, qRoutedBy, clusterName, snapAt)
	if err != nil {
		return nil, fmt.Errorf("insert routed_by: %w", err)
	}

	// ─────────────────────────────────────────────
	// Step 4: connects_to (eBPF 관찰된 pod→pod 통신)
	// IP 우선 매칭 + 서비스명(해시 제거) 폴백
	// ─────────────────────────────────────────────
	qConnectsTo := `
		WITH latest_pods AS (
			SELECT pod_uid, name, namespace, pod_ip,
			       regexp_replace(name, '-[a-z0-9]+-[a-z0-9]+$', '') AS svc_name
			FROM cluster_pods
			WHERE cluster_name = $1
			  AND snapshot_at = (SELECT MAX(snapshot_at) FROM cluster_pods WHERE cluster_name = $1)
			  AND name NOT LIKE 'tetragon%'
			  AND name NOT LIKE 'ebs-csi-node%'
		),
		agg AS (
			-- ebpf_flow_agg(집계 테이블)에서 mapped 통신만. src/dst_pod_id = "namespace/name" 풀네임.
			-- staleness: last_seen이 최근 N분(EDGE_WINDOW_MINUTES) 이내인 쌍만 = 그 이상 조용하면 죽은 것으로 간주해 제외.
			SELECT
				split_part(src_pod_id, '/', 1) AS src_ns,
				split_part(src_pod_id, '/', 2) AS src_name,
				split_part(dst_pod_id, '/', 1) AS dst_ns,
				split_part(dst_pod_id, '/', 2) AS dst_name,
				MIN(last_seen) AS first_seen,
				MAX(last_seen) AS last_seen,
				MIN(dst_port)  AS min_dst_port
			FROM ebpf_flow_agg
			WHERE mapping_status = 'mapped' AND cluster_name = $1
			  AND src_pod_id IS NOT NULL AND dst_pod_id IS NOT NULL
			  AND src_pod_id != dst_pod_id
			  AND last_seen > NOW() - make_interval(mins => $4)   -- staleness N분(EDGE_WINDOW_MINUTES)
			GROUP BY 1,2,3,4
			HAVING SUM(flow_count) >= $3                          -- 총 통신 횟수 임계값(EDGE_MIN_FLOWS)
		),
		resolved AS (
			-- (namespace, name) 정확 매칭 — IP/서비스명 폴백 불필요(StatefulSet·IP 미스매치 버그 제거)
			SELECT
				sp.pod_uid AS src_uid, sp.name AS src_name, sp.namespace AS src_namespace,
				dp.pod_uid AS dst_uid, dp.name AS dst_name, dp.namespace AS dst_namespace,
				a.first_seen, a.last_seen, a.min_dst_port
			FROM agg a
			JOIN latest_pods sp ON sp.namespace = a.src_ns AND sp.name = a.src_name
			JOIN latest_pods dp ON dp.namespace = a.dst_ns AND dp.name = a.dst_name
		)
		INSERT INTO edges (
			cluster_name,
			source_pod_uid, target_pod_uid,
			source_name, source_namespace,
			target_name, target_namespace,
			source_kind, target_kind,
			target_type,
			layer, edge_type, mode,
			weight, traffic_weight,
			first_seen_at, last_seen_at, min_dst_port,
			snapshot_at, computed_at
		)
		SELECT
			$1,
			src_uid, dst_uid,
			src_name, src_namespace,
			dst_name, dst_namespace,
			'pod', 'pod',
			'pod',
			'network', 'connects_to', 'observed',
			1, 0.8,
			first_seen, last_seen, min_dst_port,
			$2::timestamptz, NOW()
		FROM resolved
		WHERE src_uid IS NOT NULL AND dst_uid IS NOT NULL
		  AND src_uid != dst_uid
		ON CONFLICT DO NOTHING
	`
	// connects_to 튜닝: 최근 N분(EDGE_WINDOW_MINUTES, 기본10) 내 M회+(EDGE_MIN_FLOWS, 기본3) 통신한 쌍만.
	minFlows := edgeEnvInt("EDGE_MIN_FLOWS", 3)
	windowMin := edgeEnvInt("EDGE_WINDOW_MINUTES", 10)
	tag4, err := r.pool.Exec(ctx, qConnectsTo, clusterName, snapAt, minFlows, windowMin)
	if err != nil {
		return nil, fmt.Errorf("insert connects_to: %w", err)
	}

	return &edge.NetworkComputeResult{
		ClusterName: clusterName,
		SelectedBy:  int(tag1.RowsAffected()),
		Allows:      int(tag2.RowsAffected()),
		RoutedBy:    int(tag3.RowsAffected()),
		ConnectsTo:  int(tag4.RowsAffected()),
		Total:       int(tag1.RowsAffected() + tag2.RowsAffected() + tag3.RowsAffected() + tag4.RowsAffected()),
		SnapshotAt:  snapAt,
		ComputedAt:  time.Now(),
		DurationMs:  time.Since(start).Milliseconds(),
	}, nil
}

// ComputeHostEdges — Host layer edges 적재
// runs_on: 비활성화 (2026-06, 모든 pod이 가져 엣지 과다 — 팀 결정)
// escape_path: Pod→Node 탈출 위험. 조건: privileged/hostNetwork/hostPID/hostPath 중 하나 이상.
// 시스템 pod(tetragon/ebs-csi-node)은 제외.
func (r *EdgesRepo) ComputeHostEdges(ctx context.Context, clusterName string) (*edge.HostComputeResult, error) {
	start := time.Now()
	snapAt := time.Now()

	// ─────────────────────────────────────────────
	// Step 1: runs_on — 비활성화 (2026-06)
	// 사유: 모든 pod이 노드에 1개씩 가져 엣지만 많고(171) 위험 신호가 아님.
	//       탈출 위험은 escape_path가 표현.
	// ─────────────────────────────────────────────
	runsOnInserted := int64(0)

	// ─────────────────────────────────────────────
	// Step 2: escape_path (Pod → Node, 탈출 위험)
	// 조건: privileged(containers) OR host_network OR host_pid OR hostPath(volumes)
	// 사유 라벨을 target_service_name에 기록 (예: "escape:privileged,hostPath")
	// ─────────────────────────────────────────────
	qEscapePath := `
		WITH latest_pods AS (
			SELECT pod_uid, name AS pod_name, namespace, node,
			       host_network, host_pid, containers, volumes
			FROM cluster_pods
			WHERE cluster_name = $1
			  AND snapshot_at = (SELECT MAX(snapshot_at) FROM cluster_pods WHERE cluster_name = $1)
			  AND node IS NOT NULL AND node != ''
			  AND name NOT LIKE 'tetragon%'
			  AND name NOT LIKE 'ebs-csi-node%'
		),
		escape_pods AS (
			SELECT
				p.pod_uid, p.pod_name, p.namespace, p.node,
				(EXISTS (SELECT 1 FROM jsonb_array_elements(p.containers) c
				         WHERE (c->>'privileged')::boolean = true)) AS is_privileged,
				p.host_network,
				p.host_pid,
				(EXISTS (SELECT 1 FROM jsonb_array_elements(p.volumes) v
				         WHERE v->>'type' = 'hostPath')) AS has_hostpath
			FROM latest_pods p
		),
		risky AS (
			SELECT *,
				'escape:' || CONCAT_WS(',',
					CASE WHEN is_privileged THEN 'privileged' END,
					CASE WHEN host_network  THEN 'hostNetwork' END,
					CASE WHEN host_pid      THEN 'hostPID' END,
					CASE WHEN has_hostpath  THEN 'hostPath' END
				) AS reason
			FROM escape_pods
			WHERE is_privileged OR host_network OR host_pid OR has_hostpath
		),
		latest_nodes AS (
			SELECT node_uid, name AS node_name
			FROM cluster_nodes
			WHERE cluster_name = $1
			  AND snapshot_at = (SELECT MAX(snapshot_at) FROM cluster_nodes WHERE cluster_name = $1)
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
			rp.pod_uid, n.node_uid,
			rp.pod_name, rp.namespace,
			n.node_name, '',
			'pod', 'node',
			'node', rp.reason,
			'host', 'escape_path', 'declared',
			1, 0.8,
			$2::timestamptz, NOW()
		FROM risky rp
		JOIN latest_nodes n ON n.node_name = rp.node
		ON CONFLICT DO NOTHING
	`
	tag2, err := r.pool.Exec(ctx, qEscapePath, clusterName, snapAt)
	if err != nil {
		return nil, fmt.Errorf("insert escape_path: %w", err)
	}
	escapePathInserted := tag2.RowsAffected()

	return &edge.HostComputeResult{
		ClusterName: clusterName,
		RunsOn:      int(runsOnInserted),
		EscapePath:  int(escapePathInserted),
		Total:       int(runsOnInserted + escapePathInserted),
		SnapshotAt:  snapAt,
		ComputedAt:  time.Now(),
		DurationMs:  time.Since(start).Milliseconds(),
	}, nil
}

// kindToNodeType은 내부 kind를 FE용 NodeType(PascalCase)으로 변환합니다.
func kindToNodeType(kind string) string {
	switch kind {
	case "pod":
		return "Pod"
	case "service":
		return "Service"
	case "workload":
		return "Workload"
	case "secret":
		return "Secret"
	case "configmap":
		return "ConfigMap"
	case "sa":
		return "RBAC"
	case "role":
		return "RBAC"
	case "crole":
		return "RBAC"
	case "ingress":
		return "Ingress"
	case "networkpolicy":
		return "NetworkPolicy"
	case "namespace":
		return "Namespace"
	case "node":
		return "Node"
	default:
		return kind
	}
}

// BuildTopology — PM 명세서 B-1의 /api/v1/topology 응답 데이터
func (r *EdgesRepo) BuildTopology(ctx context.Context, cluster string) (*edge.TopologyResponse, error) {
	start := time.Now()

	podNodes, err := r.fetchPodNodes(ctx, cluster)
	if err != nil {
		return nil, fmt.Errorf("fetch pod nodes: %w", err)
	}

	otherNodes, err := r.fetchOtherNodes(ctx, cluster)
	if err != nil {
		return nil, fmt.Errorf("fetch other nodes: %w", err)
	}

	topoEdges, snapAt, err := r.fetchTopologyEdges(ctx, cluster)
	if err != nil {
		return nil, fmt.Errorf("fetch topology edges: %w", err)
	}

	secretNodes, _ := r.fetchSecretNodes(ctx, cluster)
	configmapNodes, _ := r.fetchConfigMapNodes(ctx, cluster)
	ingressNodes, _ := r.fetchIngressNodes(ctx, cluster)
	netpolNodes, _ := r.fetchNetworkPolicyNodes(ctx, cluster)
	namespaceNodes, _ := r.fetchNamespaceNodes(ctx, cluster)
	nodeNodes, _ := r.fetchNodeNodes(ctx, cluster)

	nodes := append(podNodes, otherNodes...)
	nodes = append(nodes, secretNodes...)
	nodes = append(nodes, configmapNodes...)
	nodes = append(nodes, ingressNodes...)
	nodes = append(nodes, netpolNodes...)
	nodes = append(nodes, namespaceNodes...)
	nodes = append(nodes, nodeNodes...)

	// orphan edge 보충: edges가 참조하지만 노드 집합에 없는 pod_uid를 cluster_pods에서
	// 보충(전체 스냅샷, pod_uid별 최신). 재생성으로 UUID가 바뀐 Pod 등으로 인한
	// orphan edge를 제거해 그래프가 끊기지 않게 한다.
	existingIDs := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		existingIDs[n.ID] = true
	}
	missingSet := make(map[string]bool)
	for _, e := range topoEdges {
		if e.Source != "" && !existingIDs[e.Source] {
			missingSet[e.Source] = true
		}
		if e.Target != "" && !existingIDs[e.Target] {
			missingSet[e.Target] = true
		}
	}
	if len(missingSet) > 0 {
		missingUIDs := make([]string, 0, len(missingSet))
		for id := range missingSet {
			missingUIDs = append(missingUIDs, id)
		}
		// pod_uid에 해당하는 것만 매칭됨(sa:/crole:/role:/external 등 합성 ID는 자동 제외).
		supplementalPods, err := r.fetchPodNodesByUIDs(ctx, cluster, missingUIDs)
		if err != nil {
			return nil, fmt.Errorf("fetch supplemental pod nodes: %w", err)
		}
		nodes = append(nodes, supplementalPods...)
	}

	for i := range nodes {
		nodes[i].NodeType = kindToNodeType(nodes[i].Kind)
	}

	return &edge.TopologyResponse{
		Cluster: cluster,
		Nodes:   nodes,
		Edges:   topoEdges,
		Meta: edge.TopologyMeta{
			NodeCount:  len(nodes),
			EdgeCount:  len(topoEdges),
			SnapshotAt: snapAt,
			BuildMs:    time.Since(start).Milliseconds(),
		},
	}, nil
}

func (r *EdgesRepo) fetchPodNodes(ctx context.Context, cluster string) ([]edge.TopologyNode, error) {
	const q = `
		SELECT 
			cp.pod_uid::text AS id,
			cp.name AS label,
			cp.namespace,
			COALESCE(cp.service_account, '') AS service_account,
			COALESCE(cp.containers->0->>'image', '') AS image_tag,
			COALESCE(cp.containers->0->>'image_digest', '') AS image_digest,
			COALESCE(fs.final_score, 0) AS risk_score,
			COALESCE(fs.risk_level, 'safe') AS risk_level,
			COALESCE(fs.used_top_cve, '') AS top_cve
		FROM cluster_pods cp
		LEFT JOIN LATERAL (
			SELECT final_score, risk_level, used_top_cve
			FROM final_scores
			WHERE cluster_name = cp.cluster_name
			  AND (
			      pod_uid = cp.pod_uid
			      OR (
			          used_image_digest IS NOT NULL 
			          AND used_image_digest != ''
			          AND used_image_digest = cp.containers->0->>'image_digest'
			      )
			  )
			ORDER BY 
			    CASE WHEN pod_uid = cp.pod_uid THEN 1 ELSE 2 END,  -- pod_uid 우선
			    snapshot_at DESC,
			    final_score DESC NULLS LAST
			LIMIT 1
		) fs ON true
		WHERE cp.cluster_name = $1
		  AND cp.snapshot_at = (SELECT MAX(snapshot_at) FROM cluster_pods WHERE cluster_name = $1)
		  AND cp.name NOT LIKE 'tetragon%'
		  AND cp.name NOT LIKE 'ebs-csi-node%'
		  AND cp.namespace <> 'default'
		ORDER BY cp.namespace, cp.name
	`
	// 기존 Scan 그대로
	rows, err := r.pool.Query(ctx, q, cluster)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []edge.TopologyNode
	for rows.Next() {
		var n edge.TopologyNode
		n.Kind = "pod"
		if err := rows.Scan(
			&n.ID, &n.Label, &n.Namespace,
			&n.ServiceAccount, &n.ImageTag, &n.ImageDigest,
			&n.RiskScore, &n.RiskLevel, &n.TopCVE,
		); err != nil {
			return nil, err
		}
		result = append(result, n)
	}
	return result, nil
}

// fetchPodNodesByUIDs — 주어진 pod_uid 집합에 대해, 스냅샷 전체에서 pod_uid별 최신
// 메타데이터(DISTINCT ON)를 가져옵니다.
//
// 용도(orphan edge 보충): edges가 참조하지만 최신 스냅샷 노드 집합에 없는 pod_uid
// (재생성으로 UUID가 바뀐 Pod 등)를 노드로 보충해 모든 edge에 끝점을 보장합니다.
// 범위 제한 없음(전체 스냅샷) — 임시 결정, 추후 팀 협의로 변경 가능.
func (r *EdgesRepo) fetchPodNodesByUIDs(ctx context.Context, cluster string, uids []string) ([]edge.TopologyNode, error) {
	if len(uids) == 0 {
		return nil, nil
	}
	const q = `
		SELECT DISTINCT ON (cp.pod_uid)
			cp.pod_uid::text AS id,
			cp.name AS label,
			cp.namespace,
			COALESCE(cp.service_account, '') AS service_account,
			COALESCE(cp.containers->0->>'image', '') AS image_tag,
			COALESCE(cp.containers->0->>'image_digest', '') AS image_digest,
			COALESCE(fs.final_score, 0) AS risk_score,
			COALESCE(fs.risk_level, 'safe') AS risk_level,
			COALESCE(fs.used_top_cve, '') AS top_cve
		FROM cluster_pods cp
		LEFT JOIN LATERAL (
			SELECT final_score, risk_level, used_top_cve
			FROM final_scores
			WHERE cluster_name = cp.cluster_name
			  AND (
			      pod_uid = cp.pod_uid
			      OR (
			          used_image_digest IS NOT NULL
			          AND used_image_digest != ''
			          AND used_image_digest = cp.containers->0->>'image_digest'
			      )
			  )
			ORDER BY
			    CASE WHEN pod_uid = cp.pod_uid THEN 1 ELSE 2 END,
			    snapshot_at DESC,
			    final_score DESC NULLS LAST
			LIMIT 1
		) fs ON true
		WHERE cp.cluster_name = $1
		  AND cp.pod_uid = ANY($2)
		ORDER BY cp.pod_uid, cp.snapshot_at DESC
	`
	rows, err := r.pool.Query(ctx, q, cluster, uids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []edge.TopologyNode
	for rows.Next() {
		var n edge.TopologyNode
		n.Kind = "pod"
		if err := rows.Scan(
			&n.ID, &n.Label, &n.Namespace,
			&n.ServiceAccount, &n.ImageTag, &n.ImageDigest,
			&n.RiskScore, &n.RiskLevel, &n.TopCVE,
		); err != nil {
			return nil, err
		}
		result = append(result, n)
	}
	return result, rows.Err()
}

// fetchOtherNodes — SA, Role, ClusterRole, Service, Image, CVE 노드 unique 추출
func (r *EdgesRepo) fetchOtherNodes(ctx context.Context, cluster string) ([]edge.TopologyNode, error) {
	const q = `
		WITH non_pod_nodes AS (
			-- source 측: service_account, service, ingress, role, cluster_role
			SELECT DISTINCT
				source_pod_uid AS id,
				CASE source_kind 
					WHEN 'service_account' THEN 'sa'
					WHEN 'cluster_role' THEN 'crole'
					ELSE source_kind
				END AS kind,
				source_name AS label,
				source_namespace AS ns
			FROM edges
			WHERE cluster_name = $1
			  AND source_kind IN ('service_account', 'service', 'ingress')
			  AND source_pod_uid IS NOT NULL
			  AND COALESCE(source_namespace,'') <> 'default'
			
			UNION
			
			-- target 측: SA/Role/ClusterRole 가상 노드
			SELECT DISTINCT
				target_service_name AS id,
				CASE target_kind
					WHEN 'service_account' THEN 'sa'
					WHEN 'cluster_role' THEN 'crole'
					WHEN 'role' THEN 'role'
					ELSE target_kind
				END AS kind,
				target_name AS label,
				target_namespace AS ns
			FROM edges
			WHERE cluster_name = $1
			  AND target_kind IN ('service_account', 'service', 'image', 'cve', 'role', 'cluster_role')
			  AND target_service_name IS NOT NULL
			  AND target_service_name != ''
			  AND target_pod_uid IS NULL
			  AND COALESCE(target_namespace,'') <> 'default'
		)
		SELECT id, kind, label, COALESCE(ns, '') AS ns
		FROM non_pod_nodes
		WHERE id IS NOT NULL
	`
	rows, err := r.pool.Query(ctx, q, cluster)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []edge.TopologyNode
	for rows.Next() {
		var n edge.TopologyNode
		if err := rows.Scan(&n.ID, &n.Kind, &n.Label, &n.Namespace); err != nil {
			return nil, err
		}
		result = append(result, n)
	}
	return result, nil
}

// fetchTopologyEdges — edges 테이블에서 layer/edge_type별 latest snapshot edge들
func (r *EdgesRepo) fetchTopologyEdges(ctx context.Context, cluster string) ([]edge.TopologyEdge, time.Time, error) {
	const q = `
		WITH latest_per_combo AS (
			SELECT DISTINCT ON (layer, edge_type) 
				layer, edge_type, snapshot_at AS snap
			FROM edges 
			WHERE cluster_name = $1
			ORDER BY layer, edge_type, snapshot_at DESC
		)
		SELECT
			'e_' || e.id::text AS edge_id,
			e.source_pod_uid AS source,
			COALESCE(e.target_pod_uid::text, e.target_service_name, '') AS target,
			e.layer, e.edge_type, e.mode,
			e.weight, e.traffic_weight,
			e.snapshot_at
		FROM edges e
		JOIN latest_per_combo lpc 
		  ON e.layer = lpc.layer 
		 AND e.edge_type = lpc.edge_type 
		 AND e.snapshot_at = lpc.snap
		WHERE e.cluster_name = $1
		  AND COALESCE(e.source_namespace,'') <> 'default'
		  AND COALESCE(e.target_namespace,'') <> 'default'
		ORDER BY e.layer, e.edge_type
	`
	rows, err := r.pool.Query(ctx, q, cluster)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer rows.Close()

	var result []edge.TopologyEdge
	var latestSnap time.Time
	for rows.Next() {
		var e edge.TopologyEdge
		var snapAt time.Time
		if err := rows.Scan(
			&e.ID, &e.Source, &e.Target,
			&e.Layer, &e.EdgeType, &e.Mode,
			&e.Weight, &e.TrafficWeight,
			&snapAt,
		); err != nil {
			return nil, time.Time{}, err
		}
		result = append(result, e)
		if snapAt.After(latestSnap) {
			latestSnap = snapAt
		}
	}
	return result, latestSnap, nil
}

// LatestPodSnapshot은 cluster_pods의 최신 snapshot 시각을 반환합니다.
func (r *EdgesRepo) LatestPodSnapshot(ctx context.Context, cluster string) (time.Time, error) {
	var t time.Time
	err := r.pool.QueryRow(ctx, `
		SELECT COALESCE(MAX(snapshot_at), 'epoch'::timestamptz)
		FROM cluster_pods WHERE cluster_name = $1
	`, cluster).Scan(&t)
	return t, err
}

// fetchWorkloadNodes — cluster_workloads → Workload 노드
func (r *EdgesRepo) fetchWorkloadNodes(ctx context.Context, cluster string) ([]edge.TopologyNode, error) {
	const q = `
		SELECT workload_uid AS id, name, namespace
		FROM cluster_workloads
		WHERE cluster_name = $1
		  AND snapshot_at = (SELECT MAX(snapshot_at) FROM cluster_workloads WHERE cluster_name = $1)
		  AND namespace <> 'default'
		  AND kind IN ('Deployment', 'StatefulSet', 'DaemonSet')
	`
	return r.scanSimpleNodes(ctx, q, cluster, "workload")
}

func (r *EdgesRepo) fetchSecretNodes(ctx context.Context, cluster string) ([]edge.TopologyNode, error) {
	const q = `
		SELECT secret_uid AS id, name, namespace
		FROM cluster_secrets
		WHERE cluster_name = $1
		  AND snapshot_at = (SELECT MAX(snapshot_at) FROM cluster_secrets WHERE cluster_name = $1)
		  AND namespace <> 'default'
	`
	return r.scanSimpleNodes(ctx, q, cluster, "secret")
}

func (r *EdgesRepo) fetchConfigMapNodes(ctx context.Context, cluster string) ([]edge.TopologyNode, error) {
	const q = `
		SELECT configmap_uid AS id, name, namespace
		FROM cluster_configmaps
		WHERE cluster_name = $1
		  AND snapshot_at = (SELECT MAX(snapshot_at) FROM cluster_configmaps WHERE cluster_name = $1)
		  AND namespace <> 'default'
	`
	return r.scanSimpleNodes(ctx, q, cluster, "configmap")
}

func (r *EdgesRepo) fetchIngressNodes(ctx context.Context, cluster string) ([]edge.TopologyNode, error) {
	const q = `
		SELECT ingress_uid AS id, name, namespace
		FROM cluster_ingresses
		WHERE cluster_name = $1
		  AND snapshot_at = (SELECT MAX(snapshot_at) FROM cluster_ingresses WHERE cluster_name = $1)
		  AND namespace <> 'default'
	`
	return r.scanSimpleNodes(ctx, q, cluster, "ingress")
}

func (r *EdgesRepo) fetchNetworkPolicyNodes(ctx context.Context, cluster string) ([]edge.TopologyNode, error) {
	const q = `
		SELECT policy_uid AS id, name, namespace
		FROM cluster_network_policies
		WHERE cluster_name = $1
		  AND snapshot_at = (SELECT MAX(snapshot_at) FROM cluster_network_policies WHERE cluster_name = $1)
		  AND namespace <> 'default'
	`
	return r.scanSimpleNodes(ctx, q, cluster, "networkpolicy")
}

// Node — namespace 없음 (클러스터 레벨)
func (r *EdgesRepo) fetchNodeNodes(ctx context.Context, cluster string) ([]edge.TopologyNode, error) {
	const q = `
		SELECT node_uid AS id, name, '' AS namespace
		FROM cluster_nodes
		WHERE cluster_name = $1
		  AND snapshot_at = (SELECT MAX(snapshot_at) FROM cluster_nodes WHERE cluster_name = $1)
	`
	return r.scanSimpleNodes(ctx, q, cluster, "node")
}

// Namespace — uid 없음, namespace 값을 ID로
func (r *EdgesRepo) fetchNamespaceNodes(ctx context.Context, cluster string) ([]edge.TopologyNode, error) {
	const q = `
		SELECT namespace AS id, namespace AS name, namespace
		FROM cluster_namespaces
		WHERE cluster_name = $1
		  AND snapshot_at = (SELECT MAX(snapshot_at) FROM cluster_namespaces WHERE cluster_name = $1)
		  AND namespace <> 'default'
	`
	return r.scanSimpleNodes(ctx, q, cluster, "namespace")
}

// 공통 스캔 헬퍼
func (r *EdgesRepo) scanSimpleNodes(ctx context.Context, q, cluster, kind string) ([]edge.TopologyNode, error) {
	rows, err := r.pool.Query(ctx, q, cluster)
	if err != nil {
		return nil, fmt.Errorf("fetch %s nodes: %w", kind, err)
	}
	defer rows.Close()

	var result []edge.TopologyNode
	for rows.Next() {
		var n edge.TopologyNode
		n.Kind = kind
		if err := rows.Scan(&n.ID, &n.Label, &n.Namespace); err != nil {
			return nil, err
		}
		result = append(result, n)
	}
	return result, rows.Err()
}

// CleanupOldSnapshots는 layer×edge_type별 최신 snapshot만 남기고 삭제합니다.
// 5분 주기 파이프라인의 snapshot 누적 방지 (retention).
func (r *EdgesRepo) CleanupOldSnapshots(ctx context.Context, clusterName string) (int64, error) {
	tag, err := r.pool.Exec(ctx, `
		DELETE FROM edges
		WHERE cluster_name = $1
		  AND (layer, edge_type, snapshot_at) NOT IN (
		    SELECT layer, edge_type, MAX(snapshot_at)
		    FROM edges WHERE cluster_name = $1
		    GROUP BY layer, edge_type)
	`, clusterName)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// DeleteEdgesBefore는 주어진 시각 이전(snapshot_at < before)의 엣지를 전부 삭제합니다.
// AnalysisScheduler가 "이번 사이클 시작 시각" 기준으로 호출 → 이번 사이클에 재계산되지 않은
// (옛 스냅샷) 레이어가 남지 않게 한다. 레이어별 최신 유지(CleanupOldSnapshots)와 달리,
// 레이어 간 스냅샷 시점 불일치(→ topology orphan/X2 중복)를 원천 차단한다.
func (r *EdgesRepo) DeleteEdgesBefore(ctx context.Context, clusterName string, before time.Time) (int64, error) {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM edges WHERE cluster_name = $1 AND snapshot_at < $2`,
		clusterName, before,
	)
	if err != nil {
		return 0, fmt.Errorf("delete edges before %v: %w", before, err)
	}
	return tag.RowsAffected(), nil
}
