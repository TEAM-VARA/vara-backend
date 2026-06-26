// 위치 제안: internal/service/blast_graph_service.go
// 패키지명/핸들러 구조체/pgx 버전은 네 레포 관례에 맞춰 조정해줘 (아래 "붙일 곳 3군데" 참고).
//
// 하는 일 (A 작업):
//   blast_edges(직통 엣지 = 한 다리씩)를 읽어서, 출발 파드 A에서 BFS로 닿는
//   모든 엣지를 전부 모아 nodes/edges JSON으로 내려준다. (트리로 안 줄이고 다 그림)
//   - win_channel 은 그대로 내려주고 색 매핑은 프론트(Cytoscape)에서 한다.
//   - p (= p_edge) 도 같이 내려줘서 프론트의 threshold 슬라이더가 쓰게 한다.
//     ⚠ 슬라이더는 "화면에서 숨기기"로만. 총위험도(OR) 계산은 절대 필터 안 건 전체 그래프로.
//
// FE 색 매핑 참고:  host → 핑크(#EC4899) / network → 파랑(#3B82F6) / rbac → 주황(#F97316)

package service

import (
	"context"
	"fmt"
	"log"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool" // pgx v4면 "github.com/jackc/pgx/v4/pgxpool"
)

// ─────────────────────────────────────────────────────────────
// DB: blast_edges 한 줄
// ─────────────────────────────────────────────────────────────
type BlastEdge struct {
	SourceUID, TargetUID string

	PHost, PRbac, PNet float64 // 채널 3개
	PEdge              float64 // = max(3채널) = P(source→target)

	WinChannel string // "host" | "network" | "rbac"
	Reason     string // 예: "network: eBPF flow, B.Risk=0.630" → 툴팁용

	SourceName, SourceNamespace string
	TargetName, TargetNamespace string
}

// ─────────────────────────────────────────────────────────────
// 프론트로 내려줄 그래프
// ─────────────────────────────────────────────────────────────
type GraphNode struct {
	ID         string  `json:"id"`          // pod_uid (고유 식별자)
	Label      string  `json:"label"`       // 표시 이름 (없으면 uid 앞 8자)
	Namespace  string  `json:"namespace"`   // 4계층 띠 배치 등에 사용
	Hop        int     `json:"hop"`         // A→이 노드 최단 hop 수 (A=0). orbital 반지름(링)용 ⭐
	ReachProb  float64 `json:"reach_prob"`  // A→이 노드 max-path 도달확률 (0~1, A=1.0). 참고용
	ChokeScore float64 `json:"choke_score"` // = reach_prob(A→X) × total_risk(X): X를 통과하는 기대 위험(risk-hub)
	RiskScore  float64 `json:"risk_score"`  // 이 파드 자체 위험(final_scores.final_score), FE 색용
}

type GraphEdge struct {
	Source     string  `json:"source"`
	Target     string  `json:"target"`
	WinChannel string  `json:"win_channel"` // 색 결정 (FE 매핑)
	P          float64 `json:"p"`           // p_edge, 슬라이더용 (표시 필터 전용)
	Reason     string  `json:"reason,omitempty"`
}

type BlastGraphResult struct {
	SourceUID string      `json:"source_uid"`
	Nodes     []GraphNode `json:"nodes"`
	Edges     []GraphEdge `json:"edges"`
	TotalRisk float64     `json:"total_risk"` // 이 파드의 총위험도(MC)
}

// ─────────────────────────────────────────────────────────────
//  1. DB에서 "최신 스냅샷"의 blast_edges 로드
//     real 컬럼은 ::float8 캐스팅해서 float64로 깔끔하게 스캔
//
// ─────────────────────────────────────────────────────────────
func LoadBlastEdges(ctx context.Context, pool *pgxpool.Pool, cluster string) ([]BlastEdge, error) {
	const q = `
		SELECT source_pod_uid, target_pod_uid,
		       p_host::float8, p_rbac::float8, p_net::float8, p_edge::float8,
		       win_channel,
		       COALESCE(reason, ''),
		       COALESCE(source_name, ''), COALESCE(source_namespace, ''),
		       COALESCE(target_name, ''), COALESCE(target_namespace, '')
		FROM blast_edges
		WHERE cluster_name = $1
		  AND snapshot_at = (
		      SELECT MAX(snapshot_at) FROM blast_edges WHERE cluster_name = $1
		  )`

	rows, err := pool.Query(ctx, q, cluster)
	if err != nil {
		return nil, fmt.Errorf("query blast_edges: %w", err)
	}
	defer rows.Close()

	var out []BlastEdge
	for rows.Next() {
		var e BlastEdge
		if err := rows.Scan(
			&e.SourceUID, &e.TargetUID,
			&e.PHost, &e.PRbac, &e.PNet, &e.PEdge,
			&e.WinChannel, &e.Reason,
			&e.SourceName, &e.SourceNamespace,
			&e.TargetName, &e.TargetNamespace,
		); err != nil {
			return nil, fmt.Errorf("scan blast_edge: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ─────────────────────────────────────────────────────────────
// 2) A(source)에서 닿는 모든 엣지를 BFS로 수집 (전부 그리기)
//   - 순수 함수라 DB 없이 단위테스트 가능 (이미 검증함)
//   - 사이클 안전(방문 노드는 다시 큐에 안 넣음), self-loop 제외
//   - 노드는 실제 포함된 엣지의 양 끝에서만 만들어서 dangling 엣지 0 보장
//
// ─────────────────────────────────────────────────────────────
func BuildBlastGraphFromPod(edges []BlastEdge, sourceUID string) BlastGraphResult {
	// 인접 리스트: source_uid → 나가는 엣지들
	adj := make(map[string][]BlastEdge, len(edges))
	for _, e := range edges {
		if e.SourceUID == e.TargetUID {
			continue // self-loop 방지
		}
		adj[e.SourceUID] = append(adj[e.SourceUID], e)
	}

	// 노드 표시 정보 (uid → name/namespace)
	type meta struct{ name, ns string }
	nodeMeta := map[string]meta{}
	remember := func(uid, name, ns string) {
		if uid == "" {
			return
		}
		m := nodeMeta[uid]
		if m.name == "" && name != "" {
			m.name = name
		}
		if m.ns == "" && ns != "" {
			m.ns = ns
		}
		nodeMeta[uid] = m
	}

	visited := map[string]bool{sourceUID: true}
	depth := map[string]int{sourceUID: 0} // A로부터의 최단 hop 수 (BFS 레벨)
	queue := []string{sourceUID}
	var resultEdges []GraphEdge

	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		for _, e := range adj[u] {
			remember(e.SourceUID, e.SourceName, e.SourceNamespace)
			remember(e.TargetUID, e.TargetName, e.TargetNamespace)

			resultEdges = append(resultEdges, GraphEdge{
				Source:     e.SourceUID,
				Target:     e.TargetUID,
				WinChannel: e.WinChannel,
				P:          e.PEdge,
				Reason:     e.Reason,
			})

			if !visited[e.TargetUID] {
				visited[e.TargetUID] = true
				depth[e.TargetUID] = depth[u] + 1
				queue = append(queue, e.TargetUID)
			}
		}
	}
	remember(sourceUID, "", "") // 시작 노드가 어떤 엣지에도 안 잡혔을 경우 대비

	reach := ComputeReachProb(edges, sourceUID) // 각 노드까지 도달확률 (max-path)

	nodes := make([]GraphNode, 0, len(visited))
	for uid := range visited {
		m := nodeMeta[uid]
		label := m.name
		if label == "" {
			label = shortUID(uid)
		}
		nodes = append(nodes, GraphNode{ID: uid, Label: label, Namespace: m.ns, Hop: depth[uid], ReachProb: reach[uid]})
	}

	return BlastGraphResult{SourceUID: sourceUID, Nodes: nodes, Edges: resultEdges}
}

func shortUID(uid string) string {
	if len(uid) > 8 {
		return uid[:8]
	}
	return uid
}

// ─────────────────────────────────────────────────────────────
//  3. Gin 핸들러
//     GET /api/v1/scoring/blast-graph?cluster=vara-eks-test&pod=<source_pod_uid>
//
// ─────────────────────────────────────────────────────────────
type BlastGraphHandler struct {
	Pool *pgxpool.Pool
}

func (h *BlastGraphHandler) Handle(c *gin.Context) {
	cluster := c.Query("cluster")
	pod := c.Query("pod")
	if cluster == "" || pod == "" {
		c.JSON(400, gin.H{"error": "cluster, pod 쿼리 파라미터가 필요합니다"})
		return
	}

	edges, err := LoadBlastEdges(c.Request.Context(), h.Pool, cluster)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	result := BuildBlastGraphFromPod(edges, pod)
	// total_risk: blast_pair_risk 사전계산값(MC)을 읽음. 소스 단위 동일값이라 MAX 1개로 충분.
	// 행 없음(신규 파드/스케줄러 미실행)이면 COALESCE로 0. (라이브 MC 재계산 제거)
	if err := h.Pool.QueryRow(c.Request.Context(),
		`SELECT COALESCE(MAX(total_risk), 0)::float8 FROM blast_pair_risk
		 WHERE cluster_name = $1 AND src_pod_uid = $2`, cluster, pod).Scan(&result.TotalRisk); err != nil {
		log.Printf("blast-graph: total_risk 로드 실패 (0으로 둠): %v", err) // 그래프는 계속 그림
	}

	// choke = risk-hub score: reach_prob(A→X) × total_risk(X)
	// blast_pair_risk(MC 사전계산)에서 조회 — MC 재실행 없이 조회+곱셈만.
	if chokeScores, err := loadRiskHubChoke(c.Request.Context(), h.Pool, cluster, pod); err != nil {
		log.Printf("blast-graph: choke(risk-hub) 로드 실패 (choke 비움): %v", err) // 그래프는 계속 그림
	} else {
		for i := range result.Nodes {
			result.Nodes[i].ChokeScore = chokeScores[result.Nodes[i].ID] // 없으면 0
		}
	}

	// ── ③ 노드별 risk_score = final_scores.final_score (FE 색용) ──
	if rs, err := LoadFinalScores(c.Request.Context(), h.Pool, cluster); err != nil {
		log.Printf("blast-graph: final_scores 로드 실패 (risk_score 비움): %v", err) // 그래프는 계속 그림
	} else {
		for i := range result.Nodes {
			result.Nodes[i].RiskScore = rs[result.Nodes[i].ID] // 없으면 0
		}
	}

	c.JSON(200, result)
}

// ─────────────────────────────────────────────────────────────
//  공격 시나리오 그래프 — 출발(src)·선택(dst) "사이의 모든 노드" 서브그래프
//
//  프론트가 출발 노드 + 노드 하나를 더 선택하면, 그 둘 사이의 전파 경로 위에 있는
//  모든 노드를 보여준다. "사이에 있다" = src에서 닿고(reach(src→X)>0) X에서 dst에도
//  닿는다(reach(X→dst)>0). 둘 다여야 src→…→X→…→dst 경로 위의 노드다.
//  중간 노드 1개를 "고르는" 게 아니라(=choke), 사이 경로 전체를 그릴 수 있게 노드+엣지를 다 준다.
//  reach 값은 blast_pair_risk(MC 사전계산), 엣지는 blast_edges(직통)에서 노드셋 내부만 추린다.
// ─────────────────────────────────────────────────────────────

// BetweenNode — src·dst 사이 서브그래프의 노드 1개.
type BetweenNode struct {
	UID          string  `json:"uid"`
	Name         string  `json:"name"`
	Role         string  `json:"role"` // "src" | "between" | "dst"
	ReachFromSrc float64 `json:"reach_from_src"` // reach_prob(src→이 노드)  (src 자신=1.0)
	ReachToDst   float64 `json:"reach_to_dst"`   // reach_prob(이 노드→dst)  (dst 자신=1.0)
	RiskScore    float64 `json:"risk_score"`     // 이 노드 자체 위험(final_score), FE 색용
}

// BetweenEdge — 서브그래프 엣지(양 끝이 모두 노드셋 안인 blast_edges).
type BetweenEdge struct {
	Source     string  `json:"source"`
	Target     string  `json:"target"`
	WinChannel string  `json:"win_channel"`
	P          float64 `json:"p"`
	Reason     string  `json:"reason,omitempty"`
}

// BlastBetweenResult — 출발·선택 노드 사이의 경로 서브그래프.
type BlastBetweenResult struct {
	Cluster       string        `json:"cluster"`
	SrcUID        string        `json:"src_uid"`
	SrcName       string        `json:"src_name"`
	DstUID        string        `json:"dst_uid"`
	DstName       string        `json:"dst_name"`
	ReachSrcToDst float64       `json:"reach_src_to_dst"` // src→dst 도달확률(0이면 경로 없음)
	Nodes         []BetweenNode `json:"nodes"`
	Edges         []BetweenEdge `json:"edges"`
}

// loadBetweenNodes — src에서 닿고(reach(src→X)>0) dst에도 닿는(reach(X→dst)>0) "사이 노드"들.
// reach(X→dst)=0인 X는 JOIN에서 자동 제외 → 경로 위 노드만 남는다. src·dst 자신은 제외(엔드포인트는 호출부에서 추가).
func loadBetweenNodes(ctx context.Context, pool *pgxpool.Pool, cluster, src, dst string) ([]BetweenNode, error) {
	const q = `
		SELECT a2x.dst_pod_uid, a2x.dst_pod_name,
		       a2x.reach_prob::float8                 AS reach_from_src,
		       x2t.reach_prob::float8                 AS reach_to_dst,
		       COALESCE(f.final_score, 0)::float8     AS risk_score
		FROM blast_pair_risk a2x
		JOIN blast_pair_risk x2t
		  ON x2t.cluster_name = a2x.cluster_name
		 AND x2t.src_pod_uid  = a2x.dst_pod_uid
		 AND x2t.dst_pod_uid  = $3
		LEFT JOIN LATERAL (
			SELECT final_score FROM final_scores
			WHERE cluster_name = a2x.cluster_name AND pod_uid = a2x.dst_pod_uid
			ORDER BY snapshot_at DESC LIMIT 1
		) f ON TRUE
		WHERE a2x.cluster_name = $1
		  AND a2x.src_pod_uid  = $2
		  AND a2x.dst_pod_uid <> $2
		  AND a2x.dst_pod_uid <> $3
		ORDER BY reach_from_src DESC, a2x.dst_pod_name ASC`
	rows, err := pool.Query(ctx, q, cluster, src, dst)
	if err != nil {
		return nil, fmt.Errorf("between-nodes query: %w", err)
	}
	defer rows.Close()

	var out []BetweenNode
	for rows.Next() {
		n := BetweenNode{Role: "between"}
		if err := rows.Scan(&n.UID, &n.Name, &n.ReachFromSrc, &n.ReachToDst, &n.RiskScore); err != nil {
			return nil, fmt.Errorf("scan between node: %w", err)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// loadBetweenEdges — 노드셋(src·dst·사이 노드 전부) 내부에서 양 끝이 모두 노드셋에 속하는 blast_edges.
// 노드셋을 SQL CTE로 다시 계산(사이 노드 = nodeset)해서 그 안의 직통 엣지만 추린다.
func loadBetweenEdges(ctx context.Context, pool *pgxpool.Pool, cluster, src, dst string) ([]BetweenEdge, error) {
	const q = `
		WITH nodeset AS (
			SELECT a2x.dst_pod_uid AS uid
			FROM blast_pair_risk a2x
			JOIN blast_pair_risk x2t
			  ON x2t.cluster_name = a2x.cluster_name
			 AND x2t.src_pod_uid  = a2x.dst_pod_uid
			 AND x2t.dst_pod_uid  = $3
			WHERE a2x.cluster_name = $1 AND a2x.src_pod_uid = $2
			UNION SELECT $2
			UNION SELECT $3
		)
		SELECT e.source_pod_uid, e.target_pod_uid, e.win_channel,
		       e.p_edge::float8, COALESCE(e.reason, '')
		FROM blast_edges e
		WHERE e.cluster_name = $1
		  AND e.snapshot_at = (SELECT MAX(snapshot_at) FROM blast_edges WHERE cluster_name = $1)
		  AND e.source_pod_uid IN (SELECT uid FROM nodeset)
		  AND e.target_pod_uid IN (SELECT uid FROM nodeset)`
	rows, err := pool.Query(ctx, q, cluster, src, dst)
	if err != nil {
		return nil, fmt.Errorf("between-edges query: %w", err)
	}
	defer rows.Close()

	var out []BetweenEdge
	for rows.Next() {
		var e BetweenEdge
		if err := rows.Scan(&e.Source, &e.Target, &e.WinChannel, &e.P, &e.Reason); err != nil {
			return nil, fmt.Errorf("scan between edge: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// BlastBetween : GET /api/v1/scoring/blast-between?cluster=<name>&src=<src_pod_uid>&dst=<dst_pod_uid>
//
// 출발(src)·선택(dst) 노드 "사이의 모든 노드"를 경로 서브그래프로 반환한다(노드+엣지).
// 공격 시나리오 그래프(노드 하나 더 선택 시)가 src→…→dst 경로 전체를 그리는 데 쓴다.
func (h *BlastGraphHandler) BlastBetween(c *gin.Context) {
	cluster := c.Query("cluster")
	src := c.Query("src")
	dst := c.Query("dst")
	if cluster == "" || src == "" || dst == "" {
		c.JSON(400, gin.H{"error": "cluster, src, dst 쿼리 파라미터가 모두 필요합니다"})
		return
	}
	if src == dst {
		c.JSON(400, gin.H{"error": "src와 dst가 같습니다"})
		return
	}

	res := BlastBetweenResult{Cluster: cluster, SrcUID: src, DstUID: dst, Nodes: []BetweenNode{}, Edges: []BetweenEdge{}}

	// src→dst 직접 도달확률 + 양끝 이름 (이 한 행이 없으면 src→dst 경로 자체가 없음).
	var srcRisk, dstRisk float64
	if err := h.Pool.QueryRow(c.Request.Context(),
		`SELECT src_pod_name, dst_pod_name, reach_prob::float8
		 FROM blast_pair_risk
		 WHERE cluster_name=$1 AND src_pod_uid=$2 AND dst_pod_uid=$3 LIMIT 1`,
		cluster, src, dst).Scan(&res.SrcName, &res.DstName, &res.ReachSrcToDst); err != nil {
		c.JSON(404, gin.H{
			"error":   "src→dst 경로가 없습니다(도달 불가) 또는 blast_pair_risk 미적재",
			"hint":    "POST /api/v1/analysis/refresh 로 MC 사전계산 필요할 수 있음",
			"cluster": cluster, "src": src, "dst": dst,
		})
		return
	}
	// 양끝 자기 위험(final_score) — best-effort.
	_ = h.Pool.QueryRow(c.Request.Context(),
		`SELECT final_score::float8 FROM final_scores WHERE cluster_name=$1 AND pod_uid=$2 ORDER BY snapshot_at DESC LIMIT 1`,
		cluster, src).Scan(&srcRisk)
	_ = h.Pool.QueryRow(c.Request.Context(),
		`SELECT final_score::float8 FROM final_scores WHERE cluster_name=$1 AND pod_uid=$2 ORDER BY snapshot_at DESC LIMIT 1`,
		cluster, dst).Scan(&dstRisk)

	between, err := loadBetweenNodes(c.Request.Context(), h.Pool, cluster, src, dst)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	edges, err := loadBetweenEdges(c.Request.Context(), h.Pool, cluster, src, dst)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	// 노드 = src + 사이 노드 전부 + dst (엔드포인트 reach는 자기 1.0 / src→dst 값으로 채움).
	res.Nodes = append(res.Nodes, BetweenNode{
		UID: src, Name: res.SrcName, Role: "src",
		ReachFromSrc: 1.0, ReachToDst: res.ReachSrcToDst, RiskScore: srcRisk,
	})
	res.Nodes = append(res.Nodes, between...)
	res.Nodes = append(res.Nodes, BetweenNode{
		UID: dst, Name: res.DstName, Role: "dst",
		ReachFromSrc: res.ReachSrcToDst, ReachToDst: 1.0, RiskScore: dstRisk,
	})
	res.Edges = edges

	c.JSON(200, res)
}

// ─────────────────────────────────────────────────────────────
//  NetworkPolicy 봉쇄 cascade — 선택 pod의 network 차단 시 끊기는 노드를 hop 파동별로
//
//  선택 pod(block)에 default-deny NetworkPolicy를 걸면 그 pod의 network 엣지(ingress+egress)가
//  0이 된다(rbac/host는 NetworkPolicy로 안 막히므로 유지). 그 뒤 focus(src) 기준 도달을 재계산해서
//  "이제 못 닿는 노드"를 파동으로 나눈다:
//    1hop = 끊긴 직후 생존 영역에서 바로 떨어져나간 노드
//    2hop = 1hop 노드를 거쳐야만 닿던 노드 … (계속)
//  한 번에 다 사라지는 대신 번지는 순서를 FE가 단계별로 그릴 수 있게 한다.
// ─────────────────────────────────────────────────────────────

type CutNode struct {
	UID       string  `json:"uid"`
	Name      string  `json:"name"`
	RiskScore float64 `json:"risk_score"`
}

type CutEdge struct {
	Source     string  `json:"source"`
	Target     string  `json:"target"`
	WinChannel string  `json:"win_channel"`
	P          float64 `json:"p"`
}

// CutWave — 같은 hop에 끊기는 노드 + 그 노드로 들어오던(끊긴 원인) 엣지.
type CutWave struct {
	Hop   int       `json:"hop"`
	Nodes []CutNode `json:"nodes"`
	Edges []CutEdge `json:"edges"`
}

type BlastCutResult struct {
	Cluster           string    `json:"cluster"`
	SrcUID            string    `json:"src_uid"`
	SrcName           string    `json:"src_name"`
	Blocked           []CutEdge `json:"blocked"`       // 요청한 차단 연결(echo, p=요청 시점 미상이라 0)
	CutEdges          []CutEdge `json:"cut_edges"`     // 그 차단으로 실제 사라진 엣지(network이 유일 채널이던 것)
	Waves             []CutWave `json:"waves"`         // hop=1,2,3…
	DisconnectedCount int       `json:"disconnected_count"`
	SurvivorCount     int       `json:"survivor_count"`
}

// reachableFrom — src에서 survives(e)==true 인 엣지만 따라 BFS로 닿는 노드 집합(src 포함).
func reachableFrom(edges []BlastEdge, src string, survives func(BlastEdge) bool) map[string]bool {
	adj := map[string][]BlastEdge{}
	for _, e := range edges {
		if e.SourceUID == e.TargetUID || !survives(e) {
			continue
		}
		adj[e.SourceUID] = append(adj[e.SourceUID], e)
	}
	seen := map[string]bool{src: true}
	q := []string{src}
	for len(q) > 0 {
		u := q[0]
		q = q[1:]
		for _, e := range adj[u] {
			if !seen[e.TargetUID] {
				seen[e.TargetUID] = true
				q = append(q, e.TargetUID)
			}
		}
	}
	return seen
}

// BlastCut : POST /api/v1/scoring/blast-cut
//   body: { "cluster":..., "src":<focus_uid>, "blocked_edges":[ {"source":..,"target":..}, ... ] }
//
// focus(src) 영향범위에서, 차단한 peer 연결들(blocked_edges, directed)의 network 채널을 0으로 두고
// 도달을 재계산해 끊기는 노드를 hop 파동별로 반환. (rbac/host는 NetworkPolicy로 안 막히므로 유지)
func (h *BlastGraphHandler) BlastCut(c *gin.Context) {
	var req struct {
		Cluster      string `json:"cluster"`
		Src          string `json:"src"`
		BlockedEdges []struct {
			Source string `json:"source"`
			Target string `json:"target"`
		} `json:"blocked_edges"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "JSON 본문 파싱 실패: " + err.Error()})
		return
	}
	if req.Cluster == "" || req.Src == "" || len(req.BlockedEdges) == 0 {
		c.JSON(400, gin.H{"error": "cluster, src, blocked_edges(1개 이상)가 필요합니다"})
		return
	}
	cluster, src := req.Cluster, req.Src

	// 차단 연결(directed): source→target의 network 채널을 0으로 둔다. ingress 차단=peer→node, egress 차단=node→peer.
	blocked := map[[2]string]bool{}
	for _, b := range req.BlockedEdges {
		blocked[[2]string{b.Source, b.Target}] = true
	}

	edges, err := LoadBlastEdges(c.Request.Context(), h.Pool, cluster)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	// 이름/위험도 보조 맵.
	nameOf := map[string]string{}
	for _, e := range edges {
		if e.SourceName != "" {
			nameOf[e.SourceUID] = e.SourceName
		}
		if e.TargetName != "" {
			nameOf[e.TargetUID] = e.TargetName
		}
	}
	riskOf, _ := LoadFinalScores(c.Request.Context(), h.Pool, cluster) // 실패해도 nil map → 0

	// 차단 연결의 network 채널을 0으로 둔 뒤 엣지 생존 판정(rbac/host는 NetworkPolicy로 안 막힘).
	survivesAfter := func(e BlastEdge) bool {
		pnet := e.PNet
		if blocked[[2]string{e.SourceUID, e.TargetUID}] {
			pnet = 0
		}
		return maxF3(e.PHost, e.PRbac, pnet) > 0
	}
	survivesAll := func(e BlastEdge) bool { return e.PEdge > 0 } // 저장 엣지는 전부 >0

	before := reachableFrom(edges, src, survivesAll)
	after := reachableFrom(edges, src, survivesAfter)

	// 끊긴 노드 D = before − after (src 제외).
	disconnected := map[string]bool{}
	for uid := range before {
		if uid != src && !after[uid] {
			disconnected[uid] = true
		}
	}

	// 파동(hop) 분류: 생존영역(after)에서 D로 들어가는 경계를 1hop, 그 다음을 BFS로.
	fullAdj := map[string][]BlastEdge{}
	for _, e := range edges {
		if e.SourceUID == e.TargetUID {
			continue
		}
		fullAdj[e.SourceUID] = append(fullAdj[e.SourceUID], e)
	}
	wave := map[string]int{}
	var queue []string
	for _, e := range edges { // seed: survivor → D
		if after[e.SourceUID] && disconnected[e.TargetUID] && wave[e.TargetUID] == 0 {
			wave[e.TargetUID] = 1
			queue = append(queue, e.TargetUID)
		}
	}
	for len(queue) > 0 { // BFS: D 안에서 번짐
		u := queue[0]
		queue = queue[1:]
		for _, e := range fullAdj[u] {
			if disconnected[e.TargetUID] && wave[e.TargetUID] == 0 {
				wave[e.TargetUID] = wave[u] + 1
				queue = append(queue, e.TargetUID)
			}
		}
	}

	res := BlastCutResult{
		Cluster: cluster, SrcUID: src, SrcName: nameOf[src],
		Blocked:  []CutEdge{},
		CutEdges: []CutEdge{}, Waves: []CutWave{},
		DisconnectedCount: len(disconnected), SurvivorCount: len(after),
	}
	for _, b := range req.BlockedEdges { // 요청한 차단 연결 echo
		res.Blocked = append(res.Blocked, CutEdge{Source: b.Source, Target: b.Target, WinChannel: "network"})
	}

	// 끊긴(=block network 차단으로 사라진) 엣지 모으기.
	for _, e := range edges {
		if survivesAll(e) && !survivesAfter(e) {
			res.CutEdges = append(res.CutEdges, CutEdge{e.SourceUID, e.TargetUID, e.WinChannel, e.PEdge})
		}
	}

	// hop별 노드/엣지 묶기.
	maxHop := 0
	for _, hp := range wave {
		if hp > maxHop {
			maxHop = hp
		}
	}
	for hop := 1; hop <= maxHop; hop++ {
		w := CutWave{Hop: hop, Nodes: []CutNode{}, Edges: []CutEdge{}}
		for uid, hp := range wave {
			if hp == hop {
				w.Nodes = append(w.Nodes, CutNode{UID: uid, Name: nameOf[uid], RiskScore: riskOf[uid]})
			}
		}
		// 이 wave 노드로 들어오던 엣지(원인): source가 생존영역 또는 더 앞 wave.
		for _, e := range edges {
			if wave[e.TargetUID] != hop {
				continue
			}
			if after[e.SourceUID] || (wave[e.SourceUID] > 0 && wave[e.SourceUID] < hop) {
				w.Edges = append(w.Edges, CutEdge{e.SourceUID, e.TargetUID, e.WinChannel, e.PEdge})
			}
		}
		res.Waves = append(res.Waves, w)
	}

	c.JSON(200, res)
}

// loadRiskHubChoke: choke 점수를 blast_pair_risk(MC 사전계산)에서 계산.
//
//	choke(X) = reach_prob(A→X) × total_risk(X)
//	         = "A가 X에 닿을 확률" × "X가 퍼뜨리는 기대 규모"
//
// MC 재실행 없이 조회+곱셈만. reach_prob(A→X)=(src=A,dst=X)행, total_risk(X)=(src=X)행의 total_risk.
// ⚠ blast_pair_risk가 채워져 있어야 함(POST /api/v1/analysis/refresh). 비어 있으면 choke=0.
func loadRiskHubChoke(ctx context.Context, pool *pgxpool.Pool, cluster, source string) (map[string]float64, error) {
	const q = `
		SELECT b1.dst_pod_uid,
		       (b1.reach_prob * COALESCE(b2.total_risk, 0))::float8 AS score
		FROM blast_pair_risk b1
		LEFT JOIN LATERAL (
			SELECT total_risk FROM blast_pair_risk
			WHERE cluster_name = b1.cluster_name AND src_pod_uid = b1.dst_pod_uid LIMIT 1
		) b2 ON TRUE
		WHERE b1.cluster_name = $1 AND b1.src_pod_uid = $2`

	rows, err := pool.Query(ctx, q, cluster, source)
	if err != nil {
		return nil, fmt.Errorf("risk-hub choke query: %w", err)
	}
	defer rows.Close()

	out := make(map[string]float64)
	for rows.Next() {
		var uid string
		var sc float64
		if err := rows.Scan(&uid, &sc); err != nil {
			return nil, err
		}
		out[uid] = sc
	}
	return out, rows.Err()
}

// 최신 스냅샷의 파드별 final_score → map[pod_uid]score
func LoadFinalScores(ctx context.Context, pool *pgxpool.Pool, cluster string) (map[string]float64, error) {
	// 파드별 최신 final_score (단일 MAX 스냅샷에 묶지 않음).
	// 단일/소수 파드만 담긴 부분 스냅샷이 MAX가 되면 MAX 기준 조인은 거의 미스 → risk_score 0.
	// DISTINCT ON으로 각 파드의 가장 최근 점수를 가져와 스냅샷 시점 어긋남에 강건하게 한다.
	// (근본: 부분 스냅샷 생성 + retention 충돌은 별도 이슈 todo-partial-snapshot-retention)
	rows, err := pool.Query(ctx, `
		SELECT DISTINCT ON (pod_uid) pod_uid, final_score::float8
		FROM final_scores
		WHERE cluster_name = $1
		ORDER BY pod_uid, snapshot_at DESC
	`, cluster)
	if err != nil {
		return nil, fmt.Errorf("load final_scores: %w", err)
	}
	defer rows.Close()
	m := make(map[string]float64)
	for rows.Next() {
		var uid string
		var sc float64
		if err := rows.Scan(&uid, &sc); err != nil {
			return nil, err
		}
		m[uid] = sc
	}
	return m, rows.Err()
}

// ─────────────────────────────────────────────────────────────
// 4) blast_pair_risk 읽기 핸들러 (orbital 랭킹/가중치)
//    그래프 "모양"은 blast-graph(blast_edges), "가중치·랭킹"은 여기(blast_pair_risk).
//    reach_prob = MC 도달확률, total_risk = Σ_B reach_prob (소스별 동일값, 행마다 중복).
// ─────────────────────────────────────────────────────────────

// TopSources — total_risk 큰 순서로 소스 파드 랭킹 (orbital 시작점 고르기용).
// GET /api/v1/scoring/blast-pairs/top-sources?cluster=<name>&limit=20
func (h *BlastGraphHandler) TopSources(c *gin.Context) {
	cluster := c.Query("cluster")
	if cluster == "" {
		c.JSON(400, gin.H{"error": "cluster 쿼리 파라미터가 필요합니다"})
		return
	}
	limit := queryIntDefault(c, "limit", 20, 200)

	rows, err := h.Pool.Query(c.Request.Context(), `
		SELECT src_pod_uid, max(src_pod_name) AS src_pod_name,
		       max(total_risk)::float8 AS total_risk, count(*) AS reached
		FROM blast_pair_risk
		WHERE cluster_name = $1
		GROUP BY src_pod_uid
		ORDER BY total_risk DESC
		LIMIT $2`, cluster, limit)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type srcRow struct {
		SrcUID    string  `json:"src_pod_uid"`
		SrcName   string  `json:"src_pod_name"`
		TotalRisk float64 `json:"total_risk"`
		Reached   int     `json:"reached"`
	}
	out := make([]srcRow, 0, limit)
	for rows.Next() {
		var r srcRow
		if err := rows.Scan(&r.SrcUID, &r.SrcName, &r.TotalRisk, &r.Reached); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		out = append(out, r)
	}
	c.JSON(200, gin.H{"cluster": cluster, "sources": out})
}

// TopPairs — reach_prob 큰 순서로 A→B 쌍 랭킹 (가장 위험한 전파 쌍). idx_blast_pair_risk_top 사용.
// GET /api/v1/scoring/blast-pairs/top-pairs?cluster=<name>&limit=50
func (h *BlastGraphHandler) TopPairs(c *gin.Context) {
	cluster := c.Query("cluster")
	if cluster == "" {
		c.JSON(400, gin.H{"error": "cluster 쿼리 파라미터가 필요합니다"})
		return
	}
	limit := queryIntDefault(c, "limit", 50, 500)

	rows, err := h.Pool.Query(c.Request.Context(), `
		SELECT src_pod_uid, src_pod_name, dst_pod_uid, dst_pod_name,
		       reach_prob::float8, total_risk::float8
		FROM blast_pair_risk
		WHERE cluster_name = $1
		ORDER BY reach_prob DESC
		LIMIT $2`, cluster, limit)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type pairRow struct {
		SrcUID    string  `json:"src_pod_uid"`
		SrcName   string  `json:"src_pod_name"`
		DstUID    string  `json:"dst_pod_uid"`
		DstName   string  `json:"dst_pod_name"`
		ReachProb float64 `json:"reach_prob"`
		TotalRisk float64 `json:"total_risk"`
	}
	out := make([]pairRow, 0, limit)
	for rows.Next() {
		var r pairRow
		if err := rows.Scan(&r.SrcUID, &r.SrcName, &r.DstUID, &r.DstName, &r.ReachProb, &r.TotalRisk); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		out = append(out, r)
	}
	c.JSON(200, gin.H{"cluster": cluster, "pairs": out})
}

// PairsBySource — 한 소스의 도달 대상별 MC 도달확률 + 총위험도 (orbital 노드 강조 오버레이용).
// GET /api/v1/scoring/blast-pairs?cluster=<name>&src=<src_pod_uid>
func (h *BlastGraphHandler) PairsBySource(c *gin.Context) {
	cluster := c.Query("cluster")
	src := c.Query("src")
	if cluster == "" || src == "" {
		c.JSON(400, gin.H{"error": "cluster, src 쿼리 파라미터가 필요합니다"})
		return
	}

	rows, err := h.Pool.Query(c.Request.Context(), `
		SELECT dst_pod_uid, dst_pod_name, reach_prob::float8, total_risk::float8
		FROM blast_pair_risk
		WHERE cluster_name = $1 AND src_pod_uid = $2
		ORDER BY reach_prob DESC`, cluster, src)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type dstRow struct {
		DstUID    string  `json:"dst_pod_uid"`
		DstName   string  `json:"dst_pod_name"`
		ReachProb float64 `json:"reach_prob"`
	}
	out := []dstRow{}
	var totalRisk float64
	for rows.Next() {
		var r dstRow
		if err := rows.Scan(&r.DstUID, &r.DstName, &r.ReachProb, &totalRisk); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		out = append(out, r)
	}
	c.JSON(200, gin.H{"cluster": cluster, "src_pod_uid": src, "total_risk": totalRisk, "reaches": out})
}

// queryIntDefault — 양의 정수 쿼리 파라미터 파싱. 없거나 잘못되면 def, maxN 초과면 maxN.
func queryIntDefault(c *gin.Context, name string, def, maxN int) int {
	v := c.Query(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	if n > maxN {
		return maxN
	}
	return n
}

// ── 붙일 곳 3군데 ────────────────────────────────────────────
// (1) import: pgx 버전 확인 (v5/v4). gin import 경로는 그대로일 것.
// (2) pgxpool.Pool: 네 앱에서 쓰는 풀을 BlastGraphHandler{Pool: pool} 로 주입.
//     이미 핸들러 구조체가 있으면 거기에 Handle 메서드만 옮겨 붙여도 됨.
// (3) 라우터 등록 (cmd/server/main.go 등):
//        bg := &service.BlastGraphHandler{Pool: pool}
//        r.GET("/api/v1/scoring/blast-graph", bg.Handle)
