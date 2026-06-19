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
	"math/rand"

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
	ID        string `json:"id"`        // pod_uid (고유 식별자)
	Label     string `json:"label"`     // 표시 이름 (없으면 uid 앞 8자)
	Namespace string `json:"namespace"` // 4계층 띠 배치 등에 사용
	ReachProb float64 `json:"reach_prob"` // A→이 노드 도달확률 (0~1, A 자신=1.0)
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
// 1) DB에서 "최신 스냅샷"의 blast_edges 로드
//    real 컬럼은 ::float8 캐스팅해서 float64로 깔끔하게 스캔
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
//    - 순수 함수라 DB 없이 단위테스트 가능 (이미 검증함)
//    - 사이클 안전(방문 노드는 다시 큐에 안 넣음), self-loop 제외
//    - 노드는 실제 포함된 엣지의 양 끝에서만 만들어서 dangling 엣지 0 보장
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
		nodes = append(nodes, GraphNode{ID: uid, Label: label, Namespace: m.ns, ReachProb: reach[uid]})
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
// 3) Gin 핸들러
//    GET /api/v1/scoring/blast-graph?cluster=vara-eks-test&pod=<source_pod_uid>
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
	result.TotalRisk = ComputeCriticalityMC(edges, pod, 5000, rand.New(rand.NewSource(42)))
	c.JSON(200, result)
}

// ── 붙일 곳 3군데 ────────────────────────────────────────────
// (1) import: pgx 버전 확인 (v5/v4). gin import 경로는 그대로일 것.
// (2) pgxpool.Pool: 네 앱에서 쓰는 풀을 BlastGraphHandler{Pool: pool} 로 주입.
//     이미 핸들러 구조체가 있으면 거기에 Handle 메서드만 옮겨 붙여도 됨.
// (3) 라우터 등록 (cmd/server/main.go 등):
//        bg := &service.BlastGraphHandler{Pool: pool}
//        r.GET("/api/v1/scoring/blast-graph", bg.Handle)