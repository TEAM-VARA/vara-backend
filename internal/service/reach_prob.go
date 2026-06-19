package service

import (
	"container/heap"
	"math"
)

// ComputeReachProb: 출발 파드 A에서 각 노드 B까지 "가장 확률 높은 경로"의 도달확률을 반환.
//
// 핵심 아이디어: 경로 확률은 곱셈(0.8 × 0.5 ...)이라 최단경로 알고리즘이 못 다룸.
// 그래서 가중치를 -ln(p_edge)로 바꾸면 곱셈이 덧셈이 되고,
// "확률 최대 경로 = 이 가중치 합이 최소인 경로" 가 되어 Dijkstra로 풀린다.
//   - reachProb(A→B) = exp(-dist[B]),  A 자신은 1.0
//   - p_edge <= 0 인 엣지는 도달 불가로 보고 skip
//   - 순수함수: DB 없이 합성 엣지로 단위테스트 가능
func ComputeReachProb(edges []BlastEdge, sourceUID string) map[string]float64 {
	// 인접 리스트: u -> [(v, negLog)]
	type arc struct {
		to     string
		negLog float64
	}
	adj := make(map[string][]arc)
	for _, e := range edges {
		if e.SourceUID == e.TargetUID {
			continue // self-loop 제외
		}
		if e.PEdge <= 0 {
			continue // 확률 0 이하 = 도달 불가
		}
		negLog := -math.Log(e.PEdge) // p가 클수록 negLog는 0에 가까움(= 가까운 거리)
		adj[e.SourceUID] = append(adj[e.SourceUID], arc{to: e.TargetUID, negLog: negLog})
	}

	dist := map[string]float64{sourceUID: 0} // 누적 -ln(p). source는 0 (= 확률 1.0)
	h := &minHeap{{uid: sourceUID, dist: 0}}
	heap.Init(h)

	for h.Len() > 0 {
		cur := heap.Pop(h).(pqItem)
		if d, ok := dist[cur.uid]; ok && cur.dist > d {
			continue // 이미 더 짧은 경로로 확정됨 → stale 항목 skip
		}
		for _, a := range adj[cur.uid] {
			nd := cur.dist + a.negLog
			if old, ok := dist[a.to]; !ok || nd < old {
				dist[a.to] = nd
				heap.Push(h, pqItem{uid: a.to, dist: nd})
			}
		}
	}

	reach := make(map[string]float64, len(dist))
	for uid, d := range dist {
		reach[uid] = math.Exp(-d) // exp(-0) = 1.0 (source)
	}
	return reach
}

// ── Go 표준 container/heap 쓰려면 이 인터페이스 5개 구현 필요 (보일러플레이트) ──
type pqItem struct {
	uid  string
	dist float64
}
type minHeap []pqItem

func (h minHeap) Len() int           { return len(h) }
func (h minHeap) Less(i, j int) bool { return h[i].dist < h[j].dist } // dist 작은 게 먼저
func (h minHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *minHeap) Push(x interface{}) { *h = append(*h, x.(pqItem)) }
func (h *minHeap) Pop() interface{} {
	old := *h
	n := len(old)
	it := old[n-1]
	*h = old[:n-1]
	return it
}