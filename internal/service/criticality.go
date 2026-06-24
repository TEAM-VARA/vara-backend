package service

import "math/rand"

// ComputeCriticalityMC: 파드 A의 총위험도 = "A 털리면 영향받는 파드 기대 개수".
// 매 시행마다 각 엣지를 p_edge 확률로 "살리고", A에서 살아있는 엣지로 BFS →
// 닿은 파드 수를 셈. 그 평균이 총위험도.
//   · 모든 경로 자동 OR-combine (살아있는 경로 하나라도 있으면 닿음)
//   · 사이클·공유엣지 자연 처리 (공유엣지는 시행당 한 번만 샘플 → 의존성 정확)
func ComputeCriticalityMC(edges []BlastEdge, sourceUID string, trials int, rng *rand.Rand) float64 {
	type arc struct {
		dst string
		p   float64
	}
	adj := make(map[string][]arc, len(edges))
	for _, e := range edges {
		if e.SourceUID == e.TargetUID {
			continue // self-loop 제외
		}
		adj[e.SourceUID] = append(adj[e.SourceUID], arc{e.TargetUID, e.PEdge})
	}

	totalReached := 0
	for t := 0; t < trials; t++ {
		visited := map[string]bool{sourceUID: true}
		queue := []string{sourceUID}
		for len(queue) > 0 {
			u := queue[0]
			queue = queue[1:]
			for _, a := range adj[u] {
				if visited[a.dst] {
					continue
				}
				if rng.Float64() < a.p { // 이 엣지가 이번 시행에 성공
					visited[a.dst] = true
					queue = append(queue, a.dst)
				}
			}
		}
		totalReached += len(visited) - 1 // 자기 자신 제외
	}
	return float64(totalReached) / float64(trials)
}

// ComputeReachProbMC: 소스 A → 각 목적지 B의 도달확률을 MC로 추정.
// 매 시행 각 엣지를 p_edge로 샘플 → A에서 BFS로 닿은 노드 집계.
// reachProb(B) = (B에 닿은 시행 수) / trials.  (참고: Σ_B reachProb(B) = total_risk)
//   · ComputeCriticalityMC와 동일한 시뮬레이션이며, 스칼라 합 대신 dst별로 집계만 다름
func ComputeReachProbMC(edges []BlastEdge, sourceUID string, trials int, rng *rand.Rand) map[string]float64 {
	type arc struct {
		dst string
		p   float64
	}
	adj := make(map[string][]arc, len(edges))
	for _, e := range edges {
		if e.SourceUID == e.TargetUID {
			continue // self-loop 제외
		}
		adj[e.SourceUID] = append(adj[e.SourceUID], arc{e.TargetUID, e.PEdge})
	}

	hits := make(map[string]int)
	for t := 0; t < trials; t++ {
		visited := map[string]bool{sourceUID: true}
		queue := []string{sourceUID}
		for len(queue) > 0 {
			u := queue[0]
			queue = queue[1:]
			for _, a := range adj[u] {
				if visited[a.dst] {
					continue
				}
				if rng.Float64() < a.p { // 이 엣지가 이번 시행에 성공
					visited[a.dst] = true
					queue = append(queue, a.dst)
				}
			}
		}
		for b := range visited {
			if b != sourceUID {
				hits[b]++
			}
		}
	}

	out := make(map[string]float64, len(hits))
	inv := 1.0 / float64(trials)
	for b, c := range hits {
		out[b] = float64(c) * inv
	}
	return out
}