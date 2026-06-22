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