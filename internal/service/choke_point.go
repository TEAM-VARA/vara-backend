package service

// ComputeChokeScores: 노드별 choke score = "그 노드를 제거하면 A(source)의 blast가 얼마나 줄어드나".
//
//	choke[X] = baseline − reachableWithoutX
//	  baseline          = A에서 BFS로 닿는 노드 수 (A 자신 포함)
//	  reachableWithoutX = X(와 X에 연결된 엣지 전부) 뺀 그래프에서 A가 닿는 수
//
// 확률(p_edge)은 안 씀 — "닿느냐(reachability)"만 봄. 전체 그래프 기준(슬라이더 필터 무관).
// 순수함수: DB 없이 단위테스트 가능.
func ComputeChokeScores(edges []BlastEdge, sourceUID string) map[string]int {
	adj := make(map[string][]string, len(edges))
	for _, e := range edges {
		if e.SourceUID == e.TargetUID {
			continue // self-loop 제외
		}
		adj[e.SourceUID] = append(adj[e.SourceUID], e.TargetUID)
	}

	baseSet := chokeReachable(adj, sourceUID, "")
	baseline := len(baseSet)

	choke := make(map[string]int)
	for x := range baseSet {
		if x == sourceUID {
			continue // source 자신은 제거 후보 아님
		}
		choke[x] = baseline - len(chokeReachable(adj, sourceUID, x))
	}
	return choke
}

// chokeReachable: source에서 BFS로 닿는 집합. exclude!="" 이면 그 노드를 통째로 제거한 셈.
func chokeReachable(adj map[string][]string, source, exclude string) map[string]bool {
	if source == exclude {
		return map[string]bool{}
	}
	visited := map[string]bool{source: true}
	queue := []string{source}
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		for _, v := range adj[u] {
			if v == exclude || visited[v] {
				continue
			}
			visited[v] = true
			queue = append(queue, v)
		}
	}
	return visited
}
