package service

import (
	"context"
	"fmt"
	"hash/fnv"
	"math/rand"
	"sort"
	"time"

	"github.com/vara/backend/internal/domain/edge"
)

// ============================================================================
// Blast Radius Simulate — MC(몬테카를로) 확률 전파 모드
//
// 기존 topology 모드(PageRank+BFS, edge_service.go)의 한계:
//   - 조치 = layer 엣지 통째 제거(binary) → 하위 파드는 "전부 끊김(0)" 아니면 "그대로"
//   - PageRank 재계산은 전역 중심성이라 살아남은 노드 점수를 사실상 못 내림
//
// MC 모드는 blast_edges의 채널 확률(p_host/p_rbac/p_net)을 "감쇠"하고,
// Common-Random-Numbers(공통난수) 몬테카를로로 도달확률 reach_prob(0~1)를 재계산한다.
//   - 한 채널만 줄여도 p_edge=max(3채널)이라 다른 채널이 살아있으면 엣지는 "약해질 뿐"
//   - 약해진 확률을 MC가 하위로 전파 → 상류 약화가 하위 파드 reach_prob를 비례 감소시킴
//   - risk_after(B) = risk_before(B) × reach_prob_after/before → 연속적 색 변화
//
// CRN: baseline·simulated 두 패스에 시행별 동일 난수 u_e를 써서 페어링한다.
// 감쇠는 확률만 낮추므로 시행마다 (sim 생존 ⊆ base 생존) → delta ≥ 0 보장·저분산.
// ============================================================================

// keepFactor — Effectiveness(0~1, 기본 1.0=완전 차단) → 잔존계수 keep=1-eff.
// nil/범위밖은 완전 차단(keep=0)으로 정규화한다.
func keepFactor(eff *float64) float64 {
	if eff == nil {
		return 0 // 기본: 완전 차단
	}
	e := *eff
	if e < 0 || e > 1 {
		return 0
	}
	return 1 - e
}

// mitigationChannel — 조치 1건이 이 엣지의 어떤 채널을 감쇠하는지. 매칭 안 되면 ok=false.
//
//	netpol_denyall : source의 나가는 엣지 전부 → network
//	netpol_peer    : source→Target(peer) 엣지만 → network
//	rbac_revoke    : source의 나가는 엣지 전부 → rbac
//	mount_remove   : source의 나가는 엣지 전부 → host
//
// CVE(cve_image/cve_id)는 여기서 안 다룬다 — p_net=대상 risk라 "패치 후 risk 재계산"이
// 필요하므로 서비스(DB)가 미리 podUID→잔존계수(cveKeep)로 해석해 attenuate에 넘긴다.
func mitigationChannel(e BlastEdge, source string, m edge.AppliedMitigation) (string, bool) {
	switch m.Kind {
	case "netpol_denyall":
		if e.SourceUID == source {
			return blastChannelNetwork, true
		}
	case "netpol_peer":
		if e.SourceUID == source && e.TargetUID == m.Target {
			return blastChannelNetwork, true
		}
	case "rbac_revoke":
		if e.SourceUID == source {
			return blastChannelRBAC, true
		}
	case "mount_remove":
		if e.SourceUID == source {
			return blastChannelHost, true
		}
	}
	return "", false
}

// attenuateForMitigations — applied[] 조치를 blast_edges 채널 확률에 적용한 사본을 만든다.
// 입력 edges는 변형하지 않는다. 감쇠된 엣지 목록(before/after)도 함께 반환한다.
//
// cveKeep[podUID] = 그 파드로 들어오는 network 확률(p_net)에 곱할 잔존계수(0~1).
// CVE 패치로 대상 파드의 risk가 내려가면 인바운드 p_net(=대상 risk)도 비례 감소한다.
// nil/빈 맵이면 CVE 효과 없음.
func attenuateForMitigations(edges []BlastEdge, source string, applied []edge.AppliedMitigation, cveKeep map[string]float64) ([]BlastEdge, []edge.AttenuatedEdge) {
	out := make([]BlastEdge, len(edges))
	copy(out, edges)

	for _, m := range applied {
		keep := keepFactor(m.Effectiveness)
		for i := range out {
			ch, ok := mitigationChannel(out[i], source, m)
			if !ok {
				continue
			}
			switch ch {
			case blastChannelNetwork:
				out[i].PNet *= keep
			case blastChannelRBAC:
				out[i].PRbac *= keep
			case blastChannelHost:
				out[i].PHost *= keep
			}
			out[i].PEdge = maxF3(out[i].PHost, out[i].PRbac, out[i].PNet)
		}
	}

	// CVE 패치: 대상 파드로 들어오는 network 엣지(p_net=대상 risk)를 잔존계수만큼 감쇠.
	for i := range out {
		if k, ok := cveKeep[out[i].TargetUID]; ok && out[i].PNet > 0 {
			out[i].PNet *= k
			out[i].PEdge = maxF3(out[i].PHost, out[i].PRbac, out[i].PNet)
		}
	}

	// 채널별 before/after diff (여러 조치가 같은 엣지를 쳤어도 원본 대비 최종값으로 1건씩).
	var att []edge.AttenuatedEdge
	emit := func(i int, ch string, before, after float64) {
		if after < before {
			att = append(att, edge.AttenuatedEdge{
				Source: out[i].SourceUID, Target: out[i].TargetUID,
				Channel: ch, PBefore: before, PAfter: after,
			})
		}
	}
	for i := range out {
		emit(i, blastChannelNetwork, edges[i].PNet, out[i].PNet)
		emit(i, blastChannelRBAC, edges[i].PRbac, out[i].PRbac)
		emit(i, blastChannelHost, edges[i].PHost, out[i].PHost)
	}
	return out, att
}

// computeReachProbPairedMC — baseline(base)·simulated(sim) 두 그래프의 source→각 노드
// 도달확률을 CRN 몬테카를로로 동시 추정한다. base/sim은 같은 인덱스 순서를 공유해야 한다
// (sim은 base를 인덱스 보존 복사·감쇠한 것). seed 고정 → 결정적·재현 가능.
func computeReachProbPairedMC(base, sim []BlastEdge, source string, trials int, seed int64) (map[string]float64, map[string]float64) {
	type arc struct {
		to  string
		idx int
	}
	adj := make(map[string][]arc, len(base))
	for i := range base {
		if base[i].SourceUID == base[i].TargetUID {
			continue // self-loop 제외
		}
		adj[base[i].SourceUID] = append(adj[base[i].SourceUID], arc{base[i].TargetUID, i})
	}

	hits0 := make(map[string]int)
	hits1 := make(map[string]int)
	u := make([]float64, len(base))

	// bfs — alive(idx)가 그 엣지의 PEdge를 반환. PEdge > u[idx]면 이번 시행에 생존.
	bfs := func(pEdge func(int) float64, hits map[string]int) {
		visited := map[string]bool{source: true}
		queue := []string{source}
		for len(queue) > 0 {
			n := queue[0]
			queue = queue[1:]
			for _, a := range adj[n] {
				if visited[a.to] {
					continue
				}
				if pEdge(a.idx) > u[a.idx] {
					visited[a.to] = true
					queue = append(queue, a.to)
				}
			}
		}
		for v := range visited {
			if v != source {
				hits[v]++
			}
		}
	}

	for t := 0; t < trials; t++ {
		rng := rand.New(rand.NewSource(seed + int64(t)))
		for i := range u {
			u[i] = rng.Float64() // 두 패스 공유(CRN)
		}
		bfs(func(i int) float64 { return base[i].PEdge }, hits0)
		bfs(func(i int) float64 { return sim[i].PEdge }, hits1)
	}

	inv := 1.0 / float64(trials)
	r0 := make(map[string]float64, len(hits0))
	r1 := make(map[string]float64, len(hits1))
	for k, v := range hits0 {
		r0[k] = float64(v) * inv
	}
	for k, v := range hits1 {
		r1[k] = float64(v) * inv
	}
	return r0, r1
}

// bfsHopLayerBlast — sim 그래프(PEdge>0)에서 source로부터 최단 hop과 첫 도달 채널(layer)을 구한다.
func bfsHopLayerBlast(edges []BlastEdge, source string) (map[string]int, map[string]string) {
	type arc struct {
		to, ch string
	}
	adj := make(map[string][]arc, len(edges))
	for _, e := range edges {
		if e.SourceUID == e.TargetUID || e.PEdge <= 0 {
			continue
		}
		adj[e.SourceUID] = append(adj[e.SourceUID], arc{e.TargetUID, e.WinChannel})
	}
	hop := map[string]int{source: 0}
	layer := map[string]string{}
	queue := []string{source}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, a := range adj[n] {
			if _, ok := hop[a.to]; ok {
				continue
			}
			hop[a.to] = hop[n] + 1
			layer[a.to] = a.ch
			queue = append(queue, a.to)
		}
	}
	return hop, layer
}

// colorLevelByRisk — risk_after(0~100)를 헤더 위험도와 같은 등급컷으로 색칠.
// (final.go ClassifyFinalLevel과 동일 컷: 80/50/20)
func colorLevelByRisk(riskAfter float64, dropped, reachable bool) string {
	switch {
	case dropped || !reachable:
		return "removed"
	case riskAfter >= 80:
		return "emergency"
	case riskAfter >= 50:
		return "warning"
	case riskAfter >= 20:
		return "caution"
	default:
		return "safe"
	}
}

// seedForSim — (cluster, source)에서 결정적 시드 생성. 같은 입력 → 같은 결과.
func seedForSim(cluster, source string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(cluster))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(source))
	return int64(h.Sum64() & 0x7fffffffffffffff)
}

// SimulateBlastRadiusMC — blast_edges 확률 전파 기반 simulate(보안 적용 → 재계산).
// topology 모드(SimulateBlastRadius)와 응답 스키마는 같고, 점수 의미만 다르다:
//
//	blast_score = Σ_B reach_prob(source→B)  (= 기대 도달 파드 수, blast_pair_risk.total_risk와 동일 정의)
//	delta       = baseline_score − blast_score
//	node.reach_prob / risk_after = 연속값(상류 약화가 하위로 전파)
func (s *EdgeService) SimulateBlastRadiusMC(ctx context.Context, req edge.SimulateBlastRequest) (*edge.SimulateBlastResponse, error) {
	start := time.Now()
	if s.pool == nil {
		return nil, fmt.Errorf("mc 모드 simulate 불가: pool 미주입")
	}
	trials := req.Trials
	if trials <= 0 {
		trials = 2000
	}

	edges, err := LoadBlastEdges(ctx, s.pool, req.Cluster)
	if err != nil {
		return nil, err
	}
	riskMap, _ := LoadFinalScores(ctx, s.pool, req.Cluster) // best-effort: 실패 시 risk 0

	// uid → 이름, 전체 노드 집합(out_of용)
	nameMap := make(map[string]string)
	nodeSet := make(map[string]struct{})
	for _, e := range edges {
		if e.SourceName != "" {
			nameMap[e.SourceUID] = e.SourceName
		}
		if e.TargetName != "" {
			nameMap[e.TargetUID] = e.TargetName
		}
		nodeSet[e.SourceUID] = struct{}{}
		nodeSet[e.TargetUID] = struct{}{}
	}

	// CVE 패치(cve_image/cve_id)를 대상 파드 → 인바운드 network 잔존계수로 해석(DB).
	cveKeep, err := s.resolveCVEKeep(ctx, req.Cluster, req.Applied)
	if err != nil {
		return nil, err
	}

	simEdges, attenuated := attenuateForMitigations(edges, req.Source, req.Applied, cveKeep)
	seed := seedForSim(req.Cluster, req.Source)
	r0, r1 := computeReachProbPairedMC(edges, simEdges, req.Source, trials, seed)

	simHop, simLayer := bfsHopLayerBlast(simEdges, req.Source)

	// 점수 = Σ reach (source 제외, r0/r1은 이미 source 제외 누적).
	baselineScore := sumFloatMap(r0)
	blastScore := sumFloatMap(r1)

	// 노드 = baseline ∪ sim 도달 노드. 안정 순서를 위해 정렬.
	idSet := make(map[string]struct{}, len(r0)+len(r1))
	for id := range r0 {
		idSet[id] = struct{}{}
	}
	for id := range r1 {
		idSet[id] = struct{}{}
	}
	ids := make([]string, 0, len(idSet))
	for id := range idSet {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	byLayer := make(map[string]int)
	nodes := make([]edge.SimNode, 0, len(ids))
	for _, id := range ids {
		rb := r0[id] // reach before
		ra := r1[id] // reach after
		reachable := ra > 0
		dropped := rb > 0 && ra == 0

		riskBefore := riskMap[id]
		riskAfter := riskBefore
		switch {
		case !reachable:
			riskAfter = 0
		case rb > 0:
			if ratio := ra / rb; ratio < 1 {
				riskAfter = riskBefore * ratio // 전파 약화분 투영
			}
		}

		sn := edge.SimNode{
			ID:              id,
			Name:            nameMap[id],
			Reachable:       reachable,
			Criticality:     ra,
			Contribution:    ra,
			ReachProb:       ra,
			ReachProbBefore: rb,
			Dropped:         dropped,
			RiskBefore:      riskBefore,
			RiskAfter:       riskAfter,
		}
		if reachable {
			if h, ok := simHop[id]; ok {
				hh := h
				sn.Hop = &hh
			}
			if l, ok := simLayer[id]; ok {
				ll := l
				sn.Layer = &ll
				byLayer[l]++
			}
		}
		sn.ColorLevel = colorLevelByRisk(riskAfter, dropped, reachable)
		nodes = append(nodes, sn)
	}

	// 완전히 끊긴 엣지(p_edge 0)는 RemovedEdge로도 내려 FE 페이드아웃 호환.
	removed := make([]edge.RemovedEdge, 0)
	for i := range edges {
		if edges[i].PEdge > 0 && simEdges[i].PEdge <= 0 {
			removed = append(removed, edge.RemovedEdge{
				Source: edges[i].SourceUID, Target: edges[i].TargetUID, Layer: edges[i].WinChannel,
			})
		}
	}

	outOf := float64(len(nodeSet))
	if _, ok := nodeSet[req.Source]; ok {
		outOf-- // source 제외 = 이론상 최대 도달 수
	}

	return &edge.SimulateBlastResponse{
		Source:          req.Source,
		Hops:            req.Hops,
		OutOf:           outOf,
		BaselineScore:   round2(baselineScore),
		BlastScore:      round2(blastScore),
		Delta:           round2(baselineScore - blastScore),
		ByLayer:         byLayer,
		Nodes:           nodes,
		EdgesRemoved:    removed,
		EdgesAttenuated: attenuated,
		Mode:            "mc",
		BuildMs:         time.Since(start).Milliseconds(),
	}, nil
}

// ── 작은 헬퍼 ──

func sumFloatMap(m map[string]float64) float64 {
	var s float64
	for _, v := range m {
		s += v
	}
	return s
}

func round2(f float64) float64 {
	return float64(int64(f*100+0.5)) / 100
}
