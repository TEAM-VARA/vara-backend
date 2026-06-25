package service

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vara/backend/internal/domain/scoring"
)

// ============================================================================
// 보완 적용 시 blast_risk(전파 총위험도) 하락량 — total_risk 재계산 기반
//
// blast_risk = blast_pair_risk.total_risk = Σ_B reach_prob(A→B)
//   ("A가 털리면 닿는 파드 기대 개수"). 화면 표시값은 사전계산(MC) 저장값(shown)을 쓴다.
//
// 보완 하락량은 "그 보완이 닫는 채널(rbac/network/host)을 이 Pod의 나가는 엣지에서 0으로 두고
// reach를 다시 계산한" 값과의 차이다(= risk_score 쪽 재계산 방식과 동일 철학):
//
//	delta = baseline − after        (baseline/after 둘 다 Σreach 재계산 공간)
//	after_shown = shown − delta      (저장 total_risk에 delta만큼 적용, 0 클램프)
//
// 채널 매핑: RBAC 보완 → rbac 채널, NetworkPolicy 보완 → network 채널, Mount 보완 → host 채널.
// (blast_edges의 PRbac/PNet/PHost를 0으로 두고 PEdge=max(3채널) 재산정 → ComputeReachProb 재실행)
//
// ⚠ 한계: blast_edges의 채널 확률은 사전계산값이라 "권한 1개·설정 1개" 단위로 되돌릴 수 없다.
// 따라서 개별 항목(권한 1개·privileged 1개)은 Δ0 + 사유로 두고, 채널을 통째로 닫는 "그룹"·
// "technique 단위 보완"에 실제 하락을 싣는다. (risk_score 쪽 MAX/tier Δ0 철학과 동일.)
// ============================================================================

// blast 채널 식별자(blast_edges.win_channel과 동일 표기).
const (
	blastChannelRBAC    = "rbac"
	blastChannelNetwork = "network"
	blastChannelHost    = "host"
)

// blastReducer — 한 source Pod 기준으로 total_risk 하락을 재계산하는 헬퍼.
type blastReducer struct {
	edges    []BlastEdge // 클러스터 최신 스냅샷 blast_edges 전체
	src      string      // source pod uid
	shown    float64     // blast_pair_risk.total_risk(저장 MC값) — 표시 앵커
	baseline float64     // Σ reach(A→B) 재계산 — delta 계산 앵커
}

// newBlastReducer — 엣지/표시값으로 reducer 생성(baseline은 즉시 재계산).
func newBlastReducer(edges []BlastEdge, src string, shown float64) *blastReducer {
	return &blastReducer{
		edges:    edges,
		src:      src,
		shown:    shown,
		baseline: sumReachExcl(edges, src),
	}
}

// loadBlastReducer — DB에서 total_risk(저장값) + 최신 blast_edges를 읽어 reducer를 만든다.
// best-effort: 조회 실패/미계산이면 shown=0·edges=nil(모든 delta 0)로 둔다(시나리오 생성 안 막음).
func loadBlastReducer(ctx context.Context, pool *pgxpool.Pool, cluster, src string) *blastReducer {
	var shown float64
	var edges []BlastEdge
	if pool != nil {
		// total_risk: 소스 단위 동일값이라 MAX 1개로 충분(blast_graph_service와 동일 쿼리).
		_ = pool.QueryRow(ctx,
			`SELECT COALESCE(MAX(total_risk), 0)::float8 FROM blast_pair_risk
			 WHERE cluster_name = $1 AND src_pod_uid = $2`, cluster, src).Scan(&shown)
		if e, err := LoadBlastEdges(ctx, pool, cluster); err == nil {
			edges = e
		}
	}
	return newBlastReducer(edges, src, shown)
}

// closeChannel — 이 Pod의 나가는 엣지에서 channel을 0으로 두고 재계산한 blast 하락.
// targetName!="" 이면 그 대상 Pod로 가는 엣지만(NetworkPolicy를 연결별로 쪼갤 때).
func (b *blastReducer) closeChannel(channel, targetName string) *scoring.RiskReduction {
	if b == nil {
		return nil
	}
	after := sumReachExcl(zeroChannelOutgoing(b.edges, b.src, channel, targetName), b.src)
	delta := b.baseline - after
	if delta < 0 {
		delta = 0
	}
	af := b.shown - delta
	if af < 0 {
		af = 0
	}
	return &scoring.RiskReduction{
		Axis:   scoring.AxisBlast,
		Before: scoring.RoundTo2(b.shown),
		After:  scoring.RoundTo2(af),
		Delta:  scoring.RoundTo2(delta),
	}
}

// zeroDelta — blast 축이지만 하락 0(개별 항목: 채널을 단독으로 닫지 못함).
func (b *blastReducer) zeroDelta() *scoring.RiskReduction {
	if b == nil {
		return nil
	}
	return &scoring.RiskReduction{
		Axis:   scoring.AxisBlast,
		Before: scoring.RoundTo2(b.shown),
		After:  scoring.RoundTo2(b.shown),
		Delta:  0,
	}
}

// sumReachExcl — total_risk 정의대로 source 자신(reach=1.0)을 빼고 Σ reach(A→B).
func sumReachExcl(edges []BlastEdge, src string) float64 {
	reach := ComputeReachProb(edges, src)
	var sum float64
	for uid, p := range reach {
		if uid == src {
			continue
		}
		sum += p
	}
	return sum
}

// zeroChannelOutgoing — src에서 나가는 엣지의 한 채널을 0으로 두고 PEdge=max(3채널) 재산정한 사본.
// 입력은 변형하지 않는다(복사본 반환). targetName!=""이면 그 대상으로 가는 엣지만.
func zeroChannelOutgoing(edges []BlastEdge, src, channel, targetName string) []BlastEdge {
	out := make([]BlastEdge, len(edges))
	copy(out, edges)
	for i := range out {
		if out[i].SourceUID != src {
			continue
		}
		if targetName != "" && out[i].TargetName != targetName {
			continue
		}
		switch channel {
		case blastChannelNetwork:
			out[i].PNet = 0
		case blastChannelRBAC:
			out[i].PRbac = 0
		case blastChannelHost:
			out[i].PHost = 0
		}
		out[i].PEdge = maxF3(out[i].PHost, out[i].PRbac, out[i].PNet)
	}
	return out
}

func maxF3(a, b, c float64) float64 {
	m := a
	if b > m {
		m = b
	}
	if c > m {
		m = c
	}
	return m
}

// 개별 항목 Δ0 사유(채널은 "능력 전체 제거" 단위라 항목 하나로는 안 닫힘).
const (
	blastZeroReasonRBAC  = "이 권한 하나로는 측면이동(rbac) 채널이 닫히지 않습니다 — 'SA 위험 권한 전부 회수'(그룹)에서 blast 하락이 반영됩니다."
	blastZeroReasonMount = "이 설정 하나로는 노드 공유(host) 채널이 닫히지 않습니다 — 'privileged·hostPath·host* 전부 제거'(그룹)에서 blast 하락이 반영됩니다."
)

// blastReasonIfZero — 채널을 닫아도 Δ0이면(그 채널 전파 없음/다른 채널 우세) 안내 문구, 아니면 빈 문자열.
func blastReasonIfZero(rr *scoring.RiskReduction, channelLabel string) string {
	if rr == nil || rr.Delta > 0 {
		return ""
	}
	return fmt.Sprintf("이 Pod의 %s 채널 전파가 없어(또는 다른 채널이 우세) blast 하락이 없습니다.", channelLabel)
}

// attachBlastReductionsToItems — granular 보완 항목/그룹(remediation_items)의 RiskReduction을
// blast 축으로 덮어쓴다. CVE·외부노출(risk 축)은 손대지 않는다.
//
//	개별 rbac/mount 항목 → Δ0 + 사유(그룹에서 실제 하락)
//	rbac:sa:* 그룹      → rbac 채널 차단 재계산
//	mount:pod 그룹      → host 채널 차단 재계산
//	net:isolation 항목  → network 채널(이 Pod egress) 차단 재계산
func (s *ScenarioService) attachBlastReductionsToItems(res *scoring.PodScenarioResult, br *blastReducer) {
	if res == nil || br == nil {
		return
	}
	for i := range res.RemediationItems {
		it := &res.RemediationItems[i]
		switch {
		case it.Kind == "rbac":
			it.RiskReduction = *br.zeroDelta()
			it.ZeroReason = blastZeroReasonRBAC
		case it.Kind == "mount":
			it.RiskReduction = *br.zeroDelta()
			it.ZeroReason = blastZeroReasonMount
		case it.Kind == "net" && it.ID == "net:isolation":
			rr := br.closeChannel(blastChannelNetwork, "") // default-deny = 이 Pod의 network 채널 차단
			it.RiskReduction = *rr
			it.ZeroReason = blastReasonIfZero(rr, "network")
			// cve / net:exposure → risk 축 그대로 유지
		}
	}
	for i := range res.RemediationGroups {
		g := &res.RemediationGroups[i]
		switch g.Kind {
		case "rbac":
			rr := br.closeChannel(blastChannelRBAC, "")
			g.RiskReduction = *rr
			g.ZeroReason = blastReasonIfZero(rr, "rbac")
		case "mount":
			rr := br.closeChannel(blastChannelHost, "")
			g.RiskReduction = *rr
			g.ZeroReason = blastReasonIfZero(rr, "host")
			// cve:image → risk 축 그대로 유지
		}
	}
}
