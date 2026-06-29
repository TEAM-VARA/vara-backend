package service

import (
	"testing"

	"github.com/vara/backend/internal/domain/edge"
)

// be — 채널 확률로 BlastEdge 생성(PEdge=max 자동). win_channel은 max 채널로 둔다.
func be(src, dst string, host, rbac, net float64) BlastEdge {
	pe := maxF3(host, rbac, net)
	win := "network"
	switch pe {
	case host:
		win = "host"
	case rbac:
		win = "rbac"
	}
	return BlastEdge{
		SourceUID: src, TargetUID: dst,
		SourceName: src, TargetName: dst,
		PHost: host, PRbac: rbac, PNet: net, PEdge: pe,
		WinChannel: win,
	}
}

func fptr(v float64) *float64 { return &v }

// ── attenuateForMitigations ───────────────────────────────────────────────

func TestKeepFactor(t *testing.T) {
	cases := []struct {
		in   *float64
		want float64
	}{
		{nil, 0},          // 기본 = 완전 차단
		{fptr(1.0), 0},    // 100% 효과 = 완전 차단
		{fptr(0.5), 0.5},  // 절반 효과 = 절반 잔존
		{fptr(0.0), 1.0},  // 0% 효과 = 그대로
		{fptr(-1), 0},     // 범위밖 → 완전 차단
		{fptr(2), 0},      // 범위밖 → 완전 차단
	}
	for _, c := range cases {
		if got := keepFactor(c.in); got != c.want {
			t.Errorf("keepFactor(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestAttenuate_NetpolDenyAll(t *testing.T) {
	// A→B: net 우세지만 rbac도 살아있음. denyall이면 net만 0 → PEdge=rbac(0.3)로 약화(완전 제거 아님).
	edges := []BlastEdge{
		be("A", "B", 0, 0.3, 0.8),
		be("B", "C", 0, 0, 0.5), // 비인접 → 불변
	}
	sim, att := attenuateForMitigations(edges, "A", []edge.AppliedMitigation{
		{Kind: "netpol_denyall"},
	}, nil)
	if sim[0].PNet != 0 {
		t.Errorf("A->B PNet should be 0, got %v", sim[0].PNet)
	}
	if sim[0].PEdge != 0.3 {
		t.Errorf("A->B PEdge should fall to rbac=0.3 (max remaining), got %v", sim[0].PEdge)
	}
	if sim[1].PNet != 0.5 {
		t.Errorf("B->C must be untouched (not source-outgoing), got %v", sim[1].PNet)
	}
	if len(att) != 1 || att[0].Channel != "network" || att[0].PBefore != 0.8 || att[0].PAfter != 0 {
		t.Errorf("expected 1 network attenuation 0.8->0, got %+v", att)
	}
}

func TestAttenuate_PartialEffectiveness(t *testing.T) {
	// 50% 효과 → net 0.8*0.5=0.4. PEdge도 0.4.
	edges := []BlastEdge{be("A", "B", 0, 0, 0.8)}
	sim, _ := attenuateForMitigations(edges, "A", []edge.AppliedMitigation{
		{Kind: "netpol_denyall", Effectiveness: fptr(0.5)},
	}, nil)
	if sim[0].PNet != 0.4 || sim[0].PEdge != 0.4 {
		t.Errorf("partial: expected PNet=PEdge=0.4, got net=%v edge=%v", sim[0].PNet, sim[0].PEdge)
	}
}

func TestAttenuate_CVEInbound(t *testing.T) {
	// cveKeep[B]=0.25 → B로 들어오는 network 엣지(p_net=B.Risk)를 25%로 감쇠(부분 패치).
	edges := []BlastEdge{
		be("A", "B", 0, 0, 0.8), // 인바운드 to B → 감쇠 대상
		be("B", "C", 0, 0, 0.5), // 아웃바운드 → 불변
	}
	sim, _ := attenuateForMitigations(edges, "A", nil, map[string]float64{"B": 0.25})
	if sim[0].PNet != 0.2 { // 0.8 × 0.25
		t.Errorf("inbound A->B should scale to 0.2, got %v", sim[0].PNet)
	}
	if sim[1].PNet != 0.5 {
		t.Errorf("outbound B->C must be untouched, got %v", sim[1].PNet)
	}
}

// ── CVE → risk 분해 (riskRatioAfterPatch) ─────────────────────────────────

func TestRiskRatioAfterPatch(t *testing.T) {
	// final = (0.7·global + 0.3·exp)·toxic. 여기선 global=80, toxic=1.0, exp=20 → final=62.
	p := podRisk{final: 62, global: 80, toxic: 1.0}

	// 이미지 전체 패치(newGlobal=0): newFinal = 62 − 0.7·80·1 = 6 → ratio = 6/62 ≈ 0.0968.
	if r := riskRatioAfterPatch(p, 0); r < 0.09 || r > 0.105 {
		t.Errorf("full patch ratio = %.4f, want ~0.097", r)
	}
	// top CVE만 제거, 차순위 global=50: newFinal = 62 − 0.7·(80−50) = 41 → ratio = 41/62 ≈ 0.661.
	if r := riskRatioAfterPatch(p, 50); r < 0.65 || r > 0.67 {
		t.Errorf("partial patch ratio = %.4f, want ~0.661", r)
	}
	// newGlobal=global(변화 없음) → ratio 1.
	if r := riskRatioAfterPatch(p, 80); r != 1 {
		t.Errorf("no-change ratio = %.4f, want 1", r)
	}
	// final 0 → ratio 1 (이미 risk 0).
	if r := riskRatioAfterPatch(podRisk{final: 0, global: 0, toxic: 1}, 0); r != 1 {
		t.Errorf("zero-final ratio = %.4f, want 1", r)
	}
	// toxic 배수 반영: toxic=1.5면 패치 효과도 1.5배. final=(0.7·80+0.3·20)·1.5=93.
	pt := podRisk{final: 93, global: 80, toxic: 1.5}
	// newFinal = 93 − 0.7·80·1.5 = 9 → ratio = 9/93 ≈ 0.0968.
	if r := riskRatioAfterPatch(pt, 0); r < 0.09 || r > 0.105 {
		t.Errorf("toxic full patch ratio = %.4f, want ~0.097", r)
	}
}

// ── MC 전파 ────────────────────────────────────────────────────────────────

const mcTrials = 40000

func approx(t *testing.T, label string, got, want, tol float64) {
	t.Helper()
	if d := got - want; d < -tol || d > tol {
		t.Errorf("%s = %.4f, want ~%.4f (±%.2f)", label, got, want, tol)
	}
}

// 직선 사슬: A→B(0.8)→C(0.5). A→B를 절반(0.4)으로 줄이면 C가 0.4→0.2로 비례 하락(전파).
func TestMC_StraightChain_Propagation(t *testing.T) {
	edges := []BlastEdge{
		be("A", "B", 0, 0, 0.8),
		be("B", "C", 0, 0, 0.5),
	}
	sim, _ := attenuateForMitigations(edges, "A", []edge.AppliedMitigation{
		{Kind: "netpol_peer", Target: "B", Effectiveness: fptr(0.5)}, // A→B net 0.8→0.4
	}, nil)
	seed := seedForSim("c", "A")
	r0, r1 := computeReachProbPairedMC(edges, sim, "A", mcTrials, seed)

	approx(t, "baseline B", r0["B"], 0.8, 0.02)
	approx(t, "baseline C", r0["C"], 0.40, 0.02) // 0.8*0.5
	approx(t, "sim B", r1["B"], 0.40, 0.02)      // 0.8→0.4
	approx(t, "sim C", r1["C"], 0.20, 0.02)      // 0.4*0.5 — 상류 약화가 C로 전파됨
}

// 우회 경로: A→B(0.8)→C(0.5) + A→C 직통(0.5). A→B를 끊어도 C는 직통으로 부분 생존(0으로 안 떨어짐).
func TestMC_AlternatePath_PartialSurvive(t *testing.T) {
	edges := []BlastEdge{
		be("A", "B", 0, 0, 0.8),
		be("B", "C", 0, 0, 0.5),
		be("A", "C", 0, 0, 0.5), // 직통 우회
	}
	// baseline C = 1-(1-0.4)(1-0.5) = 0.7
	sim, _ := attenuateForMitigations(edges, "A", []edge.AppliedMitigation{
		{Kind: "netpol_peer", Target: "B"}, // A→B 완전 차단
	}, nil)
	seed := seedForSim("c", "A")
	r0, r1 := computeReachProbPairedMC(edges, sim, "A", mcTrials, seed)

	approx(t, "baseline C", r0["C"], 0.70, 0.02)
	approx(t, "sim C", r1["C"], 0.50, 0.02) // 직통만 남음 — 0이 아니라 부분 생존
	if r1["B"] > 0.01 {
		t.Errorf("B should be cut (A->B blocked), got %.4f", r1["B"])
	}
}

// CRN 단조성: 모든 노드 r1 ≤ r0 (감쇠는 확률만 낮추므로 시행마다 sim⊆base).
func TestMC_CRN_Monotone(t *testing.T) {
	edges := []BlastEdge{
		be("A", "B", 0, 0.6, 0.8),
		be("B", "C", 0, 0, 0.5),
		be("A", "C", 0, 0, 0.3),
		be("C", "D", 0.4, 0, 0.4),
	}
	sim, _ := attenuateForMitigations(edges, "A", []edge.AppliedMitigation{
		{Kind: "netpol_denyall"},          // A 아웃 net 0
		{Kind: "rbac_revoke", Target: ""}, // A 아웃 rbac 0
	}, nil)
	seed := seedForSim("c", "A")
	r0, r1 := computeReachProbPairedMC(edges, sim, "A", mcTrials, seed)
	for id := range r0 {
		if r1[id] > r0[id]+1e-9 {
			t.Errorf("monotonicity violated: node %s r1=%.4f > r0=%.4f", id, r1[id], r0[id])
		}
	}
}

// 빈 applied → baseline == sim (전 노드 동일).
func TestMC_NoMitigation_Identity(t *testing.T) {
	edges := []BlastEdge{
		be("A", "B", 0, 0, 0.8),
		be("B", "C", 0, 0, 0.5),
	}
	sim, att := attenuateForMitigations(edges, "A", nil, nil)
	if len(att) != 0 {
		t.Errorf("no mitigation → no attenuation, got %+v", att)
	}
	seed := seedForSim("c", "A")
	r0, r1 := computeReachProbPairedMC(edges, sim, "A", mcTrials, seed)
	for id := range r0 {
		if r0[id] != r1[id] {
			t.Errorf("node %s baseline %.4f != sim %.4f with no mitigation", id, r0[id], r1[id])
		}
	}
}
