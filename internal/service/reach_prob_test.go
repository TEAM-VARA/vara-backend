package service

import (
	"math"
	"testing"
)

func almostEqual(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// 단일 경로: A -0.8-> B -0.5-> C → C는 0.8*0.5=0.4
func TestComputeReachProb_singlePath(t *testing.T) {
	edges := []BlastEdge{
		{SourceUID: "A", TargetUID: "B", PEdge: 0.8},
		{SourceUID: "B", TargetUID: "C", PEdge: 0.5},
	}
	r := ComputeReachProb(edges, "A")
	if !almostEqual(r["A"], 1.0) { t.Errorf("A=1.0 여야 하는데 %v", r["A"]) }
	if !almostEqual(r["B"], 0.8) { t.Errorf("B=0.8 여야 하는데 %v", r["B"]) }
	if !almostEqual(r["C"], 0.4) { t.Errorf("C=0.4 여야 하는데 %v", r["C"]) }
}

// 두 경로 → 더 높은 확률 선택: 직통 A->C 0.3 vs 우회 A->B->C 0.4 → 0.4 선택
func TestComputeReachProb_picksMaxPath(t *testing.T) {
	edges := []BlastEdge{
		{SourceUID: "A", TargetUID: "C", PEdge: 0.3},
		{SourceUID: "A", TargetUID: "B", PEdge: 0.8},
		{SourceUID: "B", TargetUID: "C", PEdge: 0.5},
	}
	r := ComputeReachProb(edges, "A")
	if !almostEqual(r["C"], 0.4) { t.Errorf("C는 max-path 0.4 여야 하는데 %v", r["C"]) }
}

// 도달 불가: A와 끊긴 D->C 는 결과에 없어야 함
func TestComputeReachProb_unreachable(t *testing.T) {
	edges := []BlastEdge{
		{SourceUID: "A", TargetUID: "B", PEdge: 0.8},
		{SourceUID: "D", TargetUID: "C", PEdge: 0.9},
	}
	r := ComputeReachProb(edges, "A")
	if _, ok := r["C"]; ok { t.Errorf("C는 A에서 도달 불가여야 하는데 %v", r["C"]) }
}

// 사이클 안전 종료: A->B->A
func TestComputeReachProb_cycle(t *testing.T) {
	edges := []BlastEdge{
		{SourceUID: "A", TargetUID: "B", PEdge: 0.8},
		{SourceUID: "B", TargetUID: "A", PEdge: 0.5},
	}
	r := ComputeReachProb(edges, "A")
	if !almostEqual(r["A"], 1.0) { t.Errorf("A=1.0 유지여야 하는데 %v", r["A"]) }
	if !almostEqual(r["B"], 0.8) { t.Errorf("B=0.8 여야 하는데 %v", r["B"]) }
}