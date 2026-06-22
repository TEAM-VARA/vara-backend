package service

import (
	"math"
	"math/rand"
	"testing"
)

// 모든 엣지 p=1.0 → 항상 닿음 → 정확히 도달 노드 수 (변동 없음)
func TestCriticalityMC_allCertain(t *testing.T) {
	edges := []BlastEdge{
		{SourceUID: "A", TargetUID: "B", PEdge: 1.0},
		{SourceUID: "B", TargetUID: "C", PEdge: 1.0},
	}
	got := ComputeCriticalityMC(edges, "A", 1000, rand.New(rand.NewSource(1)))
	if got != 2.0 {
		t.Fatalf("p=1.0 전부면 정확히 2.0, got %v", got)
	}
}

// A에서 나가는 엣지 없음 → 0
func TestCriticalityMC_noReach(t *testing.T) {
	edges := []BlastEdge{{SourceUID: "X", TargetUID: "Y", PEdge: 1.0}}
	got := ComputeCriticalityMC(edges, "A", 1000, rand.New(rand.NewSource(1)))
	if got != 0.0 {
		t.Fatalf("A 무관 엣지뿐이면 0, got %v", got)
	}
}

// 단일 엣지 A→B p=0.5 → ≈0.5 (5만 시행, 허용오차)
func TestCriticalityMC_singleApprox(t *testing.T) {
	edges := []BlastEdge{{SourceUID: "A", TargetUID: "B", PEdge: 0.5}}
	got := ComputeCriticalityMC(edges, "A", 50000, rand.New(rand.NewSource(42)))
	if math.Abs(got-0.5) > 0.02 {
		t.Fatalf("≈0.5 기대, got %v", got)
	}
}

// OR-combine 확인: A→C(0.3) + A→B(1.0)→C(0.5)
//   B=항상 1.0, C=두 경로 OR=1-(1-0.3)(1-0.5)=0.65 → 총 ≈1.65
func TestCriticalityMC_orCombine(t *testing.T) {
	edges := []BlastEdge{
		{SourceUID: "A", TargetUID: "C", PEdge: 0.3},
		{SourceUID: "A", TargetUID: "B", PEdge: 1.0},
		{SourceUID: "B", TargetUID: "C", PEdge: 0.5},
	}
	got := ComputeCriticalityMC(edges, "A", 50000, rand.New(rand.NewSource(7)))
	want := 1.0 + 0.65
	if math.Abs(got-want) > 0.02 {
		t.Fatalf("OR-combine 기대 %v, got %v", want, got)
	}
}