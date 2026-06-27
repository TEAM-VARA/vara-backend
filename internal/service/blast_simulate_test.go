package service

import (
	"math"
	"testing"

	"github.com/vara/backend/internal/domain/edge"
)

// 합성 topology: A(source) ─net─ B ─net─ C, A ─sc─ D (supply_chain), A ─id─ E (identity)
func sampleEdges() []edge.TopologyEdge {
	return []edge.TopologyEdge{
		{ID: "e1", Source: "A", Target: "B", Layer: "network", EdgeType: "can_reach"},
		{ID: "e2", Source: "B", Target: "C", Layer: "network", EdgeType: "can_reach"},
		{ID: "e3", Source: "A", Target: "D", Layer: "supply_chain", EdgeType: "shares_image"},
		{ID: "e4", Source: "A", Target: "E", Layer: "identity", EdgeType: "assumes"},
	}
}

func TestBuildRemoveSet_NetpolDenyAll(t *testing.T) {
	edges := sampleEdges()
	rs := buildRemoveSet(edges, "A", []edge.AppliedMitigation{
		{Layer: "network", Kind: "netpol_denyall"},
	})
	// A에 인접한 network 엣지(e1)만 제거. B-C(e2)는 A 비인접이라 유지.
	if !rs[topoEdgeKey(edges[0])] {
		t.Errorf("expected A->B network edge removed")
	}
	if rs[topoEdgeKey(edges[1])] {
		t.Errorf("B->C should NOT be removed (not incident to source)")
	}
	if rs[topoEdgeKey(edges[2])] || rs[topoEdgeKey(edges[3])] {
		t.Errorf("non-network layers must be untouched")
	}
}

func TestBuildRemoveSet_NetpolPeer(t *testing.T) {
	edges := sampleEdges()
	rs := buildRemoveSet(edges, "A", []edge.AppliedMitigation{
		{Layer: "network", Kind: "netpol_peer", Target: "B"},
	})
	if !rs[topoEdgeKey(edges[0])] {
		t.Errorf("A<->B network edge should be removed")
	}
	if len(rs) != 1 {
		t.Errorf("only the source<->peer edge should be removed, got %d", len(rs))
	}
}

func TestBuildRemoveSet_CVEImageAndRBAC(t *testing.T) {
	edges := sampleEdges()
	rs := buildRemoveSet(edges, "A", []edge.AppliedMitigation{
		{Layer: "supply_chain", Kind: "cve_image", Target: "sha256:x"},
		{Layer: "identity", Kind: "rbac_revoke", Target: "sa: ns/sa"},
	})
	if !rs[topoEdgeKey(edges[2])] {
		t.Errorf("supply_chain edge should be removed")
	}
	if !rs[topoEdgeKey(edges[3])] {
		t.Errorf("identity edge should be removed")
	}
	if rs[topoEdgeKey(edges[0])] || rs[topoEdgeKey(edges[1])] {
		t.Errorf("network edges must be untouched")
	}
}

func TestComputeBlastScore_NilCritDefaultsToOne(t *testing.T) {
	reach := []edge.ReachableNode{
		{NodeID: "B", Hop: 1, Layer: "network"}, // 0.6^0 * 1.0 * 1 = 1.0
		{NodeID: "C", Hop: 2, Layer: "network"}, // 0.6^1 * 1.0 * 1 = 0.6
	}
	got := computeBlastScore(reach, nil)
	want := 1.6
	if math.Abs(got-want) > 1e-9 {
		t.Errorf("blast score = %v, want %v", got, want)
	}
}

func TestComputeBlastScore_CritScales(t *testing.T) {
	reach := []edge.ReachableNode{{NodeID: "B", Hop: 1, Layer: "network"}}
	crit := map[string]float64{"B": 2.0}
	got := computeBlastScore(reach, crit) // 1.0 * 1.0 * 2.0
	if math.Abs(got-2.0) > 1e-9 {
		t.Errorf("blast score with crit = %v, want 2.0", got)
	}
}

func TestComputeBlastScore_Cap(t *testing.T) {
	reach := make([]edge.ReachableNode, 0, 100)
	for i := 0; i < 100; i++ {
		reach = append(reach, edge.ReachableNode{NodeID: "n", Hop: 1, Layer: "network"})
	}
	if got := computeBlastScore(reach, nil); got != 25.0 {
		t.Errorf("expected cap 25.0, got %v", got)
	}
}

func TestNormalizePageRank_MeanIsOne(t *testing.T) {
	pr := map[string]float64{"a": 0.5, "b": 0.3, "c": 0.2} // sum=1, N=3
	norm := normalizePageRank(pr)
	var sum float64
	for _, v := range norm {
		sum += v
	}
	mean := sum / 3.0
	if math.Abs(mean-1.0) > 1e-9 {
		t.Errorf("normalized mean = %v, want 1.0", mean)
	}
	// a는 평균 이상이므로 >1
	if norm["a"] <= 1.0 {
		t.Errorf("high-pagerank node should normalize >1, got %v", norm["a"])
	}
}

func TestColorLevel(t *testing.T) {
	cases := []struct {
		contrib float64
		dropped bool
		want    string
	}{
		{0, true, "removed"},
		{2.0, false, "emergency"},
		{1.0, false, "warning"},
		{0.5, false, "caution"},
		{0.1, false, "safe"},
		{2.0, true, "removed"}, // dropped이 우선
	}
	for _, c := range cases {
		if got := colorLevel(c.contrib, c.dropped); got != c.want {
			t.Errorf("colorLevel(%v, %v) = %q, want %q", c.contrib, c.dropped, got, c.want)
		}
	}
}
