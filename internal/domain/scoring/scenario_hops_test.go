package scoring

import (
	"strings"
	"testing"
)

// 엣지마다 살아있는 채널을 모두 풀고(여러 채널 동시), 멀티홉(A→B→C)으로 이어진다.
func TestBuildHopScenarios(t *testing.T) {
	edges := []HopEdge{
		// A→B: network + rbac 둘 다 살아있음(win=network).
		{SourceUID: "A", TargetUID: "B", SourceName: "app", TargetName: "db",
			PNet: 0.63, PRBAC: 1.0, WinChannel: "network", Reason: "network: eBPF flow, B.Risk=0.630"},
		// B→C: host로만 도달(win=host).
		{SourceUID: "B", TargetUID: "C", SourceName: "db", TargetName: "node-mate",
			PHost: 1.0, WinChannel: "host", Reason: "host: escape + same node n1"},
	}
	hops, truncated := BuildHopScenarios(edges, "A")
	if truncated {
		t.Fatalf("예상치 못한 truncate")
	}
	if len(hops) != 2 {
		t.Fatalf("hops = %d, want 2: %+v", len(hops), hops)
	}

	// 1홉 A→B: network + rbac 2채널
	h1 := hops[0]
	if h1.Hop != 1 || h1.SourceName != "app" || h1.TargetName != "db" {
		t.Errorf("1홉 메타 오류: %+v", h1)
	}
	if len(h1.Channels) != 2 {
		t.Fatalf("1홉 채널 = %d, want 2 (network+rbac): %+v", len(h1.Channels), h1.Channels)
	}
	if h1.Channels[0].Channel != "network" || h1.Channels[1].Channel != "rbac" {
		t.Errorf("채널 순서 오류: %+v", h1.Channels)
	}
	// 승자(network)에만 reason, 비승자(rbac)는 빈 값
	if h1.Channels[0].Reason == "" {
		t.Errorf("network(win) reason 누락")
	}
	if h1.Channels[1].Reason != "" {
		t.Errorf("rbac(비win) reason은 비어야 함: %q", h1.Channels[1].Reason)
	}
	if !strings.Contains(h1.Channels[1].Scenario, "db") || !strings.Contains(h1.Channels[1].Scenario, "명령을 실행") {
		t.Errorf("rbac 줄글 오류: %q", h1.Channels[1].Scenario)
	}

	// 2홉 B→C: host 1채널, hop=2
	h2 := hops[1]
	if h2.Hop != 2 || h2.SourceName != "db" || h2.TargetName != "node-mate" {
		t.Errorf("2홉 메타 오류: %+v", h2)
	}
	if len(h2.Channels) != 1 || h2.Channels[0].Channel != "host" {
		t.Fatalf("2홉 채널 오류: %+v", h2.Channels)
	}
}

// 사이클이 있어도 무한루프 없이 종료한다(엣지는 1회만).
func TestBuildHopScenarios_Cycle(t *testing.T) {
	edges := []HopEdge{
		{SourceUID: "A", TargetUID: "B", PNet: 1.0, WinChannel: "network"},
		{SourceUID: "B", TargetUID: "A", PNet: 1.0, WinChannel: "network"},
	}
	hops, _ := BuildHopScenarios(edges, "A")
	if len(hops) != 2 {
		t.Fatalf("hops = %d, want 2 (A→B, B→A 각 1회): %+v", len(hops), hops)
	}
}
