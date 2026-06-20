package scoring

import (
	"strings"
	"testing"
)

// 이 pod의 나가는 엣지(1홉)마다 살아있는 채널을 모두 풀어준다(여러 채널 동시).
func TestBuildOutgoingScenarios(t *testing.T) {
	edges := []HopEdge{
		// app→db: network + rbac 둘 다 살아있음(win=network).
		{SourceUID: "A", TargetUID: "B", SourceName: "app", TargetName: "db",
			PNet: 0.63, PRBAC: 1.0, WinChannel: "network", Reason: "network: eBPF flow, B.Risk=0.630"},
		// app→node-mate: host로만(win=host).
		{SourceUID: "A", TargetUID: "C", SourceName: "app", TargetName: "node-mate",
			PHost: 1.0, WinChannel: "host", Reason: "host: escape + same node n1"},
		// self-loop은 제외
		{SourceUID: "A", TargetUID: "A", SourceName: "app", TargetName: "app", PNet: 1.0, WinChannel: "network"},
	}
	hops := BuildOutgoingScenarios(edges)
	if len(hops) != 2 {
		t.Fatalf("hops = %d, want 2 (self-loop 제외): %+v", len(hops), hops)
	}

	// 엣지1 app→db: network + rbac 2채널, network 우선
	h1 := hops[0]
	if h1.TargetName != "db" || len(h1.Channels) != 2 {
		t.Fatalf("엣지1 오류: %+v", h1)
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

	// 엣지2 app→node-mate: host 1채널
	h2 := hops[1]
	if h2.TargetName != "node-mate" || len(h2.Channels) != 1 || h2.Channels[0].Channel != "host" {
		t.Fatalf("엣지2 오류: %+v", h2)
	}
}
