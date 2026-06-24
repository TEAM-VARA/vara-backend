package scoring

import "testing"

// 3분류 빌더: CVE 정렬, 권한 node+양방향 엣지(rbac/host), NetworkPolicy ingress(dst)/egress(src) 분리 + isolation별 recommendation.
func TestBuildCategories(t *testing.T) {
	in := CategoriesInput{
		CVEs: []CVEItem{
			{ID: "CVE-B", Score: 75, Severity: "high"},
			{ID: "CVE-A", Score: 90, Severity: "critical", Fixed: "1.2.4"},
		},
		SAName: "ci-sa",
		AllPerms: []PermItem{
			{Verb: "*", Resource: "*"},
			{Verb: "get", Resource: "secrets"},
			{Verb: "create", Resource: "pods/exec"},
			{Verb: "get", Resource: "pods"}, // read-only → filterRisky 제외
		},
		PrivilegedContainers: []string{"app"},
		HostPathVolumes:      []string{"data"},
		HostNetwork:          true,
		OutEdges: []CatEdge{
			{Peer: "db", WinChannel: "network", PNet: 0.8},
			{Peer: "batch", WinChannel: "rbac", PRBAC: 0.5, Reason: "rbac: exec"},
		},
		InEdges: []CatEdge{
			{Peer: "frontend", WinChannel: "network", PNet: 0.7},
			{Peer: "host-peer", WinChannel: "host", PHost: 0.6},
		},
		NetworkIsolation: "none",
	}
	c := BuildCategories(in)

	// ── CVE: 점수 내림차순 ──
	if len(c.CVE) != 2 || c.CVE[0].ID != "CVE-A" || c.CVE[1].ID != "CVE-B" {
		t.Errorf("CVE 정렬 실패: %+v", c.CVE)
	}

	// ── 권한 ──
	type pk struct{ kind, dir, peer string }
	got := map[pk]bool{}
	rbacNode := 0
	for _, p := range c.Privilege {
		got[pk{p.Kind, p.Dir, p.Peer}] = true
		if p.Kind == "rbac" && p.Dir == "node" {
			rbacNode++
		}
	}
	if rbacNode != 3 { // */*, get secrets, create pods/exec — read(get pods)는 제외
		t.Errorf("node rbac 위험권한 수=%d (want 3, read 제외)", rbacNode)
	}
	for _, want := range []pk{
		{"privileged", "node", ""}, {"hostPath", "node", ""}, {"hostNetwork", "node", ""},
		{"rbac", "src", "batch"},   // 나가는 rbac 엣지
		{"host", "dst", "host-peer"}, // 들어오는 host 엣지
	} {
		if !got[want] {
			t.Errorf("권한 항목 누락: %+v", want)
		}
	}
	// network 채널 엣지(db, frontend)는 권한이 아니라 NetworkPolicy로 가야 함
	if got[pk{"rbac", "src", "db"}] || got[pk{"host", "dst", "frontend"}] {
		t.Errorf("network 엣지가 권한 항목에 잘못 들어감")
	}

	// ── NetworkPolicy ──
	np := c.NetworkPolicy
	if np.Recommendation != "whitelist_create" {
		t.Errorf("isolation none → recommendation=%q (want whitelist_create)", np.Recommendation)
	}
	if len(np.IngressPeers) != 1 || np.IngressPeers[0].Peer != "frontend" {
		t.Errorf("ingress peers=%+v (want [frontend], dst network 엣지)", np.IngressPeers)
	}
	if len(np.EgressPeers) != 1 || np.EgressPeers[0].Peer != "db" {
		t.Errorf("egress peers=%+v (want [db], src network 엣지)", np.EgressPeers)
	}

	// ── isolation별 recommendation 매핑 ──
	if BuildCategories(CategoriesInput{NetworkIsolation: "deny_all"}).NetworkPolicy.Recommendation != "already_strict" {
		t.Errorf("deny_all → already_strict 여야")
	}
	if BuildCategories(CategoriesInput{NetworkIsolation: "both"}).NetworkPolicy.Recommendation != "whitelist_prune" {
		t.Errorf("both → whitelist_prune 여야")
	}
}
