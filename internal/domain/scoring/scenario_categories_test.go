package scoring

import (
	"strings"
	"testing"
)

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

// rbac 엣지 권한 항목: 출발 SA의 초기권한(LateralPerms)을 지목해 "…해제하세요",
// 비면 blast reason의 rbac 상세 → 일반 회수 문구 순으로 폴백한다(양방향).
func TestEdgePrivInitialPerms(t *testing.T) {
	in := CategoriesInput{
		SAName: "ci-sa",
		OutEdges: []CatEdge{
			// 초기권한 직접 지목 (출발 = 이 Pod, SA = ci-sa)
			{Peer: "batch", WinChannel: "rbac", PRBAC: 1, SrcSA: "ci-sa", LateralPerms: []string{"create pods/exec", "get nodes/proxy"}},
			// 초기권한 없음 → reason(rbac:) 폴백
			{Peer: "api", WinChannel: "rbac", PRBAC: 1, Reason: "rbac: portforward (포트 접근) ns=default"},
			// 초기권한 없음 + reason이 rbac 아님 → 일반 폴백(회수)
			{Peer: "host-svc", WinChannel: "rbac", PRBAC: 1, Reason: "host: escape same node n1"},
		},
		InEdges: []CatEdge{
			// 들어오는 엣지: 출발 pod의 SA 지목
			{Peer: "attacker", WinChannel: "rbac", PRBAC: 1, SrcSA: "batch-sa", LateralPerms: []string{"create pods/exec"}},
		},
	}
	c := BuildCategories(in)

	find := func(dir, peer string) *CatPrivilege {
		for i := range c.Privilege {
			if c.Privilege[i].Kind == "rbac" && c.Privilege[i].Dir == dir && c.Privilege[i].Peer == peer {
				return &c.Privilege[i]
			}
		}
		return nil
	}

	// src + 초기권한 직접 지목
	if p := find("src", "batch"); p == nil {
		t.Fatal("src/batch rbac 권한 항목 누락")
	} else {
		if !strings.Contains(p.Text, "create pods/exec") || !strings.Contains(p.Text, "해제하세요") {
			t.Errorf("초기권한 지목 실패: text=%q", p.Text)
		}
		if p.SA != "ci-sa" || len(p.Perms) != 2 {
			t.Errorf("SA/Perms 미설정: sa=%q perms=%v", p.SA, p.Perms)
		}
		if !strings.Contains(p.Remove, "create pods/exec") {
			t.Errorf("remove에 권한 누락: %q", p.Remove)
		}
	}

	// src + reason 폴백 (초기권한 없음)
	if p := find("src", "api"); p == nil {
		t.Fatal("src/api rbac 권한 항목 누락")
	} else if !strings.Contains(p.Text, "portforward") || !strings.Contains(p.Text, "해제하세요") {
		t.Errorf("reason 폴백 실패: text=%q", p.Text)
	}

	// src + 일반 폴백 (reason이 rbac 아님) → "회수", "해제하세요" 아님
	if p := find("src", "host-svc"); p == nil {
		t.Fatal("src/host-svc rbac 권한 항목 누락")
	} else if strings.Contains(p.Text, "해제하세요") || !strings.Contains(p.Text, "회수") {
		t.Errorf("일반 폴백이어야: text=%q", p.Text)
	}

	// dst + 출발 SA 지목
	if p := find("dst", "attacker"); p == nil {
		t.Fatal("dst/attacker rbac 권한 항목 누락")
	} else if !strings.Contains(p.Text, "batch-sa") || !strings.Contains(p.Text, "create pods/exec") || !strings.Contains(p.Text, "해제하세요") {
		t.Errorf("dst 출발 SA 지목 실패: text=%q", p.Text)
	}
}
