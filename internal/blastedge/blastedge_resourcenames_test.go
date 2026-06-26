package blastedge

import "testing"

// resourceNames(=파드 이름) 좁힘 동작 검증.
// BuildEdges 의 kExec 분기가 Perm.ResourceName 을 읽어, 지정 시 그 이름의 파드로만
// 엣지를 만드는지 / nil 이면 기존대로 ns 스코프 전체로 만드는지(회귀)를 확인한다.
//
// 공통 토폴로지: source a(dev, token) + 타겟 b,c(dev, 서로 다른 노드).
// a 는 privileged 아님 + flow 없음 → host·network 채널 0 → RBAC 엣지만 관측된다.
func resourceNamesFixture() map[string]PodFact {
	return map[string]PodFact{
		"a": {UID: "a", Name: "pod-a", Namespace: "dev", Node: "n1", Running: true, SANamespace: "dev", SAName: "sa-a", HasSAToken: true},
		"b": {UID: "b", Name: "pod-b", Namespace: "dev", Node: "n2", Running: true},
		"c": {UID: "c", Name: "pod-c", Namespace: "dev", Node: "n3", Running: true},
	}
}

// ResourceName 지정 → 그 이름의 파드로만 엣지(나머지는 제외).
func TestRBACExecResourceNameNarrows(t *testing.T) {
	perms := map[string][]Perm{
		"dev/sa-a": {{APIGroup: "", Resource: "pods/exec", Verb: "create", Namespace: ns("dev"), ResourceName: ns("pod-b")}},
	}
	edges := BuildEdges(resourceNamesFixture(), perms, nil)

	// a→b: resourceNames=pod-b 와 일치 → rbac 엣지 생성
	e := findEdge(edges, "a", "b")
	if e == nil || e.PRBAC != 1 || e.WinChannel != "rbac" {
		t.Fatalf("a→b want rbac=1 win=rbac (resourceNames=pod-b), got %+v", e)
	}
	if e.Reason != "rbac: exec → pod-b" {
		t.Errorf("a→b reason want %q, got %q", "rbac: exec → pod-b", e.Reason)
	}

	// a→c: pod-c 는 resourceNames 밖 → 엣지 없어야 함
	if e := findEdge(edges, "a", "c"); e != nil {
		t.Errorf("a→c must not exist (resourceNames=pod-b excludes pod-c), got %+v", e)
	}
}

// ResourceName == nil → 범위 제한 없음 → ns 스코프 전체로 엣지(회귀 방지).
func TestRBACExecResourceNameNilUnrestricted(t *testing.T) {
	perms := map[string][]Perm{
		"dev/sa-a": {{APIGroup: "", Resource: "pods/exec", Verb: "create", Namespace: ns("dev")}}, // ResourceName nil
	}
	edges := BuildEdges(resourceNamesFixture(), perms, nil)

	// nil → dev 네임스페이스의 모든 running 파드(b, c)로 엣지
	for _, dst := range []string{"b", "c"} {
		if e := findEdge(edges, "a", dst); e == nil || e.PRBAC != 1 || e.WinChannel != "rbac" {
			t.Errorf("a→%s want rbac=1 win=rbac (nil resourceNames = ns 전체), got %+v", dst, e)
		}
	}
	// reason 은 기존 ns 스코프 포맷 유지
	if e := findEdge(edges, "a", "b"); e != nil && e.Reason != "rbac: exec/attach/ephemeral ns=dev" {
		t.Errorf("a→b reason want %q, got %q", "rbac: exec/attach/ephemeral ns=dev", e.Reason)
	}
}
