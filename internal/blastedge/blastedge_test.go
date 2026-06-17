package blastedge

import (
	"math"
	"testing"
)

func ns(s string) *string { return &s }

func findEdge(edges []Edge, src, dst string) *Edge {
	for i := range edges {
		if edges[i].SrcUID == src && edges[i].DstUID == dst {
			return &edges[i]
		}
	}
	return nil
}

// fixture:
//   a: dev/n1, running, privileged, token, SA dev/sa-a has pods/exec ns=dev
//   b: dev/n1, running, token (target)
//   c: dev/n2, running, token (target; exec reaches via ns=dev, not host)
//   d: prod/n2, running, token, risk 0.5 (network target of a)
//   e: dev/n3, NOT running (exec must skip)
//   f: dev/n1, running, token, SA dev/sa-f has pods/exec ns=dev but HasSAToken=false (source gate)
func fixture() (map[string]PodFact, map[string][]Perm, []Flow) {
	pods := map[string]PodFact{
		"a": {UID: "a", Namespace: "dev", Node: "n1", Running: true, SANamespace: "dev", SAName: "sa-a", Privileged: true, HasSAToken: true, Risk: 0.2},
		"b": {UID: "b", Namespace: "dev", Node: "n1", Running: true, SANamespace: "dev", SAName: "sa-b", HasSAToken: true, Risk: 0.7},
		"c": {UID: "c", Namespace: "dev", Node: "n2", Running: true, SANamespace: "dev", SAName: "sa-c", HasSAToken: true, Risk: 0.6},
		"d": {UID: "d", Namespace: "prod", Node: "n2", Running: true, SANamespace: "prod", SAName: "sa-d", HasSAToken: true, Risk: 0.5},
		"e": {UID: "e", Namespace: "dev", Node: "n3", Running: false, SANamespace: "dev", SAName: "sa-e", HasSAToken: true, Risk: 0.9},
		"f": {UID: "f", Namespace: "dev", Node: "n1", Running: true, SANamespace: "dev", SAName: "sa-f", HasSAToken: false, Risk: 0.4},
	}
	perms := map[string][]Perm{
		"dev/sa-a": {{APIGroup: "", Resource: "pods/exec", Verb: "create", Namespace: ns("dev")}},
		"dev/sa-c": {{APIGroup: "", Resource: "pods/portforward", Verb: "create", Namespace: ns("dev")}},
		"dev/sa-f": {{APIGroup: "", Resource: "pods/exec", Verb: "create", Namespace: ns("dev")}},
	}
	flows := []Flow{{SrcUID: "a", DstUID: "d"}} // a→d network only
	return pods, perms, flows
}

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

func TestHostAndRBACTie(t *testing.T) {
	edges := BuildEdges(fixture())
	// a→b: host(same node n1)=1 AND rbac(exec dev)=1 → p_edge=1, win=host (tie priority)
	e := findEdge(edges, "a", "b")
	if e == nil {
		t.Fatal("a→b edge missing")
	}
	if e.PHost != 1 || e.PRBAC != 1 {
		t.Errorf("a→b channels: host=%v rbac=%v want 1/1", e.PHost, e.PRBAC)
	}
	if e.PEdge != 1 || e.WinChannel != "host" || !approx(e.NegLogP, 0) {
		t.Errorf("a→b finalize: p_edge=%v win=%s neglog=%v want 1/host/0", e.PEdge, e.WinChannel, e.NegLogP)
	}
}

func TestRBACExecNamespaceAndRunning(t *testing.T) {
	edges := BuildEdges(fixture())
	// a→c: rbac exec (c in dev), host=0 (c on n2) → win=rbac
	if e := findEdge(edges, "a", "c"); e == nil || e.PRBAC != 1 || e.PHost != 0 || e.WinChannel != "rbac" {
		t.Errorf("a→c want rbac=1 host=0 win=rbac, got %+v", e)
	}
	// a→e must NOT exist: e is not running (exec skips) and on n3 (no host)
	if e := findEdge(edges, "a", "e"); e != nil {
		t.Errorf("a→e should not exist (e not running, different node), got %+v", e)
	}
}

func TestNetworkChannel(t *testing.T) {
	edges := BuildEdges(fixture())
	// a→d: only network, B.Risk=0.5
	e := findEdge(edges, "a", "d")
	if e == nil {
		t.Fatal("a→d edge missing")
	}
	if e.PNet != 0.5 || e.WinChannel != "network" {
		t.Errorf("a→d want net=0.5 win=network, got net=%v win=%s", e.PNet, e.WinChannel)
	}
	if !approx(e.NegLogP, -math.Log(0.5)) {
		t.Errorf("a→d neg_log_p=%v want %v", e.NegLogP, -math.Log(0.5))
	}
}

func TestSourceTokenGate(t *testing.T) {
	edges := BuildEdges(fixture())
	// f has pods/exec but HasSAToken=false → NO rbac edge from f
	for _, e := range edges {
		if e.SrcUID == "f" {
			t.Errorf("f has no SA token → must not be an RBAC source, got edge f→%s (%+v)", e.DstUID, e)
		}
	}
	// but f is still reachable as a target: a→f via host (f on n1, running)
	if e := findEdge(edges, "a", "f"); e == nil || e.PHost != 1 {
		t.Errorf("a→f host edge expected (f on n1), got %+v", e)
	}
}

func TestNoSelfLoop(t *testing.T) {
	edges := BuildEdges(fixture())
	for _, e := range edges {
		if e.SrcUID == e.DstUID {
			t.Errorf("self-loop edge %s→%s", e.SrcUID, e.DstUID)
		}
		if e.PEdge <= 0 || e.PEdge > 1 {
			t.Errorf("%s→%s p_edge out of range: %v", e.SrcUID, e.DstUID, e.PEdge)
		}
	}
}

func TestPortForwardUsesRisk(t *testing.T) {
	edges := BuildEdges(fixture())
	// c는 dev에 pods/portforward → c→b는 B.Risk(b)=0.7로 rbac 채널
	e := findEdge(edges, "c", "b")
	if e == nil {
		t.Fatal("c→b portforward edge missing")
	}
	if !approx(e.PRBAC, 0.7) || e.WinChannel != "rbac" {
		t.Errorf("c→b want rbac=0.7 win=rbac (portforward→B.Risk), got rbac=%v win=%s", e.PRBAC, e.WinChannel)
	}
	// 저위험 pod로의 portforward도 그 pod의 risk를 그대로 사용
	if e := findEdge(edges, "c", "a"); e == nil || !approx(e.PRBAC, 0.2) {
		t.Errorf("c→a want rbac=0.2 (a.Risk), got %+v", e)
	}
}
