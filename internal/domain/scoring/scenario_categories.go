package scoring

import (
	"fmt"
	"sort"
	"strings"
)

// ============================================================================
// 공격 시나리오 3분류 출력: CVE / 권한(RBAC·privileged) / NetworkPolicy
//
// 기존 findings·줄글·remediation_items와 별개의 "보기 좋은" 구조화 뷰(비파괴 — PodScenarioResult.Categories).
//   - CVE      : 이 Pod 이미지의 CVE만(점수 내림차순).
//   - Privilege: 이 Pod의 위험 RBAC·privileged·host 설정(dir=node) + 양방향 blast 엣지 중 rbac·host 채널
//                (dir=src 이 Pod→peer / dst peer→이 Pod). 각 항목에 "없앨 권한/설정".
//   - NetworkPolicy: 양방향 엣지의 network 도달 peer를 ingress(dst)/egress(src)로 나눠, 방향별 일반 권고
//                (정책 없으면 default-deny+필요 peer만 / 있으면 불필요 peer 제거 — allow/제거 판단은 사람).
// ============================================================================

type CatCVE struct {
	ID       string  `json:"id"`
	Severity string  `json:"severity,omitempty"`
	CVSS     float64 `json:"cvss,omitempty"`
	KEV      bool    `json:"kev,omitempty"`
	Fixed    string  `json:"fixed,omitempty"`
	Text     string  `json:"text"`
}

// CatPrivilege — 권한 항목(이 Pod 자체 또는 엣지 1건).
type CatPrivilege struct {
	Kind    string `json:"kind"`              // rbac | privileged | hostPath | hostNetwork | hostPID
	Dir     string `json:"dir"`               // node(이 Pod 자체) | src(이 Pod→peer) | dst(peer→이 Pod)
	Peer    string `json:"peer,omitempty"`    // 엣지 상대 Pod (dir=src/dst)
	Channel string `json:"channel,omitempty"` // rbac | host (엣지일 때)
	Remove  string `json:"remove"`            // 없앨 권한/설정
	Text    string `json:"text"`
	Reason  string `json:"reason,omitempty"` // 엣지 근거(blast reason 원문)
}

type CatNetPeer struct {
	Peer      string `json:"peer"`
	Namespace string `json:"namespace,omitempty"`
}

type CatNetworkPolicy struct {
	Isolation      string       `json:"isolation"`               // none|egress_only|both|deny_all|unknown
	Recommendation string       `json:"recommendation"`          // whitelist_create | whitelist_prune | already_strict
	IngressPeers   []CatNetPeer `json:"ingress_peers,omitempty"` // 들어오는(dst) network 도달 peer
	EgressPeers    []CatNetPeer `json:"egress_peers,omitempty"`  // 나가는(src) network 도달 peer
	Text           string       `json:"text"`
}

type ScenarioCategories struct {
	CVE           []CatCVE         `json:"cve"`
	Privilege     []CatPrivilege   `json:"privilege"`
	NetworkPolicy CatNetworkPolicy `json:"networkpolicy"`
}

// CatEdge — 양방향 엣지 입력(서비스가 blast_edges에서 채움). Peer = 엣지 상대 Pod.
type CatEdge struct {
	Peer, Namespace    string
	WinChannel         string // host|rbac|network (max 채널)
	Reason             string
	PHost, PRBAC, PNet float64
}

type CategoriesInput struct {
	CVEs []CVEItem // 이 Pod 이미지 CVE 전체

	// 권한(node-level)
	SAName               string
	AllPerms             []PermItem // SA 최종 권한 전체 → 내부에서 risky만 추림
	PrivilegedContainers []string
	HostPathVolumes      []string
	HostNetwork, HostPID bool

	// 양방향 엣지
	OutEdges []CatEdge // src=이 Pod
	InEdges  []CatEdge // dst=이 Pod

	NetworkIsolation string // none|egress_only|both|deny_all|unknown
}

// BuildCategories — 입력 신호 → 3분류 구조화 뷰.
func BuildCategories(in CategoriesInput) ScenarioCategories {
	var c ScenarioCategories

	// ───────── CVE (이 Pod만, 점수 내림차순) ─────────
	cves := append([]CVEItem(nil), in.CVEs...)
	sort.SliceStable(cves, func(i, j int) bool { return cves[i].Score > cves[j].Score })
	for _, v := range cves {
		c.CVE = append(c.CVE, CatCVE{
			ID: v.ID, Severity: v.Severity, CVSS: v.Score, Fixed: v.Fixed, Text: cveText(v),
		})
	}

	// ───────── 권한: node-level (이 Pod 자체) ─────────
	sa := in.SAName
	if sa == "" {
		sa = "이 SA"
	}
	for _, p := range filterRisky(in.AllPerms) {
		res := permResource(p)
		c.Privilege = append(c.Privilege, CatPrivilege{
			Kind: "rbac", Dir: "node",
			Remove: p.Verb + " " + res,
			Text:   fmt.Sprintf("%s의 '%s %s' 권한 회수", sa, p.Verb, res),
		})
	}
	for _, n := range in.PrivilegedContainers {
		c.Privilege = append(c.Privilege, CatPrivilege{
			Kind: "privileged", Dir: "node", Remove: "privileged(" + n + ")",
			Text: fmt.Sprintf("컨테이너 '%s'의 privileged 제거 (PSA restricted)", n),
		})
	}
	for _, v := range in.HostPathVolumes {
		c.Privilege = append(c.Privilege, CatPrivilege{
			Kind: "hostPath", Dir: "node", Remove: "hostPath(" + v + ")",
			Text: fmt.Sprintf("hostPath 볼륨 '%s' 제거 또는 readOnly 강제", v),
		})
	}
	if in.HostNetwork {
		c.Privilege = append(c.Privilege, CatPrivilege{Kind: "hostNetwork", Dir: "node", Remove: "hostNetwork", Text: "hostNetwork 비활성화"})
	}
	if in.HostPID {
		c.Privilege = append(c.Privilege, CatPrivilege{Kind: "hostPID", Dir: "node", Remove: "hostPID", Text: "hostPID 비활성화"})
	}

	// ───────── 권한: 양방향 엣지 (rbac·host 채널) ─────────
	seenPriv := map[string]bool{}
	addEdgePriv := func(e CatEdge, dir string) {
		// rbac 채널: win=rbac 이거나 p_rbac>0(가려진 측면이동 권한도 실재)
		if e.WinChannel == "rbac" || e.PRBAC > 0 {
			key := "rbac|" + dir + "|" + e.Peer
			if !seenPriv[key] {
				seenPriv[key] = true
				c.Privilege = append(c.Privilege, edgePriv("rbac", dir, e, sa))
			}
		}
		// host 채널: win=host 이거나 p_host>0(노드 공유 탈출)
		if e.WinChannel == "host" || e.PHost > 0 {
			key := "host|" + dir + "|" + e.Peer
			if !seenPriv[key] {
				seenPriv[key] = true
				c.Privilege = append(c.Privilege, edgePriv("host", dir, e, sa))
			}
		}
	}
	for _, e := range in.OutEdges {
		addEdgePriv(e, "src")
	}
	for _, e := range in.InEdges {
		addEdgePriv(e, "dst")
	}

	// ───────── NetworkPolicy: network 도달 peer를 방향별로 ─────────
	c.NetworkPolicy = buildNetPol(in.NetworkIsolation,
		networkPeers(in.InEdges), networkPeers(in.OutEdges))

	return c
}

// edgePriv — 엣지 1건 → 권한 항목(채널·방향별 remove 문구).
func edgePriv(channel, dir string, e CatEdge, sa string) CatPrivilege {
	p := CatPrivilege{Kind: channel, Dir: dir, Peer: e.Peer, Channel: channel, Reason: e.Reason}
	switch {
	case channel == "rbac" && dir == "src":
		p.Remove = sa + "의 측면이동 권한(exec/attach 등) 회수"
		p.Text = fmt.Sprintf("이 Pod→'%s': 권한으로 침투 가능 — %s의 해당 권한을 회수", e.Peer, sa)
	case channel == "rbac" && dir == "dst":
		p.Remove = fmt.Sprintf("출발 Pod '%s'의 이 Pod 대상 권한 회수", e.Peer)
		p.Text = fmt.Sprintf("'%s'→이 Pod: 권한으로 침투당함 — 출발 측 SA 권한을 회수", e.Peer)
	case channel == "host" && dir == "src":
		p.Remove = "이 Pod의 노드 공유(privileged/hostPath) 제거"
		p.Text = fmt.Sprintf("이 Pod→'%s': 노드 공유로 도달 — 이 Pod의 host 설정 제거", e.Peer)
	default: // host, dst
		p.Remove = fmt.Sprintf("출발 Pod '%s'의 노드 공유(privileged/hostPath) 제거", e.Peer)
		p.Text = fmt.Sprintf("'%s'→이 Pod: 노드 공유로 도달당함 — 출발 측 host 설정 제거", e.Peer)
	}
	return p
}

// networkPeers — 엣지 중 network 채널(win=network 또는 p_net>0)의 상대 peer를 중복 제거해 반환.
func networkPeers(edges []CatEdge) []CatNetPeer {
	seen := map[string]bool{}
	var out []CatNetPeer
	for _, e := range edges {
		if e.Peer == "" || seen[e.Peer] {
			continue
		}
		if e.WinChannel == "network" || e.PNet > 0 {
			seen[e.Peer] = true
			out = append(out, CatNetPeer{Peer: e.Peer, Namespace: e.Namespace})
		}
	}
	return out
}

// buildNetPol — 격리 등급 + 방향별 peer → NetworkPolicy 권고(방식 B: 방향별 일반 권고).
func buildNetPol(isolation string, ingress, egress []CatNetPeer) CatNetworkPolicy {
	np := CatNetworkPolicy{Isolation: isolation, IngressPeers: ingress, EgressPeers: egress}
	inList := peerNames(ingress)
	egList := peerNames(egress)

	switch isolation {
	case "", "none", "unknown":
		np.Recommendation = "whitelist_create"
		np.Text = fmt.Sprintf(
			"default-deny NetworkPolicy를 적용하고, ingress는 [%s] 중, egress는 [%s] 중 업무상 필요한 peer:port만 허용하세요.",
			orNone(inList), orNone(egList))
	case "deny_all":
		np.Recommendation = "already_strict"
		np.Text = "이미 default-deny로 격리돼 있어 추가 NetworkPolicy 조치는 불필요합니다."
	default: // egress_only | both — 일부 정책 존재
		np.Recommendation = "whitelist_prune"
		np.Text = fmt.Sprintf(
			"이미 NetworkPolicy가 일부 적용돼 있습니다. 도달 가능한 peer 중 불필요한 것을 allow에서 제거하세요 — ingress: [%s], egress: [%s].",
			orNone(inList), orNone(egList))
	}
	return np
}

func peerNames(ps []CatNetPeer) string {
	names := make([]string, 0, len(ps))
	for _, p := range ps {
		names = append(names, p.Peer)
	}
	return strings.Join(names, ", ")
}

func orNone(s string) string {
	if s == "" {
		return "없음"
	}
	return s
}
