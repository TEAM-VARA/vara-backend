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
	Package  string  `json:"package,omitempty"` // 이 CVE를 포함한 패키지명 (어떤 패키지 때문에 취약한지)
	Text     string  `json:"text"`
}

// CatPrivilege — 권한 항목(이 Pod 자체 또는 엣지 1건).
type CatPrivilege struct {
	Kind    string   `json:"kind"`              // rbac | privileged | hostPath | hostNetwork | hostPID
	Dir     string   `json:"dir"`               // node(이 Pod 자체) | src(이 Pod→peer) | dst(peer→이 Pod)
	Peer    string   `json:"peer,omitempty"`    // 엣지 상대 Pod (dir=src/dst)
	SA      string   `json:"sa,omitempty"`      // 해제 대상 권한을 가진 출발 SA (rbac 엣지)
	Channel string   `json:"channel,omitempty"` // rbac | host (엣지일 때)
	Perms   []string `json:"perms,omitempty"`   // 해제할 초기권한 "verb resource" 목록 (rbac 엣지·node 인과의 트리거)
	Remove  string   `json:"remove"`            // 없앨 권한/설정
	Text    string   `json:"text"`
	Reason  string   `json:"reason,omitempty"` // 엣지 근거(blast reason 원문)

	// node 인과(dir=node, kind=rbac) 전용 — "원래 권한 → 위험 트리거 →(룰)→ 상승 권한" 체인.
	//   TriggerPerms   : 위험한 "원래(흡수 전)" 권한 = 회수 대상 (Perms와 동일 값).
	//   EscalatedPerms : 그 트리거로 흡수(상승)한 권한.
	//   Rule           : 트리거된 권한상승 룰 ID (R-DIRECT-01 등).
	TriggerPerms   []string `json:"trigger_perms,omitempty"`
	EscalatedPerms []string `json:"escalated_perms,omitempty"`
	Rule           string   `json:"rule,omitempty"`
}

// RBACEscalation — "원래(흡수 전) 위험 권한(트리거)"이 한 룰을 거쳐 "흡수(상승) 권한"으로 번지는 한 건.
// 서비스가 transition_triggers(어떤 원래 권한이 룰을 트리거했나) + rbac_escalation_paths(그래서
// 흡수한 권한)를 via_transition(룰 ID)으로 묶어 채운다.
type RBACEscalation struct {
	Rule           string   // 트리거된 권한상승 룰 ID
	TriggerPerms   []string // 그 룰을 트리거한 "원래(흡수 전)" 위험 권한 "verb resource"
	EscalatedPerms []string // 그 결과 흡수(상승)한 권한 "verb resource"
}

type CatNetPeer struct {
	Peer      string `json:"peer"`
	PodUID    string `json:"pod_uid,omitempty"` // blast-cut blocked_edges 구성용 (이 peer pod의 uid)
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
	PeerUID            string // 엣지 상대 Pod의 pod_uid (blast-cut blocked_edges 구성용)
	WinChannel         string // host|rbac|network (max 채널)
	Reason             string
	PHost, PRBAC, PNet float64

	// rbac 엣지 출발 측 신원·초기권한(서비스가 rbac_sa_initial_permissions에서 채움).
	//   SrcSA        : 그 엣지를 만든 권한을 가진 출발 pod의 SA 이름.
	//   LateralPerms : 그 SA의 흡수 전(initial) 권한 중 측면이동 verb만 "verb resource"로 추린 것.
	// 비어 있으면 edgePriv가 reason→일반 문구 순으로 폴백한다.
	SrcSA        string
	LateralPerms []string
}

type CategoriesInput struct {
	CVEs []CVEItem // 이 Pod 이미지 CVE 전체

	// 권한(node-level)
	SAName               string
	InitialPerms         []PermItem       // SA "원래(흡수 전)" 권한 전체 → 내부에서 risky만 추림 (rbac_sa_initial_permissions)
	Escalations          []RBACEscalation // 그중 권한상승을 일으킨 트리거→흡수 인과(룰별)
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
			ID: v.ID, Severity: v.Severity, CVSS: v.Score, Fixed: v.Fixed, Package: v.Package, Text: cveText(v),
		})
	}

	// ───────── 권한: node-level (이 Pod 자체) — 원래 권한 → 위험 트리거 →(룰)→ 상승 ─────────
	// 회수 대상은 "원래(흡수 전) 직접 보유" 권한뿐(rbac_sa_initial_permissions). 흡수로 생긴 최종권한은
	// 직접 회수가 불가능 — 그 상승을 일으킨 "원래 위험 권한(트리거)"을 끊어야 사라진다. 따라서
	//   ① 권한상승을 일으킨 트리거는 "이 원래 권한 때문에 →(룰)→ 이 권한으로 상승" 인과 카드로,
	//   ② 상승과 무관하게 직접 보유한 위험 권한은 단순 회수 카드로 출력한다.
	sa := in.SAName
	if sa == "" {
		sa = "이 SA"
	}
	trigSeen := map[string]bool{}
	for _, e := range in.Escalations {
		for _, t := range e.TriggerPerms {
			trigSeen[t] = true
		}
		trig := strings.Join(e.TriggerPerms, ", ")
		esc := strings.Join(e.EscalatedPerms, ", ")
		p := CatPrivilege{
			Kind: "rbac", Dir: "node",
			Perms:          e.TriggerPerms,
			TriggerPerms:   e.TriggerPerms,
			EscalatedPerms: e.EscalatedPerms,
			Rule:           e.Rule,
			Remove:         fmt.Sprintf("%s의 원래 권한 '%s' 회수", sa, orPerm(trig)),
		}
		if esc != "" {
			p.Text = fmt.Sprintf("%s가 원래 보유한 위험 권한 '%s'(으)로 %s 룰이 트리거돼 '%s' 권한으로 상승합니다 — 이 원래 권한을 회수하면 상승이 끊깁니다",
				sa, orPerm(trig), orRule(e.Rule), esc)
		} else {
			p.Text = fmt.Sprintf("%s가 원래 보유한 위험 권한 '%s'(으)로 %s 룰이 트리거돼 권한 상승이 일어납니다 — 이 원래 권한을 회수하세요",
				sa, orPerm(trig), orRule(e.Rule))
		}
		c.Privilege = append(c.Privilege, p)
	}
	for _, perm := range filterRisky(in.InitialPerms) {
		res := permResource(perm)
		label := perm.Verb + " " + res
		if trigSeen[label] || trigSeen[perm.Verb+" "+perm.Resource] {
			continue // 이미 위 인과 카드에서 트리거로 지목됨
		}
		c.Privilege = append(c.Privilege, CatPrivilege{
			Kind: "rbac", Dir: "node",
			Perms:  []string{label},
			Remove: fmt.Sprintf("%s의 '%s' 권한 회수", sa, label),
			Text:   fmt.Sprintf("%s가 원래 직접 보유한 위험 권한 '%s' — 회수 권장", sa, label),
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
//
// rbac 엣지는 그 엣지를 만든 "출발 SA의 실제 초기권한"(e.LateralPerms, rbac_sa_initial_permissions)을
// 직접 지목해 "…권한을 해제하세요"로 안내한다. 초기권한 조회가 비면(흡수로 생긴 권한·테이블 미적재 등)
// blast reason의 rbac 상세 → 일반 문구 순으로 폴백한다.
func edgePriv(channel, dir string, e CatEdge, sa string) CatPrivilege {
	p := CatPrivilege{Kind: channel, Dir: dir, Peer: e.Peer, Channel: channel, Reason: e.Reason}
	switch {
	case channel == "rbac" && dir == "src":
		srcSA := firstNonEmpty(e.SrcSA, sa)
		p.SA, p.Perms = srcSA, e.LateralPerms
		if detail := permLabel(e.LateralPerms, e.Reason); detail != "" {
			p.Remove = fmt.Sprintf("%s의 '%s' 권한 해제", srcSA, detail)
			p.Text = fmt.Sprintf("이 Pod→'%s': %s의 '%s' 권한으로 측면 이동 가능 — 해당 권한을 해제하세요", e.Peer, srcSA, detail)
		} else {
			p.Remove = srcSA + "의 측면이동 권한(exec/attach 등) 회수"
			p.Text = fmt.Sprintf("이 Pod→'%s': 권한으로 침투 가능 — %s의 해당 권한을 회수", e.Peer, srcSA)
		}
	case channel == "rbac" && dir == "dst":
		p.SA, p.Perms = e.SrcSA, e.LateralPerms
		srcLabel := firstNonEmpty(e.SrcSA, "출발 측 SA")
		if detail := permLabel(e.LateralPerms, e.Reason); detail != "" {
			p.Remove = fmt.Sprintf("출발 Pod '%s'의 %s '%s' 권한 해제", e.Peer, srcLabel, detail)
			p.Text = fmt.Sprintf("'%s'→이 Pod: 출발 SA %s의 '%s' 권한으로 침투당함 — 해당 권한을 해제하세요", e.Peer, srcLabel, detail)
		} else {
			p.Remove = fmt.Sprintf("출발 Pod '%s'의 이 Pod 대상 권한 회수", e.Peer)
			p.Text = fmt.Sprintf("'%s'→이 Pod: 권한으로 침투당함 — 출발 측 SA 권한을 회수", e.Peer)
		}
	case channel == "host" && dir == "src":
		p.Remove = "이 Pod의 노드 공유(privileged/hostPath) 제거"
		p.Text = fmt.Sprintf("이 Pod→'%s': 노드 공유로 도달 — 이 Pod의 host 설정 제거", e.Peer)
	default: // host, dst
		p.Remove = fmt.Sprintf("출발 Pod '%s'의 노드 공유(privileged/hostPath) 제거", e.Peer)
		p.Text = fmt.Sprintf("'%s'→이 Pod: 노드 공유로 도달당함 — 출발 측 host 설정 제거", e.Peer)
	}
	return p
}

// permLabel — rbac 엣지에서 보여줄 권한 문자열. 초기권한 목록(perms)이 있으면 그것을,
// 없으면 blast reason의 rbac 상세("rbac: …"의 뒤쪽)를 쓴다. 둘 다 없으면 "".
func permLabel(perms []string, reason string) string {
	if len(perms) > 0 {
		return strings.Join(perms, ", ")
	}
	if rest, ok := strings.CutPrefix(reason, "rbac:"); ok {
		return strings.TrimSpace(rest)
	}
	return ""
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// networkPeers — 엣지 중 network 채널(win=network 또는 p_net>0)의 상대 peer를 중복 제거해 반환.
// dedup 키는 uid 우선(없으면 이름) — 동명 pod(그룹 멤버 등)를 한 항목으로 합치지 않도록.
func networkPeers(edges []CatEdge) []CatNetPeer {
	seen := map[string]bool{}
	var out []CatNetPeer
	for _, e := range edges {
		if e.Peer == "" {
			continue
		}
		key := e.PeerUID
		if key == "" {
			key = e.Peer
		}
		if seen[key] {
			continue
		}
		if e.WinChannel == "network" || e.PNet > 0 {
			seen[key] = true
			out = append(out, CatNetPeer{Peer: e.Peer, PodUID: e.PeerUID, Namespace: e.Namespace})
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

// orPerm — 트리거/상승 권한 문자열이 비면 안전한 폴백 라벨.
func orPerm(s string) string {
	if s == "" {
		return "(권한 미상)"
	}
	return s
}

// orRule — 룰 ID가 비면 일반 표현으로 폴백.
func orRule(s string) string {
	if s == "" {
		return "권한상승"
	}
	return s
}
