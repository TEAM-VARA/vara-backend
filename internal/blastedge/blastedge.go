// Package blastedge builds the directed blast graph rows (blast_edges table):
// for each ordered pod pair A->B it computes P(B|A) = max(host, rbac, network)
// plus the precomputed fields the score consumer needs (p_edge, neg_log_p,
// win_channel). Pure logic, no DB — the loader/repo feed it inputs.
//
// Design: docs/blast-channels-spec.md
package blastedge

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// PodFact — per-pod precomputed facts needed to generate edges.
type PodFact struct {
	UID        string
	Name       string
	Namespace  string
	Node       string // node name the pod runs on ("" = unknown)
	Running    bool   // phase == Running
	SANamespace string // service account namespace (= pod namespace)
	SAName      string // service account name (cluster_pods.service_account)
	Privileged  bool   // any container privileged → host escape capability (v1)
	HostPath    bool   // mounts a (sensitive) hostPath → host escape (v1: loader decides)
	HasSAToken  bool   // SA token mounted → attacker in this pod can wield its SA (RBAC source gate)
	Risk        float64 // B.Risk (likelihood 0..1), used as network success prob when this pod is a target
}

// Perm — one effective RBAC permission of a service account.
type Perm struct {
	APIGroup     string
	Resource     string
	Verb         string
	Namespace    *string // nil => cluster-wide
	ResourceName *string // nil => unrestricted (v1 ignores for matching)
}

// Flow — an observed directed network connection A->B (eBPF).
type Flow struct {
	SrcUID string
	DstUID string
}

// Edge — a finalized directed blast edge (one blast_edges row).
type Edge struct {
	SrcUID, DstUID     string
	PHost, PRBAC, PNet float64
	PEdge, NegLogP     float64
	WinChannel         string // "host" | "rbac" | "network"
	Reason             string
	DstValue           float64
}

// RBAC 채널은 1/0 — 공격성공확률은 직접 제어라 1.0 고정, "어렵다"는 전부 도달 게이트로 본다.
// v1 범위 = C(exec/attach/ephemeral) + D(nodes/proxy)만. PV·G는 제외.
// (제외 이유·재추가 조건: docs/blast-channels-spec.md §2 "v1 결정")
const (
	wExec       = 1.0 // C: exec/attach/ephemeral
	wNodesProxy = 1.0 // D: nodes/proxy
)

// channelAcc accumulates the max per-channel probability + reason for one ordered pair.
type channelAcc struct {
	host, rbac, net    float64
	hostR, rbacR, netR string
}

// rbacKind classifies a permission for the RBAC channel (transition group C/D/G).
type rbacKind int

const (
	kNone        rbacKind = iota
	kExec                 // C: exec/attach/ephemeral → running pods in ns scope (success 1.0)
	kNodesProxy           // D: nodes/proxy → all running pods (success 1.0)
	kPortForward          // C-net: pods/portforward → ns scope running pods, success = B.Risk
)

func classifyRBAC(p Perm) rbacKind {
	core := p.APIGroup == "" || p.APIGroup == "*"
	if !core {
		return kNone
	}
	r, v := p.Resource, p.Verb
	switch {
	case r == "pods/exec" && anyVerb(v, "create", "get"):
		return kExec
	case r == "pods/attach" && anyVerb(v, "create", "get"):
		return kExec
	case r == "pods/ephemeralcontainers" && anyVerb(v, "update", "patch"):
		return kExec
	case r == "pods/portforward" && anyVerb(v, "create", "get"):
		return kPortForward // 포트 접근만 → 성공확률 = B.Risk (B를 익스플로잇해야)
	case r == "nodes/proxy" && anyVerb(v, "get", "create"):
		return kNodesProxy
	case r == "*" && (v == "*" || anyVerb(v, "create", "get", "update", "patch", "delete")):
		// 와일드카드 resource = 모든 pod 도달 → exec 취급(보수적)
		return kExec
	}
	// v1 제외 (docs/blast-channels-spec.md §2 "v1 결정"):
	//   - persistentvolumes create        : PV→PVC→pod 마운트 다단계, 동반권한 미검증
	//   - pods delete/deletecollection·pods/eviction create + nodes update/patch (G): 스케줄러 재배치 불확실
	return kNone
}

// IsLateralMovement reports whether p is a lateral-movement permission that can
// create an RBAC blast edge (exec/attach/ephemeral, nodes/proxy, pods/portforward,
// or a core wildcard). Mirrors classifyRBAC so the scenario "권한" 뷰가 엣지 생성과
// 같은 기준으로 "측면이동 권한"을 추려낸다 (단일 출처).
func IsLateralMovement(p Perm) bool {
	return classifyRBAC(p) != kNone
}

func anyVerb(v string, opts ...string) bool {
	if v == "*" {
		return true
	}
	for _, o := range opts {
		if v == o {
			return true
		}
	}
	return false
}

// BuildEdges computes all directed blast edges from precomputed inputs.
//
//	pods       : every pod by UID (with facts)
//	permsBySA  : "saNamespace/saName" -> effective (final) perms of that SA
//	flows      : observed directed A->B network flows (eBPF)
//
// value(B) is v1 = 1.0 (set on each edge); swap to vertical_direct later.
func BuildEdges(pods map[string]PodFact, permsBySA map[string][]Perm, flows []Flow) []Edge {
	pairs := map[[2]string]*channelAcc{}
	getPair := func(src, dst string) *channelAcc {
		k := [2]string{src, dst}
		ca := pairs[k]
		if ca == nil {
			ca = &channelAcc{}
			pairs[k] = ca
		}
		return ca
	}

	// indexes for target selection
	podsByNode := map[string][]string{}
	podsByNS := map[string][]string{}
	allUIDs := make([]string, 0, len(pods))
	for _, p := range sortedPods(pods) {
		if excludeFromGraph(p) {   // 시스템 파드는 타겟 후보에서도 제외
			continue
		}
		allUIDs = append(allUIDs, p.UID)
		if p.Node != "" {
			podsByNode[p.Node] = append(podsByNode[p.Node], p.UID)
		}
		podsByNS[p.Namespace] = append(podsByNS[p.Namespace], p.UID)
	}

	// ---- HOST: A 탈출(privileged/hostPath) ∧ B 같은 노드 → 1.0 ----
	for _, a := range sortedPods(pods) {
		if a.Node == "" || !(a.Privileged || a.HostPath) {
			continue
		}
		if excludeFromGraph(a) {   // ← 추가
			continue
		}
		for _, dst := range podsByNode[a.Node] {
			if dst == a.UID {
				continue
			}
			ca := getPair(a.UID, dst)
			if 1.0 > ca.host {
				ca.host = 1.0
				ca.hostR = "host: escape(privileged/hostPath) + same node " + a.Node
			}
		}
	}

	// ---- RBAC: 전파권한 → 타겟 pod (source token gate) ----
	for _, a := range sortedPods(pods) {
		if !a.HasSAToken { // 공격자가 A의 SA 토큰을 못 얻으면 A의 RBAC 엣지 사용 불가
			continue
		}
		if excludeFromGraph(a) {
			continue
		}
		perms := permsBySA[a.SANamespace+"/"+a.SAName]
		if len(perms) == 0 {
			continue
		}
		for _, p := range perms {
			switch classifyRBAC(p) {
			case kExec:
				for _, dst := range targetsForNS(p.Namespace, podsByNS, allUIDs) {
					b := pods[dst]
					if dst == a.UID || !b.Running {
						continue
					}
					if !resourceNameAllows(p, b) { // resourceNames 좁힘: 지정 시 그 파드만
						continue
					}
					reason := "rbac: exec/attach/ephemeral ns=" + scopeStr(p.Namespace)
					if p.ResourceName != nil {
						reason = "rbac: exec → " + *p.ResourceName // 좁혀진 경로 표시(툴팁)
					}
					bump(getPair(a.UID, dst), wExec, reason)
				}
			case kNodesProxy:
				for _, dst := range allUIDs { // v1: 전체(노드 resourceNames 무시)
					b := pods[dst]
					if dst == a.UID || !b.Running {
						continue
					}
					bump(getPair(a.UID, dst), wNodesProxy, "rbac: nodes/proxy (kubelet API)")
				}
			case kPortForward:
				// 포트 접근만 → 성공확률 = B.Risk. 타겟은 exec와 동일(ns scope running pod).
				for _, dst := range targetsForNS(p.Namespace, podsByNS, allUIDs) {
					b := pods[dst]
					if dst == a.UID || !b.Running {
						continue
					}
					if !resourceNameAllows(p, b) { // resourceNames 좁힘: 지정 시 그 파드만
						continue
					}
					reason := "rbac: portforward (포트 접근 → B.Risk) ns=" + scopeStr(p.Namespace)
					if p.ResourceName != nil {
						reason = "rbac: portforward → " + *p.ResourceName // 좁혀진 경로 표시(툴팁)
					}
					bump(getPair(a.UID, dst), b.Risk, reason)
				}
			}
		}
	}

	// ---- NETWORK: A→B flow → B.Risk ----
	for _, f := range flows {
		if f.SrcUID == f.DstUID {
			continue
		}
		b, ok := pods[f.DstUID]
		if !ok || b.Risk <= 0 {
			continue
		}
		if excludeFromGraph(b) { // ← 추가: target 이 시스템/VARA면 제외
			continue
		}
		if a, ok := pods[f.SrcUID]; ok && excludeFromGraph(a) { // ← 추가: source 가 시스템/VARA면 제외
			continue
		}
		ca := getPair(f.SrcUID, f.DstUID)
		if b.Risk > ca.net {
			ca.net = b.Risk
			ca.netR = fmt.Sprintf("network: eBPF flow, B.Risk=%.3f", b.Risk)
		}
	}

	// ---- finalize: max → edge ----
	out := make([]Edge, 0, len(pairs))
	for k, ca := range pairs {
		if e := finalize(k[0], k[1], ca); e != nil {
			out = append(out, *e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SrcUID != out[j].SrcUID {
			return out[i].SrcUID < out[j].SrcUID
		}
		return out[i].DstUID < out[j].DstUID
	})
	return out
}

// bump raises the RBAC channel to w (keeping the strongest reason).
func bump(ca *channelAcc, w float64, reason string) {
	if w > ca.rbac {
		ca.rbac = w
		ca.rbacR = reason
	}
}

// finalize picks p_edge = max(channels) with tie priority host > rbac > network.
func finalize(src, dst string, ca *channelAcc) *Edge {
	pe, win, reason := ca.host, "host", ca.hostR
	if ca.rbac > pe {
		pe, win, reason = ca.rbac, "rbac", ca.rbacR
	}
	if ca.net > pe {
		pe, win, reason = ca.net, "network", ca.netR
	}
	if pe <= 0 {
		return nil // 엣지 없음 → 미적재
	}
	if pe > 1 {
		pe = 1
	}
	return &Edge{
		SrcUID: src, DstUID: dst,
		PHost: ca.host, PRBAC: ca.rbac, PNet: ca.net,
		PEdge: pe, NegLogP: -math.Log(pe),
		WinChannel: win, Reason: reason,
		DstValue: 1.0, // v1 = 개수
	}
}

// resourceNameAllows reports whether perm p may target pod b under its
// resourceNames scope.
//
//	p.ResourceName == nil → 범위 제한 없음(cluster/ns 전체) → 항상 허용(기존 동작).
//	지정 시            → 파드 이름 정확 매칭만 허용(와일드카드 없음).
//
// exec/attach/ephemeralcontainers·portforward 는 서브리소스라 K8s authorizer 가
// resourceNames 를 강제한다 → blast 그래프도 같은 기준으로 타겟을 좁힌다.
// (nodes/proxy 는 노드 이름 기준이라 여기 해당 없음 — kNodesProxy 분기 참고.)
//
// TODO: 이 resourceNames 해석은 rbacchain(fixpoint/semantics.go)이 이미 하는 것을
// blastedge 에 중복 구현한 것이다. 장기적으로 rbacchain 결과를 단일 출처로 소비하도록
// 통합 — 한쪽만 고치고 까먹는 drift 위험 (핸드오프 §함정 4 / 백로그).
func resourceNameAllows(p Perm, b PodFact) bool {
	return p.ResourceName == nil || b.Name == *p.ResourceName
}

func targetsForNS(ns *string, podsByNS map[string][]string, all []string) []string {
	if ns == nil { // cluster-wide
		return all
	}
	return podsByNS[*ns]
}

func scopeStr(ns *string) string {
	if ns == nil {
		return "*"
	}
	return *ns
}

func sortedPods(m map[string]PodFact) []PodFact {
	out := make([]PodFact, 0, len(m))
	for _, p := range m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UID < out[j].UID })
	return out
}

// isSystemNS — 클러스터 운영용 시스템 네임스페이스. blast 그래프에서 제외한다.
// (kube-system DaemonSet/SA가 host·rbac 노이즈를 만드는 것을 차단 — 고객 워크로드 침해만 본다.)
func isSystemNS(ns string) bool {
	switch ns {
	case "kube-system", "kube-public", "kube-node-lease":
		return true
	}
	return false
}

func excludeFromGraph(p PodFact) bool {
	if isSystemNS(p.Namespace) {
		return true
	}
	if strings.HasPrefix(p.Name, "vara-") {
		return true
	}
	return false
}