package scoring

import (
	"fmt"
	"strings"
)

// BlastEdge — blast_edges 한 행의 시나리오용 읽기 뷰 (source=이 Pod 기준 outgoing).
//
// Channel(win_channel)·Reason은 blast 모델이 이미 계산·분류한 값이고,
// TargetName은 도달 대상 Pod의 실제 이름이다.
type BlastEdge struct {
	Channel    string  // host | rbac | network (= win_channel, max 채널)
	Reason     string  // 드릴다운 설명 (예: "rbac: exec/attach/ephemeral ns=dev")
	TargetName string  // 도달 대상 Pod 이름
	RBACProb   float64 // p_rbac. win_channel이 host/network라도 >0이면 rbac 측면이동 권한이 실재.
	NetProb    float64 // p_net. win_channel이 host/rbac라도 >0이면 네트워크 도달이 실재 → NetworkPolicy 권고 대상.
}

// ScenarioInput — pod 1개의 "이미 수집되는" 신호 모음.
//
// 채워 넣는 소스 (scenario_handler.go 참고):
//
//	MOUNT  : cluster_pods.containers(privileged)·volumes(type=hostPath)·host_network·host_pid
//	RBAC   : rbacchain effective permissions (verb·resource)
//	NET    : attack_path_scores.NetworkDetails(isolation) + exposure_scores + edges(network)
//	VULN   : sbom/global_image + platform/kev + platform/epss + CVSS 벡터
type ScenarioInput struct {
	// 식별
	PodName        string
	PodUID         string
	Namespace      string
	ClusterName    string
	ServiceAccount string
	RiskScore      float64
	RiskLevel      string

	// MOUNT (cluster_pods)
	PrivilegedContainers []string // privileged=true 컨테이너 이름들
	HostNetwork          bool
	HostPID              bool
	HostPathVolumes      []string // type=hostPath 볼륨 이름 (writable 미확정)

	// RBAC (rbacchain effective permissions)
	CanListSecrets      bool
	CanExec             bool
	CanCreateWorkload   bool
	CanBindClusterAdmin bool
	CanWriteWebhook     bool
	CanDeleteEvents     bool
	IsClusterAdmin      bool

	// RBAC 근거 권한(verb/resource). 채워지면 해당 finding의 caveat에 부기한다(심사 증적성).
	// 예: "create deployments, create jobs". 정밀(rbacchain) 경로에서만 채워짐.
	CreateWorkloadPerms string
	WriteWebhookPerms   string
	DeleteEventsPerms   string
	ExecPerms           string // 측면이동(exec into container) 근거 — 예: "create pods/exec, get pods/attach"

	// NET
	NetworkIsolation string // none|egress_only|both|deny_all|unknown
	Exposed          bool
	ExposedVia       string // "Service(LoadBalancer)" 등
	ReachablePods    []string

	// OUTGOING (blast_edges 전파 엣지). 채워지면 outgoing 섹션을 이걸로 대체하고,
	// 비어있으면 기존 휴리스틱(NetworkIsolation/CanExec/...)으로 폴백한다.
	ReachEdges []BlastEdge

	// VULN (sbom/global + kev/epss + cvss 벡터)
	TopCVE                   string
	CVEScore                 float64
	CVEKEV                   bool
	CVERemote                bool // AV:N
	CVEScopeChanged          bool // S:C (v3.1) / Subsequent System (v4.0)
	CVEAvailabilityImpact    bool // A:H / VA:H
	CVEConfidentialityImpact bool // C:H / VC:H

	// CVE narrative enrichment(설계서 §4). 캐시 hit 시 채워지며 VULN finding에 부착되고
	// incoming 줄글을 module/class/mechanism으로 강화한다. nil이면 기존 generic 줄글 폴백.
	CVEEnrichment *CVEEnrichment

	// 수집 가용성 (gap 고지용)
	IRSACollected bool // SA annotations(IRSA) 수집 여부 (현재 false)
}

// BuildPodScenario — 신호 → 공격 시나리오 줄글 + 보완대책 줄글 + 구조화 findings.
//
// collected_now=gap/no 인 technique은 보수적 표기(confidence=low/heuristic, caveat)로 처리하고,
// 미수집 항목은 Notes로 한계를 고지한다.
func BuildPodScenario(in ScenarioInput) PodScenarioResult {
	var fs []ScenarioFinding
	sa := in.ServiceAccount
	if sa == "" {
		sa = "서비스계정"
	}

	// ───────── 진입 (incoming) ─────────
	if in.Exposed {
		via := in.ExposedVia
		if via == "" {
			via = "외부에 노출된"
		}
		fs = append(fs, mkFinding("MS-TA9005", DirIncoming, TacticInitialAccess,
			fmt.Sprintf("이 Pod이 %s 상태라, 공격자가 클러스터 밖에서 직접 접근해 처음 침투할 수 있습니다.", via),
			"high", ""))
	}
	if in.TopCVE != "" && in.CVERemote {
		f := mkFinding("VULN", DirIncoming, TacticInitialAccess,
			vulnIncomingScenario(in), "heuristic", "CVSS 벡터(AV:N) 기반 추정")
		f.CVE = in.TopCVE
		f.Enrichment = in.CVEEnrichment // 캐시 hit 시 부착(설계서 §4) — nil이면 omitempty
		fs = append(fs, f)
	}

	// ───────── 노드 상태 (node) ─────────
	for _, c := range in.PrivilegedContainers {
		fs = append(fs, mkFinding("MS-TA9018", DirNode, TacticPrivEsc,
			fmt.Sprintf("컨테이너 '%s'가 privileged로 실행되고 있어, 공격자가 호스트 커널 권한을 그대로 악용해 노드(호스트)를 장악할 수 있습니다.", c),
			"high", ""))
	}
	for _, v := range in.HostPathVolumes {
		fs = append(fs, mkFinding("MS-TA9013", DirNode, TacticPersistence,
			fmt.Sprintf("이 Pod이 호스트 경로 볼륨('%s')을 마운트하고 있어, 쓰기가 가능하다면 공격자가 노드 파일시스템에 침투·잔존할 수 있습니다.", v),
			"low", "현재 수집 데이터로는 readOnly(쓰기 가능) 여부를 확정하지 못함"))
	}
	if in.CanListSecrets {
		fs = append(fs, mkFinding("MS-TA9025", DirNode, TacticCredAccess,
			fmt.Sprintf("%s에 secrets 읽기 권한이 있어, 공격자가 클러스터에 저장된 비밀번호·토큰을 꺼내 자격증명을 탈취할 수 있습니다.", sa),
			"high", ""))
	}
	if in.CanCreateWorkload {
		fs = append(fs, mkFinding("MS-TA9012", DirNode, TacticPersistence,
			fmt.Sprintf("%s에 워크로드 생성 권한이 있어, 공격자가 악성 컨테이너를 상주시켜 재시작 후에도 잠복할 수 있습니다.", sa),
			"high", in.CreateWorkloadPerms))
	}
	if in.CanWriteWebhook {
		fs = append(fs, mkFinding("MS-TA9015", DirNode, TacticPersistence,
			fmt.Sprintf("%s에 admission 웹훅 구성 권한이 있어, 공격자가 가짜 검문 웹훅을 심어 모든 요청을 가로채며 잠복할 수 있습니다.", sa),
			"high", in.WriteWebhookPerms))
	}
	if in.CanDeleteEvents {
		fs = append(fs, mkFinding("MS-TA9022", DirNode, TacticDefenseEvade,
			fmt.Sprintf("%s에 events 삭제 권한이 있어, 공격자가 흔적(이벤트 로그)을 지워 탐지를 회피할 수 있습니다.", sa),
			"high", in.DeleteEventsPerms))
	}
	if in.IsClusterAdmin || in.CanBindClusterAdmin {
		fs = append(fs, mkFinding("MS-TA9019", DirNode, TacticPrivEsc,
			fmt.Sprintf("%s가 높은 RBAC 권한(클러스터 관리자 또는 바인딩 생성)을 가져, 공격자가 스스로 권한을 끌어올려 클러스터 전체를 장악할 수 있습니다.", sa),
			"high", ""))
	}
	if in.TopCVE != "" && in.CVEAvailabilityImpact {
		f := mkFinding("VULN", DirNode, TacticImpact,
			fmt.Sprintf("이미지 취약점(%s)이 가용성에 영향을 줘, 공격자가 서비스 중단·파괴를 일으킬 수 있습니다.", cveLabel(in)),
			"heuristic", "CVSS 가용성 영향 기반")
		f.CVE = in.TopCVE
		fs = append(fs, f)
	} else if in.TopCVE != "" && in.CVEConfidentialityImpact {
		f := mkFinding("VULN", DirNode, TacticCredAccess,
			fmt.Sprintf("이미지 취약점(%s)이 정보 유출로 이어져, 공격자가 민감정보를 수집할 수 있습니다.", cveLabel(in)),
			"heuristic", "CVSS 기밀성 영향 기반")
		f.CVE = in.TopCVE
		fs = append(fs, f)
	}
	if in.TopCVE != "" && in.CVEScopeChanged {
		f := mkFinding("VULN", DirNode, TacticPrivEsc,
			fmt.Sprintf("이미지 취약점(%s)이 컨테이너 권한 경계를 벗어나(CVSS Scope 변경), 공격자가 호스트/노드로 권한을 끌어올리거나 탈출할 수 있습니다.", cveLabel(in)),
			"heuristic", "CVSS Scope:Changed(또는 v4.0 후속 시스템 영향) 기반")
		f.CVE = in.TopCVE
		fs = append(fs, f)
	}

	// ───────── 전파 (outgoing) ─────────
	// 네트워크 '도달'은 blast_edges(directed)가 있으면 그걸로(채널·이유·실제 타겟), 없으면
	// 휴리스틱(9034)으로 구성한다. 반면 SA '능력' 기반 전파(exec/워크로드/토큰)는 네트워크
	// 토폴로지와 무관하므로 blast 유무와 상관없이 항상 평가하되, blast가 이미 같은 technique을
	// 낸 경우(예: rbac-exec 엣지→9006)에만 중복을 피한다.
	emitted := map[string]bool{}
	if len(in.ReachEdges) > 0 {
		for _, f := range buildOutgoingFromBlast(in.ReachEdges, sa, in.ExecPerms) {
			emitted[f.MSTA] = true
			fs = append(fs, f)
		}
	} else if in.NetworkIsolation == "none" || in.NetworkIsolation == "" || in.NetworkIsolation == "unknown" {
		reach := ""
		if len(in.ReachablePods) > 0 {
			reach = fmt.Sprintf("(예: %s)", strings.Join(trimN(in.ReachablePods, 3), ", "))
		}
		conf := "high"
		caveat := ""
		if in.NetworkIsolation == "" || in.NetworkIsolation == "unknown" {
			conf, caveat = "heuristic", "NetworkPolicy 격리 상태 미상 — 보수적으로 도달 가능 가정"
		}
		fs = append(fs, mkFinding("MS-TA9034", DirOutgoing, TacticLateral,
			fmt.Sprintf("이 Pod을 막는 NetworkPolicy가 없어, 공격자가 네트워크로 옆 Pod%s까지 옮겨갈 수 있습니다.", reach),
			conf, caveat))
	}
	// SA 능력 기반 전파 — blast 유무와 무관하게 항상 평가(중복 technique만 회피).
	if in.CanExec && !emitted["MS-TA9006"] {
		fs = append(fs, mkFinding("MS-TA9006", DirOutgoing, TacticExecution,
			fmt.Sprintf("%s에 pods/exec 권한이 있어, 공격자가 다른 컨테이너 안으로 들어가 명령을 실행할 수 있습니다.", sa),
			"high", in.ExecPerms))
	}
	if in.CanCreateWorkload && !emitted["MS-TA9008"] {
		fs = append(fs, mkFinding("MS-TA9008", DirOutgoing, TacticExecution,
			fmt.Sprintf("%s에 워크로드 생성 권한이 있어, 공격자가 새 컨테이너를 띄워 임의 코드를 실행할 수 있습니다.", sa),
			"high", in.CreateWorkloadPerms))
	}
	// 9016: SA 토큰이 과대권한이면 측면 이동 통로
	if (in.IsClusterAdmin || in.CanListSecrets || in.CanCreateWorkload || in.CanExec) && !emitted["MS-TA9016"] {
		fs = append(fs, mkFinding("MS-TA9016", DirOutgoing, TacticLateral,
			fmt.Sprintf("%s 토큰이 API 권한을 갖고 마운트돼 있어, 공격자가 그 토큰으로 API 서버에 인증해 다른 자원으로 이동할 수 있습니다.", sa),
			"heuristic", "automountServiceAccountToken 기본값(true) 가정"))
	}

	// ───────── 분류 + 줄글 조립 ─────────
	res := PodScenarioResult{
		ClusterName: in.ClusterName,
		PodUID:      in.PodUID,
		PodName:     in.PodName,
		Namespace:   in.Namespace,
		RiskScore:   in.RiskScore,
		RiskLevel:   in.RiskLevel,
		Findings:    fs,
	}
	for _, f := range fs {
		switch f.Direction {
		case DirIncoming:
			res.Incoming = append(res.Incoming, f)
		case DirNode:
			res.NodeStates = append(res.NodeStates, f)
		case DirOutgoing:
			res.Outgoing = append(res.Outgoing, f)
		}
	}
	res.AttackScenario = composeScenario(res.Incoming, res.NodeStates, res.Outgoing)
	res.Mitigations = collectMitigations(fs, networkReachableTargets(in))
	res.Mitigation = composeMitigationText(res.Mitigations)

	// 수집 갭 고지
	if len(in.HostPathVolumes) > 0 {
		res.Notes = append(res.Notes, "hostPath의 쓰기 가능 여부(readOnly)는 현재 미수집이라 9013은 보수적으로 표기됨.")
	}
	if !in.IRSACollected {
		res.Notes = append(res.Notes, "SA의 IRSA(IAM) 정보 미수집으로 클라우드 자원 접근(9020)은 평가에서 제외됨.")
	}
	return res
}

// blastChannelTech — blast_edges의 (win_channel, reason) → outgoing technique 매핑.
//
//	network                    → MS-TA9034 (Cluster internal networking, 측면 이동)
//	rbac + portforward         → MS-TA9034 (포트 접근 = 네트워크 도달, 측면 이동)
//	rbac + exec/nodes-proxy 등 → MS-TA9006 (Exec into container, 코드 실행)
//	host (노드 공유 탈출)        → MS-TA9018 (Privileged container, 측면 이동)
//
// 매핑 안 되는 채널이면 ok=false.
func blastChannelTech(channel, reason string) (msta, tactic string, ok bool) {
	switch channel {
	case "network":
		return "MS-TA9034", TacticLateral, true
	case "host":
		return "MS-TA9018", TacticLateral, true
	case "rbac":
		if strings.Contains(reason, "portforward") {
			return "MS-TA9034", TacticLateral, true
		}
		return "MS-TA9006", TacticExecution, true
	}
	return "", "", false
}

// blastSentence — technique별 전파 줄글. targets는 도달 대상 Pod 이름(최대 3개+외 N개).
func blastSentence(msta, sa, targets string) string {
	switch msta {
	case "MS-TA9034":
		return fmt.Sprintf("이 Pod에서 네트워크로 옆 Pod%s까지 직접 도달해 옮겨갈 수 있습니다.", targets)
	case "MS-TA9006":
		return fmt.Sprintf("%s 권한으로 다른 컨테이너%s 안에 들어가 명령을 실행할 수 있습니다.", sa, targets)
	case "MS-TA9018":
		return fmt.Sprintf("이 Pod이 노드(호스트)를 장악할 수 있어, 같은 노드의 다른 Pod%s까지 손을 뻗칠 수 있습니다.", targets)
	}
	return fmt.Sprintf("이 Pod에서 다른 Pod%s로 이동할 수 있습니다.", targets)
}

// buildOutgoingFromBlast — blast_edges 전파 엣지 → outgoing findings.
//
// 같은 technique으로 매핑되는 엣지는 1건으로 묶고, 도달 대상 이름과 대표 reason(첫 엣지)을 모은다.
// 입력은 호출부에서 p_edge desc 정렬되어 들어오므로 첫 reason이 가장 강한 근거다.
func buildOutgoingFromBlast(edges []BlastEdge, sa, execPerms string) []ScenarioFinding {
	type agg struct {
		tactic  string
		reason  string   // 대표 근거 (첫 엣지)
		targets []string // 중복 제거된 타겟 이름
		seen    map[string]bool
	}
	order := []string{}
	byTech := map[string]*agg{}
	addTarget := func(msta, tactic, reason, target string) {
		a := byTech[msta]
		if a == nil {
			a = &agg{tactic: tactic, reason: reason, seen: map[string]bool{}}
			byTech[msta] = a
			order = append(order, msta)
		}
		if target != "" && !a.seen[target] {
			a.seen[target] = true
			a.targets = append(a.targets, target)
		}
	}

	// 1) win_channel(= max 채널) 기준 매핑: network/portforward→9034, exec/nodes-proxy→9006, host→9018.
	for _, e := range edges {
		if msta, tactic, ok := blastChannelTech(e.Channel, e.Reason); ok {
			addTarget(msta, tactic, e.Reason, e.TargetName)
		}
	}

	// 2) rbac 채널이 win_channel 경합에서 host/network에 가려졌더라도(p_rbac>0) 측면이동 가능
	//    RBAC 권한은 실재하므로, 그 타겟을 9006(exec into container)에 합친다.
	//    win_channel=rbac 케이스는 (1)에서 이미 9006(exec)/9034(portforward)로 처리됐고,
	//    여기서는 host/network가 이긴 엣지의 가려진 rbac 도달성을 복원한다. 타겟은 (1)과 dedup.
	latentReason := "rbac: 측면이동 가능 권한(exec/attach 등) — 채널 경합에서 host/network에 가려짐"
	if execPerms != "" {
		// rbacchain에서 읽은 실제 권한을 부기 (가려진 채널이라 더 구체적으로).
		latentReason = execPerms + " (채널 경합에서 host/network에 가려짐)"
	}
	for _, e := range edges {
		if e.RBACProb <= 0 || e.Channel == "rbac" {
			continue // rbac이 이미 이긴 엣지는 (1)에서 처리(portforward=9034 포함) — 중복 회피
		}
		addTarget("MS-TA9006", TacticExecution, latentReason, e.TargetName)
	}

	out := make([]ScenarioFinding, 0, len(order))
	for _, msta := range order {
		a := byTech[msta]
		targets := ""
		if len(a.targets) > 0 {
			targets = fmt.Sprintf("(예: %s%s)", strings.Join(trimN(a.targets, 3), ", "), moreN(len(a.targets), 3))
		}
		out = append(out, mkFinding(msta, DirOutgoing, a.tactic,
			blastSentence(msta, sa, targets), "high", a.reason))
	}
	return out
}

// networkReachableTargets — 이 Pod에서 "네트워크로" 도달 가능한 대상 Pod 이름(중복 제거, 강한 순).
//
// NetworkPolicy는 특정 Pod↔Pod 통신 단위 통제라, "NetworkPolicy 없음" 보완을 한 줄로 퉁치는 대신
// 연결되는 Pod마다 한 항목씩 권고하기 위한 입력이다(scenario.go collectMitigations).
//
// 대상 판정: blast_edges 중 win_channel=network 이거나 p_net>0(host/rbac에 가려진 잠재 네트워크 도달).
// rbac-portforward(9034로 병합되지만 채널은 rbac)는 네트워크 채널이 아니라 제외한다.
// 엣지가 없으면(폴백) NetworkPolicy 격리 상태가 열려 있을 때(none/unknown) ReachablePods를 쓴다.
func networkReachableTargets(in ScenarioInput) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, e := range in.ReachEdges {
		if e.TargetName == "" || seen[e.TargetName] {
			continue
		}
		if e.Channel == "network" || e.NetProb > 0 {
			seen[e.TargetName] = true
			out = append(out, e.TargetName)
		}
	}
	// 폴백: 전파 엣지가 없고 격리가 열려 있으면(none/unknown) 휴리스틱 도달 목록을 쓴다.
	if len(in.ReachEdges) == 0 &&
		(in.NetworkIsolation == "none" || in.NetworkIsolation == "" || in.NetworkIsolation == "unknown") {
		for _, p := range in.ReachablePods {
			if p == "" || seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// moreN — n개 중 앞 limit개만 노출할 때 " 외 N개" 꼬리표. 초과 없으면 빈 문자열.
func moreN(n, limit int) string {
	if n > limit {
		return fmt.Sprintf(" 외 %d개", n-limit)
	}
	return ""
}

// vulnIncomingScenario — 진입(incoming) VULN 줄글. enrichment(설계서 §4)가 있으면
// "취약 컴포넌트 · 취약점 클래스 · 메커니즘"으로 구체화하고, 없으면 기존 generic 줄글로 폴백한다.
// (메커니즘은 검증 통과분만 채워지므로 환각 0 — §7.2 null 규칙)
func vulnIncomingScenario(in ScenarioInput) string {
	e := in.CVEEnrichment
	if e == nil {
		return fmt.Sprintf("이 Pod 이미지에 원격 악용 가능한 취약점(%s)이 있어, 공격자가 네트워크로 바로 코드 실행을 노릴 수 있습니다.", cveLabel(in))
	}

	// 컴포넌트 + 클래스 표제 (module_short 없으면 "취약 컴포넌트" 폴백 — 메서드명 생성 금지)
	comp := e.ModuleShort
	if comp == "" {
		comp = e.Module
	}
	if comp == "" {
		comp = "취약 컴포넌트"
	}
	class := e.VulnClassLabelShort
	if class == "" {
		class = e.VulnClassLabel
	}

	var b strings.Builder
	b.WriteString(comp)
	if class != "" {
		b.WriteString(" · ")
		b.WriteString(class)
	}
	if e.Impact != "" {
		b.WriteString(" · ")
		b.WriteString(e.Impact)
	}
	fmt.Fprintf(&b, " 취약점(%s).", cveLabel(in))

	// 메커니즘(검증 통과분만) — 있으면 한 절 덧붙인다.
	if e.MechanismShort != "" {
		b.WriteString(" ")
		b.WriteString(e.MechanismShort)
		if !strings.HasSuffix(e.MechanismShort, ".") {
			b.WriteString(".")
		}
	}

	// 원격/인증 절
	switch {
	case e.Remote && e.Unauth:
		b.WriteString(" 인증 없이 네트워크에서 원격 악용 가능.")
	case e.Remote:
		b.WriteString(" 네트워크에서 원격 악용 가능.")
	}
	return b.String()
}

// cveLabel — "CVE-2025-1234, CVSS 9.8, KEV 등재" 형태의 라벨
func cveLabel(in ScenarioInput) string {
	s := in.TopCVE
	if in.CVEScore > 0 {
		s += fmt.Sprintf(", CVSS %.1f", in.CVEScore)
	}
	if in.CVEKEV {
		s += ", KEV 등재"
	}
	return s
}

func trimN(xs []string, n int) []string {
	if len(xs) > n {
		return xs[:n]
	}
	return xs
}
