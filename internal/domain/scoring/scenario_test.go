package scoring

import (
	"strings"
	"testing"
)

// 위험 pod: privileged + hostPath + secrets + 워크로드생성 + cluster-admin + 노출 + 원격/가용성 CVE + netpol 없음
func TestBuildPodScenario_Rich(t *testing.T) {
	in := ScenarioInput{
		PodName: "ci-runner-abc", PodUID: "uid-1", Namespace: "prod",
		ClusterName: "vara-eks-test", ServiceAccount: "ci-runner",
		Exposed: true, ExposedVia: "Service(LoadBalancer)로 외부 노출된",
		PrivilegedContainers:  []string{"app"},
		HostPathVolumes:       []string{"host-root"},
		CanListSecrets:        true,
		CanCreateWorkload:     true,
		IsClusterAdmin:        true,
		NetworkIsolation:      "none",
		ReachablePods:         []string{"db-pod", "cache-pod", "queue-pod", "extra"},
		TopCVE:                "CVE-2025-1234",
		CVEScore:              9.8,
		CVEKEV:                true,
		CVERemote:             true,
		CVEAvailabilityImpact: true,
	}
	r := BuildPodScenario(in)

	// 괄호 마커(【】) 없이 자연 연결어로 진입→장악→전파가 이어진다.
	if strings.Contains(r.AttackScenario, "【") || strings.Contains(r.AttackScenario, "】") {
		t.Errorf("괄호 마커가 남아있음: %q", r.AttackScenario)
	}
	if !strings.Contains(r.AttackScenario, "일단 이 Pod을 차지하면") ||
		!strings.Contains(r.AttackScenario, "그리고 여기서") {
		t.Fatalf("장악/전파 연결어 누락: %q", r.AttackScenario)
	}
	if !strings.Contains(r.AttackScenario, "privileged") {
		t.Errorf("privileged 시나리오 누락")
	}
	if !strings.Contains(r.AttackScenario, "CVE-2025-1234") {
		t.Errorf("CVE 시나리오 누락")
	}
	if !strings.HasPrefix(r.Mitigation, "다음 조치를 권장합니다") {
		t.Errorf("보완 줄글 형식 오류: %q", r.Mitigation)
	}
	if len(r.Incoming) != 2 {
		t.Errorf("incoming = %d, want 2", len(r.Incoming))
	}
	if len(r.NodeStates) == 0 || len(r.Outgoing) == 0 {
		t.Errorf("node/outgoing 비어있음: node=%d out=%d", len(r.NodeStates), len(r.Outgoing))
	}
	// ReachablePods 는 최대 3개만 노출
	if strings.Contains(r.AttackScenario, "extra") {
		t.Errorf("ReachablePods 가 3개 초과로 노출됨")
	}
	// caveat(※ 추정 근거)는 괄호 제거 정책으로 프로즈에 싣지 않고, 구조화 Caveat 필드에만 남긴다.
	var hostCaveat string
	for _, f := range r.NodeStates {
		if f.MSTA == "MS-TA9013" {
			hostCaveat = f.Caveat
		}
	}
	if !strings.Contains(hostCaveat, "readOnly") {
		t.Errorf("hostPath caveat(구조화 필드) 누락: %q", hostCaveat)
	}
	if strings.Contains(r.AttackScenario, "(※") {
		t.Errorf("caveat 괄호가 프로즈에 남아있음: %q", r.AttackScenario)
	}
}

// blast_edges 전파 엣지가 있으면 outgoing을 그 directed 엣지로 구성한다(휴리스틱 폴백 안 함).
//   network               → MS-TA9034 (측면 이동)
//   rbac + portforward    → MS-TA9034 (네트워크 도달이므로 9034로 병합)
//   rbac + exec/attach 등 → MS-TA9006 (코드 실행)
//   host (노드 공유)        → MS-TA9018 (측면 이동)
func TestBuildPodScenario_BlastOutgoing(t *testing.T) {
	in := ScenarioInput{
		PodName: "ci-runner", PodUID: "uid-1", Namespace: "prod", ServiceAccount: "ci-sa",
		// 휴리스틱이라면 9034(NetworkPolicy 없음)·9006(exec)가 떴겠지만 blast가 있으면 대체된다.
		NetworkIsolation: "none",
		CanExec:          true,
		ReachEdges: []BlastEdge{
			{Channel: "network", Reason: "network: same-ns no netpol", TargetName: "db-pod"},
			{Channel: "network", Reason: "network: ...", TargetName: "cache-pod"},
			{Channel: "network", Reason: "network: ...", TargetName: "queue-pod"},
			{Channel: "network", Reason: "network: ...", TargetName: "log-pod"}, // 4번째 → "외 N개"
			{Channel: "rbac", Reason: "rbac: portforward svc/api", TargetName: "gw-pod"},
			{Channel: "rbac", Reason: "rbac: exec/attach ns=prod", TargetName: "admin-pod"},
			{Channel: "host", Reason: "host: shared node ip-10-0-1-5", TargetName: "node-mate"},
		},
	}
	r := BuildPodScenario(in)

	byMSTA := map[string]ScenarioFinding{}
	for _, f := range r.Outgoing {
		byMSTA[f.MSTA] = f
	}
	// blast 3 technique: 9034(network+portforward 병합)·9006(exec)·9018(host)
	// + SA 능력 기반 9016(CanExec=true → blast 유무와 무관하게 항상 평가). 총 4건.
	if len(r.Outgoing) != 4 {
		t.Fatalf("outgoing = %d, want 4 (9034/9006/9018/9016): %+v", len(r.Outgoing), r.Outgoing)
	}
	for _, want := range []string{"MS-TA9034", "MS-TA9006", "MS-TA9018", "MS-TA9016"} {
		if _, ok := byMSTA[want]; !ok {
			t.Errorf("outgoing technique %s 누락", want)
		}
	}
	// 9006은 blast(rbac-exec)에서 1번만 — 능력 기반 9006과 중복 방출되면 안 된다.
	count9006 := 0
	for _, f := range r.Outgoing {
		if f.MSTA == "MS-TA9006" {
			count9006++
		}
	}
	if count9006 != 1 {
		t.Errorf("9006 중복 방출: %d건 (blast + 능력 dedup 실패)", count9006)
	}

	// 9034: blast 줄글(직접 도달)이어야 하고, 휴리스틱 줄글(NetworkPolicy 없음)이면 안 된다.
	net := byMSTA["MS-TA9034"]
	if !strings.Contains(net.Scenario, "직접 도달") {
		t.Errorf("9034 blast 줄글 아님: %q", net.Scenario)
	}
	if strings.Contains(net.Scenario, "NetworkPolicy가 없어") {
		t.Errorf("9034가 휴리스틱 줄글로 폴백됨: %q", net.Scenario)
	}
	// 대표 근거(첫 엣지 reason)가 caveat에 실린다.
	if net.Caveat != "network: same-ns no netpol" {
		t.Errorf("9034 대표 reason 불일치: %q", net.Caveat)
	}
	// 타겟은 최대 3개만 노출 + "외 N개" 꼬리표 (network 4 + portforward 1 = 5개 → 외 2개).
	if !strings.Contains(net.Scenario, "db-pod") || !strings.Contains(net.Scenario, "외 2개") {
		t.Errorf("9034 타겟/꼬리표 누락: %q", net.Scenario)
	}
	if strings.Contains(net.Scenario, "log-pod") {
		t.Errorf("9034 타겟이 3개 초과로 노출됨: %q", net.Scenario)
	}

	// 9006(rbac exec)은 도달 대상 이름을 포함한다.
	if !strings.Contains(byMSTA["MS-TA9006"].Scenario, "admin-pod") {
		t.Errorf("9006 타겟 누락: %q", byMSTA["MS-TA9006"].Scenario)
	}
}

// rbac이 채널 경합(win_channel=host)에서 졌지만 p_rbac>0이면, 그 타겟이 9006(exec)에 합쳐진다.
// (host로 가려진 rbac 측면이동 권한을 시나리오에서 복원)
func TestBuildPodScenario_BlastRBACHiddenByHost(t *testing.T) {
	in := ScenarioInput{
		PodName: "p", PodUID: "u", Namespace: "prod", ServiceAccount: "svc-sa",
		ReachEdges: []BlastEdge{
			// host가 이긴 엣지(privileged 같은 노드)지만 rbac exec 권한도 있어 p_rbac=1.0.
			{Channel: "host", Reason: "host: escape(privileged/hostPath) + same node n1",
				TargetName: "victim-pod", RBACProb: 1.0},
		},
	}
	r := BuildPodScenario(in)

	byMSTA := map[string]ScenarioFinding{}
	for _, f := range r.Outgoing {
		byMSTA[f.MSTA] = f
	}
	// host 엣지 → 9018, 가려진 rbac → 9006(victim-pod 합쳐짐)
	if _, ok := byMSTA["MS-TA9018"]; !ok {
		t.Errorf("host 엣지 9018 누락")
	}
	ex, ok := byMSTA["MS-TA9006"]
	if !ok {
		t.Fatalf("가려진 rbac이 9006으로 복원되지 않음: %+v", r.Outgoing)
	}
	if !strings.Contains(ex.Scenario, "victim-pod") {
		t.Errorf("9006에 rbac 타겟 누락: %q", ex.Scenario)
	}
}

// MS-TA9034(NetworkPolicy 없음) 보완은 "default-deny 한 줄"로 퉁치지 않고, 네트워크로 도달하는
// 대상 Pod마다 한 항목씩 쪼개 권고한다(Pod↔Pod 통신 단위 통제). portforward(rbac)·host 대상은 제외.
func TestBuildPodScenario_NetworkPolicyPerConnection(t *testing.T) {
	in := ScenarioInput{
		PodName: "ci-runner", PodUID: "uid-1", Namespace: "prod", ServiceAccount: "ci-sa",
		ReachEdges: []BlastEdge{
			{Channel: "network", Reason: "network: same-ns no netpol", TargetName: "db-pod", NetProb: 0.9},
			{Channel: "network", Reason: "network: ...", TargetName: "cache-pod", NetProb: 0.8},
			// host로 win 했지만 p_net>0 → 잠재 네트워크 도달이라 NetworkPolicy 권고 대상.
			{Channel: "host", Reason: "host: shared node", TargetName: "log-pod", NetProb: 0.5},
			// rbac portforward는 9034로 병합되지만 네트워크 채널이 아니므로 연결별 권고에서 제외.
			{Channel: "rbac", Reason: "rbac: portforward svc/api", TargetName: "gw-pod"},
		},
	}
	r := BuildPodScenario(in)

	// 9034 보완이 db/cache/log 3건으로 쪼개졌는지(각 Target 지정), gw-pod는 빠졌는지 확인.
	got := map[string]string{} // target → text
	others := 0
	for _, m := range r.Mitigations {
		if m.MSTA == "MS-TA9034" {
			if m.Target == "" {
				t.Errorf("9034 보완에 Target 비어있음: %+v", m)
			}
			got[m.Target] = m.Text
		} else {
			others++
		}
	}
	for _, want := range []string{"db-pod", "cache-pod", "log-pod"} {
		txt, ok := got[want]
		if !ok {
			t.Errorf("연결별 NetworkPolicy 권고에 %s 누락: %+v", want, r.Mitigations)
			continue
		}
		if !strings.Contains(txt, want) || !strings.Contains(txt, "NetworkPolicy") {
			t.Errorf("%s 권고 줄글 형식 오류: %q", want, txt)
		}
	}
	if _, ok := got["gw-pod"]; ok {
		t.Errorf("portforward(rbac) 대상 gw-pod가 NetworkPolicy 권고에 잘못 포함됨")
	}
	if len(got) != 3 {
		t.Errorf("연결별 9034 보완 = %d건, want 3 (db/cache/log)", len(got))
	}
}

// 폴백: 전파 엣지가 없고 격리가 열려 있으면(none) ReachablePods로 연결별 NetworkPolicy 권고를 만든다.
func TestBuildPodScenario_NetworkPolicyFallbackReachablePods(t *testing.T) {
	in := ScenarioInput{
		PodName: "p", PodUID: "u", Namespace: "prod", ServiceAccount: "sa",
		NetworkIsolation: "none",
		ReachablePods:    []string{"db-pod", "cache-pod"},
	}
	r := BuildPodScenario(in)

	targets := map[string]bool{}
	for _, m := range r.Mitigations {
		if m.MSTA == "MS-TA9034" && m.Target != "" {
			targets[m.Target] = true
		}
	}
	if !targets["db-pod"] || !targets["cache-pod"] {
		t.Errorf("폴백 ReachablePods 연결별 권고 누락: %+v", r.Mitigations)
	}
}

// 신호 없는 pod: 폴백 메시지
func TestBuildPodScenario_Empty(t *testing.T) {
	r := BuildPodScenario(ScenarioInput{PodName: "clean", NetworkIsolation: "deny_all"})
	if len(r.Findings) != 0 {
		t.Errorf("findings = %d, want 0", len(r.Findings))
	}
	if !strings.Contains(r.AttackScenario, "식별되지 않았습니다") {
		t.Errorf("폴백 메시지 누락: %q", r.AttackScenario)
	}
}

// 보완 줄글은 technique 중복 제거 (9008/9016 처럼 node+outgoing 양쪽 등장해도 1회)
func TestBuildPodScenario_MitigationDeduped(t *testing.T) {
	r := BuildPodScenario(ScenarioInput{
		ServiceAccount: "web-sa", CanListSecrets: true, NetworkIsolation: "both",
	})
	// secrets(node 9025) + SA token(outgoing 9016) = 보완 2건
	if strings.Count(r.Mitigation, "(") < 2 {
		t.Errorf("보완 항목 수 부족: %q", r.Mitigation)
	}
}
