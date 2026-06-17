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

	if !strings.Contains(r.AttackScenario, "【진입】") ||
		!strings.Contains(r.AttackScenario, "【장악 후】") ||
		!strings.Contains(r.AttackScenario, "【전파】") {
		t.Fatalf("3단계 줄글 누락: %q", r.AttackScenario)
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
	// 9013 은 writable 미확정 caveat 포함
	if !strings.Contains(r.AttackScenario, "readOnly") {
		t.Errorf("hostPath caveat 누락")
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
