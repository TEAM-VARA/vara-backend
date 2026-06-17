package scoring

import (
	"fmt"
	"strings"
)

// ScenarioInput — pod 1개의 "이미 수집되는" 신호 모음.
//
// 채워 넣는 소스 (scenario_handler.go 참고):
//   MOUNT  : cluster_pods.containers(privileged)·volumes(type=hostPath)·host_network·host_pid
//   RBAC   : rbacchain effective permissions (verb·resource)
//   NET    : attack_path_scores.NetworkDetails(isolation) + exposure_scores + edges(network)
//   VULN   : sbom/global_image + platform/kev + platform/epss + CVSS 벡터
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

	// NET
	NetworkIsolation string // none|egress_only|both|deny_all|unknown
	Exposed          bool
	ExposedVia       string // "Service(LoadBalancer)" 등
	ReachablePods    []string

	// VULN (sbom/global + kev/epss + cvss 벡터)
	TopCVE                   string
	CVEScore                 float64
	CVEKEV                   bool
	CVERemote                bool // AV:N
	CVEScopeChanged          bool // S:C (v3.1) / Subsequent System (v4.0)
	CVEAvailabilityImpact    bool // A:H / VA:H
	CVEConfidentialityImpact bool // C:H / VC:H

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
			fmt.Sprintf("이 Pod 이미지에 원격 악용 가능한 취약점(%s)이 있어, 공격자가 네트워크로 바로 코드 실행을 노릴 수 있습니다.", cveLabel(in)),
			"heuristic", "CVSS 벡터(AV:N) 기반 추정")
		f.CVE = in.TopCVE
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
			"high", ""))
	}
	if in.CanWriteWebhook {
		fs = append(fs, mkFinding("MS-TA9015", DirNode, TacticPersistence,
			fmt.Sprintf("%s에 admission 웹훅 구성 권한이 있어, 공격자가 가짜 검문 웹훅을 심어 모든 요청을 가로채며 잠복할 수 있습니다.", sa),
			"high", ""))
	}
	if in.CanDeleteEvents {
		fs = append(fs, mkFinding("MS-TA9022", DirNode, TacticDefenseEvade,
			fmt.Sprintf("%s에 events 삭제 권한이 있어, 공격자가 흔적(이벤트 로그)을 지워 탐지를 회피할 수 있습니다.", sa),
			"high", ""))
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

	// ───────── 전파 (outgoing) ─────────
	if in.NetworkIsolation == "none" || in.NetworkIsolation == "" || in.NetworkIsolation == "unknown" {
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
	if in.CanExec {
		fs = append(fs, mkFinding("MS-TA9006", DirOutgoing, TacticExecution,
			fmt.Sprintf("%s에 pods/exec 권한이 있어, 공격자가 다른 컨테이너 안으로 들어가 명령을 실행할 수 있습니다.", sa),
			"high", ""))
	}
	if in.CanCreateWorkload {
		fs = append(fs, mkFinding("MS-TA9008", DirOutgoing, TacticExecution,
			fmt.Sprintf("%s에 워크로드 생성 권한이 있어, 공격자가 새 컨테이너를 띄워 임의 코드를 실행할 수 있습니다.", sa),
			"high", ""))
	}
	// 9016: SA 토큰이 과대권한이면 측면 이동 통로
	if in.IsClusterAdmin || in.CanListSecrets || in.CanCreateWorkload || in.CanExec {
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
	res.Mitigations = collectMitigations(fs)
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
