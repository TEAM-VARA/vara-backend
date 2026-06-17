package scoring

import (
	"fmt"
	"strings"
)

// ============================================================================
// 공격 시나리오 / 보완대책 "줄글" 생성 (ATT&CK technique 기반)
//
// 입력 : pod에서 이미 수집되는 신호 (ScenarioInput, scenario_build.go)
// 출력 : PodScenarioResult — 공격 시나리오 줄글 + 보완대책 줄글 + 구조화 findings
//
// 모델 : 전이(엣지) tactic = 어떻게 도달/전파하나, 상태(노드) tactic = 여기서 뭘 하나
//   direction: incoming(진입) / node(노드 상태) / outgoing(전파)
//
// catalog는 outputs/technique_catalog.csv 와 동기. DB 시드 대신 우선 코드 임베드.
// ============================================================================

// 전이 tactic (엣지)
const (
	TacticInitialAccess = "초기 침투"
	TacticExecution     = "코드 실행"
	TacticLateral       = "측면 이동"
	TacticPrivEsc       = "권한 상승"
)

// 상태 tactic (노드)
const (
	TacticPersistence  = "지속"
	TacticCredAccess   = "자격증명 접근"
	TacticCollection   = "데이터 수집"
	TacticImpact       = "파괴"
	TacticDefenseEvade = "방어 회피"
)

// direction
const (
	DirIncoming = "incoming"
	DirNode     = "node"
	DirOutgoing = "outgoing"
)

// ScenarioFinding — 탐지된 technique 1건 (줄글 포함)
type ScenarioFinding struct {
	MSTA       string   `json:"ms_ta,omitempty"`
	MitreT     string   `json:"mitre_t,omitempty"`
	CVE        string   `json:"cve,omitempty"`
	Name       string   `json:"name"`
	Bucket     string   `json:"bucket"`     // RBAC|NET|MOUNT|VULN
	Direction  string   `json:"direction"`  // incoming|node|outgoing
	Tactic     string   `json:"tactic"`     // 한국어 tactic 라벨
	Scenario   string   `json:"scenario"`   // 한 문장 시나리오 줄글
	Mitigation string   `json:"mitigation"` // 한 문장 보완 줄글
	MitreM     []string `json:"mitre_m,omitempty"`
	Confidence string   `json:"confidence"` // high|heuristic|low
	Caveat     string   `json:"caveat,omitempty"`
}

// ScenarioMitigation — 보완대책 1건 (개조식 항목).
//
// mitigation 줄글과 별개로, 프론트에서 항목을 클릭하면 Key(또는 MSTA)로
// 백엔드 조치 로직을 분기할 수 있도록 technique 단위로 분리한다.
type ScenarioMitigation struct {
	Key    string   `json:"key"`            // 조치 분기 키 (ms_ta, VULN은 "VULN")
	MSTA   string   `json:"ms_ta,omitempty"`
	MitreT string   `json:"mitre_t,omitempty"`
	Bucket string   `json:"bucket"` // RBAC|NET|MOUNT|VULN
	CVE    string   `json:"cve,omitempty"`
	Text   string   `json:"text"`             // 보완 줄글 (한 항목, MITRE 태그 제외)
	MitreM []string `json:"mitre_m,omitempty"` // 클릭 시 참조할 MITRE mitigation 코드
}

// PodScenarioResult — pod 1개의 최종 출력 (페이지 렌더용)
type PodScenarioResult struct {
	ClusterName string  `json:"cluster_name"`
	PodUID      string  `json:"pod_uid"`
	PodName     string  `json:"pod_name"`
	Namespace   string  `json:"namespace"`
	RiskScore   float64 `json:"risk_score"`
	RiskLevel   string  `json:"risk_level"`

	// ★ 페이지에 그대로 출력되는 줄글
	AttackScenario string `json:"attack_scenario"`
	Mitigation     string `json:"mitigation"`

	// 보완대책 구조화 (프론트 클릭 → 백엔드 조치 분기용). Mitigation 줄글과 1:1 대응.
	Mitigations []ScenarioMitigation `json:"mitigations"`

	// 구조화 (UI 칩/패널용)
	Findings   []ScenarioFinding `json:"findings"`
	Incoming   []ScenarioFinding `json:"incoming"`
	NodeStates []ScenarioFinding `json:"node_states"`
	Outgoing   []ScenarioFinding `json:"outgoing"`

	Notes []string `json:"notes,omitempty"` // 수집 갭 등 한계 고지
}

// techMeta — technique 정적 메타 (이름/MITRE/보완 줄글)
type techMeta struct {
	Name       string
	MitreT     string
	Bucket     string
	MitreM     []string
	Mitigation string // 보완대책 줄글 (정적)
}

// techCatalog — technique_catalog.csv 와 동기화된 임베드 카탈로그
var techCatalog = map[string]techMeta{
	"MS-TA9005": {"Exposed sensitive interface", "T1133", "NET", []string{"M1035", "M1030"},
		"외부 노출을 최소화하고(Service type LB/NodePort 지양) Ingress 인증 게이트웨이와 ingress NetworkPolicy로 접근을 제한하세요."},
	"MS-TA9006": {"Exec into container", "T1609", "RBAC", []string{"M1038", "M1026"},
		"서비스계정에서 pods/exec·attach 권한을 회수하고 exec 호출을 감사 로깅하세요."},
	"MS-TA9008": {"New container", "T1610", "RBAC", []string{"M1038", "M1042"},
		"워크로드 생성 권한을 CD 파이프라인·운영 주체로 한정하고 PSA restricted·이미지 출처 검증을 적용하세요."},
	"MS-TA9012": {"Backdoor container", "T1543", "RBAC", []string{"M1045", "M1047"},
		"컨트롤러 생성 권한을 제한하고 이미지 서명 검증·GitOps drift 탐지를 적용하세요."},
	"MS-TA9013": {"Writable hostPath mount", "T1611", "MOUNT", []string{"M1048", "M1038"},
		"PSA restricted로 hostPath를 차단하고, 불가피하면 readOnly 마운트로 강제하세요."},
	"MS-TA9015": {"Malicious admission controller", "T1546", "RBAC", []string{"M1026", "M1047"},
		"웹훅 구성(webhookconfiguration) 쓰기 권한을 cluster-admin으로만 한정하고 변경을 모니터링하세요."},
	"MS-TA9016": {"Container service account", "T1528", "RBAC", []string{"M1026", "M1041"},
		"automountServiceAccountToken=false로 토큰 마운트를 끄고 SA 권한을 최소화하며 단명 토큰을 쓰세요."},
	"MS-TA9018": {"Privileged container", "T1610", "MOUNT", []string{"M1048", "M1038"},
		"privileged 설정을 제거하고 PSA restricted(allowPrivilegeEscalation=false, capabilities drop)를 적용하세요."},
	"MS-TA9019": {"Cluster-admin binding", "T1078.003", "RBAC", []string{"M1026", "M1018"},
		"bind·escalate·rolebinding 생성 권한을 회수하고 cluster-admin 바인딩을 감사하세요."},
	"MS-TA9020": {"Access cloud resources", "T1078.004", "RBAC", []string{"M1026", "M1032"},
		"IMDSv2 hop-limit=1을 강제하고 IRSA IAM 권한을 최소화하며 IMDS egress를 NetworkPolicy로 차단하세요."},
	"MS-TA9022": {"Delete K8s events", "T1070", "RBAC", []string{"M1029", "M1022"},
		"events 삭제 권한을 회수하고 감사 로그를 외부에 불변 저장(SIEM)하세요."},
	"MS-TA9025": {"List K8s secrets", "T1552.007", "RBAC", []string{"M1041", "M1026"},
		"secrets 읽기 권한을 최소화하고 etcd 암호화·외부 시크릿 매니저를 적용하세요."},
	"MS-TA9034": {"Cluster internal networking", "T1210", "NET", []string{"M1030", "M1035"},
		"default-deny NetworkPolicy로 통신을 차단하고 필요한 경로만 허용(마이크로세분화)하세요."},
	"VULN": {"Known vulnerability (CVE)", "", "VULN", []string{"M1051"},
		"영향받는 패키지를 패치(fixed) 버전으로 업그레이드하고, KEV 등재·EPSS 높은 취약점을 우선 처리하세요."},
}

// mkFinding — catalog 메타를 채운 finding 생성 (CVE는 호출부에서 설정)
func mkFinding(id, dir, tactic, scenario, confidence, caveat string) ScenarioFinding {
	m := techCatalog[id]
	f := ScenarioFinding{
		Name:       m.Name,
		MitreT:     m.MitreT,
		Bucket:     m.Bucket,
		Direction:  dir,
		Tactic:     tactic,
		Scenario:   scenario,
		Mitigation: m.Mitigation,
		MitreM:     m.MitreM,
		Confidence: confidence,
		Caveat:     caveat,
	}
	if id != "VULN" {
		f.MSTA = id
	}
	return f
}

// composeScenario — incoming→node→outgoing 순서로 공격 시나리오 줄글(문단) 생성
func composeScenario(incoming, node, outgoing []ScenarioFinding) string {
	var b strings.Builder
	if len(incoming) > 0 {
		b.WriteString("【진입】 ")
		b.WriteString(joinSentences(incoming))
		b.WriteString(" ")
	}
	if len(node) > 0 {
		b.WriteString("【장악 후】 일단 이 Pod을 차지하면, ")
		b.WriteString(joinSentences(node))
		b.WriteString(" ")
	}
	if len(outgoing) > 0 {
		b.WriteString("【전파】 그리고 여기서 ")
		b.WriteString(joinSentences(outgoing))
	}
	s := strings.TrimSpace(b.String())
	if s == "" {
		return "현재 수집된 신호에서는 두드러진 공격 시나리오가 식별되지 않았습니다."
	}
	return s
}

func joinSentences(fs []ScenarioFinding) string {
	parts := make([]string, 0, len(fs))
	for _, f := range fs {
		s := f.Scenario
		if f.Caveat != "" {
			s += "(※ " + f.Caveat + ")"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " ")
}

// collectMitigations — technique 중복 제거 후 구조화된 보완 항목 리스트 생성.
//
// 각 항목은 프론트에서 클릭 시 Key(ms_ta, VULN은 "VULN")로 백엔드 조치 로직을
// 분기할 수 있도록 finding과 분리한다. 줄글(composeMitigationText)과 1:1 대응.
func collectMitigations(fs []ScenarioFinding) []ScenarioMitigation {
	seen := map[string]bool{}
	out := make([]ScenarioMitigation, 0, len(fs))
	for _, f := range fs {
		key := f.MSTA
		if key == "" {
			key = "VULN"
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ScenarioMitigation{
			Key:    key,
			MSTA:   f.MSTA,
			MitreT: f.MitreT,
			Bucket: f.Bucket,
			CVE:    f.CVE,
			Text:   f.Mitigation,
			MitreM: f.MitreM,
		})
	}
	return out
}

// composeMitigationText — 구조화 보완 항목을 사람이 읽는 줄글로 조립.
// 단일 항목은 한 줄, 여러 항목은 개조식(번호 + 줄바꿈). MITRE 코드는 괄호 태그로 부기.
func composeMitigationText(items []ScenarioMitigation) string {
	if len(items) == 0 {
		return "추가로 식별된 보완 조치가 없습니다."
	}
	line := func(m ScenarioMitigation) string {
		if len(m.MitreM) > 0 {
			return m.Text + " (MITRE " + strings.Join(m.MitreM, "/") + ")"
		}
		return m.Text
	}
	if len(items) == 1 {
		return "다음 조치를 권장합니다. " + line(items[0])
	}
	var b strings.Builder
	b.WriteString("다음 조치를 권장합니다.")
	for i, it := range items {
		fmt.Fprintf(&b, "\n%d. %s", i+1, line(it))
	}
	return b.String()
}
