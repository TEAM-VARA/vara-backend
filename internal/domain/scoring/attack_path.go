package scoring

import "time"

// ─────────────────────────────────────────
// Attack Path Scope (공격 경로 범위) 도메인
// ─────────────────────────────────────────
//
// 점수 공식 (Phase 1, K8s 기반):
//   Total = RBAC(40) + Network(30) + Mount(30)
//
// 의미:
//   "이 Pod이 침해됐을 때 공격자가 어디까지 갈 수 있는가"
//   - 높을수록 위험: 광범위한 K8s 권한, 격리 부재, 민감 자원 접근

// ─────────────────────────────────────────
// 점수 한도
// ─────────────────────────────────────────

const (
	AttackPathMaxRBAC    = 40
	AttackPathMaxNetwork = 30
	AttackPathMaxMount   = 30
	AttackPathMaxTotal   = AttackPathMaxRBAC + AttackPathMaxNetwork + AttackPathMaxMount
)

// ─────────────────────────────────────────
// RBAC 권한 레벨
// ─────────────────────────────────────────

const (
	// 가장 위험: cluster-admin 또는 동등한 권한
	RBACLevelClusterAdmin = "cluster-admin" // 40점

	// 와일드카드 verbs/resources (cluster-admin은 아니지만 광범위)
	RBACLevelWildcard = "wildcard" // 35점

	// secrets 접근 (탈취 가능)
	RBACLevelSecretsAccess = "secrets_access" // 30점

	// pod exec, port-forward, create (lateral movement)
	RBACLevelPodExec = "pod_exec" // 25점

	// 일반 read 권한 (정보 수집 가능)
	RBACLevelReadOnly = "read_only" // 10점

	// 권한 없음
	RBACLevelNone = "none" // 0점
)

// ─────────────────────────────────────────
// NetworkPolicy 격리 레벨
// ─────────────────────────────────────────

const (
	// 적용된 NetworkPolicy 없음 (모든 통신 허용 = 격리 안 됨)
	NetworkIsolationNone = "none" // 30점

	// egress만 제한
	NetworkIsolationEgressOnly = "egress_only" // 20점

	// egress + ingress 둘 다 제한
	NetworkIsolationBoth = "both" // 10점

	// default-deny (모든 통신 차단 후 명시적 허용만)
	NetworkIsolationDenyAll = "deny_all" // 0점
)

// ─────────────────────────────────────────
// 데이터 타입
// ─────────────────────────────────────────

// AttackPathResult는 단일 Pod의 공격 경로 범위 평가 결과입니다.
type AttackPathResult struct {
	// 식별
	ClusterName  string `json:"cluster_name"`
	PodUID       string `json:"pod_uid"`
	PodName      string `json:"pod_name"`
	PodNamespace string `json:"pod_namespace"`
	// 종합 점수
	TotalScore int `json:"total_score"` // 0~100
	// 항목별 점수
	RBACScore    int `json:"rbac_score"`    // 0~40
	NetworkScore int `json:"network_score"` // 0~30
	MountScore   int `json:"mount_score"`   // 0~30
	// 판정 근거
	RBACDetails    RBACDetails    `json:"rbac_details"`
	NetworkDetails NetworkDetails `json:"network_details"`
	MountDetails   MountDetails   `json:"mount_details"`
	// 시점
	SnapshotAt time.Time `json:"snapshot_at"`
	ComputedAt time.Time `json:"computed_at"`

	// ─── Runtime 분석 (eBPF 기반, nullable) ───
	// 데이터 없으면 nil — service에서 채워짐
	RuntimeNetworkScore    *int                   `json:"runtime_network_score,omitempty"`
	RuntimeNetworkDetails  *RuntimeNetworkDetails `json:"runtime_network_details,omitempty"`
	UsesHostNetwork        *bool                  `json:"uses_host_network,omitempty"`
	OvergrantRatio         *float64               `json:"overgrant_ratio,omitempty"`
	OvergrantedPermissions *OvergrantPermissions  `json:"overgranted_permissions,omitempty"`
}

// RBACDetails는 RBAC 평가의 근거입니다.
type RBACDetails struct {
	// 평가된 ServiceAccount
	ServiceAccount string `json:"service_account"`

	// 결정된 권한 레벨 (가장 높은 것)
	Level string `json:"level"`

	// 매핑된 RoleBinding/ClusterRoleBinding 이름
	MatchedBindings []string `json:"matched_bindings,omitempty"`

	// 매핑된 Role/ClusterRole 이름
	MatchedRoles []string `json:"matched_roles,omitempty"`

	// 위험 신호 (디버깅용)
	HasWildcard      bool `json:"has_wildcard"`
	HasSecretsAccess bool `json:"has_secrets_access"`
	HasPodExec       bool `json:"has_pod_exec"`
	IsClusterAdmin   bool `json:"is_cluster_admin"`
}

// NetworkDetails는 NetworkPolicy 격리 평가의 근거입니다.
type NetworkDetails struct {
	// 격리 레벨
	Isolation string `json:"isolation"`

	// Pod에 매칭되는 NetworkPolicy 이름들
	MatchedPolicies []string `json:"matched_policies,omitempty"`

	// 정책 타입 카운트
	HasIngressRules bool `json:"has_ingress_rules"`
	HasEgressRules  bool `json:"has_egress_rules"`
}

// MountDetails는 민감 자원 마운트 평가의 근거입니다.
type MountDetails struct {
	// 호스트 자원 접근 (매우 위험)
	HostNetwork bool `json:"host_network"`
	HostPID     bool `json:"host_pid"`
	HostIPC     bool `json:"host_ipc"`
	HasHostPath bool `json:"has_host_path"`

	// privileged 컨테이너 (커널 권한)
	HasPrivileged bool `json:"has_privileged"`

	// 마운트 개수
	SecretMounts    int `json:"secret_mounts"`
	ConfigMapMounts int `json:"configmap_mounts"`
}

// ─────────────────────────────────────────
// API DTO
// ─────────────────────────────────────────

// AttackPathComputeRequest는 클러스터 단위 계산 요청입니다.
type AttackPathComputeRequest struct {
	ClusterName string `json:"cluster_name" binding:"required"`
}

// AttackPathComputeResponse는 일괄 계산 결과 요약입니다.
type AttackPathComputeResponse struct {
	ClusterName string             `json:"cluster_name"`
	SnapshotAt  time.Time          `json:"snapshot_at"`
	Computed    int                `json:"computed"`
	HighRisk    int                `json:"high_risk"`   // score >= 70
	MediumRisk  int                `json:"medium_risk"` // 40 <= score < 70
	LowRisk     int                `json:"low_risk"`    // score < 40
	Details     []AttackPathResult `json:"details"`
}

// ─────────────────────────────────────────
// 점수 계산 함수
// ─────────────────────────────────────────

// ComputeRBACScore는 RBAC 권한 레벨로부터 점수를 산정합니다.
func ComputeRBACScore(level string) int {
	switch level {
	case RBACLevelClusterAdmin:
		return 40
	case RBACLevelWildcard:
		return 35
	case RBACLevelSecretsAccess:
		return 30
	case RBACLevelPodExec:
		return 25
	case RBACLevelReadOnly:
		return 10
	default:
		return 0
	}
}

// ComputeNetworkScore는 NetworkPolicy 격리 레벨로부터 점수를 산정합니다.
func ComputeNetworkScore(isolation string) int {
	switch isolation {
	case NetworkIsolationNone:
		return 30
	case NetworkIsolationEgressOnly:
		return 20
	case NetworkIsolationBoth:
		return 10
	case NetworkIsolationDenyAll:
		return 0
	default:
		return 30 // 알 수 없으면 보수적으로 위험 처리
	}
}

// ComputeMountScore는 마운트 정보로부터 점수를 산정합니다.
//
// 위험 등급별 점수:
//   30: hostPath/hostNetwork/hostPID/hostIPC/privileged 중 하나라도 있음
//   20: secret 2개 이상 마운트
//   10: secret 1개 또는 configmap 마운트
//    0: 아무것도 안 함
func ComputeMountScore(d MountDetails) int {
	// 가장 위험 그룹
	if d.HostNetwork || d.HostPID || d.HostIPC || d.HasHostPath || d.HasPrivileged {
		return 30
	}
	// 시크릿 2개 이상
	if d.SecretMounts >= 2 {
		return 20
	}
	// 시크릿 1개 또는 configmap
	if d.SecretMounts >= 1 || d.ConfigMapMounts >= 1 {
		return 10
	}
	return 0
}

// ClassifyAttackPathLevel은 종합 점수를 등급으로 분류합니다.
func ClassifyAttackPathLevel(score int) string {
	switch {
	case score >= 70:
		return "High"
	case score >= 40:
		return "Medium"
	case score > 0:
		return "Low"
	default:
		return "Minimal"
	}
}
