package service

import (
	"context"
	"fmt"
	"time"

	"github.com/vara/backend/internal/domain/scoring"
	"github.com/vara/backend/internal/repository/postgres"
)

// AttackPathService는 공격 경로 범위(Attack Path Scope)를 평가합니다.
//
// Phase 1 알고리즘:
//   1. 각 cluster_* 테이블의 최신 snapshot 독립적으로 조회
//   2. 모든 Pod에 대해 3개 항목 평가
//      a. RBAC:    Pod의 SA → RoleBinding/ClusterRoleBinding → Role/ClusterRole.rules
//      b. Network: 같은 namespace의 NetworkPolicy 중 podSelector 매칭
//      c. Mount:   Pod의 hostNetwork/hostPath/privileged/secret/configmap 카운트
//   3. 항목별 점수 합산 (0~100)
//   4. 결과 영속화
type AttackPathService struct {
	repo *postgres.AttackPathRepo
}

// NewAttackPathService는 AttackPathService를 생성합니다.
func NewAttackPathService(repo *postgres.AttackPathRepo) *AttackPathService {
	return &AttackPathService{repo: repo}
}

// ComputeForCluster는 클러스터의 모든 Pod에 대해 공격 경로 범위를 계산합니다.
func (s *AttackPathService) ComputeForCluster(ctx context.Context, clusterName string) (*scoring.AttackPathComputeResponse, error) {
	if clusterName == "" {
		return nil, fmt.Errorf("cluster_name is required")
	}

	// 1. 각 테이블의 최신 snapshot 조회 (독립적)
	podsSnapshot, err := s.repo.GetLatestPodsSnapshot(ctx, clusterName)
	if err != nil {
		return nil, fmt.Errorf("find pods snapshot: %w", err)
	}
	crbSnapshot, _ := s.repo.GetLatestClusterRoleBindingsSnapshot(ctx, clusterName)
	rbSnapshot, _ := s.repo.GetLatestRoleBindingsSnapshot(ctx, clusterName)
	crSnapshot, _ := s.repo.GetLatestClusterRolesSnapshot(ctx, clusterName)
	rSnapshot, _ := s.repo.GetLatestRolesSnapshot(ctx, clusterName)
	npSnapshot, _ := s.repo.GetLatestNetworkPoliciesSnapshot(ctx, clusterName)

	fmt.Printf("info: attack-path snapshots cluster=%s pods=%s crb=%s rb=%s cr=%s r=%s np=%s\n",
		clusterName, podsSnapshot, crbSnapshot, rbSnapshot, crSnapshot, rSnapshot, npSnapshot)

	// 2. Pod 목록 로드
	pods, err := s.repo.ListPodsForAttackPath(ctx, clusterName, podsSnapshot)
	if err != nil {
		return nil, fmt.Errorf("load pods: %w", err)
	}

	fmt.Printf("info: attack-path computing for %d pods\n", len(pods))

	// 3. 각 Pod 평가
	results := make([]scoring.AttackPathResult, 0, len(pods))
	now := time.Now()
	high, medium, low := 0, 0, 0

	for _, pod := range pods {
		result := s.evaluatePod(ctx, pod, clusterName,
			crbSnapshot, rbSnapshot, crSnapshot, rSnapshot, npSnapshot,
			podsSnapshot, now)

		// 등급 분류
		switch {
		case result.TotalScore >= 70:
			high++
		case result.TotalScore >= 40:
			medium++
		case result.TotalScore > 0:
			low++
		}

		results = append(results, result)
	}

	// 4. 저장
	if err := s.repo.UpsertBatch(ctx, results); err != nil {
		return nil, fmt.Errorf("save results: %w", err)
	}

	return &scoring.AttackPathComputeResponse{
		ClusterName: clusterName,
		SnapshotAt:  podsSnapshot,
		Computed:    len(results),
		HighRisk:    high,
		MediumRisk:  medium,
		LowRisk:     low,
		Details:     results,
	}, nil
}

// GetByPodUID는 단일 Pod의 결과를 조회합니다.
func (s *AttackPathService) GetByPodUID(ctx context.Context, clusterName, podUID string) (*scoring.AttackPathResult, error) {
	return s.repo.GetByPodUID(ctx, clusterName, podUID)
}

// ListByCluster는 클러스터 결과를 모두 반환합니다.
func (s *AttackPathService) ListByCluster(ctx context.Context, clusterName string) ([]scoring.AttackPathResult, error) {
	return s.repo.ListByCluster(ctx, clusterName)
}

// ─────────────────────────────────────────
// 내부 평가 로직
// ─────────────────────────────────────────

// evaluatePod는 단일 Pod에 대해 3개 항목을 평가합니다.
func (s *AttackPathService) evaluatePod(
	ctx context.Context,
	pod postgres.PodForAttackPath,
	clusterName string,
	crbSnapshot, rbSnapshot, crSnapshot, rSnapshot, npSnapshot time.Time,
	podsSnapshot time.Time,
	now time.Time,
) scoring.AttackPathResult {

	result := scoring.AttackPathResult{
		ClusterName:  clusterName,
		PodUID:       pod.PodUID,
		PodName:      pod.Name,
		PodNamespace: pod.Namespace,
		SnapshotAt:   podsSnapshot,
		ComputedAt:   now,
	}

	// 1. RBAC 평가
	rbacScore, rbacDetails := s.evaluateRBAC(ctx, pod, clusterName,
		crbSnapshot, rbSnapshot, crSnapshot, rSnapshot)
	result.RBACScore = rbacScore
	result.RBACDetails = rbacDetails

	// 2. NetworkPolicy 평가
	netScore, netDetails := s.evaluateNetwork(ctx, pod, clusterName, npSnapshot)
	result.NetworkScore = netScore
	result.NetworkDetails = netDetails

	// 3. Mount 평가
	mountScore, mountDetails := s.evaluateMounts(pod)
	result.MountScore = mountScore
	result.MountDetails = mountDetails

	// 4. 합산
	result.TotalScore = result.RBACScore + result.NetworkScore + result.MountScore

	return result
}

// evaluateRBAC는 Pod의 SA → Role/ClusterRole 권한을 평가합니다.
func (s *AttackPathService) evaluateRBAC(
	ctx context.Context,
	pod postgres.PodForAttackPath,
	clusterName string,
	crbSnapshot, rbSnapshot, crSnapshot, rSnapshot time.Time,
) (int, scoring.RBACDetails) {

	details := scoring.RBACDetails{
		ServiceAccount: pod.ServiceAccount,
		Level:          scoring.RBACLevelNone,
	}

	saName := pod.ServiceAccount
	if saName == "" {
		saName = "default" // K8s 기본 SA
	}

	// 1. ClusterRoleBinding (cluster-wide)
	crbMatches, err := s.repo.ListClusterRoleBindingsForSA(
		ctx, clusterName, pod.Namespace, saName, crbSnapshot, crSnapshot)
	if err != nil {
		fmt.Printf("warn: list crb for sa %s/%s failed: %v\n", pod.Namespace, saName, err)
	}

	// 2. RoleBinding (namespace 한정)
	rbMatches, err := s.repo.ListRoleBindingsForSA(
		ctx, clusterName, pod.Namespace, saName, rbSnapshot, rSnapshot, crSnapshot)
	if err != nil {
		fmt.Printf("warn: list rb for sa %s/%s failed: %v\n", pod.Namespace, saName, err)
	}

	allMatches := append(crbMatches, rbMatches...)
	if len(allMatches) == 0 {
		// 권한 없음
		return 0, details
	}

	// 각 매칭에서 위험 신호 추출
	for _, m := range allMatches {
		details.MatchedBindings = append(details.MatchedBindings, m.BindingName)
		details.MatchedRoles = append(details.MatchedRoles, m.RoleName)

		// cluster-admin 검사
		if isClusterAdminBinding(m.RoleName) {
			details.IsClusterAdmin = true
		}

		// rules 분석
		for _, rule := range m.RoleRules {
			if hasWildcard(rule) {
				details.HasWildcard = true
			}
			if hasSecretsAccess(rule) {
				details.HasSecretsAccess = true
			}
			if hasPodExec(rule) {
				details.HasPodExec = true
			}
		}
	}

	// 가장 위험한 레벨로 결정
	switch {
	case details.IsClusterAdmin:
		details.Level = scoring.RBACLevelClusterAdmin
	case details.HasWildcard:
		details.Level = scoring.RBACLevelWildcard
	case details.HasSecretsAccess:
		details.Level = scoring.RBACLevelSecretsAccess
	case details.HasPodExec:
		details.Level = scoring.RBACLevelPodExec
	default:
		// 일반 read 권한 (binding은 있지만 위 위험 신호 없음)
		details.Level = scoring.RBACLevelReadOnly
	}

	return scoring.ComputeRBACScore(details.Level), details
}

// isClusterAdminBinding은 role 이름이 cluster-admin인지 확인합니다.
func isClusterAdminBinding(roleName string) bool {
	return roleName == "cluster-admin"
}

// hasWildcard는 rule에 wildcard verb 또는 resource가 있는지 확인합니다.
func hasWildcard(rule postgres.RoleRule) bool {
	for _, v := range rule.Verbs {
		if v == "*" {
			return true
		}
	}
	for _, r := range rule.Resources {
		if r == "*" {
			return true
		}
	}
	return false
}

// hasSecretsAccess는 rule이 secrets에 대한 get/list/watch 권한을 주는지 확인합니다.
func hasSecretsAccess(rule postgres.RoleRule) bool {
	// resources에 secrets 또는 *가 있는지
	hasSecrets := false
	for _, r := range rule.Resources {
		if r == "secrets" || r == "*" {
			hasSecrets = true
			break
		}
	}
	if !hasSecrets {
		return false
	}

	// verbs에 get/list/watch/* 중 하나라도 있는지
	for _, v := range rule.Verbs {
		if v == "get" || v == "list" || v == "watch" || v == "*" {
			return true
		}
	}
	return false
}

// hasPodExec는 rule이 pod exec/portforward/create 권한을 주는지 확인합니다.
func hasPodExec(rule postgres.RoleRule) bool {
	for _, r := range rule.Resources {
		// pods/exec, pods/portforward, pods/attach 등
		if r == "pods/exec" || r == "pods/portforward" || r == "pods/attach" {
			return true
		}
		// pods + create 권한도 위험 (악성 Pod 생성)
		if r == "pods" || r == "*" {
			for _, v := range rule.Verbs {
				if v == "create" || v == "*" {
					return true
				}
			}
		}
	}
	return false
}

// evaluateNetwork는 NetworkPolicy 격리 수준을 평가합니다.
func (s *AttackPathService) evaluateNetwork(
	ctx context.Context,
	pod postgres.PodForAttackPath,
	clusterName string,
	npSnapshot time.Time,
) (int, scoring.NetworkDetails) {

	details := scoring.NetworkDetails{
		Isolation: scoring.NetworkIsolationNone,
	}

	// NetworkPolicy snapshot 없거나 데이터 없는 경우
	if npSnapshot.IsZero() {
		return scoring.ComputeNetworkScore(scoring.NetworkIsolationNone), details
	}

	policies, err := s.repo.ListNetworkPoliciesForPod(ctx, clusterName, pod.Namespace, pod.Labels, npSnapshot)
	if err != nil {
		fmt.Printf("warn: list netpol for pod %s failed: %v\n", pod.PodUID, err)
		return scoring.ComputeNetworkScore(scoring.NetworkIsolationNone), details
	}

	if len(policies) == 0 {
		// 매칭되는 NetworkPolicy 없음 = 격리 안 됨
		return scoring.ComputeNetworkScore(scoring.NetworkIsolationNone), details
	}

	// 매칭된 정책들의 policyTypes 분석
	hasIngress := false
	hasEgress := false
	for _, p := range policies {
		details.MatchedPolicies = append(details.MatchedPolicies, p.Name)
		for _, t := range p.PolicyTypes {
			if t == "Ingress" {
				hasIngress = true
			}
			if t == "Egress" {
				hasEgress = true
			}
		}
	}
	details.HasIngressRules = hasIngress
	details.HasEgressRules = hasEgress

	// 격리 레벨 결정
	switch {
	case hasIngress && hasEgress:
		// 둘 다 제한 — default-deny와 둘 다 제한의 구분은 rules 내용 봐야 함
		// 일단 "둘 다"로 처리 (Phase 1 단순화)
		details.Isolation = scoring.NetworkIsolationBoth
	case hasEgress:
		details.Isolation = scoring.NetworkIsolationEgressOnly
	case hasIngress:
		// ingress만 제한도 의미 있는 격리지만, egress가 더 위험 신호라
		// 일단 egress_only와 비슷하게 처리 (Phase 1 단순화)
		details.Isolation = scoring.NetworkIsolationEgressOnly
	default:
		details.Isolation = scoring.NetworkIsolationNone
	}

	return scoring.ComputeNetworkScore(details.Isolation), details
}

// evaluateMounts는 Pod의 마운트 위험도를 평가합니다.
func (s *AttackPathService) evaluateMounts(pod postgres.PodForAttackPath) (int, scoring.MountDetails) {
	details := scoring.MountDetails{
		HostNetwork: pod.HostNetwork,
		HostPID:     pod.HostPID,
		HostIPC:     pod.HostIPC,
	}

	// 컨테이너의 privileged 검사
	for _, c := range pod.Containers {
		if c.Privileged {
			details.HasPrivileged = true
			break
		}
	}

	// 볼륨 타입별 카운트
	for _, v := range pod.Volumes {
		switch v.Type {
		case "hostPath":
			details.HasHostPath = true
		case "secret":
			details.SecretMounts++
		case "configMap":
			details.ConfigMapMounts++
		}
	}

	return scoring.ComputeMountScore(details), details
}
