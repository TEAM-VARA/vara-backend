package service

import (
	"context"
	"fmt"
	"time"

	"github.com/vara/backend/internal/repository/postgres"
)

// ────────────────────────────────────────────────────
// RBAC Rules 수집 — overgrant 분석용
//
// evaluateRBAC과 같은 데이터를 가져오지만, 점수 계산 없이
// rules와 binding 개수만 반환.
// AttackPathService에 메서드로 추가.
// ────────────────────────────────────────────────────

// collectRBACRulesForPod — Pod의 모든 RBAC rules + binding 개수 수집
//
// 사용처:
//   enrichAttackPathWithRuntime에서 overgrant 분석에 전달
func (s *AttackPathService) collectRBACRulesForPod(
	ctx context.Context,
	pod postgres.PodForAttackPath,
	clusterName string,
	crbSnapshot, rbSnapshot, crSnapshot, rSnapshot time.Time,
) ([]postgres.RoleRule, int) {
	saName := pod.ServiceAccount
	if saName == "" {
		saName = "default"
	}

	crbMatches, err := s.repo.ListClusterRoleBindingsForSA(
		ctx, clusterName, pod.Namespace, saName, crbSnapshot, crSnapshot)
	if err != nil {
		fmt.Printf("warn: collect crb for sa %s/%s: %v\n", pod.Namespace, saName, err)
	}

	rbMatches, err := s.repo.ListRoleBindingsForSA(
		ctx, clusterName, pod.Namespace, saName, rbSnapshot, rSnapshot, crSnapshot)
	if err != nil {
		fmt.Printf("warn: collect rb for sa %s/%s: %v\n", pod.Namespace, saName, err)
	}

	allMatches := append(crbMatches, rbMatches...)
	if len(allMatches) == 0 {
		return nil, 0
	}

	allRules := []postgres.RoleRule{}
	for _, m := range allMatches {
		allRules = append(allRules, m.RoleRules...)
	}

	return allRules, len(allMatches)
}

// collectAllRBACRules — 모든 Pod의 RBAC rules 일괄 수집
//
// 사용처:
//   ComputeForCluster에서 enrich 호출 직전
//
// 반환:
//   rulesByPod:        pod_uid → []RoleRule
//   bindingCountByPod: pod_uid → binding 개수
func (s *AttackPathService) collectAllRBACRules(
	ctx context.Context,
	pods []postgres.PodForAttackPath,
	clusterName string,
	crbSnapshot, rbSnapshot, crSnapshot, rSnapshot time.Time,
) (map[string][]postgres.RoleRule, map[string]int) {
	rulesByPod := make(map[string][]postgres.RoleRule, len(pods))
	bindingCountByPod := make(map[string]int, len(pods))

	for _, pod := range pods {
		rules, bindingCount := s.collectRBACRulesForPod(
			ctx, pod, clusterName, crbSnapshot, rbSnapshot, crSnapshot, rSnapshot,
		)
		if len(rules) > 0 {
			rulesByPod[pod.PodUID] = rules
			bindingCountByPod[pod.PodUID] = bindingCount
		}
	}

	return rulesByPod, bindingCountByPod
}
