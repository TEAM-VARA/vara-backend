package service

import (
	"context"
	"fmt"

	"github.com/vara/backend/internal/domain/scoring"
	"github.com/vara/backend/internal/repository/postgres"
)

// ────────────────────────────────────────────────────
// Attack Path Runtime 보강
//
// 세 가지 분석:
//   1. runtime_network_score: 실제 통신 그래프 기반 보정
//   2. uses_host_network:     cluster_nodes.internal_ip와 PodIP 매칭
//   3. overgrant_ratio:       RBAC rules 권한 과다부여 분석
// ────────────────────────────────────────────────────

// enrichAttackPathWithRuntime — attack_path 결과에 runtime 분석 추가
func (s *AttackPathService) enrichAttackPathWithRuntime(
	ctx context.Context,
	clusterName string,
	pods []postgres.PodForAttackPath,
	rbacRulesByPod map[string][]postgres.RoleRule,
	rbacBindingCountByPod map[string]int,
	results []scoring.AttackPathResult,
) {
	s.enrichHostNetwork(ctx, clusterName, pods, results)
	s.enrichOvergrant(rbacRulesByPod, rbacBindingCountByPod, results)
	s.enrichNetworkRuntime(ctx, clusterName, pods, results)
}

// enrichHostNetwork — cluster_nodes.internal_ip와 PodIP 비교로 host_network 추론
func (s *AttackPathService) enrichHostNetwork(
	ctx context.Context,
	clusterName string,
	pods []postgres.PodForAttackPath,
	results []scoring.AttackPathResult,
) {
	snapshot, err := s.clusterNodesRepo.GetLatestSnapshot(ctx, clusterName)
	if err != nil {
		fmt.Printf("info: no node data for host_network inference: %v\n", err)
		return
	}

	nodeIPSet, err := s.clusterNodesRepo.ListNodeIPSet(ctx, clusterName, snapshot)
	if err != nil {
		fmt.Printf("warn: get node IPs: %v\n", err)
		return
	}

	podIPByUID := make(map[string]string, len(pods))
	for _, p := range pods {
		podIPByUID[p.PodUID] = p.PodIP
	}

	for i := range results {
		podIP := podIPByUID[results[i].PodUID]
		if podIP == "" {
			continue
		}
		usesHost := nodeIPSet.Contains(podIP)
		results[i].UsesHostNetwork = &usesHost
	}
}

// enrichOvergrant — RBAC 과다부여 분석
func (s *AttackPathService) enrichOvergrant(
	rbacRulesByPod map[string][]postgres.RoleRule,
	rbacBindingCountByPod map[string]int,
	results []scoring.AttackPathResult,
) {
	for i := range results {
		podUID := results[i].PodUID
		rules, hasRules := rbacRulesByPod[podUID]
		if !hasRules || len(rules) == 0 {
			continue
		}
		bindingCount := rbacBindingCountByPod[podUID]

		overgrant, ratio := AnalyzeOvergrant(rules, bindingCount)
		results[i].OvergrantRatio = &ratio
		results[i].OvergrantedPermissions = overgrant
	}
}

// enrichNetworkRuntime — eBPF network_flows 기반 통신 분석
func (s *AttackPathService) enrichNetworkRuntime(
	ctx context.Context,
	clusterName string,
	pods []postgres.PodForAttackPath,
	results []scoring.AttackPathResult,
) {
	hasData, err := s.ebpfRepo.HasAnyEbpfData(ctx, clusterName, s.config.WindowHours)
	if err != nil {
		fmt.Printf("warn: check ebpf data: %v\n", err)
		return
	}
	if !hasData {
		for i := range results {
			results[i].RuntimeNetworkDetails = &scoring.RuntimeNetworkDetails{
				WindowHours:   s.config.WindowHours,
				DataAvailable: false,
			}
			score := results[i].NetworkScore
			results[i].RuntimeNetworkScore = &score
		}
		return
	}

	srcPodIDs := []string{}
	srcPodIDToResultIdx := make(map[string]int)

	for i, res := range results {
		srcPodID := MakeSrcPodID(res.PodNamespace, res.PodName)
		if MatchesExcludePattern(srcPodID, s.config.ExcludePodPatterns) {
			continue
		}
		srcPodIDs = append(srcPodIDs, srcPodID)
		srcPodIDToResultIdx[srcPodID] = i
	}

	if len(srcPodIDs) == 0 {
		return
	}

	flowMap, err := s.ebpfRepo.BatchGetOutboundFlows(ctx, clusterName, srcPodIDs, s.config.WindowHours)
	if err != nil {
		fmt.Printf("warn: batch outbound flows: %v\n", err)
		return
	}

	podIPIdx := BuildPodIPIndex(pods)

	for srcPodID, agg := range flowMap {
		idx, ok := srcPodIDToResultIdx[srcPodID]
		if !ok {
			continue
		}

		internalTargets := []string{}
		externalIPs := []string{}
		seenInternalUIDs := make(map[string]struct{})
		seenExternalIPs := make(map[string]struct{})

		for _, dstIP := range agg.ExternalDstIPs {
			if scoring.IsInternalIP(dstIP) {
				if entry, ok := podIPIdx.Get(dstIP); ok {
					if _, seen := seenInternalUIDs[entry.PodUID]; !seen {
						internalTargets = append(internalTargets, entry.PodUID)
						seenInternalUIDs[entry.PodUID] = struct{}{}
					}
				}
			} else {
				if _, seen := seenExternalIPs[dstIP]; !seen {
					externalIPs = append(externalIPs, dstIP)
					seenExternalIPs[dstIP] = struct{}{}
				}
			}
		}

		diversity := 0.0
		if agg.TotalFlowCount > 0 {
			uniqueDsts := len(internalTargets) + len(externalIPs)
			diversity = float64(uniqueDsts) / float64(agg.TotalFlowCount)
			if diversity > 1.0 {
				diversity = 1.0
			}
		}

		details := scoring.RuntimeNetworkDetails{
			ActualTargetsCount:   len(internalTargets),
			InternalTargets:      internalTargets,
			ExternalTargetsCount: len(externalIPs),
			ExternalIPs:          externalIPs,
			DiversityScore:       diversity,
			WindowHours:          s.config.WindowHours,
			FlowCount:            agg.TotalFlowCount,
			DataAvailable:        true,
		}

		factor := scoring.CalculateActivityFactor(details)
		staticScore := results[idx].NetworkScore
		runtimeScore := int(float64(staticScore) * factor)
		if runtimeScore > 100 {
			runtimeScore = 100
		}

		results[idx].RuntimeNetworkScore = &runtimeScore
		results[idx].RuntimeNetworkDetails = &details
	}
}
