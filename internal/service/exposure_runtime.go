package service

import (
	"context"
	"fmt"

	"github.com/vara/backend/internal/domain/scoring"
	"github.com/vara/backend/internal/repository/postgres"
)

// ────────────────────────────────────────────────────
// Exposure Runtime 보강
//
// 기존 ComputeForCluster()의 결과(results)에
// eBPF network_flows 기반 동적 검증을 추가한다.
// ────────────────────────────────────────────────────

// enrichExposureWithRuntime — exposure 결과에 runtime 검증 추가
// results를 in-place 수정.
func (s *ExposureService) enrichExposureWithRuntime(
	ctx context.Context,
	clusterName string,
	pods []postgres.PodSnapshot,
	results []scoring.ExposureResult,
) {
	hasData, err := s.ebpfRepo.HasAnyEbpfData(ctx, clusterName, s.config.WindowHours)
	if err != nil {
		fmt.Printf("warn: check ebpf data: %v\n", err)
		return
	}
	if !hasData {
		// 데이터 없음 — 모든 결과에 data_available=false 표시
		for i := range results {
			results[i].RuntimeDetails = &scoring.RuntimeExposureDetails{
				WindowHours:   s.config.WindowHours,
				DataAvailable: false,
			}
			zero := 0
			results[i].RuntimeExternalTrafficCount = &zero
		}
		return
	}

	// exposed=true인 Pod들의 pod_ip 수집
	exposedPodIPs := []string{}
	ipToResultIdx := make(map[string]int)

	for i, res := range results {
		if !res.Exposed {
			continue
		}
		var podIP string
		for _, p := range pods {
			if p.PodUID == res.PodUID && p.PodIP != "" {
				podIP = p.PodIP
				break
			}
		}
		if podIP == "" {
			continue
		}
		exposedPodIPs = append(exposedPodIPs, podIP)
		ipToResultIdx[podIP] = i
	}

	if len(exposedPodIPs) == 0 {
		return
	}

	inboundMap, err := s.ebpfRepo.BatchGetInboundFlows(ctx, clusterName, exposedPodIPs, s.config.WindowHours)
	if err != nil {
		fmt.Printf("warn: batch inbound flows: %v\n", err)
		return
	}

	for podIP, agg := range inboundMap {
		idx, ok := ipToResultIdx[podIP]
		if !ok {
			continue
		}

		externalIPs := []string{}
		internalIPs := []string{}
		for _, srcIP := range agg.ExternalSourceIPs {
			if scoring.IsInternalIP(srcIP) {
				internalIPs = append(internalIPs, srcIP)
			} else {
				externalIPs = append(externalIPs, srcIP)
			}
		}

		actuallyAccessed := len(externalIPs) > 0
		extCount := len(externalIPs)

		results[idx].RuntimeActuallyAccessed = &actuallyAccessed
		results[idx].RuntimeExternalTrafficCount = &extCount
		results[idx].RuntimeDetails = &scoring.RuntimeExposureDetails{
			ExternalSourceIPs:   externalIPs,
			InternalSourceIPs:   internalIPs,
			FirstExternalAccess: agg.FirstAccess,
			LastExternalAccess:  agg.LastAccess,
			WindowHours:         s.config.WindowHours,
			DataAvailable:       true,
		}
	}
}
