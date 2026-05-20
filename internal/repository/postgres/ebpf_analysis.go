package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ────────────────────────────────────────────────────
// Runtime Analysis 조회 함수 (Step 2)
//
// risk scoring 보강에 사용하는 eBPF 데이터 집계 쿼리들.
// 기존 EbpfRepo에 추가 — ebpf_repo.go에 이 함수들을 append 하거나
// 별도 파일 ebpf_analysis.go로 분리.
// ────────────────────────────────────────────────────

// NetworkFlowAggregate — 특정 src Pod의 통신 패턴 집계
type NetworkFlowAggregate struct {
	SrcPodID         string
	InternalDstIPs   []string // 내부 IP 통신 대상들 (unique)
	ExternalDstIPs   []string // 외부 IP 통신 대상들 (unique)
	TotalFlowCount   int
	SuccessFlowCount int
}

// GetOutboundFlowsBySrcPod — 특정 Pod에서 나간 통신 집계
//
// 사용처:
//   - network_score 보강 (attack_path)
//   - blast radius 분석
//
// 시간 윈도우 안의 모든 network_flows를 src_pod_id로 그룹핑하여
// 통신 대상 IP들을 unique하게 수집.
func (r *EbpfRepo) GetOutboundFlowsBySrcPod(
	ctx context.Context,
	clusterName string,
	srcPodID string,
	windowHours int,
) (*NetworkFlowAggregate, error) {
	since := time.Now().Add(-time.Duration(windowHours) * time.Hour)

	const q = `
		SELECT 
			dst_ip,
			COUNT(*) AS flow_count,
			COUNT(*) FILTER (WHERE success IS TRUE OR success IS NULL) AS success_count
		FROM ebpf_network_flows
		WHERE cluster_name = $1
		  AND src_pod_id = $2
		  AND timestamp >= $3
		GROUP BY dst_ip
	`

	rows, err := r.pg.Query(ctx, q, clusterName, srcPodID, since)
	if err != nil {
		return nil, fmt.Errorf("query outbound flows: %w", err)
	}
	defer rows.Close()

	agg := &NetworkFlowAggregate{
		SrcPodID:       srcPodID,
		InternalDstIPs: []string{},
		ExternalDstIPs: []string{},
	}

	for rows.Next() {
		var dstIP string
		var flowCount, successCount int
		if err := rows.Scan(&dstIP, &flowCount, &successCount); err != nil {
			return nil, fmt.Errorf("scan flow: %w", err)
		}

		agg.TotalFlowCount += flowCount
		agg.SuccessFlowCount += successCount

		// 내부/외부 IP 분류는 service 레이어에서 (domain의 IsInternalIP)
		// 여기선 모든 IP를 ExternalDstIPs로 일단 모으고
		// → service에서 IsInternalIP로 다시 분류
		// 실제로는 cluster_pods.pod_ip 매칭으로 internal pod_uid도 식별
		agg.ExternalDstIPs = append(agg.ExternalDstIPs, dstIP)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return agg, nil
}

// ExternalInboundAggregate — 외부에서 특정 Pod IP로 들어온 트래픽 집계
type ExternalInboundAggregate struct {
	DstIP             string
	ExternalSourceIPs []string
	InternalSourceIPs []string
	FirstAccess       *time.Time
	LastAccess        *time.Time
	TotalFlowCount    int
}

// GetExternalInboundFlows — 특정 Pod IP로 외부에서 들어온 트래픽 분석
//
// 사용처:
//   - exposure 검증 (실제로 외부에서 접근됐는지)
//
// dst_ip가 podIP인 모든 flow를 src_ip별로 집계.
// service 레이어에서 IsInternalIP로 내부/외부 분류.
func (r *EbpfRepo) GetExternalInboundFlows(
	ctx context.Context,
	clusterName string,
	dstIP string,
	windowHours int,
) (*ExternalInboundAggregate, error) {
	since := time.Now().Add(-time.Duration(windowHours) * time.Hour)

	const q = `
		SELECT 
			src_ip,
			MIN(timestamp) AS first_seen,
			MAX(timestamp) AS last_seen,
			COUNT(*) AS flow_count
		FROM ebpf_network_flows
		WHERE cluster_name = $1
		  AND dst_ip = $2
		  AND timestamp >= $3
		GROUP BY src_ip
	`

	rows, err := r.pg.Query(ctx, q, clusterName, dstIP, since)
	if err != nil {
		return nil, fmt.Errorf("query inbound flows: %w", err)
	}
	defer rows.Close()

	agg := &ExternalInboundAggregate{
		DstIP:             dstIP,
		ExternalSourceIPs: []string{},
		InternalSourceIPs: []string{},
	}

	for rows.Next() {
		var srcIP string
		var firstSeen, lastSeen time.Time
		var flowCount int
		if err := rows.Scan(&srcIP, &firstSeen, &lastSeen, &flowCount); err != nil {
			return nil, fmt.Errorf("scan inbound flow: %w", err)
		}

		agg.TotalFlowCount += flowCount

		// 외부 IP 분류는 service에서 (도메인의 IsInternalIP 사용)
		// 일단 모두 ExternalSourceIPs로 수집
		agg.ExternalSourceIPs = append(agg.ExternalSourceIPs, srcIP)

		if agg.FirstAccess == nil || firstSeen.Before(*agg.FirstAccess) {
			t := firstSeen
			agg.FirstAccess = &t
		}
		if agg.LastAccess == nil || lastSeen.After(*agg.LastAccess) {
			t := lastSeen
			agg.LastAccess = &t
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return agg, nil
}

// BatchGetOutboundFlows — 여러 Pod의 통신 한 번에 조회 (성능 최적화)
//
// 사용처:
//   - attack_path compute 시 모든 Pod의 통신을 일괄 조회
//
// 반환: src_pod_id → NetworkFlowAggregate
func (r *EbpfRepo) BatchGetOutboundFlows(
	ctx context.Context,
	clusterName string,
	srcPodIDs []string,
	windowHours int,
) (map[string]*NetworkFlowAggregate, error) {
	if len(srcPodIDs) == 0 {
		return map[string]*NetworkFlowAggregate{}, nil
	}

	since := time.Now().Add(-time.Duration(windowHours) * time.Hour)

	const q = `
		SELECT 
			src_pod_id,
			dst_ip,
			COUNT(*) AS flow_count
		FROM ebpf_network_flows
		WHERE cluster_name = $1
		  AND src_pod_id = ANY($2)
		  AND timestamp >= $3
		GROUP BY src_pod_id, dst_ip
	`

	rows, err := r.pg.Query(ctx, q, clusterName, srcPodIDs, since)
	if err != nil {
		return nil, fmt.Errorf("batch query: %w", err)
	}
	defer rows.Close()

	result := make(map[string]*NetworkFlowAggregate)

	for rows.Next() {
		var srcPodID, dstIP string
		var flowCount int
		if err := rows.Scan(&srcPodID, &dstIP, &flowCount); err != nil {
			return nil, fmt.Errorf("scan batch: %w", err)
		}

		agg, ok := result[srcPodID]
		if !ok {
			agg = &NetworkFlowAggregate{
				SrcPodID:       srcPodID,
				InternalDstIPs: []string{},
				ExternalDstIPs: []string{},
			}
			result[srcPodID] = agg
		}
		agg.TotalFlowCount += flowCount
		agg.ExternalDstIPs = append(agg.ExternalDstIPs, dstIP)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	// srcPodIDs에 있지만 데이터 없는 Pod도 빈 agg 채워둠 (호출자가 nil 체크 안 해도 됨)
	for _, podID := range srcPodIDs {
		if _, ok := result[podID]; !ok {
			result[podID] = &NetworkFlowAggregate{
				SrcPodID:       podID,
				InternalDstIPs: []string{},
				ExternalDstIPs: []string{},
			}
		}
	}

	return result, nil
}

// BatchGetInboundFlows — 여러 Pod IP의 inbound 트래픽 일괄 조회
//
// 사용처:
//   - exposure compute 시 모든 노출 Pod의 외부 접근 일괄 검증
//
// 반환: dst_ip → ExternalInboundAggregate
func (r *EbpfRepo) BatchGetInboundFlows(
	ctx context.Context,
	clusterName string,
	dstIPs []string,
	windowHours int,
) (map[string]*ExternalInboundAggregate, error) {
	if len(dstIPs) == 0 {
		return map[string]*ExternalInboundAggregate{}, nil
	}

	since := time.Now().Add(-time.Duration(windowHours) * time.Hour)

	const q = `
		SELECT 
			dst_ip,
			src_ip,
			MIN(timestamp) AS first_seen,
			MAX(timestamp) AS last_seen,
			COUNT(*) AS flow_count
		FROM ebpf_network_flows
		WHERE cluster_name = $1
		  AND dst_ip = ANY($2)
		  AND timestamp >= $3
		GROUP BY dst_ip, src_ip
	`

	rows, err := r.pg.Query(ctx, q, clusterName, dstIPs, since)
	if err != nil {
		return nil, fmt.Errorf("batch inbound: %w", err)
	}
	defer rows.Close()

	result := make(map[string]*ExternalInboundAggregate)

	for rows.Next() {
		var dstIP, srcIP string
		var firstSeen, lastSeen time.Time
		var flowCount int
		if err := rows.Scan(&dstIP, &srcIP, &firstSeen, &lastSeen, &flowCount); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}

		agg, ok := result[dstIP]
		if !ok {
			agg = &ExternalInboundAggregate{
				DstIP:             dstIP,
				ExternalSourceIPs: []string{},
				InternalSourceIPs: []string{},
			}
			result[dstIP] = agg
		}
		agg.TotalFlowCount += flowCount
		agg.ExternalSourceIPs = append(agg.ExternalSourceIPs, srcIP)

		if agg.FirstAccess == nil || firstSeen.Before(*agg.FirstAccess) {
			t := firstSeen
			agg.FirstAccess = &t
		}
		if agg.LastAccess == nil || lastSeen.After(*agg.LastAccess) {
			t := lastSeen
			agg.LastAccess = &t
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	// 빈 결과도 추가
	for _, ip := range dstIPs {
		if _, ok := result[ip]; !ok {
			result[ip] = &ExternalInboundAggregate{
				DstIP:             ip,
				ExternalSourceIPs: []string{},
				InternalSourceIPs: []string{},
			}
		}
	}

	return result, nil
}

// HasAnyEbpfData — eBPF 데이터가 클러스터에 있는지 확인
//
// 사용처:
//   - runtime 분석 스킵 여부 결정 (데이터 없으면 분석 안 함)
func (r *EbpfRepo) HasAnyEbpfData(ctx context.Context, clusterName string, windowHours int) (bool, error) {
	since := time.Now().Add(-time.Duration(windowHours) * time.Hour)

	const q = `
		SELECT EXISTS(
			SELECT 1 FROM ebpf_network_flows 
			WHERE cluster_name = $1 AND timestamp >= $2 
			LIMIT 1
		)
	`

	var has bool
	err := r.pg.QueryRow(ctx, q, clusterName, since).Scan(&has)
	if err != nil && err != pgx.ErrNoRows {
		return false, fmt.Errorf("check ebpf data: %w", err)
	}
	return has, nil
}
