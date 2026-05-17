package service

import (
	"context"
	"fmt"
	"time"

	"github.com/vara/backend/internal/domain/scoring"
	"github.com/vara/backend/internal/repository/postgres"
)

// ExposureService는 인터넷 노출 여부를 판단하는 비즈니스 로직을 담당합니다.
//
// Phase 1 판단 알고리즘:
//   1. 클러스터의 최신 snapshot 가져오기
//   2. 모든 Pod에 대해:
//      a. 같은 namespace의 Service 중 selector ⊆ pod.labels인 것 찾기
//      b. 매칭된 Service.type이 LoadBalancer/NodePort면 → 노출
//      c. 매칭된 Service가 어떤 Ingress의 backend면 → 노출
//      d. 둘 다 아니면 → 비노출
//   3. 결과를 exposure_scores에 저장
//
// Phase 2 이후 추가될 항목:
//   - AWS Security Group의 0.0.0.0/0 허용 여부
//   - NetworkPolicy로 차단되는 경우 점수 감점
//   - eBPF network_flows의 실제 외부 연결 발견
type ExposureService struct {
	repo *postgres.ExposureRepo
}

// NewExposureService는 ExposureService를 생성합니다.
func NewExposureService(repo *postgres.ExposureRepo) *ExposureService {
	return &ExposureService{repo: repo}
}

// ComputeForCluster는 클러스터 전체에 대해 노출도를 계산하고 저장합니다.
//
// 동작:
//   1. 최신 snapshot 찾기
//   2. Pod / Service / Ingress 로드
//   3. 각 Pod에 대해 판정 수행
//   4. 결과를 DB에 일괄 저장
//   5. 요약 응답 반환
func (s *ExposureService) ComputeForCluster(ctx context.Context, clusterName string) (*scoring.ComputeResponse, error) {
	if clusterName == "" {
		return nil, fmt.Errorf("cluster_name is required")
	}

	// 1. 최신 snapshot 찾기
	snapshotAt, err := s.repo.GetLatestSnapshotAt(ctx, clusterName)
	if err != nil {
		return nil, fmt.Errorf("find latest snapshot: %w", err)
	}

	// 2. 데이터 로드 (Pod, Service, Ingress)
	pods, err := s.repo.ListPodsAtSnapshot(ctx, clusterName, snapshotAt)
	if err != nil {
		return nil, fmt.Errorf("load pods: %w", err)
	}

	services, err := s.repo.ListServicesAtSnapshot(ctx, clusterName, snapshotAt)
	if err != nil {
		return nil, fmt.Errorf("load services: %w", err)
	}

	ingressBackends, err := s.repo.ListIngressBackendsAtSnapshot(ctx, clusterName, snapshotAt)
	if err != nil {
		return nil, fmt.Errorf("load ingresses: %w", err)
	}

	// 3. Service ↔ Ingress 인덱스 미리 만들기 (성능)
	// key: (namespace, service_name) → []IngressSnapshot
	ingressIndex := buildIngressIndex(ingressBackends)

	// 4. 각 Pod 판정
	results := make([]scoring.ExposureResult, 0, len(pods))
	exposedCount := 0
	now := time.Now()

	for _, pod := range pods {
		result := s.evaluatePod(pod, services, ingressIndex, clusterName, snapshotAt, now)
		if result.Exposed {
			exposedCount++
		}
		results = append(results, result)
	}

	// 5. DB 저장
	if err := s.repo.UpsertExposureBatch(ctx, results); err != nil {
		return nil, fmt.Errorf("save results: %w", err)
	}

	// 6. 응답 구성
	return &scoring.ComputeResponse{
		ClusterName: clusterName,
		SnapshotAt:  snapshotAt,
		Computed:    len(results),
		Exposed:     exposedCount,
		NotExposed:  len(results) - exposedCount,
		Details:     results,
	}, nil
}

// GetByPodUID는 단일 Pod의 최근 결과를 조회합니다.
func (s *ExposureService) GetByPodUID(ctx context.Context, clusterName, podUID string) (*scoring.ExposureResult, error) {
	return s.repo.GetByPodUID(ctx, clusterName, podUID)
}

// ListByCluster는 클러스터 최신 결과를 모두 반환합니다.
func (s *ExposureService) ListByCluster(ctx context.Context, clusterName string) ([]scoring.ExposureResult, error) {
	return s.repo.ListByCluster(ctx, clusterName)
}

// ─────────────────────────────────────────
// 내부 로직 (판정 알고리즘)
// ─────────────────────────────────────────

// evaluatePod는 단일 Pod에 대해 노출 여부를 판정합니다.
//
// 평가 순서:
//   1. 모든 Service에 대해 selector 매칭 시도 (같은 namespace)
//   2. 매칭된 Service들 중 LoadBalancer/NodePort 있는지 → 외부 노출
//   3. 매칭된 Service가 Ingress backend인지 → Ingress 노출
//   4. 결과 종합
func (s *ExposureService) evaluatePod(
	pod postgres.PodSnapshot,
	services []postgres.ServiceSnapshot,
	ingressIndex map[string][]postgres.IngressSnapshot,
	clusterName string,
	snapshotAt time.Time,
	now time.Time,
) scoring.ExposureResult {

	result := scoring.ExposureResult{
		ClusterName:      clusterName,
		PodUID:           pod.PodUID,
		PodName:          pod.Name,
		PodNamespace:     pod.Namespace,
		MatchedServices:  []scoring.MatchedService{},
		MatchedIngresses: []scoring.MatchedIngress{},
		SnapshotAt:       snapshotAt,
		ComputedAt:       now,
	}

	exposed := false

	// 1. Service selector 매칭 (같은 namespace 내에서만)
	for _, svc := range services {
		if svc.Namespace != pod.Namespace {
			continue
		}
		if !scoring.SelectorMatches(scoring.PodLabels(pod.Labels), scoring.ServiceSelector(svc.Selector)) {
			continue
		}

		// 매칭됨
		externallyExposed := scoring.IsExternallyExposedServiceType(svc.Type)
		result.MatchedServices = append(result.MatchedServices, scoring.MatchedService{
			Name:              svc.Name,
			Namespace:         svc.Namespace,
			Type:              svc.Type,
			ExternallyExposed: externallyExposed,
		})

		// LoadBalancer/NodePort 만나면 외부 노출
		if externallyExposed {
			exposed = true
		}

		// 2. 이 Service가 Ingress backend로 사용되는지 확인
		key := ingressKey(svc.Namespace, svc.Name)
		if ingresses, ok := ingressIndex[key]; ok {
			for _, ig := range ingresses {
				result.MatchedIngresses = append(result.MatchedIngresses, scoring.MatchedIngress{
					Name:           ig.Name,
					Namespace:      ig.Namespace,
					ViaServiceName: svc.Name,
					Host:           ig.Host,
				})
				exposed = true // Ingress 노출도 외부 노출로 간주
			}
		}
	}

	// 3. 점수 산정
	result.Exposed = exposed
	if exposed {
		result.Score = scoring.ExposureScoreExposed
	} else {
		result.Score = scoring.ExposureScoreNotExposed
	}

	return result
}

// buildIngressIndex는 Ingress backend를 (namespace, service_name) 키로 색인합니다.
// 같은 Service가 여러 Ingress에서 참조될 수 있으므로 슬라이스 값.
func buildIngressIndex(backends []postgres.IngressSnapshot) map[string][]postgres.IngressSnapshot {
	idx := make(map[string][]postgres.IngressSnapshot)
	for _, b := range backends {
		key := ingressKey(b.Namespace, b.ServiceName)
		idx[key] = append(idx[key], b)
	}
	return idx
}

func ingressKey(namespace, serviceName string) string {
	return namespace + "/" + serviceName
}
