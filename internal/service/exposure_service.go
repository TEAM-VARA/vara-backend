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
//  1. 각 테이블(pods/services/ingresses)의 최신 snapshot 독립적으로 조회
//  2. 모든 Pod에 대해:
//     a. 같은 namespace의 Service 중 selector ⊆ pod.labels인 것 찾기
//     b. 매칭된 Service.type이 LoadBalancer/NodePort면 → 노출
//     c. 매칭된 Service가 어떤 Ingress의 backend면 → 노출
//     d. 둘 다 아니면 → 비노출
//  3. 결과를 exposure_scores에 저장
//
// 시점 정책:
//   - 각 리소스(Pod/Service/Ingress)는 cluster-agent에서 독립된 주기로 수집됨
//   - 각각의 최신 snapshot을 사용하는 게 K8s 의미론에 맞음
//     (Pod와 Service의 매칭은 "현재 상태"의 비교)
//   - 저장 시 snapshot_at은 Pod 기준 사용 (Pod가 평가 단위이므로)
type ExposureService struct {
	repo *postgres.ExposureRepo
}

// NewExposureService는 ExposureService를 생성합니다.
func NewExposureService(repo *postgres.ExposureRepo) *ExposureService {
	return &ExposureService{repo: repo}
}

// ComputeForCluster는 클러스터 전체에 대해 노출도를 계산하고 저장합니다.
func (s *ExposureService) ComputeForCluster(ctx context.Context, clusterName string) (*scoring.ComputeResponse, error) {
	if clusterName == "" {
		return nil, fmt.Errorf("cluster_name is required")
	}

	// 1. 각 테이블의 최신 snapshot 독립적으로 찾기
	podsSnapshot, err := s.repo.GetLatestPodsSnapshot(ctx, clusterName)
	if err != nil {
		return nil, fmt.Errorf("find latest pods snapshot: %w", err)
	}

	servicesSnapshot, err := s.repo.GetLatestServicesSnapshot(ctx, clusterName)
	if err != nil {
		return nil, fmt.Errorf("find latest services snapshot: %w", err)
	}

	ingressesSnapshot, err := s.repo.GetLatestIngressesSnapshot(ctx, clusterName)
	if err != nil {
		return nil, fmt.Errorf("find latest ingresses snapshot: %w", err)
	}

	// 디버그 로그
	fmt.Printf("info: exposure compute cluster=%s pods_snapshot=%s services_snapshot=%s ingresses_snapshot=%s\n",
		clusterName, podsSnapshot, servicesSnapshot, ingressesSnapshot)

	// 2. 각 snapshot 데이터 로드
	pods, err := s.repo.ListPodsAtSnapshot(ctx, clusterName, podsSnapshot)
	if err != nil {
		return nil, fmt.Errorf("load pods: %w", err)
	}

	services, err := s.repo.ListServicesAtSnapshot(ctx, clusterName, servicesSnapshot)
	if err != nil {
		return nil, fmt.Errorf("load services: %w", err)
	}

	ingressBackends, err := s.repo.ListIngressBackendsAtSnapshot(ctx, clusterName, ingressesSnapshot)
	if err != nil {
		return nil, fmt.Errorf("load ingresses: %w", err)
	}

	fmt.Printf("info: exposure compute loaded pods=%d services=%d ingress_backends=%d\n",
		len(pods), len(services), len(ingressBackends))

	// 3. Service ↔ Ingress 인덱스 미리 만들기 (성능)
	ingressIndex := buildIngressIndex(ingressBackends)

	// 4. 각 Pod 판정
	results := make([]scoring.ExposureResult, 0, len(pods))
	exposedCount := 0
	now := time.Now()

	for _, pod := range pods {
		result := s.evaluatePod(pod, services, ingressIndex, clusterName, podsSnapshot, now)
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
		SnapshotAt:  podsSnapshot,
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
// 내부 로직
// ─────────────────────────────────────────

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

	for _, svc := range services {
		if svc.Namespace != pod.Namespace {
			continue
		}
		if !scoring.SelectorMatches(scoring.PodLabels(pod.Labels), scoring.ServiceSelector(svc.Selector)) {
			continue
		}

		externallyExposed := scoring.IsExternallyExposedServiceType(svc.Type)
		result.MatchedServices = append(result.MatchedServices, scoring.MatchedService{
			Name:              svc.Name,
			Namespace:         svc.Namespace,
			Type:              svc.Type,
			ExternallyExposed: externallyExposed,
		})

		if externallyExposed {
			exposed = true
		}

		key := ingressKey(svc.Namespace, svc.Name)
		if ingresses, ok := ingressIndex[key]; ok {
			for _, ig := range ingresses {
				result.MatchedIngresses = append(result.MatchedIngresses, scoring.MatchedIngress{
					Name:           ig.Name,
					Namespace:      ig.Namespace,
					ViaServiceName: svc.Name,
					Host:           ig.Host,
				})
				exposed = true
			}
		}
	}

	result.Exposed = exposed
	if exposed {
		result.Score = scoring.ExposureScoreExposed
	} else {
		result.Score = scoring.ExposureScoreNotExposed
	}

	return result
}

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
