// GRC 보조: Cluster Reader / eBPF / CI 파이프라인이 보낸 K8s 데이터를 수신·저장하는 서비스.
// GRC Finding 평가와 PodGraph 평가에 필요한 클러스터 자산 데이터를 제공하는 데이터 수집 계층이다.
package service

import (
	"context"

	"github.com/vara/backend/internal/domain/agent"
	"github.com/vara/backend/internal/repository/postgres"
)

// AgentService : Cluster Reader / eBPF / CI 파이프라인이 보낸 데이터 처리
type AgentService struct {
	repo *postgres.AgentRepo
}

func NewAgentService(repo *postgres.AgentRepo) *AgentService {
	return &AgentService{repo: repo}
}

// PodIngestResult : Pod 이벤트 처리 결과
type PodIngestResult struct {
	Received int `json:"received"`
	Added    int `json:"added"`
	Deleted  int `json:"deleted"`
	Failed   int `json:"failed"`
}

// IngestPodEvents : Pod 이벤트 batch 처리
func (s *AgentService) IngestPodEvents(ctx context.Context, batch agent.PodEventBatch) PodIngestResult {
	res := PodIngestResult{Received: len(batch.Events)}

	for _, e := range batch.Events {
		switch e.EventType {
		case "pod_added":
			if err := s.repo.UpsertPod(ctx, e); err != nil {
				res.Failed++
				continue
			}
			res.Added++
		case "pod_deleted":
			if err := s.repo.MarkPodDeleted(ctx, e.PodUID); err != nil {
				res.Failed++
				continue
			}
			res.Deleted++
		default:
			res.Failed++
		}
	}

	return res
}

// IngestSBOM : SBOM + CVE 등록
func (s *AgentService) IngestSBOM(ctx context.Context, req agent.SBOMRequest) (int, error) {
	return s.repo.UpsertSBOM(ctx, req)
}

// IngestTraffic : 트래픽 데이터 등록
func (s *AgentService) IngestTraffic(ctx context.Context, batch agent.TrafficBatch) (int, error) {
	return s.repo.InsertTraffic(ctx, batch.Events)
}
