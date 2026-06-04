package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/vara/backend/internal/repository/postgres"
	"github.com/vara/backend/internal/service"
)

// PodDetailHandler는 단일 Pod의 모든 정보를 통합 반환합니다.
//
//	GET /api/v1/compliance/pods/:pod_name/detail?company_id=&cluster_name=&namespace=
type PodDetailHandler struct {
	clusterReaderRepo *postgres.ClusterReaderRepo
	grcSvc            *service.GRCService
}

func NewPodDetailHandler(
	clusterReaderRepo *postgres.ClusterReaderRepo,
	grcSvc *service.GRCService,
) *PodDetailHandler {
	return &PodDetailHandler{
		clusterReaderRepo: clusterReaderRepo,
		grcSvc:            grcSvc,
	}
}

// PodDetailResponse는 단일 Pod의 모든 정보를 통합한 응답입니다.
type PodDetailResponse struct {
	// Pod 메타데이터
	PodName        string          `json:"pod_name"`
	PodUID         string          `json:"pod_uid"`
	Namespace      string          `json:"namespace"`
	ClusterName    string          `json:"cluster_name"`
	Node           string          `json:"node"`
	PodIP          string          `json:"pod_ip"`
	Phase          string          `json:"phase"`
	ServiceAccount string          `json:"service_account"`
	Labels         json.RawMessage `json:"labels"`
	HostNetwork    bool            `json:"host_network"`
	StartedAt      *time.Time      `json:"started_at"`
	FirstSeenAt    *time.Time      `json:"first_seen_at"`
	LastSeenAt     *time.Time      `json:"last_seen_at"`

	// Compliance
	Compliance *service.PodComplianceResult `json:"compliance"`
	Violations *service.PodViolationsResult `json:"violations"`
}

// GetPodDetail는 단일 Pod의 전체 정보를 한번에 반환합니다.
//
// GET /api/v1/compliance/pods/:pod_name/detail?company_id=&cluster_name=&namespace=
func (h *PodDetailHandler) GetPodDetail(c *gin.Context) {
	podName := c.Param("pod_name")
	if podName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "pod_name is required"})
		return
	}
	companyID := c.Query("company_id")
	if companyID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "company_id is required"})
		return
	}
	clusterName := c.Query("cluster_name")
	if clusterName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cluster_name is required"})
		return
	}
	namespace := c.Query("namespace")

	ctx := c.Request.Context()

	// 1. Pod 메타데이터 조회 (cluster_pods → pod_uid 확보)
	pod, err := h.clusterReaderRepo.GetPodByName(ctx, clusterName, namespace, podName)
	if err != nil {
		fmt.Printf("warn: pod detail - pod not found: %v\n", err)
		c.JSON(http.StatusNotFound, gin.H{
			"error": "pod not found",
			"hint":  "클러스터 스냅샷에 해당 Pod이 존재하지 않습니다",
		})
		return
	}

	resp := PodDetailResponse{
		PodName:        pod.Name,
		PodUID:         pod.PodUID,
		Namespace:      pod.Namespace,
		ClusterName:    clusterName,
		Node:           pod.Node,
		PodIP:          pod.PodIP,
		Phase:          pod.Phase,
		ServiceAccount: pod.ServiceAccount,
		Labels:         pod.Labels,
		HostNetwork:    pod.HostNetwork,
		StartedAt:      pod.StartedAt,
	}

	// 2. Pod Master 라이프사이클 (실패해도 skip)
	if master, err := h.clusterReaderRepo.GetPodMasterByName(ctx, clusterName, pod.PodUID); err == nil {
		resp.FirstSeenAt = &master.FirstSeenAt
		resp.LastSeenAt = &master.LastSeenAt
	}

	// 3. Compliance (R-rule + F-rule, 실패 시 null)
	if result, err := h.grcSvc.GetPodCompliance(ctx, companyID, clusterName, namespace, podName); err == nil {
		resp.Compliance = result
	}

	// 4. Violations (ISMS-P 항목별 위반, 실패 시 null)
	if result, err := h.grcSvc.GetPodViolations(ctx, companyID, clusterName, namespace, podName); err == nil {
		resp.Violations = result
	}

	c.JSON(http.StatusOK, resp)
}
