package handler

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/vara/backend/internal/domain/scoring"
	"github.com/vara/backend/internal/service"
)

// PodRefreshHandler는 단일 Pod의 모든 Risk Scoring을 순차 실행합니다.
// 대시보드에서 Pod 클릭 시 5개 컴포넌트(Exposure, Attack Path, Local, Toxic, Final)를
// 한 번의 호출로 모두 재계산합니다.
type PodRefreshHandler struct {
	exposureSvc   *service.ExposureService
	attackPathSvc *service.AttackPathService
	localSvc      *service.LocalScoringService
	toxicSvc      *service.ToxicService
	finalSvc      *service.FinalScoringService
}

func NewPodRefreshHandler(
	exposureSvc *service.ExposureService,
	attackPathSvc *service.AttackPathService,
	localSvc *service.LocalScoringService,
	toxicSvc *service.ToxicService,
	finalSvc *service.FinalScoringService,
) *PodRefreshHandler {
	return &PodRefreshHandler{
		exposureSvc:   exposureSvc,
		attackPathSvc: attackPathSvc,
		localSvc:      localSvc,
		toxicSvc:      toxicSvc,
		finalSvc:      finalSvc,
	}
}

// PodRefreshResponse는 단일 Pod의 모든 점수를 한꺼번에 반환합니다.
type PodRefreshResponse struct {
	PodUID      string                    `json:"pod_uid"`
	ClusterName string                    `json:"cluster_name"`
	ComputedAt  time.Time                 `json:"computed_at"`
	DurationMs  int64                     `json:"duration_ms"`
	Exposure    *scoring.ExposureResult   `json:"exposure"`
	AttackPath  *scoring.AttackPathResult `json:"attack_path"`
	Local       *scoring.LocalScoreResult `json:"local"`
	Toxic       *scoring.ToxicResult      `json:"toxic"`
	Final       *scoring.FinalScoreResult `json:"final"`
}

// Refresh는 단일 Pod의 모든 Risk Scoring을 순차 실행합니다.
//
// POST /api/v1/scoring/pods/:pod_uid/refresh
// Body: {"cluster_name": "..."}
//
// 의존성 순서대로 실행: Exposure → Attack Path → Local → Toxic → Final
// 어느 단계라도 실패하면 500 + stage 표시 (부분 저장은 다음 호출 시 자기 치유).
func (h *PodRefreshHandler) Refresh(c *gin.Context) {
	podUID := c.Param("pod_uid")
	if podUID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "pod_uid is required"})
		return
	}

	var req scoring.ComputeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	start := time.Now()

	// 1. Exposure
	exposure, err := h.exposureSvc.ComputeForPod(ctx, req.ClusterName, podUID)
	if err != nil {
		fmt.Printf("warn: pod refresh failed at exposure: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"stage": "exposure", "error": err.Error()})
		return
	}

	// 2. Attack Path
	attackPath, err := h.attackPathSvc.ComputeForPod(ctx, req.ClusterName, podUID)
	if err != nil {
		fmt.Printf("warn: pod refresh failed at attack_path: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"stage": "attack_path", "error": err.Error()})
		return
	}

	// 3. Local (Exposure + Attack Path 결과 합성)
	local, err := h.localSvc.ComputeForPod(ctx, req.ClusterName, podUID)
	if err != nil {
		fmt.Printf("warn: pod refresh failed at local: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"stage": "local", "error": err.Error()})
		return
	}

	// 4. Toxic (시그널 조합)
	toxic, err := h.toxicSvc.ComputeForPod(ctx, req.ClusterName, podUID)
	if err != nil {
		fmt.Printf("warn: pod refresh failed at toxic: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"stage": "toxic", "error": err.Error()})
		return
	}

	// 5. Final (Global + Local + Toxic 합성)
	final, err := h.finalSvc.ComputeForPod(ctx, req.ClusterName, podUID)
	if err != nil {
		fmt.Printf("warn: pod refresh failed at final: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"stage": "final", "error": err.Error()})
		return
	}

	duration := time.Since(start)
	fmt.Printf("info: pod refresh completed cluster=%s pod_uid=%s duration_ms=%d\n",
		req.ClusterName, podUID, duration.Milliseconds())

	c.JSON(http.StatusOK, PodRefreshResponse{
		PodUID:      podUID,
		ClusterName: req.ClusterName,
		ComputedAt:  time.Now(),
		DurationMs:  duration.Milliseconds(),
		Exposure:    exposure,
		AttackPath:  attackPath,
		Local:       local,
		Toxic:       toxic,
		Final:       final,
	})
}
