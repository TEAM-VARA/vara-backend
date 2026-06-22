package handler

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/vara/backend/internal/domain/scoring"
	"github.com/vara/backend/internal/repository/postgres"
	"github.com/vara/backend/internal/service"
)

// /api/v1/pods/{pod_id}/risk            (POST) - 점수 계산
// /api/v1/pods/{pod_id}/risk/details    (GET)  - 상세 조회

type ScoringHandler struct {
	repo    *postgres.ScoringRepo
	service *service.ScoringService
	grc     *service.GRCService // ISMS-P 미준수 가산용 (코어 스코어링 불변)
}

func NewScoring(repo *postgres.ScoringRepo, svc *service.ScoringService, grc *service.GRCService) *ScoringHandler {
	return &ScoringHandler{repo: repo, service: svc, grc: grc}
}

// ComputeRisk : POST /api/v1/pods/{pod_id}/risk
func (h *ScoringHandler) ComputeRisk(c *gin.Context) {
	podID := c.Param("pod_id")
	if podID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "pod_id 필수"})
		return
	}

	var req scoring.Request
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()

	// Pod 정보 + CVE 목록 조회
	podInfo, err := h.repo.GetPodInfo(ctx, podID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Pod를 찾을 수 없습니다"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Digest 비교
	var digestCheck *scoring.DigestCheckDetail
	digestFlagged := false
	digestMessage := ""
	if podInfo.BuildDigest != "" {
		match := podInfo.BuildDigest == req.ImageDigest
		if !match {
			digestFlagged = true
			digestMessage = "빌드 시점 digest와 다름 (Drift 탐지)"
		} else {
			digestMessage = "빌드 digest와 일치"
		}
		digestCheck = &scoring.DigestCheckDetail{
			BuildDigest:   podInfo.BuildDigest,
			RuntimeDigest: req.ImageDigest,
			Match:         match,
			Note:          digestMessage,
		}
	}

	// 점수 계산
	comp, err := h.service.ComputeForCVEs(ctx, podInfo.CVEList)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	result := comp.Result
	result.DigestFlagged = digestFlagged
	result.DigestMessage = digestMessage

	// ── ISMS-P 미준수 가산 ──
	// FinalScore는 "높을수록 위험"이므로 미준수면 점수를 *더한다*(상3/중2/하1).
	// company_id·cluster_name 쿼리 파라미터가 있으면 그 pod의 ISMS-P 미준수를 합산해
	// FinalScore에 반영한다(도구 severity 보유 21개 룰 전부 — service.ismspRiskSeverity).
	// 없으면 기존 동작 그대로(스킵).
	var ismspRisk *service.ISMSPRiskBreakdown
	if h.grc != nil {
		companyID := c.Query("company_id")
		clusterName := c.Query("cluster_name")
		if companyID != "" && clusterName != "" {
			ismspRisk = h.grc.ComputePodISMSPAddend(
				ctx, companyID, clusterName, podInfo.Namespace, podInfo.PodName,
			)
			service.ApplyISMSPToFinalScore(&result, ismspRisk.Addend)
		}
	}

	// DB 저장 (ISMS-P 가산이 반영된 FinalScore로 저장)
	if err := h.repo.SaveScoring(
		ctx, podID, req.ImageName, req.ImageDigest,
		result, comp.Details, digestCheck,
	); err != nil {
		fmt.Printf("warn: save scoring failed: %v\n", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"image_name":   req.ImageName,
		"image_digest": req.ImageDigest,
		"result":       result,
		"ismsp_risk":   ismspRisk, // company_id·cluster_name 미제공 시 null
		"message": fmt.Sprintf("스코어링 완료 — 점수: %.2f / 등급: %s / CVE %d개 발견",
			result.FinalScore, result.RiskLevel, len(result.CVEList)),
	})
}

// GetRiskDetails : GET /api/v1/pods/{pod_id}/risk/details
func (h *ScoringHandler) GetRiskDetails(c *gin.Context) {
	podID := c.Param("pod_id")
	if podID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "pod_id 필수"})
		return
	}

	ctx := c.Request.Context()
	resp, err := h.repo.GetScoring(ctx, podID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "스코어링 결과 없음 — 먼저 POST /risk 를 호출하세요",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, resp)
}
