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
}

func NewScoring(repo *postgres.ScoringRepo, svc *service.ScoringService) *ScoringHandler {
	return &ScoringHandler{repo: repo, service: svc}
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

	// DB 저장
	if err := h.repo.SaveScoring(
		ctx, podID, req.ImageName, req.ImageDigest,
		result, comp.Details, digestCheck,
	); err != nil {
		fmt.Printf("warn: save scoring failed: %v\n", err)
	}

	resp := scoring.Response{
		ImageName:   req.ImageName,
		ImageDigest: req.ImageDigest,
		Result:      result,
		Message: fmt.Sprintf("스코어링 완료 — 점수: %.2f / 등급: %s / CVE %d개 발견",
			result.FinalScore, result.RiskLevel, len(result.CVEList)),
	}

	c.JSON(http.StatusOK, resp)
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
