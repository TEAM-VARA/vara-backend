package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/vara/backend/internal/domain/scoring"
	"github.com/vara/backend/internal/service"
)

// WeightsHandler는 Risk Scoring 가중치 조회/설정 API를 담당합니다.
type WeightsHandler struct {
	svc *service.WeightsService
}

func NewWeightsHandler(svc *service.WeightsService) *WeightsHandler {
	return &WeightsHandler{svc: svc}
}

// Get : GET /api/v1/scoring/weights
func (h *WeightsHandler) Get(c *gin.Context) {
	w, err := h.svc.Get(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, w)
}

// Update : PUT /api/v1/scoring/weights
// body: scoring.Weights (final/global 합 각각 1.0, toxic >= 1.0)
func (h *WeightsHandler) Update(c *gin.Context) {
	var w scoring.Weights
	if err := c.ShouldBindJSON(&w); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body: " + err.Error()})
		return
	}
	res, err := h.svc.Update(c.Request.Context(), w)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, res)
}

// Recommend : POST /api/v1/scoring/weights/recommend
// body(선택): {"profile": "환경·우선순위 설명"}
// AI가 클러스터 통계 + (선택)운영자 설명으로 추천 가중치+근거를 반환합니다(자동 적용 X).
func (h *WeightsHandler) Recommend(c *gin.Context) {
	var req struct {
		Profile string `json:"profile"`
	}
	_ = c.ShouldBindJSON(&req) // 바디 없거나 비어도 허용(profile은 선택)

	rec, err := h.svc.Recommend(c.Request.Context(), req.Profile)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, rec)
}
