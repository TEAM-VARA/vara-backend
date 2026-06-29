package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/vara/backend/internal/domain/notification"
	"github.com/vara/backend/internal/service"
)

// SlackHandler는 Slack 알림 연동 설정 API를 담당합니다.
//
// 엔드포인트:
//
//	GET  /api/v1/integrations/slack?cluster_name=  → 설정 조회 (webhook 마스킹)
//	POST /api/v1/integrations/slack                → 설정 저장
//	POST /api/v1/integrations/slack/test           → 테스트 메시지 전송
type SlackHandler struct {
	service *service.SlackService
}

func NewSlackHandler(svc *service.SlackService) *SlackHandler {
	return &SlackHandler{service: svc}
}

// Get : GET /api/v1/integrations/slack?cluster_name=
func (h *SlackHandler) Get(c *gin.Context) {
	cluster := c.Query("cluster_name")
	if cluster == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cluster_name is required"})
		return
	}
	settings, err := h.service.GetSettings(c.Request.Context(), cluster)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, settings)
}

// Upsert : POST /api/v1/integrations/slack
func (h *SlackHandler) Upsert(c *gin.Context) {
	var req notification.SlackSettings
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.ClusterName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cluster_name is required"})
		return
	}
	if err := h.service.UpsertSettings(c.Request.Context(), req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// 저장 결과를 마스킹된 형태로 반환.
	settings, err := h.service.GetSettings(c.Request.Context(), req.ClusterName)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
		return
	}
	c.JSON(http.StatusOK, settings)
}

// Test : POST /api/v1/integrations/slack/test
func (h *SlackHandler) Test(c *gin.Context) {
	var req struct {
		ClusterName string `json:"cluster_name"`
	}
	// 바디 또는 쿼리 둘 다 허용.
	_ = c.ShouldBindJSON(&req)
	cluster := req.ClusterName
	if cluster == "" {
		cluster = c.Query("cluster_name")
	}
	if cluster == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cluster_name is required"})
		return
	}
	status, err := h.service.Test(c.Request.Context(), cluster)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"status": status, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": status})
}
