package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vara/backend/internal/service"
)

type BreakdownHandler struct {
	service *service.BreakdownService
}

func NewBreakdownHandler(svc *service.BreakdownService) *BreakdownHandler {
	return &BreakdownHandler{service: svc}
}

// GetBreakdown : GET /api/v1/scoring/breakdown?cluster=&pod=
func (h *BreakdownHandler) GetBreakdown(c *gin.Context) {
	cluster := c.DefaultQuery("cluster", "vara-eks-test")
	pod := c.Query("pod")
	if pod == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "pod query param required"})
		return
	}
	bd, err := h.service.GetBreakdown(c.Request.Context(), cluster, pod)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if bd == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, bd)
}
