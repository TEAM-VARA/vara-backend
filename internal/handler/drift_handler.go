package handler

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// GetDriftFeed : GET /api/v1/feed/drift?since=<RFC3339>
//   NetworkPolicy(선언) vs 실제 통신(eBPF) 위반 목록.
//   X-Customer-ID 헤더값을 cluster_name 으로 사용.
func (h *EbpfHandler) GetDriftFeed(c *gin.Context) {
	clusterName := c.GetHeader("X-Customer-ID")
	if clusterName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Customer-ID header required"})
		return
	}
	since := time.Now().Add(-15 * time.Minute) // drift 기본 윈도우
	if s := c.Query("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			since = t
		}
	}
	items, err := h.repo.QueryDriftFeed(c.Request.Context(), clusterName, since, 200)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"events": items})
}
