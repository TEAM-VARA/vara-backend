package handler

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/vara/backend/internal/domain/notification"
	"github.com/vara/backend/internal/service"
)

// NotificationHandler는 대시보드 알림 API를 담당합니다.
type NotificationHandler struct {
	service *service.NotificationService
}

func NewNotificationHandler(svc *service.NotificationService) *NotificationHandler {
	return &NotificationHandler{service: svc}
}

// List : GET /api/v1/notifications?cluster_name=...&unread=true&severity=critical&category=new_cve&limit=20&offset=0
func (h *NotificationHandler) List(c *gin.Context) {
	clusterName := c.Query("cluster_name")
	if clusterName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cluster_name is required"})
		return
	}

	limit := 20
	if l, err := strconv.Atoi(c.Query("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}

	offset := 0
	if o, err := strconv.Atoi(c.Query("offset")); err == nil && o >= 0 {
		offset = o
	}

	req := notification.ListRequest{
		ClusterName: clusterName,
		UnreadOnly:  c.Query("unread") == "true",
		Severity:    c.Query("severity"),
		Category:    c.Query("category"),
		Limit:       limit,
		Offset:      offset,
	}

	res, err := h.service.List(c.Request.Context(), req)
	if err != nil {
		fmt.Printf("warn: list notifications failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// nil slice는 빈 배열로 응답
	if res.Notifications == nil {
		res.Notifications = []notification.Notification{}
	}

	c.JSON(http.StatusOK, res)
}

// GetCounts : GET /api/v1/notifications/counts?cluster_name=...
// FE 폴링용 (가벼운 응답)
func (h *NotificationHandler) GetCounts(c *gin.Context) {
	clusterName := c.Query("cluster_name")
	if clusterName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cluster_name is required"})
		return
	}

	counts, err := h.service.GetCounts(c.Request.Context(), clusterName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, counts)
}

// MarkRead : POST /api/v1/notifications/:id/read
func (h *NotificationHandler) MarkRead(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	if err := h.service.MarkRead(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok", "id": id})
}

// MarkAllRead : POST /api/v1/notifications/read-all?cluster_name=...
func (h *NotificationHandler) MarkAllRead(c *gin.Context) {
	clusterName := c.Query("cluster_name")
	if clusterName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cluster_name is required"})
		return
	}

	count, err := h.service.MarkAllRead(c.Request.Context(), clusterName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":       "ok",
		"cluster_name": clusterName,
		"marked_count": count,
	})
}

// Dismiss : DELETE /api/v1/notifications/:id
func (h *NotificationHandler) Dismiss(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	if err := h.service.Dismiss(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "dismissed", "id": id})
}