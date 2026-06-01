package handler

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/vara/backend/internal/service"
)

// ImageGlobalCacheHandler는 image_global_scores 캐시 API를 담당합니다.
//
// 엔드포인트:
//   POST /api/v1/scoring/global/images/:digest         캐시 확인 → 없으면 계산 + 저장
//   POST /api/v1/scoring/global/images/:digest?force=true   강제 재계산 + 저장
//   GET  /api/v1/scoring/global/images/:digest         캐시만 조회 (없으면 404)
//
// 작업 B-1의 기존 POST /scoring/global/images (body 기반)는 유지하면 됩니다.
// 본 핸들러는 path-style API + 저장이 핵심.
type ImageGlobalCacheHandler struct {
	service *service.ImageGlobalCacheService
}

// NewImageGlobalCacheHandler는 ImageGlobalCacheHandler를 생성합니다.
func NewImageGlobalCacheHandler(svc *service.ImageGlobalCacheService) *ImageGlobalCacheHandler {
	return &ImageGlobalCacheHandler{service: svc}
}

// ComputeByDigest : POST /api/v1/scoring/global/images/:digest?force=true
func (h *ImageGlobalCacheHandler) ComputeByDigest(c *gin.Context) {
	digest := c.Param("digest")
	if digest == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "digest is required"})
		return
	}
	force := c.Query("force") == "true"

	ctx := c.Request.Context()
	rec, err := h.service.ComputeAndStore(ctx, digest, force)
	if err != nil {
		fmt.Printf("warn: image_global compute failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, rec)
}

// GetByDigest : GET /api/v1/scoring/global/images/:digest
func (h *ImageGlobalCacheHandler) GetByDigest(c *gin.Context) {
	digest := c.Param("digest")
	if digest == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "digest is required"})
		return
	}

	ctx := c.Request.Context()
	rec, err := h.service.GetByDigest(ctx, digest)
	if err != nil {
		fmt.Printf("warn: image_global get failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if rec == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":  "image_global score not found, run POST first",
			"digest": digest,
		})
		return
	}

	c.JSON(http.StatusOK, rec)
}
