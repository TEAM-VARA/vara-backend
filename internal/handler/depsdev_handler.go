package handler

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/vara/backend/internal/service"
)

// DepsDevHandler는 deps.dev 버전 릴리스 수집/조회 API를 담당합니다 (3단계).
//
// 엔드포인트:
//   POST /api/v1/sboms/packages/versions/fetch?purl=...&force=true
//     PURL 하나의 버전 릴리스 날짜를 deps.dev에서 받아 저장.
//   POST /api/v1/sboms/packages/:digest/versions/fetch?force=true
//     이미지의 모든 PURL에 대해 수집.
//   GET  /api/v1/sboms/packages/versions?purl=...
//     저장된 버전 릴리스 목록 조회.
type DepsDevHandler struct {
	svc *service.DepsDevService
}

func NewDepsDevHandler(svc *service.DepsDevService) *DepsDevHandler {
	return &DepsDevHandler{svc: svc}
}

// FetchByPURL : POST /api/v1/sboms/packages/versions/fetch?purl=...&force=true
func (h *DepsDevHandler) FetchByPURL(c *gin.Context) {
	purl := c.Query("purl")
	if purl == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "purl query parameter is required"})
		return
	}
	force := c.Query("force") == "true"

	res, err := h.svc.FetchAndStore(c.Request.Context(), purl, force)
	if err != nil {
		fmt.Printf("warn: depsdev fetch failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, res)
}

// FetchByImage : POST /api/v1/sboms/packages/:digest/versions/fetch?force=true
func (h *DepsDevHandler) FetchByImage(c *gin.Context) {
	digest := c.Param("digest")
	if digest == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "digest is required"})
		return
	}
	force := c.Query("force") == "true"

	fetched, skipped, err := h.svc.FetchForImage(c.Request.Context(), digest, force)
	if err != nil {
		fmt.Printf("warn: depsdev fetch image failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"image_digest": digest,
		"fetched":      fetched,
		"skipped":      skipped,
	})
}

// Metrics : GET /api/v1/sboms/packages/metrics?purl=...
//
// 패키지의 릴리스 주기 + 벤더 보안 대응속도를 즉석 계산해 반환.
func (h *DepsDevHandler) Metrics(c *gin.Context) {
	purl := c.Query("purl")
	if purl == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "purl query parameter is required"})
		return
	}
	m, err := h.svc.GetPackageMetrics(c.Request.Context(), purl)
	if err != nil {
		fmt.Printf("warn: depsdev metrics failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, m)
}

// ListByPURL : GET /api/v1/sboms/packages/versions?purl=...
func (h *DepsDevHandler) ListByPURL(c *gin.Context) {
	purl := c.Query("purl")
	if purl == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "purl query parameter is required"})
		return
	}
	versions, err := h.svc.ListVersions(c.Request.Context(), purl)
	if err != nil {
		fmt.Printf("warn: depsdev list failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"purl":     purl,
		"total":    len(versions),
		"versions": versions,
	})
}
