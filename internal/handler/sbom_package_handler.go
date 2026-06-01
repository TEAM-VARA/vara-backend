package handler

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/vara/backend/internal/service"
)

// SBOMPackageHandler는 sbom_packages API를 담당합니다.
//
// 엔드포인트:
//   POST /api/v1/sboms/packages/extract/:digest   특정 이미지 추출/저장
//   POST /api/v1/sboms/packages/backfill          기존 모든 SBOM 일괄 추출
//   GET  /api/v1/sboms/packages/:digest           특정 이미지의 패키지 목록
//   GET  /api/v1/sboms/packages/search?name=...   이름으로 검색
type SBOMPackageHandler struct {
	service *service.SBOMPackageService
}

func NewSBOMPackageHandler(svc *service.SBOMPackageService) *SBOMPackageHandler {
	return &SBOMPackageHandler{service: svc}
}

// Extract : POST /api/v1/sboms/packages/extract/:digest
func (h *SBOMPackageHandler) Extract(c *gin.Context) {
	digest := c.Param("digest")
	if digest == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "digest is required"})
		return
	}

	ctx := c.Request.Context()
	count, err := h.service.ExtractAndStore(ctx, digest)
	if err != nil {
		fmt.Printf("warn: sbom_packages extract failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"image_digest":     digest,
		"packages_count":   count,
		"message":          fmt.Sprintf("%d packages extracted and stored", count),
	})
}

// Backfill : POST /api/v1/sboms/packages/backfill?detail=true
func (h *SBOMPackageHandler) Backfill(c *gin.Context) {
	includeDetail := c.Query("detail") == "true"

	ctx := c.Request.Context()
	result, err := h.service.Backfill(ctx, includeDetail)
	if err != nil {
		fmt.Printf("warn: sbom_packages backfill failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// List : GET /api/v1/sboms/packages/:digest
func (h *SBOMPackageHandler) List(c *gin.Context) {
	digest := c.Param("digest")
	if digest == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "digest is required"})
		return
	}

	ctx := c.Request.Context()
	packages, err := h.service.ListByImageDigest(ctx, digest)
	if err != nil {
		fmt.Printf("warn: sbom_packages list failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 생태계별 카운트
	ecosystemCount := make(map[string]int)
	for _, p := range packages {
		ecosystemCount[p.Ecosystem]++
	}

	c.JSON(http.StatusOK, gin.H{
		"image_digest":     digest,
		"total":            len(packages),
		"ecosystem_count":  ecosystemCount,
		"packages":         packages,
	})
}

// Search : GET /api/v1/sboms/packages/search?name=openssl
func (h *SBOMPackageHandler) Search(c *gin.Context) {
	name := c.Query("name")
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name query parameter is required"})
		return
	}

	ctx := c.Request.Context()
	packages, err := h.service.SearchByName(ctx, name)
	if err != nil {
		fmt.Printf("warn: sbom_packages search failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 버전별/이미지별 카운트
	versionCount := make(map[string]int)
	imageCount := make(map[string]int)
	for _, p := range packages {
		versionCount[p.Version]++
		imageCount[p.ImageDigest]++
	}

	c.JSON(http.StatusOK, gin.H{
		"name":              name,
		"total":             len(packages),
		"unique_versions":   len(versionCount),
		"unique_images":     len(imageCount),
		"version_count":     versionCount,
		"packages":          packages,
	})
}
