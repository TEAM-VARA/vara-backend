package handler

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/vara/backend/internal/domain/scoring"
	"github.com/vara/backend/internal/service"
)

// GlobalScoringHandler는 CVE Global Score API를 담당합니다.
//
// 엔드포인트:
//   POST /api/v1/scoring/global/cves/:cve_id?force=true
//     → 단일 CVE 계산 (force=true면 캐시 무시)
//
//   GET  /api/v1/scoring/global/cves/:cve_id
//     → 캐시된 점수 조회 (없으면 404)
//
//   POST /api/v1/scoring/global/images
//     Body: { "image_digest": "sha256:..." }
//     → 이미지의 모든 CVE 점수 계산 + 통합 (max)
type GlobalScoringHandler struct {
	service *service.GlobalScoringService
}

// NewGlobalScoringHandler는 GlobalScoringHandler를 생성합니다.
func NewGlobalScoringHandler(svc *service.GlobalScoringService) *GlobalScoringHandler {
	return &GlobalScoringHandler{service: svc}
}

// ComputeCVE : POST /api/v1/scoring/global/cves/:cve_id?force=true
//
// 단일 CVE의 Global Score를 계산하고 DB에 저장.
// force 쿼리 파라미터로 캐시 무시 가능.
func (h *GlobalScoringHandler) ComputeCVE(c *gin.Context) {
	cveID := strings.ToUpper(c.Param("cve_id"))
	if cveID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cve_id is required"})
		return
	}
	if !strings.HasPrefix(cveID, "CVE-") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cve_id must start with 'CVE-'"})
		return
	}

	force := c.Query("force") == "true"

	ctx := c.Request.Context()
	score, _, err := h.service.ComputeCVE(ctx, cveID, force)
	if err != nil {
		fmt.Printf("warn: compute cve failed cve=%s err=%v\n", cveID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, score)
}

// GetCVE : GET /api/v1/scoring/global/cves/:cve_id
//
// 캐시된 점수 조회. 없으면 404.
func (h *GlobalScoringHandler) GetCVE(c *gin.Context) {
	cveID := strings.ToUpper(c.Param("cve_id"))
	if cveID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cve_id is required"})
		return
	}

	ctx := c.Request.Context()
	score, err := h.service.GetCachedCVE(ctx, cveID)
	if err != nil {
		fmt.Printf("warn: get cve failed cve=%s err=%v\n", cveID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if score == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "cve score not found in cache",
			"hint":    "POST /api/v1/scoring/global/cves/" + cveID + " first",
			"cve_id":  cveID,
		})
		return
	}

	c.JSON(http.StatusOK, score)
}

// ComputeImage : POST /api/v1/scoring/global/images
//
// 이미지의 모든 CVE에 대해 점수 계산 + 통합 점수 반환.
// SBOM 테이블에서 CVE 추출, 각 CVE는 캐시 활용.
//
// 큰 이미지(수백 CVE)는 시간 오래 걸림 (NVD rate limit).
func (h *GlobalScoringHandler) ComputeImage(c *gin.Context) {
	var req scoring.ComputeImageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	force := c.Query("force") == "true"

	ctx := c.Request.Context()
	result, err := h.service.ComputeImage(ctx, req.ImageDigest, force)
	if err != nil {
		fmt.Printf("warn: compute image failed digest=%s err=%v\n", req.ImageDigest, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}
