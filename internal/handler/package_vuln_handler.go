package handler

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/vara/backend/internal/service"
)

// PackageVulnHandler는 package_vulnerabilities API를 담당합니다.
//
// 엔드포인트:
//   POST /api/v1/sboms/packages/:digest/vulnerabilities/scan?force=true
//     이미지의 모든 PURL을 osv.dev에 조회하여 취약점 저장.
//     수십 초 ~ 수 분 걸릴 수 있음 (PURL 수에 비례).
//
//   GET  /api/v1/sboms/packages/:digest/vulnerabilities
//     이미지의 모든 패키지 취약점 목록.
//
//   GET  /api/v1/sboms/packages/vulnerabilities/search?vuln_id=CVE-2024-...
//     특정 CVE/GHSA로 영향 받는 모든 PURL 검색.
//
//   GET  /api/v1/sboms/packages/vulnerabilities/by-purl?purl=pkg:deb/...
//     특정 PURL의 모든 취약점.
type PackageVulnHandler struct {
	service *service.PackageVulnService
}

func NewPackageVulnHandler(svc *service.PackageVulnService) *PackageVulnHandler {
	return &PackageVulnHandler{service: svc}
}

// Scan : POST /api/v1/sboms/packages/:digest/vulnerabilities/scan?force=true
func (h *PackageVulnHandler) Scan(c *gin.Context) {
	digest := c.Param("digest")
	if digest == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "digest is required"})
		return
	}
	force := c.Query("force") == "true"

	ctx := c.Request.Context()
	result, err := h.service.ScanImage(ctx, digest, force)
	if err != nil {
		fmt.Printf("warn: osv scan failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// ListByImage : GET /api/v1/sboms/packages/:digest/vulnerabilities
func (h *PackageVulnHandler) ListByImage(c *gin.Context) {
	digest := c.Param("digest")
	if digest == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "digest is required"})
		return
	}

	ctx := c.Request.Context()
	vulns, err := h.service.ListByImageDigest(ctx, digest)
	if err != nil {
		fmt.Printf("warn: list vulns failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 카운터 집계
	severityCounts := map[string]int{}
	uniqueVulns := map[string]bool{}
	uniquePURLs := map[string]bool{}
	for _, v := range vulns {
		severityCounts[v.SeverityLabel]++
		uniqueVulns[v.VulnID] = true
		uniquePURLs[v.PURL] = true
	}

	c.JSON(http.StatusOK, gin.H{
		"image_digest":     digest,
		"total":            len(vulns),
		"unique_vulns":     len(uniqueVulns),
		"affected_purls":   len(uniquePURLs),
		"severity_counts":  severityCounts,
		"vulnerabilities":  vulns,
	})
}

// SearchByVulnID : GET /api/v1/sboms/packages/vulnerabilities/search?vuln_id=CVE-...
func (h *PackageVulnHandler) SearchByVulnID(c *gin.Context) {
	vulnID := c.Query("vuln_id")
	if vulnID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "vuln_id query parameter is required"})
		return
	}

	ctx := c.Request.Context()
	vulns, err := h.service.SearchByVulnID(ctx, vulnID)
	if err != nil {
		fmt.Printf("warn: search by vuln id failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 영향 패키지/이미지 카운트
	uniquePURLs := map[string]bool{}
	for _, v := range vulns {
		uniquePURLs[v.PURL] = true
	}

	c.JSON(http.StatusOK, gin.H{
		"vuln_id":           vulnID,
		"total":             len(vulns),
		"affected_packages": len(uniquePURLs),
		"vulnerabilities":   vulns,
	})
}

// ListByPURL : GET /api/v1/sboms/packages/vulnerabilities/by-purl?purl=pkg:...
func (h *PackageVulnHandler) ListByPURL(c *gin.Context) {
	purl := c.Query("purl")
	if purl == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "purl query parameter is required"})
		return
	}

	ctx := c.Request.Context()
	vulns, err := h.service.ListByPURL(ctx, purl)
	if err != nil {
		fmt.Printf("warn: list by purl failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"purl":            purl,
		"total":           len(vulns),
		"vulnerabilities": vulns,
	})
}

// CVETimelineByPod : GET /api/v1/sboms/packages/vulnerabilities/timeline/pods/:pod_uid?cluster=...
//
// 한 Pod의 CVE 발생 타임라인(published_at 월별 빈도)을 반환.
func (h *PackageVulnHandler) CVETimelineByPod(c *gin.Context) {
	podUID := c.Param("pod_uid")
	clusterName := c.Query("cluster")
	if podUID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "pod_uid is required"})
		return
	}
	if clusterName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cluster query parameter is required"})
		return
	}

	ctx := c.Request.Context()
	resp, err := h.service.GetCVETimelineByPod(ctx, clusterName, podUID)
	if err != nil {
		fmt.Printf("warn: cve timeline failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// PatchStatusByPod : GET /api/v1/sboms/packages/vulnerabilities/patch-status/pods/:pod_uid?cluster=...
//
// 한 Pod의 CVE별 패치 가능 여부 요약 (patchable / no_fix).
func (h *PackageVulnHandler) PatchStatusByPod(c *gin.Context) {
	podUID := c.Param("pod_uid")
	clusterName := c.Query("cluster")
	if podUID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "pod_uid is required"})
		return
	}
	if clusterName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cluster query parameter is required"})
		return
	}

	resp, err := h.service.GetPatchStatusByPod(c.Request.Context(), clusterName, podUID)
	if err != nil {
		fmt.Printf("warn: patch status failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}
