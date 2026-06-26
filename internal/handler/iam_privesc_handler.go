package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/vara/backend/internal/repository/postgres"
)

// IamPrivescHandler 는 IAM 권한상승 탐지 결과(scan_runs / principal_results / findings)를
// 프론트엔드가 읽을 수 있게 노출하는 read-only 핸들러다. 모두 "계정별 최신 실행" 기준이며,
// 적재는 스케줄러(internal/scheduler)가, 조회는 이 핸들러가 담당한다.
type IamPrivescHandler struct {
	repo *postgres.IamPrivescResultRepo
}

func NewIamPrivescHandler(repo *postgres.IamPrivescResultRepo) *IamPrivescHandler {
	return &IamPrivescHandler{repo: repo}
}

// ListScanRuns : GET /api/v1/iam-privesc/scan-runs?account_id=...
// 계정별 "최신" 스캔 실행 요약(상태별 카운트 ❌🟡ℹ️✅ 포함). account_id 생략 시 전체 계정.
func (h *IamPrivescHandler) ListScanRuns(c *gin.Context) {
	rows, err := h.repo.ListLatestScanRuns(c.Request.Context(), c.Query("account_id"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"count": len(rows), "scan_runs": rows})
}

// ListPrincipals : GET /api/v1/iam-privesc/principals?account_id=...&status=critical|warning|info|ok
// 계정별 최신 실행의 principal(User/Role/Group) 결과 목록. status 로 위험도 필터 가능.
func (h *IamPrivescHandler) ListPrincipals(c *gin.Context) {
	status := c.Query("status")
	if status != "" && !isValidStatus(status) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status must be one of: critical, warning, info, ok"})
		return
	}
	rows, err := h.repo.ListCurrentPrincipals(c.Request.Context(), c.Query("account_id"), status)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"count": len(rows), "principals": rows})
}

// ListFindings : GET /api/v1/iam-privesc/findings?account_id=...&severity=critical|warning|info&principal_name=...
// 계정별 최신 실행의 발견 항목(단일 룰/콤보) 목록. severity / principal_name 으로 필터 가능.
func (h *IamPrivescHandler) ListFindings(c *gin.Context) {
	severity := c.Query("severity")
	if severity != "" && !isValidSeverity(severity) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "severity must be one of: critical, warning, info"})
		return
	}
	rows, err := h.repo.ListCurrentFindings(c.Request.Context(), c.Query("account_id"), severity, c.Query("principal_name"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"count": len(rows), "findings": rows})
}

func isValidStatus(s string) bool {
	switch s {
	case "critical", "warning", "info", "ok":
		return true
	}
	return false
}

func isValidSeverity(s string) bool {
	switch s {
	case "critical", "warning", "info":
		return true
	}
	return false
}
