package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/vara/backend/internal/service"
)

// RBACChainHandler는 RBAC 권한상승(fixpoint) 분석 API 입니다.
type RBACChainHandler struct {
	svc *service.RBACChainService
}

func NewRBACChainHandler(svc *service.RBACChainService) *RBACChainHandler {
	return &RBACChainHandler{svc: svc}
}

type rbacChainComputeRequest struct {
	ClusterName string `json:"cluster_name" binding:"required"`
}

// Compute — POST /scoring/rbac-chain/compute
// 한 클러스터를 분석하고 결과를 DB에 덮어쓴다.
func (h *RBACChainHandler) Compute(c *gin.Context) {
	var req rbacChainComputeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	summary, err := h.svc.Compute(c.Request.Context(), req.ClusterName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"cluster_name": req.ClusterName,
		"summary":      summary,
	})
}

// GetByCluster — GET /scoring/rbac-chain/clusters/:cluster_name
// 분석 현황 요약 + SA 성적표 목록.
func (h *RBACChainHandler) GetByCluster(c *gin.Context) {
	cluster := c.Param("cluster_name")
	meta, reports, err := h.svc.GetCluster(c.Request.Context(), cluster)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if meta == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "분석 결과 없음 (먼저 compute 실행)", "cluster_name": cluster})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"meta":        meta,
		"sa_reports":  reports,
	})
}

// GetSA — GET /scoring/rbac-chain/clusters/:cluster_name/sa/:namespace/:name
// SA 한 개의 상세(성적표 + 권한상승 경로).
func (h *RBACChainHandler) GetSA(c *gin.Context) {
	cluster := c.Param("cluster_name")
	ns := c.Param("namespace")
	name := c.Param("name")
	detail, err := h.svc.GetSA(c.Request.Context(), cluster, ns, name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if detail == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "SA 분석 결과 없음", "sa": ns + "/" + name})
		return
	}
	c.JSON(http.StatusOK, detail)
}

// GetSAPermissions — GET /scoring/rbac-chain/clusters/:cluster_name/sa/:namespace/:name/permissions
// SA 한 개의 최종 권한 전체 목록 (RC-5b). rbac_sa_permissions.
func (h *RBACChainHandler) GetSAPermissions(c *gin.Context) {
	cluster := c.Param("cluster_name")
	ns := c.Param("namespace")
	name := c.Param("name")
	perms, err := h.svc.ListSAPermissions(c.Request.Context(), cluster, ns, name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"cluster_name": cluster,
		"sa_namespace": ns,
		"sa_name":      name,
		"total":        len(perms),
		"permissions":  perms,
	})
}

// FindSAsByPermission — GET /scoring/rbac-chain/clusters/:cluster_name/permissions?resource=&verb=
// 특정 권한(resource/verb)을 가진 SA 역질의 (RC-5a). 와일드카드(*) 보유 SA도 포함.
func (h *RBACChainHandler) FindSAsByPermission(c *gin.Context) {
	cluster := c.Param("cluster_name")
	resource := c.Query("resource")
	verb := c.Query("verb")
	if resource == "" || verb == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "resource, verb 쿼리 파라미터는 필수입니다"})
		return
	}
	sas, err := h.svc.FindSAsByPermission(c.Request.Context(), cluster, resource, verb)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"cluster_name":     cluster,
		"query":            gin.H{"resource": resource, "verb": verb},
		"total":            len(sas),
		"service_accounts": sas,
	})
}

// ListRules — GET /scoring/rbac-chain/rules
// RBAC 권한상승 룰 카탈로그(22종, 050). applied_transitions / via_transition 의 룰 ID를
// 제목·설명으로 풀기 위한 참조 데이터. RC-4.
// 쿼리: ?category=direct|indirect|lateral  &  ?engine_status=default|opt-in|unwired (둘 다 선택).
func (h *RBACChainHandler) ListRules(c *gin.Context) {
	category := c.Query("category")
	engineStatus := c.Query("engine_status")
	rules, err := h.svc.ListRules(c.Request.Context(), category, engineStatus)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"total": len(rules),
		"rules": rules,
	})
}
