package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/vara/backend/internal/domain/grc"
	"github.com/vara/backend/internal/repository/postgres"
	"github.com/vara/backend/internal/service"
)

type GRCHandler struct {
	svc          *service.GRCService
	rulesetStore *service.RulesetStore
}

func NewGRC(svc *service.GRCService, rulesetStore *service.RulesetStore) *GRCHandler {
	return &GRCHandler{svc: svc, rulesetStore: rulesetStore}
}

// POST /compliance/checks
func (h *GRCHandler) CreateCheck(c *gin.Context) {
	ismspItemID := c.PostForm("isms_p_item_id")
	if ismspItemID == "" {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "isms_p_item_id 필수")
		return
	}

	companyID := c.PostForm("company_id")
	if companyID == "" || len(companyID) > 64 {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "company_id 필수 (1~64자)")
		return
	}

	autoCollect := c.PostForm("auto_collect") == "true"

	metadataStr := c.PostForm("evidence_metadata")
	if metadataStr == "" {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "evidence_metadata 필수")
		return
	}

	var metadataList []grc.EvidenceMetadata
	if err := json.Unmarshal([]byte(metadataStr), &metadataList); err != nil {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "evidence_metadata JSON 파싱 실패: "+err.Error())
		return
	}

	form, err := c.MultipartForm()
	if err != nil {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "multipart form 파싱 실패: "+err.Error())
		return
	}
	files := form.File["files"]
	if len(files) == 0 {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "files 필수")
		return
	}

	chk, err := h.svc.CreateCheck(c.Request.Context(), companyID, ismspItemID, autoCollect, files, metadataList)
	if err != nil {
		if ge, ok := err.(*service.GRCError); ok {
			grcError(c, ge.HTTPStatus, ge.Code, ge.Message)
			return
		}
		grcError(c, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"check_id":          chk.CheckID,
		"status":            chk.Status,
		"estimated_seconds": 30,
		"isms_p_item_id":    chk.ISMSPItemID,
		"company_id":        chk.CompanyID,
		"submitted_at":      chk.SubmittedAt,
	})
}

// GET /compliance/checks/:check_id
func (h *GRCHandler) GetCheck(c *gin.Context) {
	checkID := c.Param("check_id")
	if checkID == "" {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "check_id 필수")
		return
	}

	resp, err := h.svc.GetCheckDetail(c.Request.Context(), checkID)
	if err != nil {
		if ge, ok := err.(*service.GRCError); ok {
			grcError(c, ge.HTTPStatus, ge.Code, ge.Message)
			return
		}
		grcError(c, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	c.JSON(http.StatusOK, resp)
}

// GET /compliance/checks
func (h *GRCHandler) ListChecks(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	filters := postgres.CheckFilters{
		CompanyID:   c.Query("company_id"),
		ISMSPItemID: c.Query("isms_p_item_id"),
		Verdict:     c.Query("verdict"),
		Status:      c.Query("status"),
	}

	items, totalCount, err := h.svc.ListChecks(c.Request.Context(), filters, page, pageSize)
	if err != nil {
		grcError(c, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": items,
		"pagination": grc.Pagination{
			Page:       page,
			PageSize:   pageSize,
			TotalCount: totalCount,
			TotalPages: postgres.TotalPages(totalCount, pageSize),
		},
	})
}

// GET /compliance/checks/:check_id/evidence
func (h *GRCHandler) ListEvidence(c *gin.Context) {
	checkID := c.Param("check_id")
	if checkID == "" {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "check_id 필수")
		return
	}

	items, err := h.svc.ListEvidence(c.Request.Context(), checkID)
	if err != nil {
		grcError(c, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": items})
}

// GET /rulesets
func (h *GRCHandler) ListRulesets(c *gin.Context) {
	items, err := h.rulesetStore.ListItems()
	if err != nil {
		grcError(c, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": items})
}

// GET /rulesets/:item_id
func (h *GRCHandler) GetRuleset(c *gin.Context) {
	itemID := c.Param("item_id")
	raw, err := h.rulesetStore.GetRaw(itemID)
	if err != nil {
		grcError(c, http.StatusNotFound, "RULESET_NOT_FOUND", "룰셋 미존재: "+itemID)
		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", raw)
}

// ── Cloud Environments ──

type createCloudEnvRequest struct {
	CompanyID string                `json:"company_id"`
	Resources []cloudEnvResourceReq `json:"resources"`
}

type cloudEnvResourceReq struct {
	ResourceType string         `json:"resource_type"`
	ResourceName string         `json:"resource_name"`
	Namespace    string         `json:"namespace,omitempty"`
	ClusterName  string         `json:"cluster_name,omitempty"`
	RawData      map[string]any `json:"raw_data"`
}

// POST /compliance/cloud-environments
func (h *GRCHandler) CreateCloudEnvironments(c *gin.Context) {
	var req createCloudEnvRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "JSON 파싱 실패: "+err.Error())
		return
	}
	if req.CompanyID == "" {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "company_id 필수")
		return
	}
	if len(req.Resources) == 0 {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "resources 비어있음")
		return
	}

	envs := make([]grc.CloudEnvironment, len(req.Resources))
	for i, r := range req.Resources {
		if r.ResourceType == "" || r.ResourceName == "" {
			grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "resource_type, resource_name 필수")
			return
		}
		if r.RawData == nil {
			grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "raw_data 필수")
			return
		}
		envs[i] = grc.CloudEnvironment{
			CompanyID:    req.CompanyID,
			ResourceType: r.ResourceType,
			ResourceName: r.ResourceName,
			Namespace:    r.Namespace,
			ClusterName:  r.ClusterName,
			RawData:      r.RawData,
		}
	}

	created, err := h.svc.CreateCloudEnvironments(c.Request.Context(), envs)
	if err != nil {
		if ge, ok := err.(*service.GRCError); ok {
			grcError(c, ge.HTTPStatus, ge.Code, ge.Message)
			return
		}
		grcError(c, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"created": len(created),
		"data":    created,
	})
}

// GET /compliance/cloud-environments
func (h *GRCHandler) ListCloudEnvironments(c *gin.Context) {
	companyID := c.Query("company_id")
	if companyID == "" {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "company_id 필수")
		return
	}

	resourceType := c.Query("resource_type")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	items, totalCount, err := h.svc.ListCloudEnvironments(c.Request.Context(), companyID, resourceType, page, pageSize)
	if err != nil {
		grcError(c, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": items,
		"pagination": grc.Pagination{
			Page:       page,
			PageSize:   pageSize,
			TotalCount: totalCount,
			TotalPages: postgres.TotalPages(totalCount, pageSize),
		},
	})
}

func grcError(c *gin.Context, status int, code, message string) {
	c.JSON(status, gin.H{
		"error": gin.H{
			"code":    code,
			"message": message,
		},
	})
}
