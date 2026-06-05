package handler

import (
	"encoding/json"
	"log"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"

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
// Content-Type: multipart/form-data → 파일 증적 체크
// Content-Type: application/json   → Pod Graph 체크
func (h *GRCHandler) CreateCheck(c *gin.Context) {
	ct := c.GetHeader("Content-Type")
	if strings.HasPrefix(ct, "application/json") {
		h.createPodGraphCheck(c)
		return
	}
	h.createFileCheck(c)
}

func (h *GRCHandler) createFileCheck(c *gin.Context) {
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

	var metadataList []grc.EvidenceMetadata
	if metadataStr := c.PostForm("evidence_metadata"); metadataStr != "" {
		if err := json.Unmarshal([]byte(metadataStr), &metadataList); err != nil {
			grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "evidence_metadata JSON 파싱 실패: "+err.Error())
			return
		}
	}

	var files []*multipart.FileHeader
	if form, err := c.MultipartForm(); err == nil && form != nil {
		files = form.File["files"]
	}

	// files와 evidence_metadata가 둘 다 없으면 → 지침서 전용 점검 (DB 지침만 사용)
	// files가 있으면 evidence_metadata도 필수
	if len(files) > 0 && len(metadataList) == 0 {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "files 업로드 시 evidence_metadata 필수")
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

func (h *GRCHandler) createPodGraphCheck(c *gin.Context) {
	var req service.PodGraphRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "JSON 파싱 실패: "+err.Error())
		return
	}
	if req.CompanyID == "" {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "company_id 필수")
		return
	}
	if req.Pod == nil {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "pod 데이터 필수")
		return
	}

	chk, err := h.svc.CreatePodGraphCheck(c.Request.Context(), req.CompanyID, req)
	if err != nil {
		if ge, ok := err.(*service.GRCError); ok {
			grcError(c, ge.HTTPStatus, ge.Code, ge.Message)
			return
		}
		grcError(c, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"check_id":     chk.CheckID,
		"status":       chk.Status,
		"check_source": chk.CheckSource,
		"company_id":   chk.CompanyID,
		"submitted_at": chk.SubmittedAt,
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

// ── Guidelines (지침) ──

// POST /compliance/guidelines
func (h *GRCHandler) UploadGuideline(c *gin.Context) {
	companyID := c.PostForm("company_id")
	if companyID == "" {
		companyID = "test-company"
	}
	if len(companyID) > 64 {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "company_id는 64자 이하여야 합니다")
		return
	}

	var ismspItemIDPtr *string
	if v := c.PostForm("isms_p_item_id"); v != "" {
		ismspItemIDPtr = &v
	}

	file, err := c.FormFile("file")
	if err != nil {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "file 필수")
		return
	}

	g, err := h.svc.UploadGuideline(c.Request.Context(), companyID, ismspItemIDPtr, file)
	if err != nil {
		if ge, ok := err.(*service.GRCError); ok {
			grcError(c, ge.HTTPStatus, ge.Code, ge.Message)
			return
		}
		grcError(c, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	// 지침서가 특정 ISMS-P 항목에 속하면 즉시 GL 점검 트리거
	var triggeredCheckID string
	if ismspItemIDPtr != nil && *ismspItemIDPtr != "" {
		chk, trigErr := h.svc.TriggerGLCheck(c.Request.Context(), companyID, *ismspItemIDPtr)
		if trigErr != nil {
			// 업로드는 성공했으므로 점검 트리거 실패를 치명적 오류로 처리하지 않음
			log.Printf("[grc-handler] auto GL check trigger failed for %s/%s: %v", companyID, *ismspItemIDPtr, trigErr)
		} else {
			triggeredCheckID = chk.CheckID
		}
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":                  g.ID,
		"company_id":          g.CompanyID,
		"isms_p_item_id":      g.ISMSPItemID,
		"filename":            g.Filename,
		"file_size_bytes":     g.FileSizeBytes,
		"has_text":            g.ExtractedText != "",
		"has_embedding":       len(g.Embedding) > 0,
		"version":             g.Version,
		"uploaded_at":         g.UploadedAt,
		"triggered_check_id":  triggeredCheckID,
	})
}

// GET /compliance/guidelines
func (h *GRCHandler) ListGuidelines(c *gin.Context) {
	companyID := c.Query("company_id")
	if companyID == "" {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "company_id 필수")
		return
	}

	ismspItemID := c.Query("isms_p_item_id")

	items, err := h.svc.ListGuidelines(c.Request.Context(), companyID, ismspItemID)
	if err != nil {
		grcError(c, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": items})
}

// DELETE /compliance/guidelines/:id
func (h *GRCHandler) DeleteGuideline(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "id must be integer")
		return
	}

	if err := h.svc.DeleteGuideline(c.Request.Context(), id); err != nil {
		if ge, ok := err.(*service.GRCError); ok {
			grcError(c, ge.HTTPStatus, ge.Code, ge.Message)
			return
		}
		grcError(c, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "삭제 완료"})
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

// ── Pod Graph Evaluation (legacy, backward-compat) ──

// POST /compliance/pod-graph/evaluate
func (h *GRCHandler) EvaluatePodGraph(c *gin.Context) {
	var req service.PodGraphRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "JSON 파싱 실패: "+err.Error())
		return
	}
	if req.CompanyID == "" {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "company_id 필수")
		return
	}
	if req.Pod == nil {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "pod 데이터 필수")
		return
	}

	result, err := h.svc.EvaluatePodGraph(c.Request.Context(), req)
	if err != nil {
		if ge, ok := err.(*service.GRCError); ok {
			grcError(c, ge.HTTPStatus, ge.Code, ge.Message)
			return
		}
		grcError(c, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	c.JSON(http.StatusOK, result)
}

// GET /compliance/pod-graph/rulesets
func (h *GRCHandler) ListPodRulesets(c *gin.Context) {
	items, err := h.rulesetStore.ListItems()
	if err != nil {
		grcError(c, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": items})
}

// GET /compliance/pod-graph/evaluations
func (h *GRCHandler) ListPodGraphEvaluations(c *gin.Context) {
	companyID := c.Query("company_id")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	items, totalCount, err := h.svc.ListPodGraphEvaluations(c.Request.Context(), companyID, page, pageSize)
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

// GET /compliance/pod-graph/evaluations/:eval_id
func (h *GRCHandler) GetPodGraphEvaluation(c *gin.Context) {
	evalID, err := strconv.ParseInt(c.Param("eval_id"), 10, 64)
	if err != nil {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "eval_id must be integer")
		return
	}

	item, ruleResults, err := h.svc.GetPodGraphEvaluation(c.Request.Context(), evalID)
	if err != nil {
		grcError(c, http.StatusNotFound, "NOT_FOUND", "평가 결과 미존재")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":              item.ID,
		"company_id":      item.CompanyID,
		"cluster_name":    item.ClusterName,
		"pod_name":        item.PodName,
		"namespace":       item.Namespace,
		"overall_verdict": item.OverallVerdict,
		"total_rules":     item.TotalRules,
		"passed":          item.Passed,
		"failed":          item.Failed,
		"rule_results":    ruleResults,
		"created_at":      item.CreatedAt,
	})
}

// GET /compliance/pod-graph/rulesets/:item_id
func (h *GRCHandler) GetPodRuleset(c *gin.Context) {
	itemID := c.Param("item_id")
	raw, err := h.rulesetStore.GetRaw(itemID)
	if err != nil {
		grcError(c, http.StatusNotFound, "RULESET_NOT_FOUND", "룰셋 미존재: "+itemID)
		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", raw)
}

// POST /compliance/pod-graph/evaluate-cluster
func (h *GRCHandler) EvaluateCluster(c *gin.Context) {
	var req service.ClusterEvalRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "JSON 파싱 실패: "+err.Error())
		return
	}
	if req.CompanyID == "" {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "company_id 필수")
		return
	}
	if req.ClusterName == "" {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "cluster_name 필수")
		return
	}

	result, err := h.svc.EvaluateCluster(c.Request.Context(), req)
	if err != nil {
		if ge, ok := err.(*service.GRCError); ok {
			grcError(c, ge.HTTPStatus, ge.Code, ge.Message)
			return
		}
		grcError(c, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	c.JSON(http.StatusOK, result)
}

// ── Compliance Findings (F-X.X.X-K8S-NN) ──

// POST /compliance/findings/evaluate-cluster
func (h *GRCHandler) EvaluateClusterFindings(c *gin.Context) {
	var req service.FindingEvalRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "JSON 파싱 실패: "+err.Error())
		return
	}
	if req.CompanyID == "" {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "company_id 필수")
		return
	}
	if req.ClusterName == "" {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "cluster_name 필수")
		return
	}

	result, err := h.svc.EvaluateClusterFindings(c.Request.Context(), req)
	if err != nil {
		if ge, ok := err.(*service.GRCError); ok {
			grcError(c, ge.HTTPStatus, ge.Code, ge.Message)
			return
		}
		grcError(c, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	c.JSON(http.StatusOK, result)
}


// GET /compliance/findings
// Returns manual rules (judgment_mode: "manual") from the ruleset catalog.
func (h *GRCHandler) ListFindings(c *gin.Context) {
	catalog, err := h.svc.GetRuleCatalog(c.Request.Context())
	if err != nil {
		grcError(c, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": catalog.Findings, "total": len(catalog.Findings)})
}

// GET /compliance/findings/summaries
func (h *GRCHandler) ListFindingClusterSummaries(c *gin.Context) {
	companyID := c.Query("company_id")
	if companyID == "" {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "company_id 필수")
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	items, totalCount, err := h.svc.ListFindingClusterSummaries(c.Request.Context(), companyID, page, pageSize)
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

// GET /compliance/rulesets/catalog
func (h *GRCHandler) GetRuleCatalog(c *gin.Context) {
	catalog, err := h.svc.GetRuleCatalog(c.Request.Context())
	if err != nil {
		grcError(c, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	c.JSON(http.StatusOK, catalog)
}

// POST /compliance/cluster/evaluate — 통합 클러스터 컴플라이언스 (경로 B+C 병합)
func (h *GRCHandler) EvaluateClusterCompliance(c *gin.Context) {
	var req service.ClusterComplianceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "JSON 파싱 실패: "+err.Error())
		return
	}
	if req.CompanyID == "" {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "company_id 필수")
		return
	}
	if req.ClusterName == "" {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "cluster_name 필수")
		return
	}

	result, err := h.svc.EvaluateClusterCompliance(c.Request.Context(), req)
	if err != nil {
		if ge, ok := err.(*service.GRCError); ok {
			grcError(c, ge.HTTPStatus, ge.Code, ge.Message)
			return
		}
		grcError(c, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	c.JSON(http.StatusOK, result)
}

// GET /compliance/overview — 전체 항목 한눈에 (최신 평가 결과 조회)
func (h *GRCHandler) GetComplianceOverview(c *gin.Context) {
	companyID := c.Query("company_id")
	if companyID == "" {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "company_id 필수")
		return
	}
	clusterName := c.Query("cluster_name") // optional

	result, err := h.svc.GetComplianceOverview(c.Request.Context(), companyID, clusterName)
	if err != nil {
		if ge, ok := err.(*service.GRCError); ok {
			grcError(c, ge.HTTPStatus, ge.Code, ge.Message)
			return
		}
		grcError(c, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	c.JSON(http.StatusOK, result)
}

// GET /compliance/findings/summary
func (h *GRCHandler) GetFindingsSummary(c *gin.Context) {
	companyID := c.Query("company_id")
	if companyID == "" {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "company_id 필수")
		return
	}
	clusterName := c.Query("cluster_name") // optional
	if clusterName == "" {
		clusterName = c.Query("cluster_id") // fallback
	}

	summary, err := h.svc.GetLatestFindingClusterSummary(c.Request.Context(), companyID, clusterName)
	if err != nil {
		if ge, ok := err.(*service.GRCError); ok {
			grcError(c, ge.HTTPStatus, ge.Code, ge.Message)
			return
		}
		grcError(c, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	c.JSON(http.StatusOK, summary)
}

// GET /compliance/pods/:pod_name/compliance
func (h *GRCHandler) GetPodCompliance(c *gin.Context) {
	podName := c.Param("pod_name")
	if podName == "" {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "pod_name 필수")
		return
	}

	companyID := c.Query("company_id")
	if companyID == "" {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "company_id 필수")
		return
	}
	clusterName := c.Query("cluster_name") // optional
	namespace := c.Query("namespace")      // optional

	result, err := h.svc.GetPodCompliance(c.Request.Context(), companyID, clusterName, namespace, podName)
	if err != nil {
		if ge, ok := err.(*service.GRCError); ok {
			grcError(c, ge.HTTPStatus, ge.Code, ge.Message)
			return
		}
		grcError(c, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	c.JSON(http.StatusOK, result)
}

// GET /compliance/items/:item_id/violations
func (h *GRCHandler) GetISMSPItemViolations(c *gin.Context) {
	itemID := c.Param("item_id")
	if itemID == "" {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "item_id 필수")
		return
	}
	companyID := c.Query("company_id")
	if companyID == "" {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "company_id 필수")
		return
	}
	clusterName := c.Query("cluster_name") // optional

	result, err := h.svc.GetISMSPItemViolations(c.Request.Context(), companyID, clusterName, itemID)
	if err != nil {
		if ge, ok := err.(*service.GRCError); ok {
			grcError(c, ge.HTTPStatus, ge.Code, ge.Message)
			return
		}
		grcError(c, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	c.JSON(http.StatusOK, result)
}

// GET /compliance/pods/:pod_name/violations
func (h *GRCHandler) GetPodViolations(c *gin.Context) {
	podName := c.Param("pod_name")
	if podName == "" {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "pod_name 필수")
		return
	}
	companyID := c.Query("company_id")
	if companyID == "" {
		grcError(c, http.StatusBadRequest, "INVALID_REQUEST", "company_id 필수")
		return
	}
	clusterName := c.Query("cluster_name") // optional
	namespace := c.Query("namespace")      // optional

	result, err := h.svc.GetPodViolations(c.Request.Context(), companyID, clusterName, namespace, podName)
	if err != nil {
		if ge, ok := err.(*service.GRCError); ok {
			grcError(c, ge.HTTPStatus, ge.Code, ge.Message)
			return
		}
		grcError(c, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	c.JSON(http.StatusOK, result)
}

func grcError(c *gin.Context, status int, code, message string) {
	c.JSON(status, gin.H{
		"error": gin.H{
			"code":    code,
			"message": message,
		},
	})
}
