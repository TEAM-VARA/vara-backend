package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vara/backend/internal/domain/agent"
	"github.com/vara/backend/internal/repository/postgres"
)

type AwsReaderHandler struct {
	repo *postgres.AwsReaderRepo
}

func NewAwsReaderHandler(repo *postgres.AwsReaderRepo) *AwsReaderHandler {
	return &AwsReaderHandler{repo: repo}
}

func (h *AwsReaderHandler) SecurityGroups(c *gin.Context) {
	var req agent.AwsSecurityGroupsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	saved, err := h.repo.UpsertSecurityGroups(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"saved": saved})
}

func (h *AwsReaderHandler) KmsKeys(c *gin.Context) {
	var req agent.AwsKmsKeysRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	saved, err := h.repo.UpsertKmsKeys(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"saved": saved})
}

func (h *AwsReaderHandler) EksAccessConfig(c *gin.Context) {
	var req agent.AwsEksAccessConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	saved, err := h.repo.UpsertEksAccessConfig(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"saved": saved})
}

func (h *AwsReaderHandler) CloudTrailTrails(c *gin.Context) {
	var req agent.AwsCloudTrailTrailsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	saved, err := h.repo.UpsertCloudTrailTrails(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"saved": saved})
}

func (h *AwsReaderHandler) IamAuthorization(c *gin.Context) {
	var req agent.AwsIamAuthorizationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	saved, err := h.repo.UpsertIamAuthorization(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"saved": saved})
}