package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/vara/backend/internal/domain/auth"
	"github.com/vara/backend/internal/service"
)

// AuthHandler 는 /api/v1/auth/* 엔드포인트를 담당합니다.
// 응답은 FE 계약에 맞춰 평문 JSON 입니다(Envelope 미사용).
type AuthHandler struct {
	svc *service.AuthService
}

func NewAuthHandler(svc *service.AuthService) *AuthHandler {
	return &AuthHandler{svc: svc}
}

// Login : POST /api/v1/auth/login
// req {employee_id, password} → 200 {mfa, ticket} | 401
func (h *AuthHandler) Login(c *gin.Context) {
	var req auth.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	res, err := h.svc.Login(c.Request.Context(), req)
	if err != nil {
		writeAuthError(c, err)
		return
	}
	c.JSON(http.StatusOK, res)
}

// MFASetup : POST /api/v1/auth/mfa/setup
// req {ticket} → 200 {otpauth_url, secret} | 401
func (h *AuthHandler) MFASetup(c *gin.Context) {
	var req auth.SetupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	res, err := h.svc.Setup(c.Request.Context(), req)
	if err != nil {
		writeAuthError(c, err)
		return
	}
	c.JSON(http.StatusOK, res)
}

// MFAVerify : POST /api/v1/auth/mfa/verify
// req {ticket, code} → 200 {token, employee_id} | 401
func (h *AuthHandler) MFAVerify(c *gin.Context) {
	var req auth.VerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	res, err := h.svc.Verify(c.Request.Context(), req)
	if err != nil {
		writeAuthError(c, err)
		return
	}
	c.JSON(http.StatusOK, res)
}

// Logout : POST /api/v1/auth/logout → 200
func (h *AuthHandler) Logout(c *gin.Context) {
	_ = h.svc.Logout(c.Request.Context())
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// writeAuthError 는 도메인 에러를 HTTP 상태로 매핑합니다.
func writeAuthError(c *gin.Context, err error) {
	switch err {
	case auth.ErrInvalidCredentials, auth.ErrInvalidTicket, auth.ErrInvalidCode:
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
	case auth.ErrRateLimited:
		c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
	}
}
