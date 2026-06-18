package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/vara/backend/internal/domain/auth"
	"github.com/vara/backend/internal/platform/jwtutil"
)

// 컨텍스트 키
const (
	CtxEmployeeID = "employee_id"
	CtxRole       = "role"
)

// RequireAuth 는 Authorization: Bearer <session JWT> 를 검증하는 미들웨어입니다.
// 통과 시 employee_id / role 을 gin 컨텍스트에 주입합니다.
//
// 현재 기존 라우트에는 미적용(데모 흐름 보존). 보호가 필요한 그룹에만
//   api.Use(middleware.RequireAuth(jwtMgr))
// 형태로 선택 적용하세요.
func RequireAuth(mgr *jwtutil.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.GetHeader("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
		claims, err := mgr.Parse(token)
		if err != nil || claims.Purpose != auth.PurposeSession || claims.EmployeeID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}
		c.Set(CtxEmployeeID, claims.EmployeeID)
		c.Set(CtxRole, claims.Role)
		c.Next()
	}
}
