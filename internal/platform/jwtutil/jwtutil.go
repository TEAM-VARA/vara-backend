// Package jwtutil 은 인증용 JWT(HS256) 발급/검증 헬퍼입니다.
// ticket(단기, purpose=mfa) 과 세션 토큰(purpose=session) 모두 같은 Claims 로 다룹니다.
package jwtutil

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims 는 VARA 인증 토큰의 커스텀 클레임입니다.
type Claims struct {
	Purpose    string `json:"purpose"`       // "mfa" | "session"
	MFA        string `json:"mfa,omitempty"` // ticket 전용: "setup" | "required"
	EmployeeID string `json:"employee_id"`
	Role       string `json:"role,omitempty"`
	jwt.RegisteredClaims
}

// Manager 는 서명 키와 issuer 를 보관합니다.
type Manager struct {
	secret []byte
	issuer string
}

func NewManager(secret, issuer string) *Manager {
	if issuer == "" {
		issuer = "VARA"
	}
	return &Manager{secret: []byte(secret), issuer: issuer}
}

// Issue 는 지정한 purpose/유효기간으로 토큰을 서명해 반환합니다.
func (m *Manager) Issue(purpose, employeeID, role, mfa string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := &Claims{
		Purpose:    purpose,
		MFA:        mfa,
		EmployeeID: employeeID,
		Role:       role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   employeeID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString(m.secret)
}

// Parse 는 서명·만료를 검증하고 Claims 를 반환합니다.
func (m *Manager) Parse(tokenStr string) (*Claims, error) {
	tok, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return m.secret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := tok.Claims.(*Claims)
	if !ok || !tok.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}
