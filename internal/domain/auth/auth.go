package auth

import (
	"errors"
	"time"
)

// ─────────────────────────────────────────
// MFA 상태 (auth_employees.mfa_status)
// ─────────────────────────────────────────
const (
	MFAStatusSetup     = "setup"     // secret 미확정(미등록 또는 등록 중)
	MFAStatusConfirmed = "confirmed" // 첫 verify 통과 → 확정
)

// ─────────────────────────────────────────
// login 응답의 mfa 필드 값 (FE 분기 키)
// ─────────────────────────────────────────
const (
	MFAResultSetup    = "setup"    // 최초 등록 단계로 (QR)
	MFAResultRequired = "required" // 6자리 입력 단계로
)

// ─────────────────────────────────────────
// JWT purpose (ticket vs 세션 구분)
// ─────────────────────────────────────────
const (
	PurposeMFA     = "mfa"     // login 통과 표시용 단기 ticket
	PurposeSession = "session" // mfa/verify 통과 후 세션 토큰
)

// ─────────────────────────────────────────
// 도메인 에러 (핸들러에서 HTTP 상태로 매핑)
// ─────────────────────────────────────────
var (
	ErrInvalidCredentials = errors.New("invalid credentials")       // 401
	ErrInvalidTicket      = errors.New("invalid or expired ticket") // 401
	ErrInvalidCode        = errors.New("invalid or expired code")   // 401
	ErrRateLimited        = errors.New("too many attempts")         // 429
	ErrNotFound           = errors.New("employee not found")        // 내부용
)

// Employee 는 auth_employees 한 행입니다.
type Employee struct {
	ID           int64
	EmployeeID   string
	PasswordHash string
	DisplayName  string
	Role         string
	MFASecret    string // BASE32 ("" = 미발급)
	MFAStatus    string
	LastTOTPStep int64
	IsActive     bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// ─────────────────────────────────────────
// API DTO (FE 계약 1:1 — 평문 JSON, Envelope 미사용)
// ─────────────────────────────────────────

// LoginRequest : POST /api/v1/auth/login
type LoginRequest struct {
	EmployeeID string `json:"employee_id"`
	Password   string `json:"password"`
}

type LoginResponse struct {
	MFA    string `json:"mfa"`    // "setup" | "required"
	Ticket string `json:"ticket"` // ~5분 수명 임시 JWT
}

// SetupRequest : POST /api/v1/auth/mfa/setup
type SetupRequest struct {
	Ticket string `json:"ticket"`
}

type SetupResponse struct {
	OTPAuthURL string `json:"otpauth_url"` // otpauth://totp/VARA:<empid>?secret=...&issuer=VARA
	Secret     string `json:"secret"`      // 수동 입력 대체용 BASE32
}

// VerifyRequest : POST /api/v1/auth/mfa/verify (등록 확인 & 일반 로그인 공용)
type VerifyRequest struct {
	Ticket string `json:"ticket"`
	Code   string `json:"code"`
}

type VerifyResponse struct {
	Token      string `json:"token"` // 세션 JWT
	EmployeeID string `json:"employee_id"`
}
