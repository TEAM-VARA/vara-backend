package service

import (
	"context"
	"crypto/subtle"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"

	"github.com/vara/backend/internal/domain/auth"
	"github.com/vara/backend/internal/platform/jwtutil"
	"github.com/vara/backend/internal/repository/postgres"
)

// ─────────────────────────────────────────
// 정책 상수
// ─────────────────────────────────────────
const (
	ticketTTL  = 5 * time.Minute // login 통과 → mfa 단계 제한시간
	sessionTTL = 12 * time.Hour  // 세션 토큰 수명
	totpPeriod = 30              // TOTP 30초
	totpDigits = otp.DigitsSix   // 6자리

	loginRateLimit  = 10 // 사번당 rateWindow 내 login 시도
	verifyRateLimit = 7  // 사번당 rateWindow 내 verify 시도
	rateWindow      = 5 * time.Minute
)

// AuthService 는 로그인 + TOTP MFA 비즈니스 로직을 담당합니다.
type AuthService struct {
	repo   *postgres.AuthRepo
	jwt    *jwtutil.Manager
	rdb    *redis.Client // rate-limit (nil 허용 → 제한 생략)
	issuer string
}

func NewAuthService(repo *postgres.AuthRepo, jwt *jwtutil.Manager, rdb *redis.Client, issuer string) *AuthService {
	if issuer == "" {
		issuer = "VARA"
	}
	return &AuthService{repo: repo, jwt: jwt, rdb: rdb, issuer: issuer}
}

// Login 은 사번/비밀번호를 검증하고 mfa 단계용 ticket 을 발급합니다.
func (s *AuthService) Login(ctx context.Context, req auth.LoginRequest) (*auth.LoginResponse, error) {
	empID := strings.TrimSpace(req.EmployeeID)
	if empID == "" || req.Password == "" {
		return nil, auth.ErrInvalidCredentials
	}
	if !s.allow(ctx, "auth:rl:login:"+empID, loginRateLimit) {
		return nil, auth.ErrRateLimited
	}

	emp, err := s.repo.GetByEmployeeID(ctx, empID)
	if err != nil {
		if err == auth.ErrNotFound {
			// 사용자 열거 방지 — 자격 증명 오류로 통일
			return nil, auth.ErrInvalidCredentials
		}
		return nil, err
	}
	if !emp.IsActive {
		return nil, auth.ErrInvalidCredentials
	}
	if bcrypt.CompareHashAndPassword([]byte(emp.PasswordHash), []byte(req.Password)) != nil {
		return nil, auth.ErrInvalidCredentials
	}

	mfa := auth.MFAResultSetup
	if emp.MFAStatus == auth.MFAStatusConfirmed {
		mfa = auth.MFAResultRequired
	}

	ticket, err := s.jwt.Issue(auth.PurposeMFA, emp.EmployeeID, emp.Role, mfa, ticketTTL)
	if err != nil {
		return nil, err
	}
	return &auth.LoginResponse{MFA: mfa, Ticket: ticket}, nil
}

// Setup 은 ticket 을 검증하고 새 TOTP secret(미확정)을 발급합니다.
func (s *AuthService) Setup(ctx context.Context, req auth.SetupRequest) (*auth.SetupResponse, error) {
	claims, err := s.parseTicket(req.Ticket)
	if err != nil {
		return nil, err
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.issuer,
		AccountName: claims.EmployeeID,
		Period:      totpPeriod,
		Digits:      totpDigits,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, err
	}
	if err := s.repo.SetPendingSecret(ctx, claims.EmployeeID, key.Secret()); err != nil {
		return nil, err
	}
	return &auth.SetupResponse{OTPAuthURL: key.URL(), Secret: key.Secret()}, nil
}

// Verify 는 ticket + 6자리 코드를 검증하고 세션 토큰을 발급합니다.
// 등록(setup) 단계면 첫 성공 시 secret 을 확정합니다.
func (s *AuthService) Verify(ctx context.Context, req auth.VerifyRequest) (*auth.VerifyResponse, error) {
	claims, err := s.parseTicket(req.Ticket)
	if err != nil {
		return nil, err
	}
	if !s.allow(ctx, "auth:rl:verify:"+claims.EmployeeID, verifyRateLimit) {
		return nil, auth.ErrRateLimited
	}

	emp, err := s.repo.GetByEmployeeID(ctx, claims.EmployeeID)
	if err != nil {
		if err == auth.ErrNotFound {
			return nil, auth.ErrInvalidCode
		}
		return nil, err
	}
	if !emp.IsActive || emp.MFASecret == "" {
		// secret 미발급 상태에서 verify 호출 → setup 필요
		return nil, auth.ErrInvalidCode
	}

	code := strings.TrimSpace(strings.ReplaceAll(req.Code, " ", ""))
	step, ok := validateTOTP(emp.MFASecret, code, emp.LastTOTPStep)
	if !ok {
		return nil, auth.ErrInvalidCode
	}

	if emp.MFAStatus == auth.MFAStatusConfirmed {
		if err := s.repo.UpdateLastStep(ctx, emp.EmployeeID, step); err != nil {
			return nil, err
		}
	} else {
		// 첫 검증 성공 → secret 확정
		if err := s.repo.ConfirmMFA(ctx, emp.EmployeeID, step); err != nil {
			return nil, err
		}
	}

	token, err := s.jwt.Issue(auth.PurposeSession, emp.EmployeeID, emp.Role, "", sessionTTL)
	if err != nil {
		return nil, err
	}
	return &auth.VerifyResponse{Token: token, EmployeeID: emp.EmployeeID}, nil
}

// Logout 은 현재 stateless JWT 라 서버측 처리가 없습니다.
// TODO(보안): 토큰 denylist / refresh 토큰 폐기 도입.
func (s *AuthService) Logout(ctx context.Context) error {
	return nil
}

// ─────────────────────────────────────────
// 내부 헬퍼
// ─────────────────────────────────────────

// parseTicket 은 ticket JWT 를 검증하고 purpose 가 mfa 인지 확인합니다.
func (s *AuthService) parseTicket(ticket string) (*jwtutil.Claims, error) {
	if strings.TrimSpace(ticket) == "" {
		return nil, auth.ErrInvalidTicket
	}
	claims, err := s.jwt.Parse(ticket)
	if err != nil || claims.Purpose != auth.PurposeMFA || claims.EmployeeID == "" {
		return nil, auth.ErrInvalidTicket
	}
	return claims, nil
}

// validateTOTP 는 skew ±1 step 범위에서 코드를 검증하고, 매칭된 step 을 반환합니다.
// step 이 lastStep 이하이면 replay 로 간주해 거부합니다.
func validateTOTP(secret, code string, lastStep int64) (int64, bool) {
	if len(code) == 0 {
		return 0, false
	}
	now := time.Now().UTC()
	opts := totp.ValidateOpts{
		Period:    totpPeriod,
		Skew:      0, // skew 는 아래 루프에서 직접 처리
		Digits:    totpDigits,
		Algorithm: otp.AlgorithmSHA1,
	}
	for _, delta := range []int64{-1, 0, 1} {
		t := now.Add(time.Duration(delta*totpPeriod) * time.Second)
		cand, err := totp.GenerateCodeCustom(secret, t, opts)
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(cand), []byte(code)) == 1 {
			step := t.Unix() / totpPeriod
			if step <= lastStep {
				return step, false // replay
			}
			return step, true
		}
	}
	return 0, false
}

// allow 는 Redis 기반 간단 rate-limit 입니다. rdb 부재/오류 시 통과(graceful).
func (s *AuthService) allow(ctx context.Context, key string, limit int) bool {
	if s.rdb == nil {
		return true
	}
	n, err := s.rdb.Incr(ctx, key).Result()
	if err != nil {
		return true
	}
	if n == 1 {
		s.rdb.Expire(ctx, key, rateWindow)
	}
	return n <= int64(limit)
}
