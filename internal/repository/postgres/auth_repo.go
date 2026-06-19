package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vara/backend/internal/domain/auth"
)

// AuthRepo 는 auth_employees 테이블 접근을 담당합니다.
type AuthRepo struct {
	pool *pgxpool.Pool
}

func NewAuthRepo(pool *pgxpool.Pool) *AuthRepo {
	return &AuthRepo{pool: pool}
}

// GetByEmployeeID 는 사번으로 직원을 조회합니다. 없으면 auth.ErrNotFound.
func (r *AuthRepo) GetByEmployeeID(ctx context.Context, employeeID string) (*auth.Employee, error) {
	const q = `
		SELECT id, employee_id, password_hash, display_name, role,
		       mfa_secret, mfa_status, last_totp_step, is_active,
		       created_at, updated_at
		FROM auth_employees
		WHERE employee_id = $1
	`
	var (
		e      auth.Employee
		secret *string // nullable
	)
	err := r.pool.QueryRow(ctx, q, employeeID).Scan(
		&e.ID, &e.EmployeeID, &e.PasswordHash, &e.DisplayName, &e.Role,
		&secret, &e.MFAStatus, &e.LastTOTPStep, &e.IsActive,
		&e.CreatedAt, &e.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, auth.ErrNotFound
		}
		return nil, err
	}
	if secret != nil {
		e.MFASecret = *secret
	}
	return &e, nil
}

// SetPendingSecret 는 setup 단계에서 발급한 BASE32 secret 을 저장합니다.
// mfa_status 는 'setup' 으로 유지(미확정). last_totp_step 은 0 으로 초기화.
func (r *AuthRepo) SetPendingSecret(ctx context.Context, employeeID, secret string) error {
	const q = `
		UPDATE auth_employees
		SET mfa_secret = $2,
		    mfa_status = 'setup',
		    last_totp_step = 0,
		    updated_at = now()
		WHERE employee_id = $1
	`
	ct, err := r.pool.Exec(ctx, q, employeeID, secret)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return auth.ErrNotFound
	}
	return nil
}

// ConfirmMFA 는 첫 verify 성공 시 secret 을 확정하고 사용한 step 을 기록합니다.
func (r *AuthRepo) ConfirmMFA(ctx context.Context, employeeID string, step int64) error {
	const q = `
		UPDATE auth_employees
		SET mfa_status = 'confirmed',
		    last_totp_step = $2,
		    updated_at = now()
		WHERE employee_id = $1
	`
	ct, err := r.pool.Exec(ctx, q, employeeID, step)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return auth.ErrNotFound
	}
	return nil
}

// UpdateLastStep 는 replay 방지용으로 직전 사용 step 을 갱신합니다.
func (r *AuthRepo) UpdateLastStep(ctx context.Context, employeeID string, step int64) error {
	const q = `
		UPDATE auth_employees
		SET last_totp_step = $2,
		    updated_at = now()
		WHERE employee_id = $1
	`
	_, err := r.pool.Exec(ctx, q, employeeID, step)
	return err
}
