package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vara/backend/internal/domain/notification"
)

// SlackSettingsRepo는 클러스터별 Slack 연동 설정(slack_settings)을 읽고 씁니다.
//
// 주의: webhook_url은 시크릿이다. 이 레포는 평문을 저장/조회만 하며 절대 로그에 남기지 않는다.
type SlackSettingsRepo struct {
	pool *pgxpool.Pool
}

func NewSlackSettingsRepo(pool *pgxpool.Pool) *SlackSettingsRepo {
	return &SlackSettingsRepo{pool: pool}
}

// Get은 클러스터의 Slack 설정을 반환합니다. 행이 없으면 기본값(enabled=false)을 반환합니다.
func (r *SlackSettingsRepo) Get(ctx context.Context, cluster string) (*notification.SlackSettings, error) {
	const q = `
		SELECT cluster_name, enabled, webhook_url, min_severity, categories,
		       COALESCE(last_error, ''), updated_at
		FROM slack_settings WHERE cluster_name = $1`
	var s notification.SlackSettings
	err := r.pool.QueryRow(ctx, q, cluster).Scan(
		&s.ClusterName, &s.Enabled, &s.WebhookURL, &s.MinSeverity, &s.Categories,
		&s.LastError, &s.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		// 미설정 클러스터: 비활성 기본값.
		return &notification.SlackSettings{
			ClusterName: cluster,
			Enabled:     false,
			MinSeverity: notification.SeverityHigh,
			Categories:  []string{notification.CategoryNewCVE, notification.CategoryKEVAdded},
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get slack_settings: %w", err)
	}
	return &s, nil
}

// Upsert는 Slack 설정을 저장합니다 (cluster_name 기준 UPSERT, updated_at 갱신).
func (r *SlackSettingsRepo) Upsert(ctx context.Context, s notification.SlackSettings) error {
	const q = `
		INSERT INTO slack_settings (
			cluster_name, enabled, webhook_url, min_severity, categories, updated_at
		) VALUES ($1, $2, $3, $4, $5, NOW())
		ON CONFLICT (cluster_name) DO UPDATE SET
			enabled      = EXCLUDED.enabled,
			webhook_url  = EXCLUDED.webhook_url,
			min_severity = EXCLUDED.min_severity,
			categories   = EXCLUDED.categories,
			updated_at   = NOW()`
	_, err := r.pool.Exec(ctx, q,
		s.ClusterName, s.Enabled, s.WebhookURL, s.MinSeverity, s.Categories,
	)
	if err != nil {
		return fmt.Errorf("upsert slack_settings: %w", err)
	}
	return nil
}

// SetLastError는 마지막 전송 에러를 기록합니다 (빈 문자열이면 NULL로 비움).
func (r *SlackSettingsRepo) SetLastError(ctx context.Context, cluster, errMsg string) error {
	const q = `UPDATE slack_settings SET last_error = NULLIF($2, ''), updated_at = NOW() WHERE cluster_name = $1`
	if _, err := r.pool.Exec(ctx, q, cluster, errMsg); err != nil {
		return fmt.Errorf("set slack last_error: %w", err)
	}
	return nil
}
