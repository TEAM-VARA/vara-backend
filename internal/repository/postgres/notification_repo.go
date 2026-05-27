package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vara/backend/internal/domain/notification"
)

// NotificationRepo는 notifications 테이블 CRUD를 담당합니다.
type NotificationRepo struct {
	pool *pgxpool.Pool
}

func NewNotificationRepo(pool *pgxpool.Pool) *NotificationRepo {
	return &NotificationRepo{pool: pool}
}

// ─────────────────────────────────────────
// Create
// ─────────────────────────────────────────

// Create는 새 알림을 생성합니다.
func (r *NotificationRepo) Create(ctx context.Context, req notification.CreateRequest) (*notification.Notification, error) {
	if req.ClusterName == "" {
		return nil, errors.New("cluster_name is required")
	}
	if req.Severity == "" || req.Category == "" {
		return nil, errors.New("severity and category are required")
	}

	metadata := req.Metadata
	if len(metadata) == 0 {
		metadata = []byte("{}")
	}

	const query = `
		INSERT INTO notifications (
			cluster_name, severity, category, title, message, metadata
		) VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, cluster_name, severity, category, title, message, 
		          metadata, read_at, dismissed, created_at, updated_at
	`

	var n notification.Notification
	err := r.pool.QueryRow(ctx, query,
		req.ClusterName, req.Severity, req.Category,
		req.Title, req.Message, metadata,
	).Scan(
		&n.ID, &n.ClusterName, &n.Severity, &n.Category,
		&n.Title, &n.Message, &n.Metadata,
		&n.ReadAt, &n.Dismissed, &n.CreatedAt, &n.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create notification: %w", err)
	}

	return &n, nil
}

// ─────────────────────────────────────────
// List
// ─────────────────────────────────────────

// List는 필터링된 알림 목록을 반환합니다.
func (r *NotificationRepo) List(ctx context.Context, req notification.ListRequest) ([]notification.Notification, error) {
	if req.Limit <= 0 || req.Limit > 100 {
		req.Limit = 20
	}

	query := `
		SELECT id, cluster_name, severity, category, title, message,
		       metadata, read_at, dismissed, created_at, updated_at
		FROM notifications
		WHERE cluster_name = $1
		  AND dismissed = FALSE
	`
	args := []interface{}{req.ClusterName}
	argN := 2

	if req.UnreadOnly {
		query += " AND read_at IS NULL"
	}

	if req.Severity != "" {
		query += fmt.Sprintf(" AND severity = $%d", argN)
		args = append(args, req.Severity)
		argN++
	}

	if req.Category != "" {
		query += fmt.Sprintf(" AND category = $%d", argN)
		args = append(args, req.Category)
		argN++
	}

	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argN, argN+1)
	args = append(args, req.Limit, req.Offset)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list notifications: %w", err)
	}
	defer rows.Close()

	return scanNotifications(rows)
}

// ─────────────────────────────────────────
// Get By ID
// ─────────────────────────────────────────

// GetByID는 ID로 단일 알림을 조회합니다.
func (r *NotificationRepo) GetByID(ctx context.Context, id int64) (*notification.Notification, error) {
	const query = `
		SELECT id, cluster_name, severity, category, title, message,
		       metadata, read_at, dismissed, created_at, updated_at
		FROM notifications
		WHERE id = $1
	`

	var n notification.Notification
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&n.ID, &n.ClusterName, &n.Severity, &n.Category,
		&n.Title, &n.Message, &n.Metadata,
		&n.ReadAt, &n.Dismissed, &n.CreatedAt, &n.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get notification: %w", err)
	}

	return &n, nil
}

// ─────────────────────────────────────────
// Mark Read
// ─────────────────────────────────────────

// MarkRead는 알림을 읽음 처리합니다.
func (r *NotificationRepo) MarkRead(ctx context.Context, id int64) error {
	const query = `
		UPDATE notifications
		SET read_at = NOW(), updated_at = NOW()
		WHERE id = $1 AND read_at IS NULL
	`
	tag, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("mark read: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil // 이미 읽음 또는 존재 안 함 (idempotent)
	}
	return nil
}

// MarkAllRead는 클러스터의 모든 알림을 읽음 처리합니다.
func (r *NotificationRepo) MarkAllRead(ctx context.Context, clusterName string) (int64, error) {
	const query = `
		UPDATE notifications
		SET read_at = NOW(), updated_at = NOW()
		WHERE cluster_name = $1 AND read_at IS NULL AND dismissed = FALSE
	`
	tag, err := r.pool.Exec(ctx, query, clusterName)
	if err != nil {
		return 0, fmt.Errorf("mark all read: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ─────────────────────────────────────────
// Dismiss
// ─────────────────────────────────────────

// Dismiss는 알림을 숨김(dismiss) 처리합니다.
func (r *NotificationRepo) Dismiss(ctx context.Context, id int64) error {
	const query = `
		UPDATE notifications
		SET dismissed = TRUE, updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("dismiss notification: %w", err)
	}
	return nil
}

// ─────────────────────────────────────────
// Counts
// ─────────────────────────────────────────

// GetCounts는 unread/total 카운트를 반환합니다.
func (r *NotificationRepo) GetCounts(ctx context.Context, clusterName string) (*notification.CountResponse, error) {
	const query = `
		SELECT 
			COUNT(*) FILTER (WHERE read_at IS NULL AND dismissed = FALSE) AS unread,
			COUNT(*) FILTER (WHERE dismissed = FALSE) AS total
		FROM notifications
		WHERE cluster_name = $1
	`

	var c notification.CountResponse
	err := r.pool.QueryRow(ctx, query, clusterName).Scan(&c.Unread, &c.Total)
	if err != nil {
		return nil, fmt.Errorf("get counts: %w", err)
	}

	return &c, nil
}

// ─────────────────────────────────────────
// Deduplication (애플리케이션 레벨 중복 체크)
// ─────────────────────────────────────────

// ExistsRecentByVulnID는 같은 (cluster, category, vuln_id) 알림이 within 시간 내에 있는지 확인합니다.
func (r *NotificationRepo) ExistsRecentByVulnID(
	ctx context.Context,
	clusterName, category, vulnID string,
	within time.Duration,
) (bool, error) {
	const query = `
		SELECT EXISTS (
			SELECT 1 FROM notifications
			WHERE cluster_name = $1
			  AND category = $2
			  AND metadata->>'vuln_id' = $3
			  AND created_at > NOW() - $4::interval
			  AND dismissed = FALSE
		)
	`

	// pgx는 time.Duration을 직접 interval로 못 받음 → 문자열 변환
	intervalStr := fmt.Sprintf("%d seconds", int64(within.Seconds()))

	var exists bool
	err := r.pool.QueryRow(ctx, query, clusterName, category, vulnID, intervalStr).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check recent vuln notification: %w", err)
	}

	return exists, nil
}

// ─────────────────────────────────────────
// Cleanup
// ─────────────────────────────────────────

// DeleteOld는 오래된 (dismissed=true 또는 N일 이전 읽음) 알림을 삭제합니다.
func (r *NotificationRepo) DeleteOld(ctx context.Context, beforeDays int) (int64, error) {
	if beforeDays <= 0 {
		beforeDays = 30
	}

	const query = `
		DELETE FROM notifications
		WHERE (
			dismissed = TRUE
			OR (read_at IS NOT NULL AND read_at < NOW() - $1::interval)
		)
	`

	intervalStr := fmt.Sprintf("%d days", beforeDays)
	tag, err := r.pool.Exec(ctx, query, intervalStr)
	if err != nil {
		return 0, fmt.Errorf("delete old notifications: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ─────────────────────────────────────────
// 헬퍼: 행 스캔
// ─────────────────────────────────────────

func scanNotifications(rows pgx.Rows) ([]notification.Notification, error) {
	var result []notification.Notification
	for rows.Next() {
		var n notification.Notification
		err := rows.Scan(
			&n.ID, &n.ClusterName, &n.Severity, &n.Category,
			&n.Title, &n.Message, &n.Metadata,
			&n.ReadAt, &n.Dismissed, &n.CreatedAt, &n.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan notification: %w", err)
		}
		result = append(result, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}
	return result, nil
}