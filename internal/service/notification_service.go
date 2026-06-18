package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/vara/backend/internal/domain/notification"
	"github.com/vara/backend/internal/repository/postgres"
)

// NotificationService는 알림 생성/조회 비즈니스 로직을 담당합니다.
//
// 카테고리별 편의 메서드:
//   - CreateNewCVE: 신규 CVE 발견 알림 (24h dedup)
//   - CreateRiskChange: Pod 위험도 변경 (1h dedup)
//   - CreateScanComplete: 스캔 완료 요약 (no dedup)
//   - CreateKEVAdded: KEV 등재 알림 (24h dedup)
//   - CreateToxicCombo: Toxic 조합 매칭 (1h dedup)
type NotificationService struct {
	repo *postgres.NotificationRepo
}

func NewNotificationService(repo *postgres.NotificationRepo) *NotificationService {
	return &NotificationService{repo: repo}
}

// ─────────────────────────────────────────
// 기본 CRUD
// ─────────────────────────────────────────

// Create는 알림을 생성합니다 (단순, dedup 없음).
func (s *NotificationService) Create(ctx context.Context, req notification.CreateRequest) (*notification.Notification, error) {
	return s.repo.Create(ctx, req)
}

// List는 알림 목록을 반환합니다.
func (s *NotificationService) List(ctx context.Context, req notification.ListRequest) (*notification.ListResponse, error) {
	notifs, err := s.repo.List(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("list: %w", err)
	}

	counts, err := s.repo.GetCounts(ctx, req.ClusterName)
	if err != nil {
		return nil, fmt.Errorf("get counts: %w", err)
	}

	return &notification.ListResponse{
		Total:         counts.Total,
		Unread:        counts.Unread,
		Notifications: notifs,
	}, nil
}

// GetCounts는 unread/total 카운트만 반환합니다 (FE 폴링용).
func (s *NotificationService) GetCounts(ctx context.Context, clusterName string) (*notification.CountResponse, error) {
	return s.repo.GetCounts(ctx, clusterName)
}

// MarkRead는 알림을 읽음 처리합니다.
func (s *NotificationService) MarkRead(ctx context.Context, id int64) error {
	return s.repo.MarkRead(ctx, id)
}

// MarkAllRead는 클러스터의 모든 알림을 읽음 처리합니다.
func (s *NotificationService) MarkAllRead(ctx context.Context, clusterName string) (int64, error) {
	return s.repo.MarkAllRead(ctx, clusterName)
}

// Dismiss는 알림을 숨김 처리합니다.
func (s *NotificationService) Dismiss(ctx context.Context, id int64) error {
	return s.repo.Dismiss(ctx, id)
}

// ─────────────────────────────────────────
// 카테고리별 편의 메서드 (with dedup)
// ─────────────────────────────────────────

// CreateNewCVE는 신규 CVE 발견 알림을 생성합니다 (24h dedup).
func (s *NotificationService) CreateNewCVE(
	ctx context.Context,
	clusterName string,
	meta notification.NewCVEMetadata,
) (*notification.Notification, error) {
	// 중복 체크
	exists, err := s.repo.ExistsRecentByVulnID(
		ctx, clusterName, notification.CategoryNewCVE, meta.VulnID, 24*time.Hour,
	)
	if err != nil {
		return nil, fmt.Errorf("dedup check: %w", err)
	}
	if exists {
		return nil, nil // 24시간 내 동일 알림 존재 → skip
	}

	// 메타 직렬화
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("marshal metadata: %w", err)
	}

	// severity 매핑
	severity := mapSeverityLabel(meta.SeverityLabel)

	// 타이틀/메시지
	severityEmoji := severityEmoji(severity)
	title := fmt.Sprintf("%s 신규 %s CVE 발견: %s", severityEmoji, meta.SeverityLabel, meta.VulnID)
	message := fmt.Sprintf("%d개 Pod 영향, 즉시 대응 필요", meta.AffectedCount)
	if meta.AffectedCount == 0 {
		message = "패키지에 신규 CVE 발견 (영향 Pod 없음)"
	}
	// 점수 변화 문구 (B): 이 CVE로 가장 크게 오른 Pod의 상승폭
	if meta.MaxScoreDelta > 0 {
		message += fmt.Sprintf(" · 위험도 최대 +%.1f점 상승(%s)", meta.MaxScoreDelta, meta.MaxScoreDeltaPodName)
	}

	return s.repo.Create(ctx, notification.CreateRequest{
		ClusterName: clusterName,
		Severity:    severity,
		Category:    notification.CategoryNewCVE,
		Title:       title,
		Message:     message,
		Metadata:    metaJSON,
	})
}

// ExistsRecentNewCVE는 24시간 내 동일 vuln_id의 new_cve 알림이 이미 있는지 반환합니다.
// 스케줄러가 재계산(점수 델타 산정) 전에 미리 dedup을 확인해 불필요한 재계산을 건너뛰는 용도.
func (s *NotificationService) ExistsRecentNewCVE(ctx context.Context, clusterName, vulnID string) (bool, error) {
	return s.repo.ExistsRecentByVulnID(ctx, clusterName, notification.CategoryNewCVE, vulnID, 24*time.Hour)
}

// CreateRiskChange는 Pod 위험도 변경 알림을 생성합니다 (1h dedup).
func (s *NotificationService) CreateRiskChange(
	ctx context.Context,
	clusterName string,
	meta notification.RiskChangeMetadata,
) (*notification.Notification, error) {
	// 같은 Pod의 변경은 1시간 내 중복 방지 (vuln_id 자리에 pod_uid 사용)
	exists, err := s.repo.ExistsRecentByVulnID(
		ctx, clusterName, notification.CategoryRiskChange, meta.PodUID, 1*time.Hour,
	)
	if err != nil {
		return nil, fmt.Errorf("dedup check: %w", err)
	}
	if exists {
		return nil, nil
	}

	// metadata에 pod_uid를 vuln_id 슬롯에도 넣음 (dedup index 활용)
	type riskChangeWithDedup struct {
		notification.RiskChangeMetadata
		VulnID string `json:"vuln_id"`
	}
	withDedup := riskChangeWithDedup{
		RiskChangeMetadata: meta,
		VulnID:             meta.PodUID,
	}
	metaJSON, err := json.Marshal(withDedup)
	if err != nil {
		return nil, fmt.Errorf("marshal metadata: %w", err)
	}

	// 위험도가 상승했을 때만 critical/high
	severity := notification.SeverityMedium
	if isLevelUp(meta.PreviousLevel, meta.NewLevel) {
		severity = mapRiskLevelToSeverity(meta.NewLevel)
	}

	severityEmoji := severityEmoji(severity)
	title := fmt.Sprintf("%s 위험도 변경: %s", severityEmoji, meta.PodName)
	message := fmt.Sprintf("%s → %s (점수: %.1f → %.1f)",
		meta.PreviousLevel, meta.NewLevel, meta.PreviousScore, meta.NewScore)

	return s.repo.Create(ctx, notification.CreateRequest{
		ClusterName: clusterName,
		Severity:    severity,
		Category:    notification.CategoryRiskChange,
		Title:       title,
		Message:     message,
		Metadata:    metaJSON,
	})
}

// CreateScanComplete는 스캔 완료 요약 알림을 생성합니다 (no dedup, 매번 생성).
func (s *NotificationService) CreateScanComplete(
	ctx context.Context,
	clusterName string,
	meta notification.ScanCompleteMetadata,
) (*notification.Notification, error) {
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("marshal metadata: %w", err)
	}

	severity := notification.SeverityInfo
	if meta.NewVulnsCount > 0 {
		severity = notification.SeverityLow
	}
	if meta.CriticalCount > 0 {
		severity = notification.SeverityHigh
	}

	title := fmt.Sprintf("ℹ️  자동 스캔 완료: %d 이미지", meta.ScannedImages)
	message := fmt.Sprintf("신규 vuln %d개 (critical %d, high %d, %.1fs 소요)",
		meta.NewVulnsCount, meta.CriticalCount, meta.HighCount, meta.DurationSeconds)

	return s.repo.Create(ctx, notification.CreateRequest{
		ClusterName: clusterName,
		Severity:    severity,
		Category:    notification.CategoryScanComplete,
		Title:       title,
		Message:     message,
		Metadata:    metaJSON,
	})
}

// CreateKEVAdded는 기존 CVE가 KEV에 등재된 알림을 생성합니다 (24h dedup).
func (s *NotificationService) CreateKEVAdded(
	ctx context.Context,
	clusterName string,
	meta notification.NewCVEMetadata,
) (*notification.Notification, error) {
	exists, err := s.repo.ExistsRecentByVulnID(
		ctx, clusterName, notification.CategoryKEVAdded, meta.VulnID, 24*time.Hour,
	)
	if err != nil {
		return nil, fmt.Errorf("dedup check: %w", err)
	}
	if exists {
		return nil, nil
	}

	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("marshal metadata: %w", err)
	}

	title := fmt.Sprintf("🚨 CVE가 KEV에 등재: %s", meta.VulnID)
	message := fmt.Sprintf("CISA가 '실제 악용 중'으로 분류. %d개 Pod 영향", meta.AffectedCount)

	return s.repo.Create(ctx, notification.CreateRequest{
		ClusterName: clusterName,
		Severity:    notification.SeverityCritical,
		Category:    notification.CategoryKEVAdded,
		Title:       title,
		Message:     message,
		Metadata:    metaJSON,
	})
}

// ─────────────────────────────────────────
// 유틸리티
// ─────────────────────────────────────────

// mapSeverityLabel은 OSV의 severity_label을 우리 severity로 매핑합니다.
func mapSeverityLabel(label string) string {
	switch label {
	case "Critical":
		return notification.SeverityCritical
	case "High":
		return notification.SeverityHigh
	case "Medium":
		return notification.SeverityMedium
	case "Low":
		return notification.SeverityLow
	default:
		return notification.SeverityInfo
	}
}

// mapRiskLevelToSeverity는 final risk_level을 severity로 매핑합니다.
func mapRiskLevelToSeverity(riskLevel string) string {
	switch riskLevel {
	case "emergency":
		return notification.SeverityCritical
	case "warning":
		return notification.SeverityHigh
	case "caution":
		return notification.SeverityMedium
	case "safe":
		return notification.SeverityLow
	default:
		return notification.SeverityInfo
	}
}

// severityEmoji는 severity별 이모지를 반환합니다.
func severityEmoji(severity string) string {
	switch severity {
	case notification.SeverityCritical:
		return "🚨"
	case notification.SeverityHigh:
		return "🔴"
	case notification.SeverityMedium:
		return "🟠"
	case notification.SeverityLow:
		return "🟡"
	default:
		return "ℹ️"
	}
}

// isLevelUp은 위험도가 상승했는지 판단합니다.
func isLevelUp(previous, current string) bool {
	rank := map[string]int{
		"safe":      0,
		"caution":   1,
		"warning":   2,
		"emergency": 3,
	}
	prev, ok1 := rank[previous]
	curr, ok2 := rank[current]
	if !ok1 || !ok2 {
		return false
	}
	return curr > prev
}