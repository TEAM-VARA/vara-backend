package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/vara/backend/internal/domain/notification"
	"github.com/vara/backend/internal/repository/postgres"
)

// SlackService는 알림을 Slack incoming webhook으로 자동 발화합니다.
//
// 자동 발화 진입점은 Dispatch이며, NotificationService.persist(저장 직후 단일 지점)에서
// 호출됩니다 → 알림 1건당 최대 1회 발화(중복 없음).
//
// 시크릿 주의: webhook_url은 로그/GET 응답에 평문 노출 금지.
//   - 외부로 나가는 GetSettings는 MaskWebhook으로 치환.
//   - 전송 실패 로그에도 URL을 절대 포함하지 않는다.
type SlackService struct {
	repo             *postgres.SlackSettingsRepo
	http             *http.Client
	dashboardBaseURL string

	mu       sync.Mutex
	lastSent map[string]time.Time // cluster → 마지막 전송 시각 (rate limit 직렬화)
}

// NewSlackService는 SlackService를 생성합니다. dashboardBaseURL은 딥링크 prefix.
func NewSlackService(repo *postgres.SlackSettingsRepo, dashboardBaseURL string) *SlackService {
	return &SlackService{
		repo:             repo,
		http:             &http.Client{Timeout: 5 * time.Second},
		dashboardBaseURL: strings.TrimRight(dashboardBaseURL, "/"),
		lastSent:         map[string]time.Time{},
	}
}

// GetSettings는 클러스터의 Slack 설정을 반환합니다. WebhookURL은 마스킹됩니다(평문 금지).
func (s *SlackService) GetSettings(ctx context.Context, cluster string) (*notification.SlackSettings, error) {
	settings, err := s.repo.Get(ctx, cluster)
	if err != nil {
		return nil, err
	}
	settings.WebhookURL = notification.MaskWebhook(settings.WebhookURL)
	return settings, nil
}

// UpsertSettings는 설정을 저장합니다.
// webhook_url이 마스킹값("...****")이면 기존 webhook을 보존하고 다른 필드만 갱신합니다.
func (s *SlackService) UpsertSettings(ctx context.Context, in notification.SlackSettings) error {
	if in.ClusterName == "" {
		return fmt.Errorf("cluster_name is required")
	}
	if notification.IsMasked(in.WebhookURL) {
		// FE가 마스킹된 값을 그대로 돌려보낸 경우 → 실제 URL 덮어쓰지 않음.
		existing, err := s.repo.Get(ctx, in.ClusterName)
		if err != nil {
			return err
		}
		in.WebhookURL = existing.WebhookURL
	}
	if in.MinSeverity == "" {
		in.MinSeverity = notification.SeverityHigh
	}
	if in.Categories == nil {
		in.Categories = []string{}
	}
	return s.repo.Upsert(ctx, in)
}

// Test는 저장된 webhook으로 테스트 메시지 1건을 전송하고 성공/실패를 반환합니다.
func (s *SlackService) Test(ctx context.Context, cluster string) (string, error) {
	settings, err := s.repo.Get(ctx, cluster)
	if err != nil {
		return "error", err
	}
	if settings.WebhookURL == "" {
		return "no_webhook", fmt.Errorf("webhook이 설정되지 않았습니다")
	}
	text := fmt.Sprintf(":white_check_mark: VARA Slack 연동 테스트 (cluster=%s)\n알림이 정상적으로 전송됩니다.", cluster)
	if err := s.post(ctx, settings.WebhookURL, text); err != nil {
		_ = s.repo.SetLastError(ctx, cluster, err.Error())
		return "failed", err
	}
	_ = s.repo.SetLastError(ctx, cluster, "")
	return "ok", nil
}

// Dispatch는 자동 발화 진입점입니다. 설정·심각도·카테고리 매칭 시 비동기로 Slack 전송합니다.
// 비치명적: 어떤 실패도 알림 생성/파이프라인을 막지 않습니다.
func (s *SlackService) Dispatch(ctx context.Context, n *notification.Notification) {
	if n == nil {
		return
	}
	settings, err := s.repo.Get(ctx, n.ClusterName)
	if err != nil || settings == nil {
		return
	}
	if !settings.Enabled || settings.WebhookURL == "" {
		return
	}
	if slackSeverityRank(n.Severity) < slackSeverityRank(settings.MinSeverity) {
		return
	}
	if !sliceContains(settings.Categories, n.Category) {
		return
	}

	text := s.buildMessage(n)
	webhook := settings.WebhookURL
	cluster := n.ClusterName
	go func() {
		// 새 context (호출 context가 끝나도 전송은 계속). 비치명적.
		bg, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		if err := s.post(bg, webhook, text); err != nil {
			// URL은 로그 금지 — cluster/메시지 요약만.
			log.Printf("slack: dispatch failed (cluster=%s, category=%s): %v", cluster, n.Category, err)
			_ = s.repo.SetLastError(bg, cluster, err.Error())
			return
		}
		_ = s.repo.SetLastError(bg, cluster, "")
	}()
}

// buildMessage는 알림 1건을 Slack 텍스트로 변환합니다.
func (s *SlackService) buildMessage(n *notification.Notification) string {
	var b strings.Builder
	fmt.Fprintf(&b, "*[%s] %s*\n", strings.ToUpper(n.Severity), n.Title)
	if n.Message != "" {
		fmt.Fprintf(&b, "%s\n", n.Message)
	}

	// metadata 파싱 (new_cve/kev_added 구조 기준 — 다른 카테고리는 빈 값이라 무시됨).
	var meta notification.NewCVEMetadata
	_ = json.Unmarshal(n.Metadata, &meta)

	var details []string
	if meta.VulnID != "" {
		details = append(details, fmt.Sprintf("vuln_id: `%s`", meta.VulnID))
	}
	if meta.TopCVE != "" && meta.TopCVE != meta.VulnID {
		details = append(details, fmt.Sprintf("top_cve: `%s`", meta.TopCVE))
	}
	if meta.AffectedCount > 0 {
		details = append(details, fmt.Sprintf("affected_pods: %d", meta.AffectedCount))
	}
	if meta.MaxScoreDelta > 0 {
		details = append(details, fmt.Sprintf("max_score_delta: +%.1f", meta.MaxScoreDelta))
	}
	if len(details) > 0 {
		fmt.Fprintf(&b, "%s\n", strings.Join(details, " · "))
	}

	// 권장 조치(패치 fix 버전): metadata에 fixed 버전 정보가 아직 없어 생략한다.
	// TODO: todo-cve-remediation-fixedversion 연계 시 "<pkg> → <fixed> 업그레이드" 추가.

	// 딥링크
	if s.dashboardBaseURL != "" {
		link := s.dashboardBaseURL + "/notifications"
		if len(meta.AffectedPodList) > 0 && meta.AffectedPodList[0].PodUID != "" {
			link = s.dashboardBaseURL + "/blast-radius?focus=" + meta.AffectedPodList[0].PodUID
		}
		fmt.Fprintf(&b, "<%s|대시보드에서 보기>", link)
	}
	return b.String()
}

// post는 webhook으로 JSON 메시지를 전송합니다 (rate limit 직렬화 포함).
// 실패 시 에러 반환 — 단, 에러 메시지에 webhook URL은 절대 포함하지 않는다.
func (s *SlackService) post(ctx context.Context, webhook, text string) error {
	s.throttle(webhook)

	body, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook, bytes.NewReader(body))
	if err != nil {
		// err에는 URL이 포함될 수 있어 그대로 노출하지 않는다.
		return fmt.Errorf("build request failed")
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.http.Do(req)
	if err != nil {
		// net 에러 메시지에는 URL이 들어갈 수 있으므로 일반화한다.
		return fmt.Errorf("slack request failed (network/timeout)")
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		// 응답 본문은 Slack 에러 사유(예: invalid_payload)라 URL 미포함 — 일부만 노출.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("slack returned %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
}

// throttle은 같은 webhook(클러스터) 대상 전송을 1초 간격으로 직렬화합니다.
// 폭주 시 묶음전송(digest)은 TODO.
func (s *SlackService) throttle(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if last, ok := s.lastSent[key]; ok {
		if wait := time.Second - time.Since(last); wait > 0 {
			time.Sleep(wait)
		}
	}
	s.lastSent[key] = time.Now()
}

// slackSeverityRank: critical=4, high=3, medium=2, low=1, info=0.
func slackSeverityRank(severity string) int {
	switch severity {
	case notification.SeverityCritical:
		return 4
	case notification.SeverityHigh:
		return 3
	case notification.SeverityMedium:
		return 2
	case notification.SeverityLow:
		return 1
	default:
		return 0
	}
}

func sliceContains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}
