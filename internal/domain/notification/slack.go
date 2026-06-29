package notification

import "time"

// SlackSettings는 클러스터별 Slack 알림 연동 설정입니다 (slack_settings 1행에 대응).
//
// WebhookURL은 시크릿이다 — 로그/GET 응답에 평문 노출 금지(서비스 계층에서 MaskWebhook).
type SlackSettings struct {
	ClusterName string    `json:"cluster_name"`
	Enabled     bool      `json:"enabled"`
	WebhookURL  string    `json:"webhook_url"`
	MinSeverity string    `json:"min_severity"` // critical|high|medium|low|info
	Categories  []string  `json:"categories"`
	LastError   string    `json:"last_error,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// MaskWebhook은 webhook URL의 앞부분만 남기고 끝을 마스킹합니다 (평문 노출 방지).
// 빈 문자열이면 "" 반환.
func MaskWebhook(url string) string {
	if url == "" {
		return ""
	}
	// 앞 24자만 노출하고 나머지는 마스킹. 짧으면 전체를 마스킹 처리.
	const prefix = 24
	if len(url) <= prefix {
		return "****"
	}
	return url[:prefix] + "****"
}

// IsMasked는 값이 MaskWebhook이 만든 마스킹 형태(끝이 "****")인지 판별합니다.
// UpsertSettings에서 마스킹값이 들어오면 기존 webhook을 보존하는 데 씁니다.
func IsMasked(url string) bool {
	const suffix = "****"
	return len(url) >= len(suffix) && url[len(url)-len(suffix):] == suffix
}
