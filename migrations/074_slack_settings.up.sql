-- migrations/074_slack_settings.up.sql
--
-- slack_settings — 클러스터별 Slack 알림 연동 설정 (cluster_name singleton per cluster).
-- 알림 생성(NotificationService.persist) 직후 설정·심각도·카테고리 매칭 시 자동 발화한다.
--
-- 주의: webhook_url은 시크릿이다. 로그/GET 응답에 평문 노출 금지(서비스 계층에서 마스킹).

CREATE TABLE IF NOT EXISTS slack_settings (
  cluster_name  TEXT PRIMARY KEY,
  enabled       BOOLEAN NOT NULL DEFAULT false,
  webhook_url   TEXT NOT NULL DEFAULT '',     -- 시크릿: 로그/GET 응답 평문 금지
  min_severity  TEXT NOT NULL DEFAULT 'high', -- critical|high|medium|low|info
  categories    TEXT[] NOT NULL DEFAULT ARRAY['new_cve','kev_added'],
  last_error    TEXT,
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
