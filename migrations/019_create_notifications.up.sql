-- 019_create_notifications.up.sql
-- vara 대시보드 알림 시스템

CREATE TABLE IF NOT EXISTS notifications (
    id BIGSERIAL PRIMARY KEY,
    cluster_name TEXT NOT NULL,
    
    -- 알림 분류
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    category TEXT NOT NULL,  -- new_cve / risk_change / scan_complete / kev_added / toxic_combo
    
    -- 내용
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    
    -- 메타데이터 (CVE ID, 영향 Pod 등)
    metadata JSONB DEFAULT '{}',
    
    -- 상태
    read_at TIMESTAMP WITH TIME ZONE,
    dismissed BOOLEAN DEFAULT FALSE,
    
    -- 시간
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 인덱스
CREATE INDEX IF NOT EXISTS idx_notifications_cluster_created 
    ON notifications(cluster_name, created_at DESC);
    
CREATE INDEX IF NOT EXISTS idx_notifications_unread 
    ON notifications(cluster_name) 
    WHERE read_at IS NULL AND dismissed = FALSE;
    
CREATE INDEX IF NOT EXISTS idx_notifications_severity 
    ON notifications(severity, created_at DESC);

-- vuln_id 조회용 인덱스 (중복 체크는 애플리케이션 레벨)
CREATE INDEX IF NOT EXISTS idx_notifications_vuln_lookup 
    ON notifications(cluster_name, category, (metadata->>'vuln_id'), created_at DESC)
    WHERE (metadata->>'vuln_id') IS NOT NULL;

-- 주석
COMMENT ON TABLE notifications IS 'vara 대시보드 알림';
COMMENT ON COLUMN notifications.severity IS 'critical/high/medium/low/info';
COMMENT ON COLUMN notifications.category IS 'new_cve / risk_change / scan_complete / kev_added / toxic_combo';
COMMENT ON COLUMN notifications.metadata IS 'JSONB: vuln_id, affected_pods, severity_score 등';