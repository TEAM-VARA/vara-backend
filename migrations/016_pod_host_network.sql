-- ────────────────────────────────────────────
-- 016: cluster_pods 테이블에 host_network 컬럼 추가
-- ────────────────────────────────────────────
-- 목적: Pod의 hostNetwork 설정 여부 추적 (보안 분석용)
-- hostNetwork=true인 Pod는 노드 네트워크 네임스페이스를 공유하므로
-- 보안 리스크가 큼 (노드의 모든 포트/인터페이스에 직접 접근 가능)
-- ────────────────────────────────────────────

ALTER TABLE cluster_pods
ADD COLUMN IF NOT EXISTS host_network BOOLEAN NOT NULL DEFAULT FALSE;

-- 보안 분석 쿼리 최적화를 위한 부분 인덱스
-- (대부분의 Pod는 false라서 true인 것만 인덱싱 → 인덱스 작고 빠름)
CREATE INDEX IF NOT EXISTS idx_cluster_pods_host_network
ON cluster_pods (host_network)
WHERE host_network = TRUE;