-- ============================================================================
-- VARA Risk Scoring — Image Global Score (이미지 단위 위험도 영속화)
-- ============================================================================
--
-- 작업 B-1에서는 POST /scoring/global/images가 즉석 계산만 했습니다.
-- 본 마이그레이션은 그 결과를 영속화하여:
--   - 동일 이미지 재계산 비용 절감
--   - DBeaver 등으로 시각화
--   - 작업 B-3(Final Score)에서 빠른 조회
--
-- 점수 산정:
--   해당 이미지의 모든 CVE에 대해 cve_global_scores를 합산하여
--   max_score, avg_score, critical_count, high_count, active_count, poc_count 등 메트릭 도출
-- ============================================================================

CREATE TABLE IF NOT EXISTS image_global_scores (
    id                  BIGSERIAL PRIMARY KEY,

    -- 식별
    image_digest        TEXT NOT NULL,         -- sha256:... (sboms.image_digest와 동일)
    image               TEXT NOT NULL,         -- nginx:1.14.0 (사람이 읽기 좋은 tag)

    -- 점수 집계
    cve_count           INT NOT NULL,          -- 평가된 총 CVE 수
    max_score           NUMERIC(5, 2) NOT NULL,-- 가장 위험한 CVE 점수
    avg_score           NUMERIC(5, 2) NOT NULL,-- 평균 점수
    top_cve             TEXT,                  -- max_score를 가진 CVE id

    -- severity 분포
    critical_count      INT NOT NULL DEFAULT 0,
    high_count          INT NOT NULL DEFAULT 0,
    medium_count        INT NOT NULL DEFAULT 0,
    low_count           INT NOT NULL DEFAULT 0,

    -- SSVC 분포 (CVE-Global Score에서 산정한 exploitation 상태)
    active_count        INT NOT NULL DEFAULT 0,  -- KEV
    poc_count           INT NOT NULL DEFAULT 0,  -- ExploitDB만 (KEV 없음)
    none_count          INT NOT NULL DEFAULT 0,  -- 둘 다 없음

    -- 시점
    computed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ NOT NULL,    -- computed_at + 24h (TTL)

    UNIQUE (image_digest)
);

-- 인덱스
CREATE INDEX IF NOT EXISTS idx_image_global_max_score
    ON image_global_scores (max_score DESC);

CREATE INDEX IF NOT EXISTS idx_image_global_expires
    ON image_global_scores (expires_at);

CREATE INDEX IF NOT EXISTS idx_image_global_image
    ON image_global_scores (image);
