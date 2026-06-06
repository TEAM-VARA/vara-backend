-- sboms 테이블 복원
-- 배경: 초기 스키마(구 001_init.sql)가 마이그레이션 renumber 때 누락되어
--       볼륨 재생성 시 sboms가 만들어지지 않음 (relation does not exist)
-- 원본: 커밋 cdb2d74 migrations/001_init.sql
CREATE TABLE IF NOT EXISTS sboms (
    id            BIGSERIAL   PRIMARY KEY,
    image         TEXT        NOT NULL,
    image_digest  TEXT        NOT NULL,
    raw_data      JSONB,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sboms_image        ON sboms (image);
CREATE INDEX IF NOT EXISTS idx_sboms_image_digest ON sboms (image_digest);