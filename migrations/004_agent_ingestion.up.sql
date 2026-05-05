-- Agent 데이터 수신 핸들러가 UPSERT 동작하도록 제약 추가
-- + 추가 컬럼 (updated_at, deleted_at, package_name 등)

-- pods: soft delete 컬럼 추가
ALTER TABLE pods ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();
ALTER TABLE pods ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
-- deleted_at IS NULL : 현재 살아있음 / IS NOT NULL : 삭제됨

-- sboms: 같은 image_digest 중복 방지
DO $$ BEGIN
    ALTER TABLE sboms ADD CONSTRAINT sboms_image_digest_unique UNIQUE (image_digest);
EXCEPTION
    WHEN duplicate_table THEN NULL;
    WHEN duplicate_object THEN NULL;
END $$;

-- cves: 같은 (image_digest, cve_id) 중복 방지
DO $$ BEGIN
    ALTER TABLE cves ADD CONSTRAINT cves_digest_cve_unique UNIQUE (image_digest, cve_id);
EXCEPTION
    WHEN duplicate_table THEN NULL;
    WHEN duplicate_object THEN NULL;
END $$;

-- cves 테이블에 추가 정보 컬럼
ALTER TABLE cves ADD COLUMN IF NOT EXISTS package_name TEXT;
ALTER TABLE cves ADD COLUMN IF NOT EXISTS installed_version TEXT;
ALTER TABLE cves ADD COLUMN IF NOT EXISTS fixed_version TEXT;
ALTER TABLE cves ADD COLUMN IF NOT EXISTS cvss_score NUMERIC(3,1);

-- 인덱스
CREATE INDEX IF NOT EXISTS idx_pods_namespace ON pods (namespace);
CREATE INDEX IF NOT EXISTS idx_pods_image_digest ON pods (image_digest);
CREATE INDEX IF NOT EXISTS idx_cves_image_digest ON cves (image_digest);
