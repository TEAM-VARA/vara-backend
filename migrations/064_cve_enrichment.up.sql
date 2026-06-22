-- migrations/064_cve_enrichment.up.sql
--
-- CVE Narrative Enrichment (설계서 §4) — config-free, per-CVE 추출 결과 캐시.
-- cve_global_scores(점수)와 분리: advisory/fixed_versions/KEV 변동에 따른 독립 무효화·TTL.
--
-- enrichment        : §4 스키마 객체 전체(JSONB). vuln_class/module/mechanism/preconditions/
--                     fixed_versions/attack/mitigations/cvss/signals + _provenance.
-- extractor_version : 추출 파이프라인 버전. 프롬프트/스키마 변경 시 캐시 무효화.
-- source_hash       : advisory 본문(+NVD desc) 해시. 출처 변경 감지용.
-- expires_at        : NOW() + EnrichmentTTL(7d). GetFresh가 expires_at > NOW()만 반환.

CREATE TABLE IF NOT EXISTS cve_enrichment (
    cve_id            TEXT PRIMARY KEY,
    enrichment        JSONB NOT NULL,
    extractor_version TEXT  NOT NULL DEFAULT '',
    source_hash       TEXT  NOT NULL DEFAULT '',
    computed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at        TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cve_enrichment_expires ON cve_enrichment (expires_at);

COMMENT ON TABLE  cve_enrichment                   IS 'CVE 단위 narrative enrichment 캐시 (config-free, 설계서 §4)';
COMMENT ON COLUMN cve_enrichment.enrichment        IS '§4 스키마 객체 전체 (JSONB)';
COMMENT ON COLUMN cve_enrichment.extractor_version IS '추출 파이프라인 버전 — 변경 시 캐시 무효화';
COMMENT ON COLUMN cve_enrichment.source_hash       IS 'advisory 본문+NVD desc 해시 — 출처 변경 감지';
