-- VARA3 (compliance) 스키마.
-- vara-backend 와 같은 PostgreSQL DB(`vara`) 를 공유하기 위해 모든 테이블에 `compliance_` prefix 를 사용한다.
-- pgvector 는 DB 레벨 extension 이므로 한 번만 설치하면 vara-backend / VARA3 양쪽이 함께 사용한다.

CREATE EXTENSION IF NOT EXISTS vector;

DROP TABLE IF EXISTS compliance_isms_p_mappings;
DROP TABLE IF EXISTS compliance_evidence_documents;
DROP TABLE IF EXISTS compliance_isms_p_controls;
DROP TABLE IF EXISTS compliance_exposures;
DROP TABLE IF EXISTS compliance_vulnerabilities;
DROP TABLE IF EXISTS compliance_assets;

CREATE TABLE compliance_assets (
    id SERIAL PRIMARY KEY,
    asset_id TEXT UNIQUE NOT NULL,
    asset_type TEXT NOT NULL,
    name TEXT NOT NULL,
    namespace TEXT,
    cluster_name TEXT,
    cloud_provider TEXT,
    image TEXT,
    service_account TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE compliance_vulnerabilities (
    id SERIAL PRIMARY KEY,
    asset_id TEXT NOT NULL,
    image TEXT,
    scanner TEXT,
    cve_id TEXT NOT NULL,
    package_name TEXT,
    installed_version TEXT,
    fixed_version TEXT,
    severity TEXT,
    cvss FLOAT,
    epss FLOAT,
    kev BOOLEAN DEFAULT FALSE,
    description TEXT,
    patch_status TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE compliance_exposures (
    id SERIAL PRIMARY KEY,
    asset_id TEXT NOT NULL,
    exposure_level TEXT NOT NULL,
    exposure_type TEXT,
    entrypoint TEXT,
    protocol TEXT,
    port INT,
    auth_required BOOLEAN DEFAULT FALSE,
    description TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE compliance_isms_p_controls (
    id SERIAL PRIMARY KEY,
    control_id TEXT UNIQUE NOT NULL,
    domain TEXT,
    title TEXT NOT NULL,
    description TEXT,
    keywords TEXT[],
    embedding vector(1024),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE compliance_evidence_documents (
    id SERIAL PRIMARY KEY,
    source_type TEXT NOT NULL,
    asset_id TEXT,
    cve_id TEXT,
    namespace TEXT,
    severity TEXT,
    exposure_level TEXT,
    document_text TEXT NOT NULL,
    metadata JSONB DEFAULT '{}'::jsonb,
    embedding vector(1024),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE compliance_isms_p_mappings (
    id SERIAL PRIMARY KEY,
    control_id TEXT NOT NULL,
    status TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    risk_score FLOAT,
    summary TEXT,
    reason TEXT,
    recommendations TEXT[],
    evidence_ids INT[],
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX compliance_evidence_embedding_hnsw_idx
ON compliance_evidence_documents
USING hnsw (embedding vector_cosine_ops);
