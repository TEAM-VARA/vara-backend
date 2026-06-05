-- Per-sentence embeddings for guideline documents.
-- Computed at upload time so GL checks only need to embed the rule query (8 texts × ~0.5s).
-- This avoids re-embedding 300 sentences per check, which takes ~15 min on CPU BGE-M3.

CREATE TABLE IF NOT EXISTS grc_guideline_sentence_embeddings (
    id              BIGSERIAL     PRIMARY KEY,
    guideline_id    BIGINT        NOT NULL REFERENCES grc_guidelines(id) ON DELETE CASCADE,
    sentence_index  INT           NOT NULL,
    sentence_text   TEXT          NOT NULL,
    embedding       vector(1024)  NOT NULL,
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    UNIQUE(guideline_id, sentence_index)
);
CREATE INDEX IF NOT EXISTS idx_grc_gse_guideline ON grc_guideline_sentence_embeddings(guideline_id);
