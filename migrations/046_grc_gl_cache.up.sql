-- GL 룰별 Top-K 지침 문장 캐시
-- 지침서 업로드 또는 첫 체크 실행 시 사전 계산, 이후 체크에서 임베딩 재계산 생략
CREATE TABLE IF NOT EXISTS grc_gl_rule_top_sentences (
    company_id       VARCHAR(64)  NOT NULL,
    isms_p_item_id   VARCHAR(10)  NOT NULL,
    rule_id          VARCHAR(50)  NOT NULL,
    top_sentences    TEXT[]       NOT NULL,
    computed_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (company_id, isms_p_item_id, rule_id)
);

CREATE INDEX IF NOT EXISTS idx_grc_gl_rule_cache_item
    ON grc_gl_rule_top_sentences(company_id, isms_p_item_id);
