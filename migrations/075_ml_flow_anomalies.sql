CREATE TABLE IF NOT EXISTS ml_flow_anomalies (
    id           BIGSERIAL PRIMARY KEY,
    customer_id  TEXT NOT NULL,
    src_service  TEXT NOT NULL,
    dst_service  TEXT NOT NULL,
    severity     TEXT NOT NULL,
    reason       TEXT NOT NULL,
    ml_score     REAL,
    is_new_edge  BOOLEAN NOT NULL DEFAULT FALSE,
    scored_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (customer_id, src_service, dst_service)
);
CREATE INDEX IF NOT EXISTS idx_ml_anom_lookup ON ml_flow_anomalies (customer_id, src_service, dst_service);
