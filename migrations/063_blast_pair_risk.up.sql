CREATE TABLE IF NOT EXISTS blast_pair_risk (
    cluster_name text        NOT NULL,
    src_pod_uid  text        NOT NULL,
    dst_pod_uid  text        NOT NULL,
    reach_prob   real        NOT NULL,
    computed_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (cluster_name, src_pod_uid, dst_pod_uid)
);

CREATE INDEX IF NOT EXISTS idx_blast_pair_risk_top
    ON blast_pair_risk (cluster_name, reach_prob DESC);