-- 029: pod_master — current-state ledger for pod lifecycle (soft delete)
-- One row per pod (cluster_name, pod_uid). Snapshot history stays in cluster_pods.
CREATE TABLE IF NOT EXISTS pod_master (
    cluster_name     TEXT        NOT NULL,
    pod_uid          TEXT        NOT NULL,
    name             TEXT        NOT NULL,
    namespace        TEXT        NOT NULL,
    node             TEXT,
    service_account  TEXT,
    phase            TEXT,                       -- last-seen phase (problem signal)
    restart_count    INT         NOT NULL DEFAULT 0,
    first_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at     TIMESTAMPTZ NOT NULL,       -- refreshed every snapshot
    deleted_at       TIMESTAMPTZ,                -- set when pod disappears (NULL = alive)
    PRIMARY KEY (cluster_name, pod_uid)
);

-- recently-disappeared lookup (for alerts)
CREATE INDEX IF NOT EXISTS idx_pod_master_deleted
    ON pod_master (cluster_name, deleted_at DESC) WHERE deleted_at IS NOT NULL;

-- reconcile: alive pods missing from the latest snapshot
CREATE INDEX IF NOT EXISTS idx_pod_master_alive_last_seen
    ON pod_master (cluster_name, last_seen_at) WHERE deleted_at IS NULL;
