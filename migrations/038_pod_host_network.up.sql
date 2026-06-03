ALTER TABLE cluster_pods
ADD COLUMN IF NOT EXISTS host_network BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_cluster_pods_host_network
ON cluster_pods (host_network)
WHERE host_network = TRUE;
