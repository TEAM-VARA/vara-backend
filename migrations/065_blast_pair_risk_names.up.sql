
ALTER TABLE blast_pair_risk ADD COLUMN IF NOT EXISTS src_pod_name text NOT NULL DEFAULT '';

ALTER TABLE blast_pair_risk ADD COLUMN IF NOT EXISTS dst_pod_name text NOT NULL DEFAULT '';

