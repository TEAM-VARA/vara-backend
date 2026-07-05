-- migrations/078_add_host_ipc_to_cluster_pods.up.sql
ALTER TABLE cluster_pods ADD COLUMN IF NOT EXISTS host_ipc BOOLEAN DEFAULT false;
