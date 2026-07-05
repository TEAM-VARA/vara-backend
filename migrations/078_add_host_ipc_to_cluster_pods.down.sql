-- migrations/078_add_host_ipc_to_cluster_pods.down.sql
ALTER TABLE cluster_pods DROP COLUMN IF EXISTS host_ipc;
