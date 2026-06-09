-- migrations/052_add_host_pid_to_cluster_pods.up.sql
ALTER TABLE cluster_pods ADD COLUMN IF NOT EXISTS host_pid BOOLEAN DEFAULT false;