-- migrations/081_add_automount_sa_token.down.sql
ALTER TABLE cluster_pods DROP COLUMN IF EXISTS automount_sa_token;
ALTER TABLE cluster_service_accounts DROP COLUMN IF EXISTS automount_sa_token;