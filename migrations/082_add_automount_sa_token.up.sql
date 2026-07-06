ALTER TABLE cluster_pods ADD COLUMN IF NOT EXISTS automount_sa_token BOOLEAN;
ALTER TABLE cluster_service_accounts ADD COLUMN IF NOT EXISTS automount_sa_token BOOLEAN;