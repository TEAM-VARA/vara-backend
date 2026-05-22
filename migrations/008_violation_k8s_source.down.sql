ALTER TABLE grc_violations
  DROP COLUMN IF EXISTS k8s_cluster,
  DROP COLUMN IF EXISTS k8s_namespace,
  DROP COLUMN IF EXISTS k8s_kind,
  DROP COLUMN IF EXISTS k8s_name,
  DROP COLUMN IF EXISTS k8s_container;
