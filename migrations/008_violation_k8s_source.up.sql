-- Add K8s source information to violations for resource-level tracking.
ALTER TABLE grc_violations
  ADD COLUMN IF NOT EXISTS k8s_cluster    VARCHAR(255),
  ADD COLUMN IF NOT EXISTS k8s_namespace  VARCHAR(255),
  ADD COLUMN IF NOT EXISTS k8s_kind       VARCHAR(100),
  ADD COLUMN IF NOT EXISTS k8s_name       VARCHAR(255),
  ADD COLUMN IF NOT EXISTS k8s_container  VARCHAR(255);
