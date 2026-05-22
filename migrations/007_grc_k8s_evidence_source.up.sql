-- K8s 증적 출처(클러스터·네임스페이스·리소스·컨테이너) + 룰 결과에 스냅샷 저장
ALTER TABLE grc_evidence_files
  ADD COLUMN IF NOT EXISTS k8s_source JSONB;

ALTER TABLE grc_rule_results
  ADD COLUMN IF NOT EXISTS evidence_sources JSONB NOT NULL DEFAULT '[]'::jsonb;

COMMENT ON COLUMN grc_evidence_files.k8s_source IS
  'Optional K8s collection context: cluster_name, namespace, resource_kind, resource_name, container_name';

COMMENT ON COLUMN grc_rule_results.evidence_sources IS
  'JSON array of {filename, cluster_name, namespace, resource_kind, resource_name, container_name} for this rule evaluation';
