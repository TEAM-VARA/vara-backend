-- Grafana 전용 읽기 전용 계정 (RDS 보호) — RDS에 관리자로 1회 실행
-- psql "host=<RDS> dbname=vara user=<admin>" -f readonly_user.sql
CREATE ROLE grafana_ro LOGIN PASSWORD '__set_a_strong_password__';

GRANT CONNECT ON DATABASE vara TO grafana_ro;
GRANT USAGE ON SCHEMA public TO grafana_ro;

-- 현재 존재하는 모든 테이블 SELECT 권한
GRANT SELECT ON ALL TABLES IN SCHEMA public TO grafana_ro;

-- 앞으로 생길 테이블에도 자동 SELECT 부여
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO grafana_ro;

-- (선택) 특정 패널 테이블만 최소 권한으로 주려면 위 ALL 대신 아래처럼:
-- GRANT SELECT ON final_scores, grc_cluster_compliance_results,
--   rbac_sa_reports, rbac_escalation_paths, cves,
--   ebpf_network_flows, ebpf_process_events TO grafana_ro;
