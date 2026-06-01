-- migrations/005_ebpf_agent.sql
-- eBPF Agent (Tetragon) 데이터 수신용 테이블 3개
-- API 명세 v0.3 기반:
--   POST /api/v1/agent/network-flows
--   POST /api/v1/agent/dns-queries
--   POST /api/v1/agent/process-events

-- ============================================
-- 1. 통신 이벤트 (TCP/UDP)
-- ============================================
-- tcp_connect / tcp_close / udp_send 이벤트 저장
-- 5-tuple 기반 idempotent UPSERT
CREATE TABLE IF NOT EXISTS ebpf_network_flows (
  id              BIGSERIAL PRIMARY KEY,
  customer_id     TEXT NOT NULL,
  cluster_name    TEXT NOT NULL,
  node_name       TEXT NOT NULL,
  
  timestamp       TIMESTAMPTZ NOT NULL,
  event_type      TEXT NOT NULL,    -- tcp_connect / tcp_close / udp_send
  protocol        TEXT NOT NULL,    -- TCP / UDP
  
  -- 출발지 (Tetragon이 풍부한 정보 제공)
  src_pod_id      TEXT,             -- "namespace/name", 호스트 프로세스면 빈 문자열
  src_ip          TEXT NOT NULL,
  src_port        INTEGER NOT NULL,
  src_pid         INTEGER NOT NULL,
  
  -- 목적지 (IP/port만, 파드 정보는 Backend에서 cluster_pods JOIN으로 채움)
  dst_ip          TEXT NOT NULL,
  dst_port        INTEGER NOT NULL,
  
  -- tcp_connect만 (close/udp_send엔 NULL)
  success         BOOLEAN,
  
  received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  
  -- idempotent UPSERT용 unique 제약
  UNIQUE (customer_id, node_name, timestamp, src_ip, src_port, dst_ip, dst_port, event_type)
);

CREATE INDEX IF NOT EXISTS idx_ebpf_flows_timestamp 
  ON ebpf_network_flows USING BRIN (timestamp);

CREATE INDEX IF NOT EXISTS idx_ebpf_flows_src_pod 
  ON ebpf_network_flows (src_pod_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_ebpf_flows_dst 
  ON ebpf_network_flows (dst_ip, dst_port, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_ebpf_flows_cluster 
  ON ebpf_network_flows (cluster_name, timestamp DESC);


-- ============================================
-- 2. DNS 쿼리
-- ============================================
CREATE TABLE IF NOT EXISTS ebpf_dns_queries (
  id              BIGSERIAL PRIMARY KEY,
  customer_id     TEXT NOT NULL,
  cluster_name    TEXT NOT NULL,
  node_name       TEXT NOT NULL,
  
  timestamp       TIMESTAMPTZ NOT NULL,
  
  src_pod_id      TEXT,
  src_pid         INTEGER NOT NULL,
  
  query           TEXT NOT NULL,    -- 도메인 (예: "example.com")
  
  received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  
  UNIQUE (customer_id, node_name, src_pid, timestamp, query)
);

CREATE INDEX IF NOT EXISTS idx_ebpf_dns_timestamp 
  ON ebpf_dns_queries USING BRIN (timestamp);

CREATE INDEX IF NOT EXISTS idx_ebpf_dns_pod 
  ON ebpf_dns_queries (src_pod_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_ebpf_dns_query 
  ON ebpf_dns_queries (query, timestamp DESC);


-- ============================================
-- 3. 프로세스 실행 이벤트
-- ============================================
CREATE TABLE IF NOT EXISTS ebpf_process_events (
  id              BIGSERIAL PRIMARY KEY,
  customer_id     TEXT NOT NULL,
  cluster_name    TEXT NOT NULL,
  node_name       TEXT NOT NULL,
  
  timestamp       TIMESTAMPTZ NOT NULL,
  
  src_pod_id      TEXT,
  src_pid         INTEGER NOT NULL,
  
  comm            TEXT NOT NULL,    -- 실행 파일 경로 (예: "/bin/sh")
  args            JSONB,            -- 명령 인자 배열
  
  parent_pid      INTEGER,
  parent_comm     TEXT,
  
  received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  
  UNIQUE (customer_id, node_name, src_pid, timestamp)
);

CREATE INDEX IF NOT EXISTS idx_ebpf_proc_timestamp 
  ON ebpf_process_events USING BRIN (timestamp);

CREATE INDEX IF NOT EXISTS idx_ebpf_proc_pod 
  ON ebpf_process_events (src_pod_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_ebpf_proc_comm 
  ON ebpf_process_events (comm, timestamp DESC);
