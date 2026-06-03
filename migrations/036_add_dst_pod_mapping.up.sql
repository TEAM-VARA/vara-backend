ALTER TABLE ebpf_network_flows
ADD COLUMN dst_pod_id TEXT,
ADD COLUMN dst_pod_ip TEXT,
ADD COLUMN mapping_status TEXT;

-- 분석 쿼리용 인덱스
CREATE INDEX IF NOT EXISTS idx_ebpf_flows_dst_pod_id
ON ebpf_network_flows(dst_pod_id) WHERE dst_pod_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_ebpf_flows_mapping_status
ON ebpf_network_flows(mapping_status);
