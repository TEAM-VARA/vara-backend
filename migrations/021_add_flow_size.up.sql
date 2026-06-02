-- ────────────────────────────────────────────
-- 021: ebpf_network_flows에 size 컬럼 추가
-- 목적: tcp_sendmsg 전송 바이트 수 저장
--   Tetragon args[1].size_arg(문자열) → 정수 변환해서 저장
--   tcp_connect/close 등 size 없는 이벤트는 NULL
-- ────────────────────────────────────────────
ALTER TABLE ebpf_network_flows
ADD COLUMN IF NOT EXISTS size BIGINT;
