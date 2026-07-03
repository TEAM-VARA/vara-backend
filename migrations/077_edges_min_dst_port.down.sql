-- migrations/077_edges_min_dst_port.down.sql
ALTER TABLE edges DROP COLUMN IF EXISTS min_dst_port;
