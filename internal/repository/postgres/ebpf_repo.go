package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vara/backend/internal/domain/ebpf"
)

// EbpfRepo : eBPF Agent (Tetragon) 데이터를 RDS에 저장
type EbpfRepo struct {
	pg *pgxpool.Pool
}

func NewEbpfRepo(pg *pgxpool.Pool) *EbpfRepo {
	return &EbpfRepo{pg: pg}
}

// UpsertNetworkFlows : TCP/UDP 통신 이벤트 일괄 UPSERT
func (r *EbpfRepo) UpsertNetworkFlows(ctx context.Context, customerID string, req ebpf.NetworkFlowsRequest) (int, error) {
	if len(req.Events) == 0 {
		return 0, nil
	}

	tx, err := r.pg.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("tx begin: %w", err)
	}
	defer tx.Rollback(ctx)

	const q = `
		INSERT INTO ebpf_network_flows (
			customer_id, cluster_name, node_name,
			timestamp, event_type, protocol,
			src_pod_id, src_ip, src_port, src_pid,
			dst_ip, dst_port, success
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
		)
		ON CONFLICT (customer_id, node_name, timestamp, src_ip, src_port, dst_ip, dst_port, event_type) DO UPDATE SET
			success = EXCLUDED.success
	`

	saved := 0
	for _, e := range req.Events {
		var success interface{} = nil
		if e.Success != nil {
			success = *e.Success
		}

		_, err := tx.Exec(ctx, q,
			customerID, customerID, req.Node,
			e.Timestamp, e.EventType, e.Protocol,
			e.Src.PodID, e.Src.IP, e.Src.Port, e.Src.PID,
			e.Dst.IP, e.Dst.Port, success,
		)
		if err != nil {
			return 0, fmt.Errorf("upsert network flow %s/%s:%d→%s:%d: %w",
				e.EventType, e.Src.IP, e.Src.Port, e.Dst.IP, e.Dst.Port, err)
		}
		saved++
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("tx commit: %w", err)
	}
	return saved, nil
}

// UpsertDNSQueries : DNS 쿼리 이벤트 일괄 UPSERT
func (r *EbpfRepo) UpsertDNSQueries(ctx context.Context, customerID string, req ebpf.DNSQueriesRequest) (int, error) {
	if len(req.Events) == 0 {
		return 0, nil
	}

	tx, err := r.pg.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("tx begin: %w", err)
	}
	defer tx.Rollback(ctx)

	const q = `
		INSERT INTO ebpf_dns_queries (
			customer_id, cluster_name, node_name,
			timestamp, src_pod_id, src_pid, query
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7
		)
		ON CONFLICT (customer_id, node_name, src_pid, timestamp, query) DO NOTHING
	`

	saved := 0
	for _, e := range req.Events {
		_, err := tx.Exec(ctx, q,
			customerID, customerID, req.Node,
			e.Timestamp, e.Src.PodID, e.Src.PID, e.Query,
		)
		if err != nil {
			return 0, fmt.Errorf("upsert dns query %s pid=%d: %w", e.Query, e.Src.PID, err)
		}
		saved++
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("tx commit: %w", err)
	}
	return saved, nil
}

// UpsertProcessEvents : 프로세스 실행 이벤트 일괄 UPSERT
func (r *EbpfRepo) UpsertProcessEvents(ctx context.Context, customerID string, req ebpf.ProcessEventsRequest) (int, error) {
	if len(req.Events) == 0 {
		return 0, nil
	}

	tx, err := r.pg.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("tx begin: %w", err)
	}
	defer tx.Rollback(ctx)

	const q = `
		INSERT INTO ebpf_process_events (
			customer_id, cluster_name, node_name,
			timestamp, src_pod_id, src_pid,
			comm, args, parent_pid, parent_comm
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
		)
		ON CONFLICT (customer_id, node_name, src_pid, timestamp) DO UPDATE SET
			comm        = EXCLUDED.comm,
			args        = EXCLUDED.args,
			parent_pid  = EXCLUDED.parent_pid,
			parent_comm = EXCLUDED.parent_comm
	`

	saved := 0
	for _, e := range req.Events {
		args := e.Args
		if args == nil {
			args = []string{}
		}
		argsJSON, _ := json.Marshal(args)

		var parentPID interface{} = nil
		var parentComm interface{} = nil
		if e.Parent != nil {
			parentPID = e.Parent.PID
			parentComm = e.Parent.Comm
		}

		_, err := tx.Exec(ctx, q,
			customerID, customerID, req.Node,
			e.Timestamp, e.Src.PodID, e.Src.PID,
			e.Comm, argsJSON, parentPID, parentComm,
		)
		if err != nil {
			return 0, fmt.Errorf("upsert process event %s pid=%d: %w", e.Comm, e.Src.PID, err)
		}
		saved++
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("tx commit: %w", err)
	}
	return saved, nil
}