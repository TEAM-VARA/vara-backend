package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"   // ← 추가

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
            dst_ip, dst_port, success,
            dst_pod_id, dst_pod_ip, mapping_status
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
        )
        ON CONFLICT (customer_id, node_name, timestamp, src_ip, src_port, dst_ip, dst_port, event_type) DO UPDATE SET
            success = EXCLUDED.success,
            dst_pod_id = EXCLUDED.dst_pod_id,
            dst_pod_ip = EXCLUDED.dst_pod_ip,
            mapping_status = EXCLUDED.mapping_status
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
            e.Dst.PodID, e.Dst.PodIP, e.Dst.MappingStatus,
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

// processWatchlist : 피드에 노출할 "의심 명령" 목록.
// 하드코딩(시연용). 추후 DB 테이블/설정으로 승격 + ANOMALY 룰셋과 통합.
var processWatchlist = []string{
	"sh", "bash", "dash", "zsh", "ash",
	"curl", "wget", "nc", "ncat", "socat",
	"python", "python3", "perl", "ruby",
	"id", "whoami", "uname", "ps", "netstat", "ss",
}

// ProcessFeedItem : FE 피드용 단일 항목
type ProcessFeedItem struct {
	Timestamp  time.Time `json:"timestamp"`
	SrcPodID   string    `json:"src_pod_id"`
	Comm       string    `json:"comm"`
	Args       []string  `json:"args"`
	ParentComm string    `json:"parent_comm"` // 8번 ANOMALY 판정에 쓸 단서 (parent가 java면 런타임 의심)
}

// QueryProcessFeed : watchlist + namespace 필터를 적용한 process 피드 조회
func (r *EbpfRepo) QueryProcessFeed(
	ctx context.Context, customerID string, since time.Time, limit int,
) ([]ProcessFeedItem, error) {
	const q = `
		SELECT timestamp, src_pod_id, comm, args, parent_comm
		FROM ebpf_process_events
		WHERE customer_id = $1
		  AND received_at > $2
		  AND src_pod_id NOT LIKE 'default/vara-%'   -- VARA 셀프 노이즈 제외
		  AND comm = ANY($3)                         -- watchlist만
		ORDER BY timestamp DESC
		LIMIT $4
	`

	rows, err := r.pg.Query(ctx, q, customerID, since, processWatchlist, limit)
	if err != nil {
		return nil, fmt.Errorf("query process feed: %w", err)
	}
	defer rows.Close()

	items := make([]ProcessFeedItem, 0)
	for rows.Next() {
		var (
			it         ProcessFeedItem
			argsRaw    []byte  // jsonb → 일단 raw bytes로 받음
			parentComm *string // NULL 가능 (parent 없는 process)
		)
		if err := rows.Scan(&it.Timestamp, &it.SrcPodID, &it.Comm, &argsRaw, &parentComm); err != nil {
			return nil, fmt.Errorf("scan process feed: %w", err)
		}
		if len(argsRaw) > 0 {
			_ = json.Unmarshal(argsRaw, &it.Args) // jsonb([...]) → []string
		}
		if it.Args == nil {
			it.Args = []string{}
		}
		if parentComm != nil {
			it.ParentComm = *parentComm
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iter: %w", err)
	}
	return items, nil
}