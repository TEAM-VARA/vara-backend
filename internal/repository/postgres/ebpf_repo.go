package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"   // ← 추가
	"sort"   // ← 추가
	"strings" // ← 추가

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
			dst_pod_id, dst_pod_ip, mapping_status,
			size
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
		)
		ON CONFLICT (customer_id, node_name, timestamp, src_ip, src_port, dst_ip, dst_port, event_type) DO UPDATE SET
			success = EXCLUDED.success,
			dst_pod_id = EXCLUDED.dst_pod_id,
			dst_pod_ip = EXCLUDED.dst_pod_ip,
			mapping_status = EXCLUDED.mapping_status,
			size = EXCLUDED.size
	`

    saved := 0
    for _, e := range req.Events {
        var success interface{} = nil
        if e.Success != nil {
            success = *e.Success
        }

		var size interface{} = nil
		if e.Size > 0 {
			size = e.Size
		}

        _, err := tx.Exec(ctx, q,
            customerID, customerID, req.Node,
            e.Timestamp, e.EventType, e.Protocol,
            e.Src.PodID, e.Src.IP, e.Src.Port, e.Src.PID,
            e.Dst.IP, e.Dst.Port, success,
            e.Dst.PodID, e.Dst.PodIP, e.Dst.MappingStatus,
			size,
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

// UpsertFlowAgg : tcp_sendmsg 전용. 개별 row 대신 (src,dst,port,분) 단위로 누적 집계.
// 매핑(dst_pod_id, mapping_status)이 끝난 이벤트를 받아서 분 버킷에 더한다.
func (r *EbpfRepo) UpsertFlowAgg(ctx context.Context, customerID string, req ebpf.NetworkFlowsRequest) (int, error) {
	if len(req.Events) == 0 {
		return 0, nil
	}

	tx, err := r.pg.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("tx begin: %w", err)
	}
	defer tx.Rollback(ctx)

	const q = `
		INSERT INTO ebpf_flow_agg (
			customer_id, cluster_name, src_pod_id,
			dst_pod_id, dst_ip, dst_port, mapping_status,
			minute_bucket, flow_count, total_size, last_seen
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			date_trunc('minute', $8::timestamptz), 1, $9, $8
		)
		ON CONFLICT (customer_id, cluster_name, src_pod_id, dst_ip, dst_port, minute_bucket)
		DO UPDATE SET
			flow_count     = ebpf_flow_agg.flow_count + 1,
			total_size     = ebpf_flow_agg.total_size + EXCLUDED.total_size,
			last_seen      = GREATEST(ebpf_flow_agg.last_seen, EXCLUDED.last_seen),
			dst_pod_id     = EXCLUDED.dst_pod_id,
			mapping_status = EXCLUDED.mapping_status
	`

	saved := 0
	for _, e := range req.Events {
		var size int64 = 0
		if e.Size > 0 {
			size = e.Size
		}
		_, err := tx.Exec(ctx, q,
			customerID, customerID, e.Src.PodID,
			e.Dst.PodID, e.Dst.IP, e.Dst.Port, e.Dst.MappingStatus,
			e.Timestamp, size,
		)
		if err != nil {
			return 0, fmt.Errorf("upsert flow agg %s:%d→%s:%d: %w",
				e.Src.IP, e.Src.Port, e.Dst.IP, e.Dst.Port, err)
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

// processSeverity : 의심 명령에 등급/이유 부여 (R4)
func processSeverity(comm, parentComm string, eventTime time.Time, startedAt *time.Time) (severity, reason string) {
	// 컨테이너 시작 후 90초 이내 = 부팅 노이즈 → 강등
	if startedAt != nil {
		diff := eventTime.Sub(*startedAt)
		if diff >= 0 && diff <= 90*time.Second {
			return "none", "boot"
		}
	}

	if parentComm == "java" { // 앱이 직접 띄움 = RCE 강신호
		return "high", "app_spawned"
	}

	switch comm {
	case "nc", "ncat", "socat", "curl", "wget":
		return "high", "net_tool"
	case "python", "python3", "perl", "ruby":
		return "high", "interpreter"
	case "id", "whoami", "uname", "ps", "netstat", "ss":
		return "medium", "recon"
	default: // sh, bash, dash, zsh, ash
		return "medium", "shell"
	}
}

// ProcessFeedItem : FE 피드용 단일 항목
type ProcessFeedItem struct {
	Timestamp  time.Time `json:"timestamp"`
	SrcPodID   string    `json:"src_pod_id"`
	Comm       string    `json:"comm"`
	Args       []string  `json:"args"`
	Severity   string    `json:"severity"`
	ParentComm string    `json:"parent_comm"` // 8번 ANOMALY 판정에 쓸 단서 (parent가 java면 런타임 의심)
	AnomalyReason string    `json:"anomaly_reason,omitempty"`
}

// FlowFeedItem : FE FLOW 피드용 집계 항목
type FlowFeedItem struct {
	SrcService string    `json:"src_service"`
	DstService string    `json:"dst_service"`
	FlowCount  int64     `json:"flow_count"`
	TotalBytes int64     `json:"total_bytes"`
	LastSeen   time.Time `json:"last_seen"`
	Severity      string    `json:"severity"`                 // none | high
	AnomalyReason string    `json:"anomaly_reason,omitempty"` // external_egress | imds_access
}

// Event : 통합 라이브 스트림 항목 (flow/exec/dns/file 정규화)
type Event struct {
	Timestamp     time.Time `json:"timestamp"`
	Type          string    `json:"type"`   // flow | exec | dns | file
	Source        string    `json:"source"` // "namespace/pod"
	Target        string    `json:"target"`
	Severity      string    `json:"severity"`
	AnomalyReason string    `json:"anomaly_reason,omitempty"`
}

// QueryFlowFeed : (src 서비스 → dst 서비스) 집계 + 인프라(A) 표시 필터
func (r *EbpfRepo) QueryFlowFeed(
	ctx context.Context, customerID string, since time.Time, limit int,
) ([]FlowFeedItem, error) {
	const q = `
		SELECT
			regexp_replace(src_pod_id, '-[a-z0-9]+-[a-z0-9]+$', '') AS src_service,
			CASE
				WHEN mapping_status = 'imds'     THEN 'IMDS (메타데이터)'
				WHEN mapping_status = 'external' THEN 'external: ' || regexp_replace(dst_ip, '^::ffff:', '')
				ELSE regexp_replace(dst_pod_id, '-[a-z0-9]+-[a-z0-9]+$', '')
			END AS dst_service,
			CASE 
				WHEN mapping_status IN ('external','imds') THEN 'high' 
				WHEN dst_pod_id LIKE 'train-ticket/mysql%'
				     AND (src_pod_id LIKE 'train-ticket/ts-gateway-service-%'
				       OR src_pod_id LIKE 'train-ticket/ts-ui-dashboard-%') THEN 'high'
				ELSE 'none' 
			END AS severity,
			COALESCE(CASE
				WHEN mapping_status = 'imds'     THEN 'imds_access'
				WHEN mapping_status = 'external' THEN 'external_egress'
				WHEN dst_pod_id LIKE 'train-ticket/mysql%'
				     AND (src_pod_id LIKE 'train-ticket/ts-gateway-service-%'
				       OR src_pod_id LIKE 'train-ticket/ts-ui-dashboard-%') THEN 'unauthorized_db_access'
			END, '') AS anomaly_reason,
			COALESCE(sum(flow_count), 0) AS flow_count,   -- ← count(*) 에서 변경
			COALESCE(sum(total_size), 0) AS total_bytes,  -- ← sum(size) 에서 변경
			max(last_seen)               AS last_seen      -- ← max(timestamp) 에서 변경
		FROM ebpf_flow_agg                                 -- ← ebpf_network_flows 에서 변경
		WHERE customer_id = $1
		  AND minute_bucket > $2                            -- ← received_at > $2 에서 변경
		  AND src_pod_id NOT LIKE 'default/vara-%'
		  AND src_pod_id NOT LIKE 'train-ticket/nacos-%'
		  AND (
		        (mapping_status = 'mapped' AND dst_pod_id NOT LIKE 'train-ticket/nacos-%')
		     OR mapping_status IN ('external','imds')
		  )
		  AND mapping_status != 'loopback'
		GROUP BY src_service, dst_service, severity, anomaly_reason
		ORDER BY last_seen DESC
		LIMIT $3
	`
	rows, err := r.pg.Query(ctx, q, customerID, since, limit)
	if err != nil {
		return nil, fmt.Errorf("query flow feed: %w", err)
	}
	defer rows.Close()

	items := make([]FlowFeedItem, 0)
	for rows.Next() {
		var it FlowFeedItem
		if err := rows.Scan(&it.SrcService, &it.DstService, &it.Severity, &it.AnomalyReason,
			&it.FlowCount, &it.TotalBytes, &it.LastSeen,); err != nil {
			return nil, fmt.Errorf("scan flow feed: %w", err)
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iter: %w", err)
	}
	return items, nil
}

// QueryProcessFeed : watchlist + namespace 필터를 적용한 process 피드 조회
func (r *EbpfRepo) QueryProcessFeed(
	ctx context.Context, customerID string, since time.Time, limit int,
) ([]ProcessFeedItem, error) {
	const q = `
		SELECT e.timestamp, e.src_pod_id, e.comm, e.args, e.parent_comm, cp.started_at
		FROM ebpf_process_events e
		LEFT JOIN LATERAL (
			SELECT started_at
			FROM cluster_pods
			WHERE cluster_name = $1
			  AND namespace || '/' || name = e.src_pod_id
			ORDER BY snapshot_at DESC
			LIMIT 1
		) cp ON true
		WHERE e.customer_id = $1
		  AND e.received_at > $2
		  AND e.src_pod_id NOT LIKE 'default/vara-%'
		  AND e.comm = ANY($3)
		ORDER BY e.timestamp DESC
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
			startedAt  *time.Time   // ← 추가: NULL 가능
		)
		if err := rows.Scan(&it.Timestamp, &it.SrcPodID, &it.Comm, &argsRaw, &parentComm, &startedAt); err != nil {
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
		it.Severity, it.AnomalyReason = processSeverity(it.Comm, it.ParentComm, it.Timestamp, startedAt ) // R4: 부팅 노이즈 감쇠 + parent가 java면 app_spawned
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iter: %w", err)
	}
	return items, nil
}

// QueryEvents : exec + flow(+dns/file) 를 시간순 통합한 라이브 스트림
func (r *EbpfRepo) QueryEvents(
	ctx context.Context, customerID string, since time.Time,
	eventType string, anomalyOnly bool, q string, limit int,
) ([]Event, error) {
	events := make([]Event, 0)

	if eventType == "" || eventType == "flow" {
		flows, err := r.QueryFlowFeed(ctx, customerID, since, limit)
		if err != nil {
			return nil, err
		}
		for _, f := range flows {
			events = append(events, Event{
				Timestamp: f.LastSeen, Type: "flow",
				Source: f.SrcService, Target: f.DstService,
				Severity: f.Severity, AnomalyReason: f.AnomalyReason,
			})
		}
	}

	if eventType == "" || eventType == "exec" {
		execs, err := r.QueryProcessFeed(ctx, customerID, since, limit)
		if err != nil {
			return nil, err
		}
		for _, e := range execs {
			target := e.Comm
			if len(e.Args) > 0 {
				target = e.Comm + " " + strings.Join(e.Args, " ")
			}
			events = append(events, Event{
				Timestamp: e.Timestamp, Type: "exec",
				Source: e.SrcPodID, Target: target,
				Severity: e.Severity, AnomalyReason: e.AnomalyReason,
			})
		}
	}

	// dns / file : 파이프라인 미구현 → 현재 빈 결과 (FE 탭은 비어 보임)

	qLower := strings.ToLower(q)
	out := make([]Event, 0, len(events))
	for _, ev := range events {
		if anomalyOnly && (ev.Severity == "" || ev.Severity == "none") {
			continue
		}
		if qLower != "" && !strings.Contains(strings.ToLower(ev.Source), qLower) {
			continue
		}
		out = append(out, ev)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Timestamp.After(out[j].Timestamp) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}