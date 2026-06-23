package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vara/backend/internal/domain/ebpf"
	"github.com/vara/backend/internal/repository/postgres"
)

// EbpfHandler : eBPF Agent (Tetragon) 핸들러
//
// 공통 헤더:
//   X-Customer-ID  → customer_id, cluster_name
//   X-Node-Name    → node_name (페이로드 node와 일치 검증)
type EbpfHandler struct {
	repo *postgres.EbpfRepo
	pg   *pgxpool.Pool  // ★ 매핑 쿼리용 추가 ★
}

func NewEbpf(repo *postgres.EbpfRepo, pg *pgxpool.Pool) *EbpfHandler {
    return &EbpfHandler{repo: repo, pg: pg}
}

// resolveDestination : dst_ip를 분석해서 Pod 정보 반환
func (h *EbpfHandler) resolveDestination(
    ctx context.Context, clusterName, dstIP string,
) (podID, podIP, status string) {
    // IPv4-mapped IPv6 prefix 제거
    cleanIP := strings.TrimPrefix(dstIP, "::ffff:")
    
    // IP 유형 분류
    switch {
	case cleanIP == "::1" || strings.HasPrefix(cleanIP, "127."):
        return "", "", "loopback"   // ← 추가: 자기 자신 통신 (외부 아님)
		
    case strings.HasPrefix(cleanIP, "172.20."):
        // ClusterIP - 매핑 시도
        return h.lookupServiceEndpoint(ctx, clusterName, cleanIP)
    
    case strings.HasPrefix(cleanIP, "169.254."):
        return "", "", "imds"   // AWS 메타데이터
    
    case strings.HasPrefix(cleanIP, "10.0."):
        return "", "", "backend_vpc"  // vara 백엔드 VPC
    
    case strings.HasPrefix(cleanIP, "10.1."):
        return h.lookupPodIP(ctx, clusterName, cleanIP)  // Pod IP 또는 Node IP
    
    default:
        return "", "", "external"  // 외부 인터넷
    }
}

// lookupServiceEndpoint : cluster_services에서 ClusterIP로 Pod 찾기
func (h *EbpfHandler) lookupServiceEndpoint(
    ctx context.Context, clusterName, clusterIP string,
) (podID, podIP, status string) {
    var serviceName, namespace string
    var endpointsJSON []byte
    
    err := h.pg.QueryRow(ctx, `
        SELECT name, namespace, endpoints 
        FROM cluster_services 
        WHERE cluster_name = $1 AND cluster_ip = $2 
        ORDER BY snapshot_at DESC LIMIT 1
    `, clusterName, clusterIP).Scan(&serviceName, &namespace, &endpointsJSON)
    
    if errors.Is(err, pgx.ErrNoRows) {
        return "", "", "service_not_found"
    }
    if err != nil {
        return "", "", "db_error"
    }
    
    var endpoints []struct {
        Ready   bool   `json:"ready"`
        PodIP   string `json:"pod_ip"`
        PodName string `json:"pod_name"`
    }
    if err := json.Unmarshal(endpointsJSON, &endpoints); err != nil {
        return "", "", "parse_error"
    }
    
    // 첫 번째 ready endpoint 반환
    for _, ep := range endpoints {
        if ep.Ready && ep.PodName != "" {
            return namespace + "/" + ep.PodName, ep.PodIP, "mapped"
        }
    }
    
    return "", "", "no_ready_endpoint"
}

// lookupPodIP : cluster_pods에서 Pod IP로 Pod 찾기
func (h *EbpfHandler) lookupPodIP(
    ctx context.Context, clusterName, podIP string,
) (podID, podIPOut, status string) {
    var name, namespace, phase string
    
    err := h.pg.QueryRow(ctx, `
        SELECT name, namespace, phase
        FROM cluster_pods 
        WHERE cluster_name = $1 
			AND pod_ip = $2 
			AND host_network = false
        ORDER BY snapshot_at DESC LIMIT 1
    `, clusterName, podIP).Scan(&name, &namespace, &phase)
    
    if errors.Is(err, pgx.ErrNoRows) {
        return "", "", "node_ip"  // Pod 아님 (Node IP, ENI 등)
    }
    if err != nil {
        return "", "", "db_error"
    }
    
    if phase != "Running" {
        return "", "", "pod_not_running"
    }
    
    return namespace + "/" + name, podIP, "mapped"
}

// extractEbpfHeaders : 공통 헤더 추출 + 검증
func extractEbpfHeaders(c *gin.Context) (string, string, bool) {
	customerID := c.GetHeader("X-Customer-ID")
	if customerID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Customer-ID header required"})
		return "", "", false
	}

	nodeName := c.GetHeader("X-Node-Name")
	if nodeName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Node-Name header required"})
		return "", "", false
	}

	return customerID, nodeName, true
}

// NetworkFlows : POST /api/v1/agents/ebpf/network-flows
func (h *EbpfHandler) NetworkFlows(c *gin.Context) {
	customerID, nodeName, ok := extractEbpfHeaders(c)
	if !ok {
		return
	}

	var req ebpf.NetworkFlowsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Node != nodeName {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("node mismatch: header=%s, body=%s", nodeName, req.Node),
		})
		return
	}

	ctx := c.Request.Context()
	for i := range req.Events {
		podID, podIP, status := h.resolveDestination(
			ctx, customerID, req.Events[i].Dst.IP,
		)
		req.Events[i].Dst.PodID = podID
		req.Events[i].Dst.PodIP = podIP
		req.Events[i].Dst.MappingStatus = status
	}

	// ── 여기부터 변경 ──────────────────────────────
	// tcp_sendmsg는 집계 테이블(ebpf_flow_agg)로, 나머지(set_state/connect 등)는 기존 테이블로 분리
	var aggReq, rawReq ebpf.NetworkFlowsRequest
	aggReq.Node = req.Node
	rawReq.Node = req.Node
	for _, e := range req.Events {
		if e.EventType == "tcp_sendmsg" {
			aggReq.Events = append(aggReq.Events, e)
		} else {
			rawReq.Events = append(rawReq.Events, e)
		}
	}

	// 기존 테이블 먼저 저장 (set_state = 블래스트 그래프 입력이라 우선 보존)
	savedRaw, err := h.repo.UpsertNetworkFlows(ctx, customerID, rawReq)
	if err != nil {
		fmt.Printf("warn: ebpf network-flows failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// sendmsg 집계 저장
	savedAgg, err := h.repo.UpsertFlowAgg(ctx, customerID, aggReq)
	if err != nil {
		fmt.Printf("warn: ebpf flow-agg failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"node":      req.Node,
		"received":  len(req.Events),
		"saved":     savedRaw + savedAgg,
		"saved_raw": savedRaw,
		"saved_agg": savedAgg,
	})
}

// DNSQueries : POST /api/v1/agents/ebpf/dns-queries
func (h *EbpfHandler) DNSQueries(c *gin.Context) {
	customerID, nodeName, ok := extractEbpfHeaders(c)
	if !ok {
		return
	}

	var req ebpf.DNSQueriesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Node != nodeName {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("node mismatch: header=%s, body=%s", nodeName, req.Node),
		})
		return
	}

	saved, err := h.repo.UpsertDNSQueries(c.Request.Context(), customerID, req)
	if err != nil {
		fmt.Printf("warn: ebpf dns-queries failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"node":     req.Node,
		"received": len(req.Events),
		"saved":    saved,
	})
}

// ProcessEvents : POST /api/v1/agents/ebpf/process-events
func (h *EbpfHandler) ProcessEvents(c *gin.Context) {
	customerID, nodeName, ok := extractEbpfHeaders(c)
	if !ok {
		return
	}

	var req ebpf.ProcessEventsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Node != nodeName {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("node mismatch: header=%s, body=%s", nodeName, req.Node),
		})
		return
	}

	saved, err := h.repo.UpsertProcessEvents(c.Request.Context(), customerID, req)
	if err != nil {
		fmt.Printf("warn: ebpf process-events failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"node":     req.Node,
		"received": len(req.Events),
		"saved":    saved,
	})
}

// GetProcessFeed : GET /api/v1/feed/process?since=<RFC3339>
func (h *EbpfHandler) GetProcessFeed(c *gin.Context) {
	customerID := c.GetHeader("X-Customer-ID")
	if customerID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Customer-ID header required"})
		return
	}

	// since 미지정 시 최근 5분
	since := time.Now().Add(-5 * time.Minute)
	if s := c.Query("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			since = t
		}
	}

	items, err := h.repo.QueryProcessFeed(c.Request.Context(), customerID, since, 100)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"events": items})
}

// GetFlowFeed : GET /api/v1/feed/flow?since=<RFC3339>
func (h *EbpfHandler) GetFlowFeed(c *gin.Context) {
	customerID := c.GetHeader("X-Customer-ID")
	if customerID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Customer-ID header required"})
		return
	}
	since := time.Now().Add(-5 * time.Minute)
	if s := c.Query("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			since = t
		}
	}
	items, err := h.repo.QueryFlowFeed(c.Request.Context(), customerID, since, 100)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"events": items})
}

// GetEvents : GET /api/v1/events?since=&type=&anomaly_only=&q=
func (h *EbpfHandler) GetEvents(c *gin.Context) {
	customerID := c.GetHeader("X-Customer-ID")
	if customerID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Customer-ID header required"})
		return
	}
	since := time.Now().Add(-2 * time.Minute) // 라이브 기본: 최근 2분
	if s := c.Query("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			since = t
		}
	}
	events, err := h.repo.QueryEvents(
		c.Request.Context(), customerID, since,
		c.Query("type"), c.Query("anomaly_only") == "true", c.Query("q"), 200,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"events": events})
}