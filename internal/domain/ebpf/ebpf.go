package ebpf

import "time"

// ────────────────────────────────────────────
// eBPF Agent (Tetragon) 페이로드 모델
// ────────────────────────────────────────────
//
// API 명세 v0.3:
//   POST /api/v1/agent/network-flows
//   POST /api/v1/agent/dns-queries
//   POST /api/v1/agent/process-events

// Window : 배치 수집 시간 범위
type Window struct {
	From time.Time `json:"from" binding:"required"`
	To   time.Time `json:"to" binding:"required"`
}

// Common : 모든 eBPF 페이로드의 공통 필드
type Common struct {
	Node   string `json:"node" binding:"required"`
	Window Window `json:"window" binding:"required"`
}

// ── /network-flows ──

type NetworkFlowsRequest struct {
	Common
	Events []NetworkFlowEvent `json:"events" binding:"required,dive"`
}

type NetworkFlowEvent struct {
	EventType string 		 `json:"event_type" binding:"oneof=tcp_connect tcp_set_state tcp_close udp_send tcp_sendmsg"`
	Timestamp time.Time      `json:"timestamp" binding:"required"`
	Src       NetworkFlowSrc `json:"src" binding:"required"`
	Dst       NetworkFlowDst `json:"dst" binding:"required"`
	Protocol  string         `json:"protocol" binding:"required,oneof=TCP UDP"`
	Success   *bool          `json:"success"`
}

type NetworkFlowSrc struct {
	PodID string `json:"pod_id"`
	IP    string `json:"ip" binding:"required"`
	Port  int    `json:"port" binding:"required"`
	PID   int    `json:"pid" binding:"required"`
}

type NetworkFlowDst struct {
	IP   string `json:"ip" binding:"required"`
	Port int    `json:"port" binding:"required"`

	PodID         string `json:"-"`
    PodIP         string `json:"-"`
    MappingStatus string `json:"-"`
}

// ── /dns-queries ──

type DNSQueriesRequest struct {
	Common
	Events []DNSQueryEvent `json:"events" binding:"required,dive"`
}

type DNSQueryEvent struct {
	EventType string      `json:"event_type" binding:"required,oneof=dns_query"`
	Timestamp time.Time   `json:"timestamp" binding:"required"`
	Src       DNSQuerySrc `json:"src" binding:"required"`
	Query     string      `json:"query" binding:"required"`
}

type DNSQuerySrc struct {
	PodID string `json:"pod_id"`
	PID   int    `json:"pid" binding:"required"`
}

// ── /process-events ──

type ProcessEventsRequest struct {
	Common
	Events []ProcessEvent `json:"events" binding:"required,dive"`
}

type ProcessEvent struct {
	EventType string         `json:"event_type" binding:"required,oneof=exec"`
	Timestamp time.Time      `json:"timestamp" binding:"required"`
	Src       ProcessSrc     `json:"src" binding:"required"`
	Comm      string         `json:"comm" binding:"required"`
	Args      []string       `json:"args"`
	Parent    *ProcessParent `json:"parent"`
}

type ProcessSrc struct {
	PodID string `json:"pod_id"`
	PID   int    `json:"pid" binding:"required"`
}

type ProcessParent struct {
	PID  int    `json:"pid"`
	Comm string `json:"comm"`
}