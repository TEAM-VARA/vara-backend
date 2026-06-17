package notification

import (
	"encoding/json"
	"time"
)

// ─────────────────────────────────────────
// Severity 등급
// ─────────────────────────────────────────
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// ─────────────────────────────────────────
// Category 종류
// ─────────────────────────────────────────
const (
	CategoryNewCVE       = "new_cve"        // 신규 CVE 발견
	CategoryRiskChange   = "risk_change"    // Pod 위험도 변경
	CategoryScanComplete = "scan_complete"  // 자동 스캔 완료
	CategoryKEVAdded     = "kev_added"      // 기존 CVE가 KEV에 등재
	CategoryToxicCombo   = "toxic_combo"    // 새 toxic 조합 매칭
)

// ─────────────────────────────────────────
// Notification은 대시보드 알림 한 건입니다.
// ─────────────────────────────────────────
type Notification struct {
	ID          int64           `json:"id"`
	ClusterName string          `json:"cluster_name"`
	Severity    string          `json:"severity"`
	Category    string          `json:"category"`
	Title       string          `json:"title"`
	Message     string          `json:"message"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
	ReadAt      *time.Time      `json:"read_at,omitempty"`
	Dismissed   bool            `json:"dismissed"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// IsRead는 알림이 읽음 처리되었는지 반환합니다.
func (n *Notification) IsRead() bool {
	return n.ReadAt != nil
}

// ─────────────────────────────────────────
// DTO
// ─────────────────────────────────────────

// CreateRequest는 알림 생성 입력입니다.
type CreateRequest struct {
	ClusterName string          `json:"cluster_name" binding:"required"`
	Severity    string          `json:"severity" binding:"required"`
	Category    string          `json:"category" binding:"required"`
	Title       string          `json:"title" binding:"required"`
	Message     string          `json:"message" binding:"required"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
}

// ListRequest는 알림 조회 입력입니다.
type ListRequest struct {
	ClusterName string
	UnreadOnly  bool
	Severity    string
	Category    string
	Limit       int
	Offset      int
}

// ListResponse는 알림 목록 응답입니다.
type ListResponse struct {
	Total         int            `json:"total"`
	Unread        int            `json:"unread"`
	Notifications []Notification `json:"notifications"`
}

// CountResponse는 unread count 응답입니다.
type CountResponse struct {
	Unread int `json:"unread"`
	Total  int `json:"total"`
}

// ─────────────────────────────────────────
// Metadata 구조체 (카테고리별)
// ─────────────────────────────────────────

// AffectedPodRef는 new_cve 알림에 담기는 영향 Pod 한 건입니다.
type AffectedPodRef struct {
	PodUID      string `json:"pod_uid"`
	PodName     string `json:"pod_name"`
	Namespace   string `json:"namespace"`
	PackageName string `json:"package_name"` // 어떤 패키지 때문에 취약한지
	Version     string `json:"version"`

	// Blast Radius — 이 Pod이 침해됐을 때 도달 가능한 노드 수/점수 (hop 무제한)
	BlastRadius int     `json:"blast_radius,omitempty"` // 도달 가능 노드 수
	BlastScore  float64 `json:"blast_score,omitempty"`
}

// NewCVEMetadata는 new_cve 카테고리의 metadata 구조입니다.
type NewCVEMetadata struct {
	VulnID        string           `json:"vuln_id"`
	SeverityScore float64          `json:"severity_score"`
	SeverityLabel string           `json:"severity_label"`
	AffectedPods  []string         `json:"affected_pods"`             // "namespace/pod_name" 표시용
	AffectedPodList []AffectedPodRef `json:"affected_pod_list,omitempty"` // 구조화된 Pod 정보 (역추적 결과)
	AffectedCount int              `json:"affected_count"`            // 영향받는 고유 Pod 수
	TopCVE        string           `json:"top_cve,omitempty"`
	ImageDigests  []string         `json:"image_digests,omitempty"`

	// Blast Radius 요약 — 영향 Pod들 중 최대 확산 범위 (알림 메시지용)
	MaxBlastRadius  int    `json:"max_blast_radius,omitempty"`   // 가장 크게 번지는 Pod의 도달 수
	MaxBlastPodName string `json:"max_blast_pod_name,omitempty"` // 그 Pod 이름
}

// RiskChangeMetadata는 risk_change 카테고리의 metadata 구조입니다.
type RiskChangeMetadata struct {
	PodUID        string  `json:"pod_uid"`
	PodName       string  `json:"pod_name"`
	PodNamespace  string  `json:"pod_namespace"`
	PreviousLevel string  `json:"previous_level"`
	NewLevel      string  `json:"new_level"`
	PreviousScore float64 `json:"previous_score"`
	NewScore      float64 `json:"new_score"`
	Reason        string  `json:"reason"`
}

// ScanCompleteMetadata는 scan_complete 카테고리의 metadata 구조입니다.
type ScanCompleteMetadata struct {
	TotalImages     int     `json:"total_images"`
	ScannedImages   int     `json:"scanned_images"`
	NewVulnsCount   int     `json:"new_vulns_count"`
	CriticalCount   int     `json:"critical_count"`
	HighCount       int     `json:"high_count"`
	DurationSeconds float64 `json:"duration_seconds"`
}