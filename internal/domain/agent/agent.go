package agent

import "time"

// Agent 도메인 모델 (Cluster Reader Agent / eBPF Agent / CI 파이프라인)

// PodEvent : Pod 1개의 생성 또는 삭제 이벤트
type PodEvent struct {
	EventType   string    `json:"event_type" binding:"required,oneof=pod_added pod_deleted"`
	PodUID      string    `json:"pod_uid" binding:"required"`
	PodName     string    `json:"pod_name"`
	Namespace   string    `json:"namespace"`
	NodeName    string    `json:"node_name"`
	IP          string    `json:"ip"`
	Image       string    `json:"image"`
	ImageDigest string    `json:"image_digest"`
	Timestamp   time.Time `json:"timestamp"`
}

// PodEventBatch : 여러 이벤트 배치
type PodEventBatch struct {
	Events []PodEvent `json:"events" binding:"required,min=1,dive"`
}

// SBOMRequest : 이미지 1개에 대한 SBOM + CVE 정보
type SBOMRequest struct {
	Image       string         `json:"image" binding:"required"`
	ImageDigest string         `json:"image_digest" binding:"required"`
	GeneratedAt time.Time      `json:"generated_at"`
	RawData     map[string]any `json:"raw_data"`
	CVEs        []SBOMCVE      `json:"cves"`
}

// SBOMCVE : SBOM에 포함된 CVE 1건
type SBOMCVE struct {
	CVEID            string  `json:"cve_id" binding:"required"`
	Severity         string  `json:"severity"`
	PackageName      string  `json:"package_name"`
	InstalledVersion string  `json:"installed_version"`
	FixedVersion     string  `json:"fixed_version"`
	CVSSScore        float64 `json:"cvss_score"`
}

// TrafficEvent : 1분 집계 단위 트래픽
type TrafficEvent struct {
	Timestamp time.Time `json:"timestamp" binding:"required"`
	NodeName  string    `json:"node_name"`
	SrcIP     string    `json:"src_ip" binding:"required"`
	DstIP     string    `json:"dst_ip" binding:"required"`
	Bytes     int64     `json:"bytes"`
	Packets   int64     `json:"packets"`
}

type TrafficBatch struct {
	Events []TrafficEvent `json:"events" binding:"required,min=1,dive"`
}

// PodInfo : DB에 저장된 Pod 정보 (Service 계층용)
type PodInfo struct {
	PodID         string
	PodName       string
	Namespace     string
	ImageName     string
	BuildDigest   string
	RuntimeDigest string
	CVEList       []string
}
