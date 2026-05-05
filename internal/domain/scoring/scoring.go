package scoring

import "time"

// 위험 점수 도메인 모델

// Request : POST /api/v1/pods/{pod_id}/risk
type Request struct {
	ImageName   string `json:"image_name" binding:"required"`
	ImageDigest string `json:"image_digest" binding:"required"`
}

// Result : 점수 계산 결과 (응답의 "result" 부분)
type Result struct {
	// 항목별 raw 값
	CVSS      float64 `json:"cvss"`
	EPSS      float64 `json:"epss"`
	KEVListed bool    `json:"kev_listed"`
	ExploitDB bool    `json:"exploitdb"`

	// 항목별 점수 (가중치 적용 후)
	CVSSScore    float64 `json:"cvss_score"`
	EPSSScore    float64 `json:"epss_score"`
	KEVScore     float64 `json:"kev_score"`
	ExploitScore float64 `json:"exploit_score"`

	// 종합
	FinalScore    float64 `json:"final_score"`
	RiskLevel     string  `json:"risk_level"`
	DigestFlagged bool    `json:"digest_flagged"`
	DigestMessage string  `json:"digest_message,omitempty"`

	// CVE 정보
	CVEList []string `json:"cve_list"`
	TopCVE  string   `json:"top_cve"`
}

// Response : POST 응답
type Response struct {
	ImageName   string `json:"image_name"`
	ImageDigest string `json:"image_digest"`
	Result      Result `json:"result"`
	Message     string `json:"message"`
}

// DetailsResponse : GET /api/v1/pods/{pod_id}/risk/details
type DetailsResponse struct {
	PodID       string             `json:"pod_id"`
	ImageName   string             `json:"image_name"`
	ImageDigest string             `json:"image_digest"`
	Result      Result             `json:"result"`
	Details     []CVEDetail        `json:"details"`
	DigestCheck *DigestCheckDetail `json:"digest_check,omitempty"`
	ComputedAt  time.Time          `json:"computed_at"`
}

// CVEDetail : CVE 1개에 대한 항목별 상세
type CVEDetail struct {
	CVEID       string        `json:"cve_id"`
	Description string        `json:"description"`
	CVSS        CVSSDetail    `json:"cvss"`
	EPSS        EPSSDetail    `json:"epss"`
	KEV         KEVDetail     `json:"kev"`
	Exploit     ExploitDetail `json:"exploit"`
}

type CVSSDetail struct {
	Score    float64 `json:"score"`
	Severity string  `json:"severity"`
	Vector   string  `json:"vector,omitempty"`
	Note     string  `json:"note"`
}

type EPSSDetail struct {
	Score      float64 `json:"score"`
	Percentile float64 `json:"percentile"`
	Note       string  `json:"note"`
}

type KEVDetail struct {
	Listed    bool   `json:"listed"`
	DateAdded string `json:"date_added,omitempty"`
	DueDate   string `json:"due_date,omitempty"`
	Note      string `json:"note"`
}

type ExploitDetail struct {
	HasExploit  bool     `json:"has_exploit"`
	ExploitURLs []string `json:"exploit_urls,omitempty"`
	Note        string   `json:"note"`
}

type DigestCheckDetail struct {
	BuildDigest   string `json:"build_digest"`
	RuntimeDigest string `json:"runtime_digest"`
	Match         bool   `json:"match"`
	Note          string `json:"note"`
}

// Computation : Service 출력
type Computation struct {
	Result  Result
	Details []CVEDetail
	CVEList []string
}
