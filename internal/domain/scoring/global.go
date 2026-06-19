package scoring

import "time"

// ─────────────────────────────────────────
// Global Score 공식 가중치
// ─────────────────────────────────────────
//
// Final_Global = (CVSS_w × CVSS/10) + (EPSS_w × EPSS) + (SSVC_w × SSVC_value) × 100
//
// 가중치 합 = 1.0 (정규화)
// 최종 점수 = 0.0 ~ 100.0

const (
	GlobalWeightCVSS = 0.4 // CVSS 0~10 → 정규화 후 가중
	GlobalWeightEPSS = 0.3 // EPSS 0~1 (확률)
	GlobalWeightSSVC = 0.3 // SSVC 0/0.5/1 (실제 exploitation 상태)
)

// SSVC-Exploitation 상태별 점수
const (
	SSVCValueActive = 1.0 // KEV에 있음 (실제 공격 사례 보고됨)
	SSVCValuePoC    = 0.5 // ExploitDB에 있음 (공격 코드 공개)
	SSVCValueNone   = 0.0 // 알려진 exploitation 없음
)

// SSVC-Exploitation 상태 문자열 표현
const (
	SSVCExploitationActive = "active"
	SSVCExploitationPoC    = "poc"
	SSVCExploitationNone   = "none"
)

// SSVC 데이터 소스
const (
	SSVCSourceVulnrichment = "vulnrichment" // CISA (현재 미사용)
	SSVCSourceKEV          = "kev"
	SSVCSourceExploitDB    = "exploitdb"
	SSVCSourceNone         = "none"
)

// CacheTTL은 cve_global_scores의 expires_at TTL입니다.
// 외부 API 호출 비용 절감을 위해 24시간 캐시 유지.
const CacheTTL = 24 * time.Hour

// ─────────────────────────────────────────
// 도메인 타입
// ─────────────────────────────────────────

// GlobalScore는 단일 CVE의 Global Score 계산 결과입니다.
type GlobalScore struct {
	// 식별
	CVEID string `json:"cve_id"`

	// CVSS (NVD 출처)
	CVSSScore    float64 `json:"cvss_score"`
	CVSSSeverity string  `json:"cvss_severity"`
	CVSSVector   string  `json:"cvss_vector,omitempty"`
	CVSSFound    bool    `json:"cvss_found"`

	// EPSS (FIRST.org)
	EPSSScore      float64 `json:"epss_score"`
	EPSSPercentile float64 `json:"epss_percentile"`
	EPSSFound      bool    `json:"epss_found"`

	// SSVC-Exploitation
	SSVCExploitation string `json:"ssvc_exploitation"` // active/poc/none
	SSVCSource       string `json:"ssvc_source"`       // kev/exploitdb/none
	InKEV            bool   `json:"in_kev"`
	InExploitDB      bool   `json:"in_exploitdb"`

	// 종합 Global Score (0~100)
	GlobalScore float64 `json:"global_score"`

	// 항목별 가중 점수 (디버깅용, 합 = GlobalScore)
	CVSSContribution float64 `json:"cvss_contribution"` // CVSS/10 × 0.4 × 100
	EPSSContribution float64 `json:"epss_contribution"` // EPSS × 0.3 × 100
	SSVCContribution float64 `json:"ssvc_contribution"` // SSVC × 0.3 × 100

	// 캐시
	ComputedAt time.Time `json:"computed_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// ImageGlobalScore는 이미지 단위 통합 점수입니다.
// 정책: 가장 위험한 CVE의 점수를 채택 (max).
type ImageGlobalScore struct {
	ImageDigest    string        `json:"image_digest"`
	Image          string        `json:"image,omitempty"`
	CVECount       int           `json:"cve_count"`
	MaxScore       float64       `json:"max_score"`       // 가장 높은 CVE 점수
	TopCVE         string        `json:"top_cve"`         // 가장 위험한 CVE
	CriticalCount  int           `json:"critical_count"`  // CVSS 9.0+
	HighCount      int           `json:"high_count"`      // CVSS 7.0~8.9
	ActiveCount    int           `json:"active_count"`    // SSVC=active (KEV)
	PoCCount       int           `json:"poc_count"`       // SSVC=poc (ExploitDB)
	CVEScores      []GlobalScore `json:"cve_scores"`      // 모든 CVE의 점수 (정렬됨, 내림차순)
	ComputedAt     time.Time     `json:"computed_at"`
}

// ─────────────────────────────────────────
// 점수 계산 함수
// ─────────────────────────────────────────

// ComputeSSVC는 KEV/ExploitDB 결과로 SSVC-Exploitation 상태를 결정합니다.
//
// 우선순위:
//   1. KEV 등재됨        → active (1.0)
//   2. ExploitDB에 있음 → poc (0.5)
//   3. 둘 다 없음        → none (0.0)
//
// Vulnrichment 추가 시 위에 1순위로 들어옴.
func ComputeSSVC(inKEV, inExploitDB bool) (exploitation, source string, value float64) {
	switch {
	case inKEV:
		return SSVCExploitationActive, SSVCSourceKEV, SSVCValueActive
	case inExploitDB:
		return SSVCExploitationPoC, SSVCSourceExploitDB, SSVCValuePoC
	default:
		return SSVCExploitationNone, SSVCSourceNone, SSVCValueNone
	}
}

// ComputeGlobalScore는 CVSS/EPSS/SSVC 값을 받아 Global Score를 계산합니다.
//
// 공식:
//   contribution_cvss = CVSS/10 × 0.4 × 100
//   contribution_epss = EPSS × 0.3 × 100
//   contribution_ssvc = SSVC × 0.3 × 100
//   global = contribution_cvss + contribution_epss + contribution_ssvc
//
// 데이터 없는 경우 0으로 처리 (조용히 무시):
//   CVSS 못 가져왔으면 → CVSS contribution = 0
//   EPSS 못 가져왔으면 → EPSS contribution = 0
func ComputeGlobalScore(cvssScore, epssScore, ssvcValue float64) (total, cvssContrib, epssContrib, ssvcContrib float64) {
	// CVSS 정규화: 0~10 → 0~1
	cvssNormalized := cvssScore / 10.0
	if cvssNormalized < 0 {
		cvssNormalized = 0
	}
	if cvssNormalized > 1 {
		cvssNormalized = 1
	}

	// EPSS 클램프: 0~1 보장
	if epssScore < 0 {
		epssScore = 0
	}
	if epssScore > 1 {
		epssScore = 1
	}

	// SSVC: 0.0 / 0.5 / 1.0 중 하나 가정

	// 가중치는 전역 설정(CurrentWeights)에서 읽는다. 미설정 시 기본값(0.4/0.3/0.3).
	w := CurrentWeights()
	cvssContrib = cvssNormalized * w.GlobalCVSS * 100
	epssContrib = epssScore * w.GlobalEPSS * 100
	ssvcContrib = ssvcValue * w.GlobalSSVC * 100

	total = cvssContrib + epssContrib + ssvcContrib

	return RoundTo2(total), RoundTo2(cvssContrib), RoundTo2(epssContrib), RoundTo2(ssvcContrib)
}

// ClassifyGlobalLevel은 Global Score를 등급으로 분류합니다.
func ClassifyGlobalLevel(score float64) string {
	switch {
	case score >= 80.0:
		return "Critical"
	case score >= 60.0:
		return "High"
	case score >= 40.0:
		return "Medium"
	case score >= 20.0:
		return "Low"
	default:
		return "Info"
	}
}

// RoundTo2는 소수점 둘째 자리에서 반올림합니다.
func RoundTo2(v float64) float64 {
	return float64(int(v*100+0.5)) / 100
}

// ─────────────────────────────────────────
// API DTO
// ─────────────────────────────────────────

// ComputeCVERequest는 단일 CVE 점수 계산 요청입니다.
// Path 파라미터로 cve_id 받음 (Body 없음).

// ComputeImageRequest는 이미지의 모든 CVE 점수 계산 요청입니다.
type ComputeImageRequest struct {
	ImageDigest string `json:"image_digest" binding:"required"`
}
