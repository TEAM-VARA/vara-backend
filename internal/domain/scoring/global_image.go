package scoring

import "time"

// ─────────────────────────────────────────
// Image Global Score 보강 (작업 B-3a)
// ─────────────────────────────────────────
//
// 작업 B-1의 ImageGlobalScore에 영속화/조회용 필드와 헬퍼를 추가합니다.
// 기존 ImageGlobalScore 구조는 그대로 두고, 부족한 필드만 별도 타입 또는 확장으로 분리.
//
// 주의: 기존 internal/domain/scoring/global.go의 ImageGlobalScore 정의가 있다면
// 여기 정의와 충돌하지 않도록 합니다. (이 파일은 추가 헬퍼/캐시 도우미만 정의)

// ImageGlobalCacheTTL: image_global_scores의 캐시 TTL.
//	cve_global_scores의 TTL과 동일하게 24시간 (의존 데이터의 신선도와 맞춤).
const ImageGlobalCacheTTL = 24 * time.Hour

// ClassifyImageRiskLevel은 image의 max_score를 등급으로 분류합니다.
//	"Critical" : score >= 90
//	"High"     : score >= 70
//	"Medium"   : score >= 40
//	"Low"      : score >  0
//	"None"     : score == 0
func ClassifyImageRiskLevel(score float64) string {
	switch {
	case score >= 90:
		return "Critical"
	case score >= 70:
		return "High"
	case score >= 40:
		return "Medium"
	case score > 0:
		return "Low"
	default:
		return "None"
	}
}

// ImageGlobalRecord는 image_global_scores 테이블의 한 행을 표현합니다.
// 작업 B-1의 ImageGlobalScore와 별개 타입 (영속화/조회 전용).
type ImageGlobalRecord struct {
	ImageDigest string  `json:"image_digest"`
	Image       string  `json:"image"`

	CVECount      int     `json:"cve_count"`
	MaxScore      float64 `json:"max_score"`
	AvgScore      float64 `json:"avg_score"`
	TopCVE        string  `json:"top_cve,omitempty"`

	CriticalCount int `json:"critical_count"`
	HighCount     int `json:"high_count"`
	MediumCount   int `json:"medium_count"`
	LowCount      int `json:"low_count"`

	ActiveCount int `json:"active_count"`
	POCCount    int `json:"poc_count"`
	NoneCount   int `json:"none_count"`

	ComputedAt time.Time `json:"computed_at"`
	ExpiresAt  time.Time `json:"expires_at"`

	// 편의 필드 (DB에 없음, 응답에 포함)
	RiskLevel string `json:"risk_level,omitempty"`
}
