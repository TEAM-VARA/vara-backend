package scoring

import "sync/atomic"

// Weights는 Risk Scoring 전역 가중치 설정입니다 (scoring_weights 단일행에 대응).
//
// 점수 계산(ComputeFinalScore/ComputeGlobalScore/EvaluateToxic)은 CurrentWeights()를 통해
// 이 값을 읽는다. 서버 기동 시 DB값으로 SetWeights, 대시보드 PUT 시에도 SetWeights.
type Weights struct {
	FinalGlobal   float64 `json:"final_weight_global"`
	FinalExposure float64 `json:"final_weight_exposure"`

	GlobalCVSS float64 `json:"global_weight_cvss"`
	GlobalEPSS float64 `json:"global_weight_epss"`
	GlobalSSVC float64 `json:"global_weight_ssvc"`

	ToxicCritical float64 `json:"toxic_critical"`
	ToxicHigh     float64 `json:"toxic_high"`
	ToxicMedium   float64 `json:"toxic_medium"`

	// 위험 등급 컷(Final/Local 공용). 0 <= caution < warning < emergency <= 100.
	CutEmergency float64 `json:"cut_emergency"`
	CutWarning   float64 `json:"cut_warning"`
	CutCaution   float64 `json:"cut_caution"`
}

// DefaultWeights는 코드 기본값입니다 (DB 미설정/로드 실패 시 폴백).
func DefaultWeights() Weights {
	return Weights{
		FinalGlobal:   FinalWeightGlobal,
		FinalExposure: FinalWeightExposure,
		GlobalCVSS:    GlobalWeightCVSS,
		GlobalEPSS:    GlobalWeightEPSS,
		GlobalSSVC:    GlobalWeightSSVC,
		ToxicCritical: 1.5,
		ToxicHigh:     1.3,
		ToxicMedium:   1.2,
		CutEmergency:  75,
		CutWarning:    50,
		CutCaution:    25,
	}
}

// currentWeights는 race-safe 전역 현재 가중치. 미설정 시 DefaultWeights로 폴백.
var currentWeights atomic.Pointer[Weights]

// SetWeights는 전역 현재 가중치를 갱신합니다 (race-safe). 서버 기동·가중치 PUT 시 호출.
func SetWeights(w Weights) {
	currentWeights.Store(&w)
}

// CurrentWeights는 현재 적용 중인 가중치를 반환합니다. 미설정 시 DefaultWeights.
func CurrentWeights() Weights {
	if p := currentWeights.Load(); p != nil {
		return *p
	}
	return DefaultWeights()
}

// ClusterPosture는 AI 가중치 추천의 "데이터 근거"로 쓰는 클러스터 현황 요약입니다.
// (final/exposure/toxic은 클러스터 최신 snapshot 기준, CVE는 스코어링된 전체 CVE 기준)
type ClusterPosture struct {
	TotalPods          int            `json:"total_pods"`
	GradeCounts        map[string]int `json:"grade_counts"`         // risk_level → 파드 수
	ExposedPods        int            `json:"exposed_pods"`         // 인터넷 노출 파드 수
	ToxicMatchedPods   int            `json:"toxic_matched_pods"`   // toxic 룰 매칭(배수>1) 파드 수
	MaxToxicMultiplier float64        `json:"max_toxic_multiplier"` // 관측된 최대 배수
	ScoredCVEs         int            `json:"scored_cves"`          // 점수화된 CVE 총수
	KevCVEs            int            `json:"kev_cves"`             // KEV 등재 CVE 수
	CVESeverity        map[string]int `json:"cve_severity"`         // CRITICAL/HIGH/... → 수
	AvgEPSS            float64        `json:"avg_epss"`             // 평균 EPSS(0~1)
}

// WeightsRecommendation은 AI가 제안한 가중치 + 근거입니다.
// ⚠ 추천만 반환하며 자동 적용하지 않습니다 — 운영자가 확인 후 PUT /scoring/weights로 적용.
type WeightsRecommendation struct {
	Recommended Weights        `json:"recommended"`       // 정규화·검증 통과한 추천값
	Current     Weights        `json:"current"`           // 현재 적용 중 가중치(비교용)
	Rationale   string         `json:"rationale"`         // 한국어 종합 근거
	Confidence  float64        `json:"confidence"`        // 0~1
	Posture     ClusterPosture `json:"posture"`           // 추천에 사용한 통계
	Profile     string         `json:"profile,omitempty"` // 운영자 입력(에코)
	Note        string         `json:"note,omitempty"`
}

// ToxicMultiplierForSeverity는 Severity(Critical/High/Medium)에 해당하는 설정 배수를 반환합니다.
// 그 외(또는 미매칭)는 1.0.
func (w Weights) ToxicMultiplierForSeverity(severity string) float64 {
	switch severity {
	case "Critical":
		return w.ToxicCritical
	case "High":
		return w.ToxicHigh
	case "Medium":
		return w.ToxicMedium
	}
	return 1.0
}
